//! SHA-512
use crate::api::*;
use crate::{consts, sha512::compress512};
use core::sync::atomic::{AtomicU32, Ordering};
use core::{fmt, slice::from_ref};
use digest::Reset;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, OutputSizeUser, TruncSide,
        UpdateCore, VariableOutputCore,
    },
    typenum::{Unsigned, U128, U64},
    HashMarker, InvalidOutputSize, Output,
};
use num_traits::ToPrimitive;
use xous::{send_message, Message};
use xous_ipc::Buffer as XousBuffer;

/// we have to make the HW_CONN static because the Digest crate assumes you can clone objects
/// and recycle them. However, it's not a problem for every server to have a unique connection
/// to the hasher service, if that's what it comes down to. The burden for tracking connections is on the
/// connector's side, not on the server's side; so when the connecting process that calls this
/// library dies, this static data dies with it.
static HW_CONN: AtomicU32 = AtomicU32::new(0);
/// a unique-enough random ID number to prove we own our connection to the hashing engine hardware
static TOKEN: [AtomicU32; 3] = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

/// Core block-level SHA-512 hasher with variable output size, using a hardware accelerator.
///
/// Supports initialization only for 32 and 64 byte output sizes,
/// i.e. 256 and 512 bits respectively. Other sizes (224 and 384 bits) fall back to software
/// emulation.
#[derive(Clone)]
pub struct Sha512VarCoreHw {
    /// software emulation state
    state: consts::State512,
    block_len: u128,
    /// whether or not this current hasher instance will use software or hardware acceleration
    use_soft: bool,
    /// specifies the strategy for fallback in case multiple hashes are initiated simultaneously
    strategy: FallbackStrategy,
    /// specifies the hash type
    config: Option<Sha2Config>,
    /// track if a hash is in progress
    in_progress: bool,
    /// track the length of the message processed so far
    length: u64,
    /// output size
    output_size: usize,
}

impl HashMarker for Sha512VarCoreHw {}

impl BlockSizeUser for Sha512VarCoreHw {
    type BlockSize = U128;
}

impl BufferKindUser for Sha512VarCoreHw {
    type BufferKind = Eager;
}

impl UpdateCore for Sha512VarCoreHw {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        if self.use_soft {
            self.block_len += blocks.len() as u128;
            compress512(&mut self.state, blocks);
        } else {
            for chunk in blocks
                .as_ref()
                .chunks(3968 / Sha512VarCoreHw::block_size())
                .into_iter()
            {
                // one SHA512 block (128 bytes) short of 4096 to give space for struct overhead in page remap
                // handling
                let mut update = Sha2Update {
                    id: [
                        TOKEN[0].load(Ordering::Relaxed),
                        TOKEN[1].load(Ordering::Relaxed),
                        TOKEN[2].load(Ordering::Relaxed),
                    ],
                    buffer: [0; 3968],
                    len: 0,
                };
                for (block_index, block) in chunk.iter().enumerate() {
                    self.length += (block.len() as u64) * 8; // we need to keep track of length in bits
                    update.len += block.len() as u16;
                    update.buffer[(block_index * block.len())..(block_index + 1) * block.len()]
                        .copy_from_slice(block.as_slice());
                }
                let buf = XousBuffer::into_buf(update).expect("couldn't map chunk into IPC buffer");
                buf.lend(self.ensure_conn(), Opcode::Update.to_u32().unwrap())
                    .expect("hardware rejected our hash chunk!");
            }
        }
    }
}

impl OutputSizeUser for Sha512VarCoreHw {
    type OutputSize = U64;
}

impl VariableOutputCore for Sha512VarCoreHw {
    const TRUNC_SIDE: TruncSide = TruncSide::Left;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let state;
        let use_soft;
        let config;
        match output_size {
            28 => {
                state = consts::H512_224;
                use_soft = true;
                config = None;
            }
            32 => {
                state = consts::H512_256;
                use_soft = false;
                config = Some(Sha2Config::Sha512Trunc256);
            }
            48 => {
                state = consts::H512_384;
                use_soft = true;
                config = None;
            }
            64 => {
                state = consts::H512_512;
                use_soft = false;
                config = Some(Sha2Config::Sha512);
            }
            _ => return Err(InvalidOutputSize),
        }
        let block_len = 0;
        let mut core = Self {
            state,
            block_len,
            use_soft,
            config,
            strategy: FallbackStrategy::HardwareThenSoftware,
            in_progress: false,
            length: 0,
            output_size,
        };
        // try to acquire a lock on the hardware, if the algorithm even supports it.
        // this can update use_soft if a lock already exists, and we have a software fallback strategy.
        if let Some(c) = config {
            core.try_acquire_hw(c);
        }
        Ok(core)
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64 as u128;
        let bit_len = 8 * (buffer.get_pos() as u128 + bs * self.block_len);

        if self.use_soft {
            buffer.len128_padding_be(bit_len, |b| compress512(&mut self.state, from_ref(b)));

            for (chunk, v) in out.chunks_exact_mut(8).zip(self.state.iter()) {
                chunk.copy_from_slice(&v.to_be_bytes());
            }
        } else {
            // send the last chunk to the Sha2 HW engine. Padding is handled in hardware.
            let mut update = Sha2Update {
                id: [
                    TOKEN[0].load(Ordering::Relaxed),
                    TOKEN[1].load(Ordering::Relaxed),
                    TOKEN[2].load(Ordering::Relaxed),
                ],
                buffer: [0; 3968],
                len: 0,
            };
            self.length += buffer.get_pos() as u64 * 8; // we need to keep track of length in bits
            update.len = buffer.get_pos() as u16;
            update.buffer[..buffer.get_pos()].copy_from_slice(buffer.get_data());
            let buf = XousBuffer::into_buf(update).expect("couldn't map chunk into IPC buffer");
            buf.lend(self.ensure_conn(), Opcode::Update.to_u32().unwrap())
                .expect("hardware rejected our hash chunk!");

            let result = Sha2Finalize {
                id: [
                    TOKEN[0].load(Ordering::Relaxed),
                    TOKEN[1].load(Ordering::Relaxed),
                    TOKEN[2].load(Ordering::Relaxed),
                ],
                result: Sha2Result::Uninitialized,
                length_in_bits: None,
            };
            let mut buf =
                XousBuffer::into_buf(result).expect("couldn't map memory for the return buffer");
            buf.lend_mut(self.ensure_conn(), Opcode::Finalize.to_u32().unwrap())
                .expect("couldn't finalize");

            let returned: Sha2Finalize = buf.to_original().expect("couldn't decode return buffer");
            match returned.result {
                Sha2Result::Sha512Result(s) => {
                    assert!(self.output_size == 64, "Got wrong result type");
                    log::debug!("bits hashed: {}", self.length);
                    if self.length
                        != returned
                            .length_in_bits
                            .expect("hardware did not return a length field!")
                    {
                        panic!("Sha512 hardware did not hash as many bits as we had expected!")
                    }
                    for (dest, &src) in out.chunks_exact_mut(1).zip(s.iter()) {
                        dest.copy_from_slice(&[src])
                    }
                }
                Sha2Result::Sha512Trunc256Result(s) => {
                    assert!(self.output_size == 32, "Got wrong result type");
                    if self.length
                        != returned
                            .length_in_bits
                            .expect("hardware did not return a length field!")
                    {
                        panic!("Sha512 hardware did not hash as many bits as we had expected!")
                    }
                    for (dest, &src) in out.chunks_exact_mut(1).zip(s.iter()) {
                        dest.copy_from_slice(&[src])
                    }
                }
                Sha2Result::SuspendError => {
                    panic!("Hardware was suspended during Sha512 operation, result is invalid.");
                }
                Sha2Result::Uninitialized => {
                    panic!("Hardware didn't copy Sha512 hash result to the return buffer.");
                }
                Sha2Result::IdMismatch => {
                    panic!("Hardware is not currently processing our block, finalize call has no meaning.");
                }
            }
        }
        self.reset_hw();
    }
}

impl Reset for Sha512VarCoreHw {
    fn reset(&mut self) {
        self.reset_hw();
    }
}

impl Sha512VarCoreHw {
    /// This function exists, but is unfortunately inaccessible because it is buried within trait
    /// wrappers that hide it.
    pub fn set_fallback_strategy(&mut self, strat: FallbackStrategy) {
        self.strategy = strat;
    }

    pub(crate) fn ensure_conn(&self) -> u32 {
        if HW_CONN.load(Ordering::Relaxed) == 0 {
            let xns = xous_names::XousNames::new().unwrap();
            HW_CONN.store(
                xns.request_connection_blocking(crate::api::SERVER_NAME_SHA512)
                    .expect("Can't connect to Sha512 server"),
                Ordering::Relaxed,
            );
            // split it this way to minimize number of round-trip calls to the trng.
            let id1: u64 = rand::random();
            let id2: u32 = rand::random();
            TOKEN[0].store((id1 >> 32) as u32, Ordering::Relaxed);
            TOKEN[1].store(id1 as u32, Ordering::Relaxed);
            TOKEN[2].store(id2, Ordering::Relaxed);
        }
        HW_CONN.load(Ordering::Relaxed)
    }
    pub fn is_idle(&self) -> Result<bool, xous::Error> {
        let response = send_message(
            self.ensure_conn(),
            Message::new_blocking_scalar(Opcode::IsIdle.to_usize().unwrap(), 0, 0, 0, 0),
        )
        .expect("Couldn't make IsIdle query");
        if let xous::Result::Scalar1(result) = response {
            if result != 0 {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(xous::Error::InternalError)
        }
    }
    pub fn acquire_suspend_lock(&self) -> Result<bool, xous::Error> {
        let response = send_message(
            self.ensure_conn(),
            Message::new_blocking_scalar(
                Opcode::AcquireSuspendLock.to_usize().unwrap(),
                0,
                0,
                0,
                0,
            ),
        )
        .expect("Couldn't issue AcquireSuspendLock message");
        if let xous::Result::Scalar1(result) = response {
            if result != 0 {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(xous::Error::InternalError)
        }
    }
    pub fn abort_suspend(&self) -> Result<(), xous::Error> {
        // we ignore the result and just turn it into () once we get anything back, as abort_suspend
        // "can't fail"
        send_message(
            self.ensure_conn(),
            Message::new_blocking_scalar(Opcode::AbortSuspendLock.to_usize().unwrap(), 0, 0, 0, 0),
        )
        .map(|_| ())
    }
    pub(crate) fn try_acquire_hw(&mut self, config: Sha2Config) {
        if !self.in_progress && self.strategy != FallbackStrategy::SoftwareOnly {
            loop {
                let conn = self.ensure_conn(); // also ensures the ID
                let response = send_message(
                    conn,
                    Message::new_blocking_scalar(
                        Opcode::AcquireExclusive.to_usize().unwrap(),
                        TOKEN[0].load(Ordering::Relaxed) as usize,
                        TOKEN[1].load(Ordering::Relaxed) as usize,
                        TOKEN[2].load(Ordering::Relaxed) as usize,
                        config.to_usize().unwrap(),
                    ),
                )
                .expect("couldn't send AcquireExclusive message to Sha2 hardware!");
                if let xous::Result::Scalar1(result) = response {
                    if result != 0 {
                        self.use_soft = false;
                        self.in_progress = true;
                        break;
                    } else {
                        if self.strategy == FallbackStrategy::HardwareThenSoftware {
                            self.use_soft = true;
                            self.in_progress = true;
                            break;
                        } else {
                            // this is hardware-exclusive mode, we block until we can get the hardware
                            xous::yield_slice();
                        }
                    }
                } else {
                    log::error!("AcquireExclusive had an unexpected error: {:?}", response);
                    panic!("Internal error in AcquireExclusive");
                }
            }
        } else if self.strategy == FallbackStrategy::SoftwareOnly {
            self.use_soft = true;
            self.in_progress = true;
        }
    }
    pub(crate) fn reset_hw(&mut self) {
        send_message(
            self.ensure_conn(),
            Message::new_blocking_scalar(
                Opcode::Reset.to_usize().unwrap(),
                TOKEN[0].load(Ordering::Relaxed) as usize,
                TOKEN[1].load(Ordering::Relaxed) as usize,
                TOKEN[2].load(Ordering::Relaxed) as usize,
                0,
            ),
        )
        .expect("couldn't send reset to hardware");
        // reset internal flags
        self.length = 0;
        self.in_progress = false;
        self.use_soft = true;
    }
}

impl AlgorithmName for Sha512VarCoreHw {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha512")
    }
}

impl fmt::Debug for Sha512VarCoreHw {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha512VarCore { ... }")
    }
}
