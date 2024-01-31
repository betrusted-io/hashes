#[allow(dead_code)]
/// The globally searchable name for the SHA-512 accelerator engine server
pub const SERVER_NAME_SHA512: &str = "_Sha512 hardware accelerator server_"; // not used in hosted config

mod rkyv_enum;
pub use rkyv_enum::*;

/// Command requesting the hardware engine to pad and finalize a hash
#[derive(Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct Sha2Finalize {
    pub id: [u32; 3],
    pub result: Sha2Result,
    pub length_in_bits: Option<u64>,
}

/// Define the valid configuration for the hardware engine
#[derive(num_derive::FromPrimitive, num_derive::ToPrimitive, Debug, Copy, Clone)]
pub(crate) enum Sha2Config {
    Sha512,
    Sha512Trunc256,
}

/// Buffer for holding data being sent to the hash engine. It is sized to maximize the utilization
/// of a single page of memory.
#[derive(Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct Sha2Update {
    pub id: [u32; 3], // our unique identifier so the server knows who the request is coming from
    pub buffer: [u8; 3968], /* leave one SHA chunk-sized space for overhead, so the whole message fits in one
                             * page of memory */
    pub len: u16, // length of just this buffer, fits in 16 bits
}

/// Action opcodes for the main server.
#[allow(dead_code)]
#[derive(num_derive::FromPrimitive, num_derive::ToPrimitive, Debug)]
pub(crate) enum Opcode {
    /// Acquire an exclusive lock on the hardware
    /// sends a 96-bit random key + config word, returns true or false if acquisition was successful
    /// note: 96-bit space has a pcollision=10^-18 for 400,000 concurrent hash requests,
    /// pcollision=10^-15 for 13,000,000 concurrent hash requests.
    /// for context, a typical consumer SSD has an uncorrectable bit error rate of 10^-15,
    /// and we probably expect about 3-4 concurrent hash requests in the worst case.
    /// Acquisition will always fail if a Suspend request is pending.
    AcquireExclusive,

    /// Used by higher level coordination processes to acquire a lock on the hardware unit
    /// to prevent any new transactions from occurring. The lock is automatically cleared on
    /// a resume, or by an explicit release
    AcquireSuspendLock,
    /// this is to be used if we decided in the end we aren't going to suspend.
    AbortSuspendLock,

    /// sends a buffer of [u8] for updating the hash
    /// This function will fail if the hardware was shut down with a suspend/resume while hashing
    Update,

    /// finalizes a hash, but exclusive lock is kept. Return value is the requested hash.
    /// This function will fail if the hardware was shut down with a suspend/resume while hashing
    Finalize,

    /// drops the lock on hardware, resets state
    /// finalize and reset are split to maintain API compatibility with the Digest API
    Reset,

    /// a function that can be polled to determine if the block has been currently acquired
    IsIdle,

    /// exit the server
    Quit,
    #[cfg(feature = "event_wait")]
    IrqEvent,
}

/// Suspend/resume operations, as utilized by the internal suspend/resume manager thread
#[derive(num_derive::FromPrimitive, num_derive::ToPrimitive, Debug)]
pub(crate) enum SusResOps {
    /// Suspend/resume callback
    SuspendResume,
    /// exit the thread
    Quit,
}

/// Define the valid fallback strategies
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum FallbackStrategy {
    /// Use hardware engine if it is immediately available, otherwise, fall back to a software implementation
    HardwareThenSoftware = 0,
    /// Use only a server-local software implementation. More performant on small hashes (less than a few hundred bytes).
    SoftwareOnly = 1,
    /// Wait for hardware to become ready. Can potentially deadlock, but useful for situations where a software
    /// hash would simply be unacceptably long (for example, doing hash verification of the entire kernel disk image)
    WaitForHardware = 2,
}
impl From<usize> for FallbackStrategy {
    fn from(value: usize) -> Self {
        match value {
            0 => FallbackStrategy::HardwareThenSoftware,
            1 => FallbackStrategy::SoftwareOnly,
            2 => FallbackStrategy::WaitForHardware,
            _ => FallbackStrategy::HardwareThenSoftware,
        }
    }
}
