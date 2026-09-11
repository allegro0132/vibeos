//! Statically composed asynchronous entropy source. Kernel policy owns claims,
//! deadlines, interrupt delivery and quarantine after an unconfirmed reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    Busy,
    Protocol,
    Unsupported,
    DriverRestarted,
    IdentityExhausted,
    Quarantined,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submission {
    pub epoch: u64,
    pub serial: u64,
}
pub const MAX_RANDOM_BYTES: usize = 64;
/// Controller-independent IRQ observations. Firmware translates and acknowledges
/// hardware status before returning; no register bit encoding crosses into the
/// kernel. Neither event is proof that a request completed successfully.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Events {
    pub completion: bool,
    pub state_changed: bool,
}
/// Firmware selects completion delivery; scheduling intervals belong to kernel
/// policy. Polling callbacks must remain bounded and must not require IRQ ack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionMode { Interrupt, Polling }
/// Storage retained by the sole driver incarnation. This description does not
/// allocate memory or grant DMA reachability; drivers own those mappings.
#[derive(Clone, Copy, Debug)]
pub enum Backing {
    /// A stable CPU-visible slab also used by hardware DMA.
    Dma { cpu_base: fn() -> usize, bytes: usize },
    /// Private controller/PIO state with no hardware DMA allocation.
    DriverOwned,
}
/// # Safety
/// Engine operations require exclusive ownership of the instance and its backing
/// state (including the DMA pool when present). Discovery runs before claims.
/// Completion reads may not race mutation.
/// Acknowledgement and quiesce must not borrow mutable instance state. Buffers
/// are copied only at finish; no caller pointer may be published to hardware.
/// A failed reset retains instance/backing ownership until confirmed retirement.
pub struct EntropyDevice {
    /// Firmware admits one entropy endpoint after resources are mapped.
    pub discover: unsafe fn() -> Option<crate::device_transport::Descriptor>,
    pub resource_kind: &'static str,
    pub transport_name: &'static str,
    /// Hardware-only best-effort stop for inconsistent CPU ownership. Must not
    /// mutate/drop software engine state, clear pending tokens or release DMA.
    /// Success is not permission to reuse an instance with an unknown CPU owner.
    pub quiesce: unsafe fn(crate::device_transport::Descriptor, usize) -> bool,
    pub completion_mode: CompletionMode,
    /// Hardware queue capacity for diagnostics, not the kernel request limit.
    pub queue_size: u16,
    pub backing: Backing,
    pub prepare: unsafe fn(usize, usize, u64, usize) -> Result<(), Error>,
    pub start: unsafe fn() -> Result<(), Error>,
    pub epoch: unsafe fn() -> u64,
    pub accepted_features: unsafe fn() -> u64,
    pub operational: unsafe fn() -> bool,
    pub submit: unsafe fn(usize) -> Result<Submission, Error>,
    pub completion: unsafe fn(Submission) -> bool,
    pub finish: unsafe fn(Submission, &mut [u8]) -> Result<usize, Error>,
    pub require_reset: unsafe fn(),
    pub reset_and_prepare: unsafe fn(u64, usize) -> Result<(), Error>,
    pub shutdown: unsafe fn(usize) -> Result<(), Error>,
    pub confirmed_reset: unsafe fn(usize, usize, usize) -> bool,
    pub acknowledge: unsafe fn(usize) -> Events,
}
extern "Rust" {
    static VIBEOS_ENTROPY_DEVICE: EntropyDevice;
}
pub fn device() -> &'static EntropyDevice {
    unsafe { &VIBEOS_ENTROPY_DEVICE }
}

/// Associates an opaque driver completion with a non-reused invocation token.
/// Serial numbers survive controller resets, so a stale waiter cannot observe
/// a new request after the hardware queue index wraps or is reset to zero.
pub struct Pending<T: Copy> {
    serial: u64,
    active: Option<(Submission, T)>,
}
impl<T: Copy> Pending<T> {
    pub const fn new() -> Self {
        Self {
            serial: 0,
            active: None,
        }
    }
    /// Reserve before publishing to hardware; rejected hardware submissions
    /// may consume serial numbers but may never cause serial reuse.
    pub fn reserve(&mut self, epoch: u64) -> Result<Submission, Error> {
        if self.active.is_some() {
            return Err(Error::Busy);
        }
        if epoch == 0 {
            return Err(Error::IdentityExhausted);
        }
        self.serial = self.serial.checked_add(1).ok_or(Error::IdentityExhausted)?;
        Ok(Submission {
            epoch,
            serial: self.serial,
        })
    }
    pub fn publish(&mut self, token: Submission, value: T) {
        assert!(self.active.is_none() && token.serial == self.serial);
        self.active = Some((token, value));
    }
    pub fn get(&self, token: Submission) -> Option<T> {
        self.active
            .filter(|(current, _)| *current == token)
            .map(|(_, value)| value)
    }
    pub fn clear(&mut self) {
        self.active = None;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_tokens_reject_stale_epochs_and_survive_reset() {
        let mut pending = Pending::new();
        assert_eq!(pending.reserve(0), Err(Error::IdentityExhausted));
        let first = pending.reserve(1).unwrap();
        pending.publish(first, 42);
        assert_eq!(pending.reserve(1), Err(Error::Busy));
        assert_eq!(pending.get(first), Some(42));
        assert_eq!(pending.get(Submission { epoch: 2, ..first }), None);
        pending.clear();
        assert_eq!(pending.get(first), None);
        let next = pending.reserve(1).unwrap();
        pending.publish(next, 43);
        assert_ne!(first, next);
        assert_eq!(pending.get(first), None);
        assert_eq!(pending.get(next), Some(43));
        pending.clear();
        pending.serial = u64::MAX;
        assert_eq!(pending.reserve(2), Err(Error::IdentityExhausted));
    }
}
