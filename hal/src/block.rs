//! Synchronous block-device contract for firmware-owned PIO instances.
//! No DMA address or caller buffer is retained after an operation returns.
//! Asynchronous DMA queue backends use a separate completion contract.
use crate::AddressRange;

pub const MAX_TRANSFER_BLOCKS: u32 = 256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    OutOfRange,
    TimedOut,
    DeviceIo,
    Unsupported,
    Protocol,
    InvalidConfiguration,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Diagnostics {
    pub command: u8,
    pub interrupt_status: u32,
    pub present_state: u32,
}

/// All operations target one permanently allocated firmware instance.
///
/// # Safety
/// The consumer must serialize initialization and every operation, including
/// diagnostics. Initialization requires all earlier calls to have returned.
/// The provider must not retain slices or callbacks. `published` is called
/// once before the first potentially mutating command reaches the device,
/// including when that command subsequently fails; it is not called for
/// validation failures. Successful writes/flushes include durable completion
/// to the extent supported by the media's protocol.
pub struct PioBlockDevice {
    pub resource_kind: &'static str,
    pub name: &'static str,
    pub registers: AddressRange,
    pub irq: u32,
    pub initialize: unsafe fn(u64, fn() -> u64, fn(core::fmt::Arguments<'_>)) -> Result<u64, Error>,
    pub read: unsafe fn(u64, &mut [u8]) -> Result<(), Error>,
    pub write: unsafe fn(u64, &[u8], bool, &mut dyn FnMut()) -> Result<(), Error>,
    pub flush: unsafe fn(&mut dyn FnMut()) -> Result<(), Error>,
    pub diagnostics: unsafe fn() -> Diagnostics,
    /// Optional explicit bring-up diagnostic, never used by ordinary I/O.
    pub probe_read: Option<unsafe fn(u64, &mut [u8], usize) -> (usize, Result<(), Error>)>,
}
extern "Rust" {
    static VIBEOS_PIO_BLOCK_DEVICE: PioBlockDevice;
}
pub fn pio_device() -> &'static PioBlockDevice {
    // SAFETY: the final firmware defines one immutable operation table.
    unsafe { &VIBEOS_PIO_BLOCK_DEVICE }
}

/// The only physical sector interval admitted to an ordinary block service.
/// Partition layout policy chooses it; the controller never chooses it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockWindow {
    first: u64,
    count: u64,
}
impl BlockWindow {
    pub fn new(capacity: u64, first: u64, count: u64) -> Result<Self, Error> {
        if count == 0
            || first
                .checked_add(count)
                .filter(|end| *end <= capacity)
                .is_none()
        {
            return Err(Error::OutOfRange);
        }
        Ok(Self { first, count })
    }
    pub fn translate(&self, logical_first: u64, bytes: usize) -> Result<u64, Error> {
        if bytes == 0 || bytes % 512 != 0 {
            return Err(Error::Protocol);
        }
        let blocks = u64::try_from(bytes / 512).map_err(|_| Error::OutOfRange)?;
        if logical_first
            .checked_add(blocks)
            .filter(|end| *end <= self.count)
            .is_none()
        {
            return Err(Error::OutOfRange);
        }
        self.first
            .checked_add(logical_first)
            .ok_or(Error::OutOfRange)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partition_translation_never_admits_boot_or_tail_sectors() {
        let window = BlockWindow::new(1000, 128, 512).unwrap();
        assert_eq!(window.translate(0, 512), Ok(128));
        assert_eq!(window.translate(511, 512), Ok(639));
        assert_eq!(window.translate(0, 512 * 512), Ok(128));
        assert_eq!(window.translate(511, 1024), Err(Error::OutOfRange));
        assert_eq!(window.translate(512, 512), Err(Error::OutOfRange));
        assert_eq!(window.translate(u64::MAX, 512), Err(Error::OutOfRange));
        assert_eq!(window.translate(0, 0), Err(Error::Protocol));
        assert_eq!(window.translate(0, 513), Err(Error::Protocol));
        assert_eq!(BlockWindow::new(1000, 900, 101), Err(Error::OutOfRange));
        assert_eq!(
            BlockWindow::new(u64::MAX, u64::MAX - 1, 2),
            Err(Error::OutOfRange)
        );
        assert_eq!(BlockWindow::new(1000, 0, 0), Err(Error::OutOfRange));
    }
}
