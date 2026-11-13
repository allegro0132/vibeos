//! One-time publication of the admitted board's immutable operation tables.
//! This registry selects implementations; it does not grant device authority.
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicU8, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoardId {
    QemuVirt,
    MilkvDuo,
    MilkvMars,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockBackend {
    None,
    Pio,
    Queued,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkBackend {
    None,
    Packet,
    Queued,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyBackend {
    None,
    Queued,
    Jitter,
}

pub struct Firmware {
    pub board: BoardId,
    pub platform: &'static crate::boot::BootPlatform,
    pub early: &'static crate::devices::EarlyDevices,
    pub block_backend: BlockBackend,
    pub network_backend: NetworkBackend,
    pub entropy_backend: EntropyBackend,
    pub block_first_sector: u64,
    pub block_sector_count: u64,
    pub pio_block: Option<&'static crate::block::PioBlockDevice>,
    pub queued_block: Option<&'static crate::queued_block::Device>,
    pub packet: Option<&'static crate::network::Device>,
    pub queued_packet: Option<&'static crate::queued_network::Device>,
    pub entropy: Option<&'static crate::entropy::EntropyDevice>,
    pub transport: Option<&'static crate::device_transport::Host>,
    pub pci: Option<&'static crate::pci::Host>,
    pub usb: Option<&'static crate::usb::Host>,
    pub polling_usb: Option<&'static crate::usb_polling::Host>,
    pub components: &'static [&'static str],
}
struct Slot {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<Firmware>>,
}
// The boot hart writes once; Release/Acquire publishes all immutable data.
unsafe impl Sync for Slot {}
static SLOT: Slot = Slot {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(MaybeUninit::uninit()),
};

/// # Safety
/// Called only by the admitted boot hart, before any device access or secondary
/// release. Every supplied instance must have exclusive firmware ownership.
pub unsafe fn publish(value: Firmware) -> Result<(), crate::boot::BootError> {
    SLOT.state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| crate::boot::BootError::AlreadyInitialized)?;
    (*SLOT.value.get()).write(value);
    SLOT.state.store(2, Ordering::Release);
    Ok(())
}
pub fn get() -> &'static Firmware {
    assert_eq!(
        SLOT.state.load(Ordering::Acquire),
        2,
        "platform not admitted"
    );
    // SAFETY: initialized once and never changed after the release publication.
    unsafe { (&*SLOT.value.get()).assume_init_ref() }
}
pub fn component_enabled(id: &str) -> bool {
    get().components.contains(&id)
}
