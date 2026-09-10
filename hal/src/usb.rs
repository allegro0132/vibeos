//! USB host inventory, bounded HID input and firmware operation contracts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidMmioRegion,
    MmioOutOfRange,
    ResetTimedOut,
    UnsupportedPageSize,
    ScratchpadsUnsupported,
    StartTimedOut,
    CommandTimedOut,
    CommandFailed(u8),
    NoSlots,
    PortResetTimedOut,
    PortNotEnabled,
    InvalidSlot,
    TransferTimedOut,
    TransferFailed(u8),
    DescriptorMalformed,
    UnsupportedConfiguration,
    NoMassStorage,
    StorageProtocol,
    StorageCommandFailed(u8),
    StorageOutOfRange,
    StorageCswSignature(u32),
    StorageCswTag(u32),
    StorageCswResidue(u32),
    StorageBlockSize(u32),
}

/// A virtual MMIO mapping already established by the embedding kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioRegion {
    base: usize,
    length: usize,
}

impl MmioRegion {
    pub const fn new(base: usize, length: usize) -> Result<Self, Error> {
        if base & 7 != 0 || length < 0x20 || base.checked_add(length).is_none() {
            return Err(Error::InvalidMmioRegion);
        }
        Ok(Self { base, length })
    }

    pub const fn base(self) -> usize {
        self.base
    }

    pub const fn length(self) -> usize {
        self.length
    }

    pub const fn contains(self, address: usize, bytes: usize) -> bool {
        address >= self.base
            && match address.checked_add(bytes) {
                Some(end) => end <= self.base + self.length,
                None => false,
            }
    }
}

pub const HID_INPUT_CAPACITY: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HidInputBatch {
    bytes: [u8; HID_INPUT_CAPACITY],
    length: u8,
    dropped: usize,
}

impl HidInputBatch {
    pub const fn new() -> Self {
        Self {
            bytes: [0; HID_INPUT_CAPACITY],
            length: 0,
            dropped: 0,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub const fn dropped(&self) -> usize {
        self.dropped
    }

    pub fn push(&mut self, byte: u8) {
        let index = usize::from(self.length);
        if index < HID_INPUT_CAPACITY {
            self.bytes[index] = byte;
            self.length += 1;
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }
}

impl Default for HidInputBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    HidKeyboard,
    MassStorage,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub version: u16,
    pub mmio_base: usize,
    pub max_slots: u8,
    pub max_ports: u8,
    pub connected_ports: u8,
    pub addressed_devices: u8,
    pub irq: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub port: u8,
    pub slot: u8,
    pub speed: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_class: u8,
    pub usb_version: u16,
    pub kind: DeviceKind,
    pub interface: u8,
    pub configuration: u8,
    pub endpoint_in: u8,
    pub endpoint_out: u8,
    pub max_packet_in: u16,
    pub max_packet_out: u16,
    pub capacity_sectors: u64,
}

/// # Safety
/// The consumer serializes all controller operations; initialization happens
/// after PCI resources are mapped and assigned. DMA remains firmware-owned.
/// IRQ acknowledgement cannot borrow mutable controller state. Callbacks and
/// sector buffers are borrowed only for the call and never retained by DMA.
pub struct Host {
    pub initialize: unsafe fn(MmioRegion, u32) -> Result<Info, Error>,
    pub info: unsafe fn() -> Info,
    pub devices: unsafe fn(&mut dyn FnMut(DeviceInfo)),
    pub interrupt_context: unsafe fn() -> usize,
    pub enable_interrupts: unsafe fn(),
    pub disable_interrupts: unsafe fn(),
    pub acknowledge: unsafe fn(usize) -> bool,
    pub read_sector: unsafe fn(u64) -> Result<[u8; 512], Error>,
    pub write_sector: unsafe fn(u64, &[u8; 512]) -> Result<(), Error>,
    pub service: unsafe fn() -> HidInputBatch,
}
extern "Rust" {
    static VIBEOS_USB_HOST: Host;
}
pub fn host() -> &'static Host {
    unsafe { &VIBEOS_USB_HOST }
}
