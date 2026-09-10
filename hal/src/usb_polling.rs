//! Static polling USB host contract for HID, BOT storage and CDC Ethernet.
//! Telemetry retains the existing diagnostic layout for console compatibility.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    InvalidDescription,
    CoreNotFound(u32),
    AhbIdleTimedOut,
    CoreResetTimedOut,
    HostModeTimedOut,
    UnsupportedDma(u8),
    DmaAddressTooWide,
    NoDevice,
    PortResetTimedOut,
    BufferTooSmall,
    InvalidDescriptor,
    TransferTimedOut,
    TransferFailed(u32),
    Stalled,
    Nak,
    StorageProtocol,
    StorageCommandFailed(u8),
    StorageCswSignature(u32),
    StorageCswTag(u32),
    StorageCswResidue(u32),
    StorageBlockSize(u32),
    StorageCbwLength(usize),
    TransferLength { expected: usize, actual: usize },
    StorageDataLength { expected: usize, actual: usize },
    StorageCswLength(usize),
    StorageCapacityTooLarge,
    StorageOutOfRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Speed {
    High,
    Full,
    Low,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    pub address: u8,
    pub speed: Speed,
    pub usb_version: u16,
    pub device_class: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub max_packet_size_0: u8,
    pub configuration_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HidKeyboardInfo {
    pub interface: u8,
    pub endpoint_in: u8,
    pub max_packet_size: u16,
    pub interval_ms: u16,
    pub protocol: HidKeyboardProtocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HidKeyboardProtocol {
    Boot,
    Report,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MassStorageInfo {
    pub configuration: u8,
    pub interface: u8,
    pub endpoint_in: u8,
    pub endpoint_out: u8,
    pub max_packet_size_in: u16,
    pub max_packet_size_out: u16,
    pub capacity_sectors: Option<u64>,
    pub block_size: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CdcEcmInfo {
    pub configuration: u8,
    pub control_interface: u8,
    pub data_interface: u8,
    pub data_alternate: u8,
    pub endpoint_in: u8,
    pub endpoint_out: u8,
    pub max_packet_size_in: u16,
    pub max_packet_size_out: u16,
    pub status_endpoint: Option<u8>,
    pub status_max_packet_size: u16,
    pub status_interval_ms: u16,
    pub mac_string_index: u8,
    pub mac_address: Option<[u8; 6]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CdcCarrierStatus {
    pub link_up: Option<bool>,
    pub rtl815x_phystatus: Option<u16>,
}

pub const MAX_CONFIGURATION_INTERFACES: usize = 8;
pub const MAX_INTERFACE_ENDPOINTS: usize = 8;
pub const MAX_DEVICE_CONFIGURATIONS: usize = 8;
pub const MAX_HID_REPORT_DESCRIPTOR_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceInfo {
    pub number: u8,
    pub alternate: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub hid_report_length: u16,
    pub interrupt_in: Option<u8>,
    pub max_packet_size: u16,
    pub interval: u8,
    pub bulk_in: Option<u8>,
    pub bulk_out: Option<u8>,
    pub bulk_in_max_packet_size: u16,
    pub bulk_out_max_packet_size: u16,
    pub cdc_mac_string_index: Option<u8>,
    pub endpoints: [Option<EndpointInfo>; MAX_INTERFACE_ENDPOINTS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointInfo {
    pub address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HidReportDescriptor {
    pub interface: u8,
    pub declared_length: u16,
    bytes: [u8; MAX_HID_REPORT_DESCRIPTOR_BYTES],
    length: usize,
}

impl HidReportDescriptor {
    pub fn new(
        interface: u8,
        declared_length: u16,
        bytes: [u8; MAX_HID_REPORT_DESCRIPTOR_BYTES],
        length: usize,
    ) -> Result<Self, Error> {
        if length > bytes.len() {
            return Err(Error::InvalidDescriptor);
        }
        Ok(Self {
            interface,
            declared_length,
            bytes,
            length,
        })
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationInfo {
    pub value: u8,
    pub total_length: u16,
    pub declared_interfaces: u8,
    pub interfaces: [Option<InterfaceInfo>; MAX_CONFIGURATION_INTERFACES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HubInfo {
    pub address: u8,
    pub ports: u8,
    pub active_port: Option<u8>,
    pub child_speed: Option<Speed>,
    pub port_status: u16,
}

pub const MAX_HUB_CHILDREN: usize = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HubChildInfo {
    pub device: DeviceInfo,
    pub parent_hub_address: u8,
    pub port: u8,
    pub port_status: u16,
    pub depth: u8,
    pub tt_hub_address: Option<u8>,
    pub tt_port: Option<u8>,
}

pub const MAX_USB_BUS_PATH_DEPTH: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbBusPath {
    pub ports: [u8; MAX_USB_BUS_PATH_DEPTH],
    pub depth: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HidInputBatch {
    bytes: [u8; 18],
    length: usize,
}

impl HidInputBatch {
    pub const fn new() -> Self {
        Self {
            bytes: [0; 18],
            length: 0,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub fn push(&mut self, byte: u8) {
        if self.length < self.bytes.len() {
            self.bytes[self.length] = byte;
            self.length += 1;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    pub core_id: u32,
    pub release: u16,
    pub irq: u32,
    pub host_channels: u8,
    pub dynamic_fifo: bool,
    pub dma_architecture: u8,
    pub fifo_depth_words: u16,
    pub dedicated_fifos: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Telemetry {
    pub clock_enable_1: u32,
    pub clock_enable_2: u32,
    pub role_override: u32,
    pub gusbcfg: u32,
    pub hprt0: u32,
    pub phy_utmi_control: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub info: Info,
    pub connected: bool,
    pub device: Option<DeviceInfo>,
    pub child: Option<DeviceInfo>,
    pub children: [Option<HubChildInfo>; MAX_HUB_CHILDREN],
    pub hub: Option<HubInfo>,
    pub hubs: [Option<HubInfo>; MAX_HUB_CHILDREN],
    pub configuration: Option<ConfigurationInfo>,
    pub configurations: [Option<ConfigurationInfo>; MAX_DEVICE_CONFIGURATIONS],
    pub configuration_device_address: Option<u8>,
    pub report_descriptor: Option<HidReportDescriptor>,
    pub keyboard: Option<HidKeyboardInfo>,
    pub keyboard_device_address: Option<u8>,
    pub mass_storage: Option<MassStorageInfo>,
    pub storage_device_address: Option<u8>,
    pub cdc_ecm: Option<CdcEcmInfo>,
    pub cdc_ecm_device_address: Option<u8>,
    pub telemetry: Telemetry,
}

pub const MAX_ETHERNET_FRAME_BYTES: usize = 1_536;

/// # Safety
/// The caller serializes every operation, including reads. Initialize must
/// succeed before any other call. Firmware owns the controller and DMA for
/// the lifetime of the system; buffers are borrowed only until return.
/// Initialization failure must permit retry without publishing a partial host.
pub struct Host {
    pub initialize: unsafe fn(hz: u64, time: fn() -> u64) -> Result<Info, Error>,
    pub connected: unsafe fn() -> bool,
    pub info: unsafe fn() -> Info,
    pub network_bus_path: unsafe fn() -> Option<UsbBusPath>,
    pub snapshot: unsafe fn() -> Snapshot,
    pub device: unsafe fn() -> Option<DeviceInfo>,
    pub keyboard: unsafe fn() -> Option<HidKeyboardInfo>,
    pub telemetry: unsafe fn() -> Telemetry,
    pub enumerate_device: unsafe fn() -> Result<Option<DeviceInfo>, Error>,
    pub configure_hid_keyboard: unsafe fn() -> Result<Option<HidKeyboardInfo>, Error>,
    pub configure_mass_storage: unsafe fn() -> Result<Option<MassStorageInfo>, Error>,
    pub switch_rtl8151_install_mode: unsafe fn() -> Result<bool, Error>,
    pub configure_cdc_ecm: unsafe fn() -> Result<Option<CdcEcmInfo>, Error>,
    pub receive_cdc_ecm: unsafe fn(output: &mut [u8]) -> Result<usize, Error>,
    pub transmit_cdc_ecm: unsafe fn(frame: &[u8]) -> Result<(), Error>,
    pub poll_cdc_ecm_carrier: unsafe fn() -> Result<CdcCarrierStatus, Error>,
    pub read_sector: unsafe fn(sector: u64) -> Result<[u8; 512], Error>,
    pub write_sector: unsafe fn(sector: u64, bytes: &[u8; 512]) -> Result<(), Error>,
    pub hub_topology_changed: unsafe fn() -> Result<bool, Error>,
    pub poll_keyboard: unsafe fn() -> Result<HidInputBatch, Error>,
}
extern "Rust" {
    static VIBEOS_POLLING_USB_HOST: Host;
}
pub fn host() -> &'static Host {
    unsafe { &VIBEOS_POLLING_USB_HOST }
}

/// Owned, implementation-private rollback words, interpreted only by platform
/// callbacks. This is part of static Rust composition, not a dynamic module ABI.
pub struct PlatformState(pub [usize; 4]);
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PlatformTelemetry {
    pub clock_enable_1: u32,
    pub clock_enable_2: u32,
    pub role_override: u32,
    pub phy_utmi_control: u32,
}
/// # Safety
/// Caller serializes preparation, rollback and controller access. Failed
/// preparation must restore any resources it changed. On subsequent controller
/// failure, rollback consumes the exact successful prepare token once. After
/// success the controller retains platform resources until shutdown; dropping
/// the token alone does not undo initialization. DMA operations synchronize all
/// required cache levels on the selected SoC.
pub struct Platform {
    pub prepare: unsafe fn(u64, fn() -> u64) -> Result<PlatformState, Error>,
    pub rollback: unsafe fn(PlatformState),
    pub telemetry: unsafe fn() -> PlatformTelemetry,
    pub dma: &'static crate::memory::DmaOps,
}
