//! CV1800B platform bring-up for the integrated Synopsys DWC2 USB 2.0 OTG core.
//!
//! This first layer owns clocks, the SoC role override and the DWC2 host core.
//! USB transactions and class drivers intentionally live above this crate.

#![cfg_attr(not(test), no_std)]

use core::{
    cell::UnsafeCell,
    sync::atomic::{compiler_fence, AtomicBool, Ordering},
};
use vibeos_hal::Dwc2Description;

const TOP_USB_ROLE: usize = 0x48;
const CLKGEN_OFFSET: usize = 0x2000;
const CLK_ENABLE_1: usize = CLKGEN_OFFSET + 0x04;
const CLK_ENABLE_2: usize = CLKGEN_OFFSET + 0x08;
const USB_CLOCKS_ENABLE_1: u32 = 0xf000_0000;
const USB_CLOCKS_ENABLE_2: u32 = 1;
const USB_ROLE_MASK: u32 = 0xc0;
const USB_ROLE_HOST: u32 = 0x40;
const USB_VBUS_POWER: u32 = 1 << 1;

const PHY_UTMI_CONTROL: usize = 0x14;
const PHY_UTMI_RESET: u32 = 0x18b;
const PHY_UTMI_RESET_SETTLE_US: u64 = 100;

const GAHBCFG: usize = 0x008;
const GUSBCFG: usize = 0x00c;
const GRSTCTL: usize = 0x010;
const GINTSTS: usize = 0x014;
const GINTMSK: usize = 0x018;
const GHWCFG2: usize = 0x048;
const GHWCFG3: usize = 0x04c;
const GHWCFG4: usize = 0x050;
const GSNPSID: usize = 0x040;
const HCFG: usize = 0x400;
const HPRT0: usize = 0x440;
const HC_BASE: usize = 0x500;
const HC_STRIDE: usize = 0x20;
const HCCHAR: usize = 0x00;
const HCSPLT: usize = 0x04;
const HCINT: usize = 0x08;
const HCINTMSK: usize = 0x0c;
const HCTSIZ: usize = 0x10;
const HCDMA: usize = 0x14;

const GAHBCFG_GLOBAL_INTERRUPT: u32 = 1;
const GAHBCFG_BURST_INCR4: u32 = 3 << 1;
const GAHBCFG_DMA_ENABLE: u32 = 1 << 5;
const GUSBCFG_FORCE_HOST: u32 = 1 << 29;
const GUSBCFG_FORCE_DEVICE: u32 = 1 << 30;
const GRSTCTL_CORE_SOFT_RESET: u32 = 1;
const GRSTCTL_CORE_SOFT_RESET_DONE: u32 = 1 << 29;
const GRSTCTL_AHB_IDLE: u32 = 1 << 31;
const GRSTCTL_RX_FIFO_FLUSH: u32 = 1 << 4;
const GRSTCTL_TX_FIFO_FLUSH: u32 = 1 << 5;
const GRSTCTL_TX_FIFO_ALL: u32 = 0x10 << 6;
const GINTSTS_CURRENT_MODE_HOST: u32 = 1;
const HPRT_CONNECT: u32 = 1;
const HPRT_ENABLE: u32 = 1 << 2;
const HPRT_RESET: u32 = 1 << 8;
const HPRT_CHANGE_BITS: u32 = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5);
const HPRT_POWER: u32 = 1 << 12;
const HPRT_SPEED_SHIFT: u32 = 17;
const HPRT_SPEED_MASK: u32 = 0x3 << HPRT_SPEED_SHIFT;

const HCCHAR_ENDPOINT_SHIFT: u32 = 11;
const HCCHAR_DIRECTION_IN: u32 = 1 << 15;
const HCCHAR_LOW_SPEED: u32 = 1 << 17;
const HCCHAR_TYPE_SHIFT: u32 = 18;
const HCCHAR_ADDRESS_SHIFT: u32 = 22;
const HCCHAR_DISABLE: u32 = 1 << 30;
const HCCHAR_ENABLE: u32 = 1 << 31;
const HCTSIZ_PACKET_SHIFT: u32 = 19;
const HCTSIZ_PID_SHIFT: u32 = 29;
const HCINT_TRANSFER_COMPLETE: u32 = 1;
const HCINT_CHANNEL_HALTED: u32 = 1 << 1;
const HCINT_STALL: u32 = 1 << 3;
const HCINT_NAK: u32 = 1 << 4;
const HCINT_ACK: u32 = 1 << 5;
const HCINT_NYET: u32 = 1 << 6;
const HCINT_ERRORS: u32 = (1 << 2) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10);

const HCSPLT_PORT_MASK: u32 = 0x7f;
const HCSPLT_HUB_ADDRESS_SHIFT: u32 = 7;
const HCSPLT_TRANSACTION_ALL: u32 = 3 << 14;
const HCSPLT_COMPLETE: u32 = 1 << 16;
const HCSPLT_ENABLE: u32 = 1 << 31;

const REGISTER_TIMEOUT_MS: u64 = 10;
const HOST_MODE_TIMEOUT_MS: u64 = 110;
const TRANSFER_TIMEOUT_MS: u64 = 250;
const DMA_BYTES: usize = 1_024;
const MAX_NAK_RETRIES: usize = 32;
const MAX_COMPLETE_SPLIT_RETRIES: usize = 16;
const HID_REPORT_BYTES: usize = 8;
const APPLE_NKRO_REPORT_BYTES: usize = 15;
const HID_INPUT_BYTES: usize = 18;
const DWC2_CORE_REVISION_4_20A: u16 = 0x420a;
const USB_CLASS_HUB: u8 = 9;
const USB_CLASS_MASS_STORAGE: u8 = 8;
const USB_MASS_STORAGE_SCSI: u8 = 6;
const USB_MASS_STORAGE_BULK_ONLY: u8 = 0x50;
const USB_DESCRIPTOR_HUB: u16 = 0x29;
const USB_PORT_FEAT_RESET: u16 = 4;
const USB_PORT_FEAT_POWER: u16 = 8;
const USB_PORT_FEAT_C_RESET: u16 = 20;
const USB_PORT_STAT_CONNECTION: u16 = 1;
const USB_PORT_STAT_ENABLE: u16 = 1 << 1;
const USB_PORT_STAT_LOW_SPEED: u16 = 1 << 9;
const USB_PORT_STAT_HIGH_SPEED: u16 = 1 << 10;
const MAX_HUB_PORTS: u8 = 15;

static CLAIMED: AtomicBool = AtomicBool::new(false);

#[repr(C, align(64))]
struct DmaBuffer(UnsafeCell<[u8; DMA_BYTES]>);

unsafe impl Sync for DmaBuffer {}

#[cfg_attr(target_arch = "riscv64", link_section = ".dma")]
static DMA: DmaBuffer = DmaBuffer(UnsafeCell::new([0; DMA_BYTES]));

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

pub const MAX_CONFIGURATION_INTERFACES: usize = 8;
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HidReportDescriptor {
    pub interface: u8,
    pub declared_length: u16,
    bytes: [u8; MAX_HID_REPORT_DESCRIPTOR_BYTES],
    length: usize,
}

impl HidReportDescriptor {
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

pub const MAX_HUB_CHILDREN: usize = MAX_HUB_PORTS as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HubChildInfo {
    pub device: DeviceInfo,
    pub parent_hub_address: u8,
    pub port: u8,
    pub port_status: u16,
    pub depth: u8,
}

const MAX_HUB_DEPTH: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SplitTarget {
    hub_address: u8,
    port: u8,
}

#[derive(Clone, Copy)]
struct TransferTarget {
    address: u8,
    endpoint_zero_max_packet: u16,
    speed: Speed,
    split: Option<SplitTarget>,
}

#[derive(Clone, Copy)]
enum KeyboardLayout {
    Boot,
    AppleReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HidInputBatch {
    bytes: [u8; HID_INPUT_BYTES],
    length: usize,
}

impl HidInputBatch {
    const fn new() -> Self {
        Self {
            bytes: [0; HID_INPUT_BYTES],
            length: 0,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    fn push(&mut self, byte: u8) {
        if self.length < self.bytes.len() {
            self.bytes[self.length] = byte;
            self.length += 1;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl SetupPacket {
    pub const fn to_bytes(self) -> [u8; 8] {
        let value = self.value.to_le_bytes();
        let index = self.index.to_le_bytes();
        let length = self.length.to_le_bytes();
        [
            self.request_type,
            self.request,
            value[0],
            value[1],
            index[0],
            index[1],
            length[0],
            length[1],
        ]
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

/// Exclusive ownership of the fixed CV1800B DWC2 host instance.
pub struct Controller {
    description: Dwc2Description,
    info: Info,
    timebase_hz: u64,
    time: fn() -> u64,
    device_address: u8,
    endpoint_zero_max_packet: u16,
    speed: Speed,
    device: Option<DeviceInfo>,
    child: Option<DeviceInfo>,
    children: [Option<HubChildInfo>; MAX_HUB_CHILDREN],
    hub: Option<HubInfo>,
    hubs: [Option<HubInfo>; MAX_HUB_CHILDREN],
    split: Option<SplitTarget>,
    configuration: Option<ConfigurationInfo>,
    report_descriptor: Option<HidReportDescriptor>,
    keyboard: Option<HidKeyboardInfo>,
    keyboard_target: Option<TransferTarget>,
    mass_storage: Option<MassStorageInfo>,
    storage_target: Option<TransferTarget>,
    storage_pid_in: DataPid,
    storage_pid_out: DataPid,
    storage_tag: u32,
    keyboard_layout: KeyboardLayout,
    keyboard_pid: DataPid,
    keyboard_last: [u8; HID_REPORT_BYTES],
    keyboard_nkro_last: [u8; APPLE_NKRO_REPORT_BYTES],
}

impl Controller {
    /// Enable the CV1800B USB clocks, select host role, reset DWC2 and power
    /// its root port. No interrupt or DMA is enabled at this stage.
    ///
    /// # Safety
    /// All ranges in `description` must be identity-mapped, strongly ordered
    /// MMIO for the CV1800B and remain exclusively owned until `shutdown`.
    /// `time` must advance monotonically in `timebase_hz` ticks.
    pub unsafe fn initialize(
        description: Dwc2Description,
        timebase_hz: u64,
        time: fn() -> u64,
    ) -> Result<Self, Error> {
        if !validate_description(description) || timebase_hz == 0 {
            return Err(Error::InvalidDescription);
        }
        if CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Busy);
        }

        let old_clocks_1 = unsafe { soc_read(description, CLK_ENABLE_1) };
        let old_clocks_2 = unsafe { soc_read(description, CLK_ENABLE_2) };
        let old_role = unsafe { soc_read(description, TOP_USB_ROLE) };
        unsafe {
            soc_write(
                description,
                CLK_ENABLE_1,
                old_clocks_1 | USB_CLOCKS_ENABLE_1,
            );
            soc_write(
                description,
                CLK_ENABLE_2,
                old_clocks_2 | USB_CLOCKS_ENABLE_2,
            );
            soc_write(
                description,
                TOP_USB_ROLE,
                (old_role & !USB_ROLE_MASK) | USB_ROLE_HOST | USB_VBUS_POWER,
            );

            // CV1800B's wrapper requires its UTMI state machine to be reset
            // after the five USB clocks are enabled. This is the same pulse
            // used by the vendor FSBL before it touches the DWC2 core.
            let old_utmi = phy_read(description, PHY_UTMI_CONTROL);
            phy_write(description, PHY_UTMI_CONTROL, PHY_UTMI_RESET);
            compiler_fence(Ordering::SeqCst);
            phy_write(description, PHY_UTMI_CONTROL, old_utmi);
        }
        compiler_fence(Ordering::SeqCst);
        delay_us(timebase_hz, time, PHY_UTMI_RESET_SETTLE_US);

        let result = unsafe { Self::initialize_core(description, timebase_hz, time) };
        match result {
            Ok(controller) => Ok(controller),
            Err(error) => {
                unsafe {
                    soc_write(description, TOP_USB_ROLE, old_role);
                    soc_write(description, CLK_ENABLE_2, old_clocks_2);
                    soc_write(description, CLK_ENABLE_1, old_clocks_1);
                }
                CLAIMED.store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    unsafe fn initialize_core(
        description: Dwc2Description,
        timebase_hz: u64,
        time: fn() -> u64,
    ) -> Result<Self, Error> {
        let core_id = unsafe { core_read(description, GSNPSID) };
        if !is_dwc2_core_id(core_id) {
            return Err(Error::CoreNotFound(core_id));
        }

        unsafe {
            core_write(description, GINTMSK, 0);
            let ahbcfg = core_read(description, GAHBCFG) & !GAHBCFG_GLOBAL_INTERRUPT;
            core_write(description, GAHBCFG, ahbcfg);
        }
        wait_for(
            description,
            GRSTCTL,
            GRSTCTL_AHB_IDLE,
            true,
            REGISTER_TIMEOUT_MS,
            timebase_hz,
            time,
        )
        .map_err(|_| Error::AhbIdleTimedOut)?;

        let usb_config = unsafe { core_read(description, GUSBCFG) };
        unsafe {
            core_write(
                description,
                GUSBCFG,
                usb_config & !(GUSBCFG_FORCE_DEVICE | GUSBCFG_FORCE_HOST),
            );
            core_write(
                description,
                GRSTCTL,
                core_read(description, GRSTCTL) | GRSTCTL_CORE_SOFT_RESET,
            );
        }
        if reset_uses_done_handshake(core_id) {
            wait_for(
                description,
                GRSTCTL,
                GRSTCTL_CORE_SOFT_RESET_DONE,
                true,
                REGISTER_TIMEOUT_MS,
                timebase_hz,
                time,
            )
            .map_err(|_| Error::CoreResetTimedOut)?;
            unsafe {
                let reset = core_read(description, GRSTCTL);
                core_write(
                    description,
                    GRSTCTL,
                    (reset & !GRSTCTL_CORE_SOFT_RESET) | GRSTCTL_CORE_SOFT_RESET_DONE,
                );
            }
        } else {
            wait_for(
                description,
                GRSTCTL,
                GRSTCTL_CORE_SOFT_RESET,
                false,
                REGISTER_TIMEOUT_MS,
                timebase_hz,
                time,
            )
            .map_err(|_| Error::CoreResetTimedOut)?;
        }
        wait_for(
            description,
            GRSTCTL,
            GRSTCTL_AHB_IDLE,
            true,
            REGISTER_TIMEOUT_MS,
            timebase_hz,
            time,
        )
        .map_err(|_| Error::AhbIdleTimedOut)?;
        unsafe {
            let usb_config = core_read(description, GUSBCFG);
            core_write(
                description,
                GUSBCFG,
                (usb_config & !GUSBCFG_FORCE_DEVICE) | GUSBCFG_FORCE_HOST,
            );
        }
        wait_for(
            description,
            GINTSTS,
            GINTSTS_CURRENT_MODE_HOST,
            true,
            HOST_MODE_TIMEOUT_MS,
            timebase_hz,
            time,
        )
        .map_err(|_| Error::HostModeTimedOut)?;

        unsafe {
            // UTMI+ at 30/60 MHz uses HCFG.FSLSPClkSel = 0.
            core_write(description, HCFG, core_read(description, HCFG) & !0x3);
            core_write(description, GINTSTS, u32::MAX);
            let port = core_read(description, HPRT0);
            core_write(description, HPRT0, (port & !HPRT_CHANGE_BITS) | HPRT_POWER);
        }

        let hwcfg2 = unsafe { core_read(description, GHWCFG2) };
        let hwcfg3 = unsafe { core_read(description, GHWCFG3) };
        let hwcfg4 = unsafe { core_read(description, GHWCFG4) };
        let dma_architecture = ((hwcfg2 >> 3) & 0x3) as u8;
        if dma_architecture == 0 {
            return Err(Error::UnsupportedDma(dma_architecture));
        }
        let dma_address = DMA.0.get() as usize;
        if dma_address > u32::MAX as usize
            || dma_address.saturating_add(DMA_BYTES) > (1usize << description.dma_address_bits)
        {
            return Err(Error::DmaAddressTooWide);
        }
        unsafe {
            let ahbcfg = core_read(description, GAHBCFG);
            core_write(
                description,
                GAHBCFG,
                (ahbcfg & !0x1e) | GAHBCFG_BURST_INCR4 | GAHBCFG_DMA_ENABLE,
            );
        }
        flush_fifos(description, timebase_hz, time)?;

        let host_channels = host_channel_count(hwcfg2);
        for channel in 0..host_channels {
            halt_channel(description, channel, timebase_hz, time)?;
        }
        Ok(Self {
            description,
            info: Info {
                core_id,
                release: core_id as u16,
                irq: description.irq,
                host_channels,
                dynamic_fifo: hwcfg2 & (1 << 19) != 0,
                dma_architecture,
                fifo_depth_words: (hwcfg3 >> 16) as u16,
                dedicated_fifos: hwcfg4 & (1 << 25) != 0,
            },
            timebase_hz,
            time,
            device_address: 0,
            endpoint_zero_max_packet: 8,
            speed: Speed::Full,
            device: None,
            child: None,
            children: [None; MAX_HUB_CHILDREN],
            hub: None,
            hubs: [None; MAX_HUB_CHILDREN],
            split: None,
            configuration: None,
            report_descriptor: None,
            keyboard: None,
            keyboard_target: None,
            mass_storage: None,
            storage_target: None,
            storage_pid_in: DataPid::Data0,
            storage_pid_out: DataPid::Data0,
            storage_tag: 1,
            keyboard_layout: KeyboardLayout::Boot,
            keyboard_pid: DataPid::Data0,
            keyboard_last: [0; HID_REPORT_BYTES],
            keyboard_nkro_last: [0; APPLE_NKRO_REPORT_BYTES],
        })
    }

    pub const fn info(&self) -> Info {
        self.info
    }

    pub fn connected(&self) -> bool {
        unsafe { core_read(self.description, HPRT0) & HPRT_CONNECT != 0 }
    }

    pub fn telemetry(&self) -> Telemetry {
        Telemetry {
            clock_enable_1: unsafe { soc_read(self.description, CLK_ENABLE_1) },
            clock_enable_2: unsafe { soc_read(self.description, CLK_ENABLE_2) },
            role_override: unsafe { soc_read(self.description, TOP_USB_ROLE) },
            gusbcfg: unsafe { core_read(self.description, GUSBCFG) },
            hprt0: unsafe { core_read(self.description, HPRT0) },
            phy_utmi_control: unsafe { phy_read(self.description, 0x14) },
        }
    }

    pub const fn device(&self) -> Option<DeviceInfo> {
        self.device
    }

    pub const fn child(&self) -> Option<DeviceInfo> {
        self.child
    }

    pub const fn children(&self) -> [Option<HubChildInfo>; MAX_HUB_CHILDREN] {
        self.children
    }

    pub const fn hubs(&self) -> [Option<HubInfo>; MAX_HUB_CHILDREN] {
        self.hubs
    }

    pub const fn keyboard(&self) -> Option<HidKeyboardInfo> {
        self.keyboard
    }

    pub const fn keyboard_device_address(&self) -> Option<u8> {
        match self.keyboard_target {
            Some(target) => Some(target.address),
            None => None,
        }
    }

    pub const fn mass_storage(&self) -> Option<MassStorageInfo> {
        self.mass_storage
    }

    pub const fn storage_device_address(&self) -> Option<u8> {
        match self.storage_target {
            Some(target) => Some(target.address),
            None => None,
        }
    }

    /// Select the detected SCSI Bulk-Only interface and probe its logical
    /// block capacity. Only LUN zero and 512-byte logical blocks are supported.
    pub fn configure_mass_storage(&mut self) -> Result<Option<MassStorageInfo>, Error> {
        let Some(mut storage) = self.mass_storage else {
            return Ok(None);
        };
        let target = self.storage_target.ok_or(Error::NoDevice)?;
        self.select_target(target);
        self.control_transfer(
            SetupPacket {
                request_type: 0,
                request: 9,
                value: u16::from(storage.configuration),
                index: 0,
                length: 0,
            },
            &mut [],
        )?;
        self.storage_pid_in = DataPid::Data0;
        self.storage_pid_out = DataPid::Data0;
        self.storage_tag = 1;
        delay_ms(self.timebase_hz, self.time, 10);

        let test_unit_ready = [0x00, 0, 0, 0, 0, 0];
        let mut ready = false;
        for _ in 0..10 {
            match self.bot_command(&test_unit_ready, true, &mut []) {
                Ok(()) => {
                    ready = true;
                    break;
                }
                Err(Error::StorageCommandFailed(_)) => {
                    let request_sense = [0x03, 0, 0, 0, 18, 0];
                    let mut sense = [0; 18];
                    let _ = self.bot_command(&request_sense, true, &mut sense);
                    delay_ms(self.timebase_hz, self.time, 100);
                }
                Err(error) => return Err(error),
            }
        }
        if !ready {
            return Err(Error::StorageCommandFailed(1));
        }

        let read_capacity = [0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut capacity = [0; 8];
        self.bot_command(&read_capacity, true, &mut capacity)?;
        let last_lba = u32::from_be_bytes(capacity[0..4].try_into().unwrap());
        let block_size = u32::from_be_bytes(capacity[4..8].try_into().unwrap());
        if block_size != 512 {
            return Err(Error::StorageBlockSize(block_size));
        }
        if last_lba == u32::MAX {
            return Err(Error::StorageCapacityTooLarge);
        }
        storage.capacity_sectors = Some(u64::from(last_lba) + 1);
        storage.block_size = Some(block_size);
        self.mass_storage = Some(storage);
        Ok(Some(storage))
    }

    pub fn read_sector(&mut self, sector: u64) -> Result<[u8; 512], Error> {
        let storage = self.mass_storage.ok_or(Error::NoDevice)?;
        let capacity = storage.capacity_sectors.ok_or(Error::StorageProtocol)?;
        if sector >= capacity || sector > u64::from(u32::MAX) {
            return Err(Error::StorageOutOfRange);
        }
        let cdb = read_10_cdb(sector as u32);
        let mut bytes = [0; 512];
        self.bot_command(&cdb, true, &mut bytes)?;
        Ok(bytes)
    }

    /// Write one logical sector using SCSI WRITE(10).
    ///
    /// Callers must ensure that overwriting the selected sector is safe.
    pub fn write_sector(&mut self, sector: u64, bytes: &[u8; 512]) -> Result<(), Error> {
        let storage = self.mass_storage.ok_or(Error::NoDevice)?;
        let capacity = storage.capacity_sectors.ok_or(Error::StorageProtocol)?;
        if sector >= capacity || sector > u64::from(u32::MAX) {
            return Err(Error::StorageOutOfRange);
        }
        let cdb = write_10_cdb(sector as u32);
        let mut data = *bytes;
        self.bot_command(&cdb, false, &mut data)
    }

    pub const fn configuration(&self) -> Option<ConfigurationInfo> {
        self.configuration
    }

    pub const fn report_descriptor(&self) -> Option<HidReportDescriptor> {
        self.report_descriptor
    }

    pub const fn hub(&self) -> Option<HubInfo> {
        self.hub
    }

    pub fn hub_topology_changed(&mut self) -> Result<bool, Error> {
        let Some(hub) = self.hub else {
            return Ok(false);
        };
        let root = self.device.ok_or(Error::NoDevice)?;
        let saved = self.current_target();
        self.select_target(TransferTarget {
            address: root.address,
            endpoint_zero_max_packet: u16::from(root.max_packet_size_0),
            speed: root.speed,
            split: None,
        });
        let result = (|| {
            for port in 1..=hub.ports {
                let connected = self.hub_port_status(port)? & USB_PORT_STAT_CONNECTION != 0;
                let enumerated = self
                    .children
                    .iter()
                    .flatten()
                    .any(|child| child.port == port);
                if connected != enumerated {
                    return Ok(true);
                }
            }
            Ok(false)
        })();
        self.select_target(saved);
        result
    }

    /// Reset the directly attached root-port device and complete USB address
    /// and device-descriptor enumeration through endpoint zero.
    pub fn enumerate_device(&mut self) -> Result<Option<DeviceInfo>, Error> {
        if !self.connected() {
            self.device = None;
            self.child = None;
            self.children = [None; MAX_HUB_CHILDREN];
            self.hub = None;
            self.hubs = [None; MAX_HUB_CHILDREN];
            self.split = None;
            self.configuration = None;
            self.report_descriptor = None;
            self.keyboard = None;
            self.keyboard_target = None;
            self.mass_storage = None;
            self.storage_target = None;
            self.device_address = 0;
            return Ok(None);
        }

        self.reset_port()?;
        self.split = None;
        self.speed = port_speed(unsafe { core_read(self.description, HPRT0) })?;
        self.device_address = 0;
        self.endpoint_zero_max_packet = match self.speed {
            Speed::High => 64,
            Speed::Full | Speed::Low => 8,
        };

        let mut descriptor = [0u8; 18];
        let prefix = SetupPacket {
            request_type: 0x80,
            request: 6,
            value: 1 << 8,
            index: 0,
            length: 8,
        };
        if self.control_transfer(prefix, &mut descriptor[..8])? != 8
            || descriptor[0] != 18
            || descriptor[1] != 1
            || !matches!(descriptor[7], 8 | 16 | 32 | 64)
        {
            return Err(Error::InvalidDescriptor);
        }
        self.endpoint_zero_max_packet = u16::from(descriptor[7]);

        self.control_transfer(
            SetupPacket {
                request_type: 0,
                request: 5,
                value: 1,
                index: 0,
                length: 0,
            },
            &mut [],
        )?;
        self.device_address = 1;
        delay_ms(self.timebase_hz, self.time, 2);

        let full = SetupPacket {
            request_type: 0x80,
            request: 6,
            value: 1 << 8,
            index: 0,
            length: descriptor.len() as u16,
        };
        if self.control_transfer(full, &mut descriptor)? != descriptor.len() {
            return Err(Error::InvalidDescriptor);
        }
        let info = parse_device_descriptor(descriptor, self.speed, self.device_address)?;
        self.endpoint_zero_max_packet = u16::from(info.max_packet_size_0);
        self.device = Some(info);
        self.child = None;
        self.children = [None; MAX_HUB_CHILDREN];
        self.hub = None;
        self.hubs = [None; MAX_HUB_CHILDREN];
        self.configuration = None;
        self.report_descriptor = None;
        self.keyboard = None;
        self.keyboard_target = None;
        self.mass_storage = None;
        self.storage_target = None;
        Ok(Some(info))
    }

    /// Select a supported HID keyboard interface exposed by the addressed
    /// device and configure its boot or report protocol input layout.
    pub fn configure_hid_keyboard(&mut self) -> Result<Option<HidKeyboardInfo>, Error> {
        let Some(target) = self.child.or(self.device) else {
            self.keyboard = None;
            self.keyboard_target = None;
            self.mass_storage = None;
            self.storage_target = None;
            return Ok(None);
        };
        if !self.connected() {
            self.keyboard = None;
            self.keyboard_target = None;
            self.mass_storage = None;
            self.storage_target = None;
            return Ok(None);
        }
        let transfer_target = self.current_target();

        let mut header = [0u8; 9];
        let request = SetupPacket {
            request_type: 0x80,
            request: 6,
            value: 2 << 8,
            index: 0,
            length: header.len() as u16,
        };
        if self.control_transfer(request, &mut header)? != header.len() {
            return Err(Error::InvalidDescriptor);
        }
        let total = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if total < header.len() || total > DMA_BYTES {
            return Err(Error::InvalidDescriptor);
        }
        let mut descriptors = [0u8; DMA_BYTES];
        let request = SetupPacket {
            length: total as u16,
            ..request
        };
        if self.control_transfer(request, &mut descriptors[..total])? != total {
            return Err(Error::InvalidDescriptor);
        }
        let (configuration, keyboard) =
            parse_hid_keyboard_configuration(&descriptors[..total], self.speed)?;
        self.configuration = Some(configuration);
        self.mass_storage = find_mass_storage(configuration);
        self.storage_target = self.mass_storage.map(|_| transfer_target);
        self.report_descriptor = None;
        let Some(keyboard) = keyboard else {
            self.keyboard = None;
            if self.child.is_none() && target.device_class == USB_CLASS_HUB {
                self.control_transfer(
                    SetupPacket {
                        request_type: 0,
                        request: 9,
                        value: u16::from(configuration.value),
                        index: 0,
                        length: 0,
                    },
                    &mut [],
                )?;
                let hub = self.configure_hub()?;
                self.hub = Some(hub);
                self.record_hub(hub)?;
                if self.enumerate_hub_children(hub, true, 1)? != 0 {
                    return self.configure_hub_child_functions();
                }
            }
            if let Some(interface) =
                configuration
                    .interfaces
                    .into_iter()
                    .flatten()
                    .find(|interface| {
                        interface.class == 3
                            && interface.interrupt_in.is_some()
                            && interface.hid_report_length != 0
                    })
            {
                self.control_transfer(
                    SetupPacket {
                        request_type: 0,
                        request: 9,
                        value: u16::from(configuration.value),
                        index: 0,
                        length: 0,
                    },
                    &mut [],
                )?;
                let requested =
                    usize::from(interface.hid_report_length).min(MAX_HID_REPORT_DESCRIPTOR_BYTES);
                let mut bytes = [0; MAX_HID_REPORT_DESCRIPTOR_BYTES];
                let length = self.control_transfer(
                    SetupPacket {
                        request_type: 0x81,
                        request: 6,
                        value: 0x22 << 8,
                        index: u16::from(interface.number),
                        length: requested as u16,
                    },
                    &mut bytes[..requested],
                )?;
                self.report_descriptor = Some(HidReportDescriptor {
                    interface: interface.number,
                    declared_length: interface.hid_report_length,
                    bytes,
                    length,
                });
                if is_apple_report_keyboard_descriptor(&bytes[..length]) {
                    self.keyboard = Some(HidKeyboardInfo {
                        interface: interface.number,
                        endpoint_in: interface.interrupt_in.unwrap_or(0),
                        max_packet_size: interface.max_packet_size,
                        interval_ms: hid_poll_interval_ms(self.speed, interface.interval),
                        protocol: HidKeyboardProtocol::Report,
                    });
                    self.keyboard_target = Some(transfer_target);
                    self.keyboard_layout = KeyboardLayout::AppleReport;
                    self.keyboard_pid = DataPid::Data0;
                    self.keyboard_last = [0; HID_REPORT_BYTES];
                    self.keyboard_nkro_last = [0; APPLE_NKRO_REPORT_BYTES];
                }
            }
            return Ok(self.keyboard);
        };

        self.control_transfer(
            SetupPacket {
                request_type: 0,
                request: 9,
                value: u16::from(configuration.value),
                index: 0,
                length: 0,
            },
            &mut [],
        )?;
        self.control_transfer(
            SetupPacket {
                request_type: 0x21,
                request: 11,
                value: 0,
                index: u16::from(keyboard.interface),
                length: 0,
            },
            &mut [],
        )?;
        self.keyboard = Some(keyboard);
        self.keyboard_target = Some(transfer_target);
        self.keyboard_layout = KeyboardLayout::Boot;
        self.keyboard_pid = DataPid::Data0;
        self.keyboard_last = [0; HID_REPORT_BYTES];
        self.keyboard_nkro_last = [0; APPLE_NKRO_REPORT_BYTES];
        Ok(Some(keyboard))
    }

    fn configure_hub_child_functions(&mut self) -> Result<Option<HidKeyboardInfo>, Error> {
        let legacy_child = self.child;

        let mut selected_keyboard = None;
        let mut selected_keyboard_target = None;
        let mut selected_keyboard_layout = KeyboardLayout::Boot;
        let mut selected_keyboard_pid = DataPid::Data0;
        let mut selected_keyboard_last = [0; HID_REPORT_BYTES];
        let mut selected_keyboard_nkro_last = [0; APPLE_NKRO_REPORT_BYTES];
        let mut selected_report_descriptor = None;
        let mut selected_keyboard_configuration = None;
        let mut selected_storage = None;
        let mut selected_storage_target = None;
        let mut selected_storage_configuration = None;

        let mut child_index = 0;
        while child_index < MAX_HUB_CHILDREN {
            let Some(child) = self.children[child_index] else {
                break;
            };
            let target = transfer_target_for_child(child);
            self.select_target(target);
            self.child = Some(child.device);
            self.configuration = None;
            self.report_descriptor = None;
            self.keyboard = None;
            self.keyboard_target = None;
            self.mass_storage = None;
            self.storage_target = None;

            self.configure_hid_keyboard()?;
            let is_hub = child.device.device_class == USB_CLASS_HUB
                || self.configuration.is_some_and(|configuration| {
                    configuration
                        .interfaces
                        .into_iter()
                        .flatten()
                        .any(|interface| interface.class == USB_CLASS_HUB)
                });
            if is_hub {
                if child.depth >= MAX_HUB_DEPTH || child.device.speed != Speed::High {
                    return Err(Error::InvalidDescriptor);
                }
                let configuration = self.configuration.ok_or(Error::InvalidDescriptor)?;
                self.control_transfer(
                    SetupPacket {
                        request_type: 0,
                        request: 9,
                        value: u16::from(configuration.value),
                        index: 0,
                        length: 0,
                    },
                    &mut [],
                )?;
                let nested_hub = self.configure_hub()?;
                self.record_hub(nested_hub)?;
                self.enumerate_hub_children(nested_hub, false, child.depth + 1)?;
                child_index += 1;
                continue;
            }
            if selected_keyboard.is_none() && self.keyboard.is_some() {
                selected_keyboard = self.keyboard;
                selected_keyboard_target = self.keyboard_target;
                selected_keyboard_layout = self.keyboard_layout;
                selected_keyboard_pid = self.keyboard_pid;
                selected_keyboard_last = self.keyboard_last;
                selected_keyboard_nkro_last = self.keyboard_nkro_last;
                selected_report_descriptor = self.report_descriptor;
                selected_keyboard_configuration = self.configuration;
            }
            if selected_storage.is_none() && self.mass_storage.is_some() {
                selected_storage = self.mass_storage;
                selected_storage_target = self.storage_target;
                selected_storage_configuration = self.configuration;
            }
            child_index += 1;
        }

        self.child = legacy_child;
        self.keyboard = selected_keyboard;
        self.keyboard_target = selected_keyboard_target;
        self.keyboard_layout = selected_keyboard_layout;
        self.keyboard_pid = selected_keyboard_pid;
        self.keyboard_last = selected_keyboard_last;
        self.keyboard_nkro_last = selected_keyboard_nkro_last;
        self.report_descriptor = selected_report_descriptor;
        self.mass_storage = selected_storage;
        self.storage_target = selected_storage_target;
        self.configuration = selected_keyboard_configuration.or(selected_storage_configuration);
        if let Some(target) = selected_keyboard_target.or(selected_storage_target) {
            self.select_target(target);
        }
        Ok(selected_keyboard)
    }

    fn record_hub(&mut self, hub: HubInfo) -> Result<(), Error> {
        let index = usize::from(hub.address.saturating_sub(1));
        let slot = self.hubs.get_mut(index).ok_or(Error::InvalidDescriptor)?;
        *slot = Some(hub);
        Ok(())
    }

    fn configure_hub(&mut self) -> Result<HubInfo, Error> {
        let mut descriptor = [0u8; 9];
        let length = self.control_transfer(
            SetupPacket {
                request_type: 0xa0,
                request: 6,
                value: USB_DESCRIPTOR_HUB << 8,
                index: 0,
                length: descriptor.len() as u16,
            },
            &mut descriptor,
        )?;
        let (ports, power_good_ms) = parse_hub_descriptor(&descriptor[..length])?;

        for port in 1..=ports {
            self.hub_port_feature(port, true, USB_PORT_FEAT_POWER)?;
        }
        delay_ms(
            self.timebase_hz,
            self.time,
            u64::from(power_good_ms.max(20)),
        );

        Ok(HubInfo {
            address: self.device_address,
            ports,
            active_port: None,
            child_speed: None,
            port_status: 0,
        })
    }

    fn hub_port_feature(&mut self, port: u8, set: bool, feature: u16) -> Result<(), Error> {
        self.control_transfer(
            SetupPacket {
                request_type: 0x23,
                request: if set { 3 } else { 1 },
                value: feature,
                index: u16::from(port),
                length: 0,
            },
            &mut [],
        )?;
        Ok(())
    }

    fn hub_port_status(&mut self, port: u8) -> Result<u16, Error> {
        let mut status = [0u8; 4];
        if self.control_transfer(
            SetupPacket {
                request_type: 0xa3,
                request: 0,
                value: 0,
                index: u16::from(port),
                length: status.len() as u16,
            },
            &mut status,
        )? != status.len()
        {
            return Err(Error::InvalidDescriptor);
        }
        Ok(u16::from_le_bytes([status[0], status[1]]))
    }

    fn enumerate_hub_children(
        &mut self,
        mut hub: HubInfo,
        reset_table: bool,
        depth: u8,
    ) -> Result<usize, Error> {
        if reset_table {
            self.child = None;
            self.children = [None; MAX_HUB_CHILDREN];
        }
        let hub_target = self.current_target();
        let mut count = self.children.iter().flatten().count();
        let initial_count = count;
        for port in 1..=hub.ports {
            self.select_target(hub_target);
            let status = self.hub_port_status(port)?;
            if status & USB_PORT_STAT_CONNECTION == 0 {
                continue;
            }
            self.hub_port_feature(port, true, USB_PORT_FEAT_RESET)?;
            delay_ms(self.timebase_hz, self.time, 60);
            let reset_status = self.hub_port_status(port)?;
            let _ = self.hub_port_feature(port, false, USB_PORT_FEAT_C_RESET);
            if reset_status & (USB_PORT_STAT_CONNECTION | USB_PORT_STAT_ENABLE)
                != USB_PORT_STAT_CONNECTION | USB_PORT_STAT_ENABLE
            {
                continue;
            }
            let speed = hub_port_speed(reset_status);
            let address = 2u8
                .checked_add(count as u8)
                .ok_or(Error::InvalidDescriptor)?;
            let info = self.enumerate_hub_child(hub, port, speed, address)?;
            let slot = self
                .children
                .get_mut(count)
                .ok_or(Error::InvalidDescriptor)?;
            *slot = Some(HubChildInfo {
                device: info,
                parent_hub_address: hub.address,
                port,
                port_status: reset_status,
                depth,
            });
            if self.child.is_none() {
                self.child = Some(info);
                hub.active_port = Some(port);
                hub.child_speed = Some(speed);
                hub.port_status = reset_status;
            }
            count += 1;
        }
        if self
            .device
            .is_some_and(|device| device.address == hub.address)
        {
            self.hub = Some(hub);
        }
        self.record_hub(hub)?;
        self.select_target(hub_target);
        Ok(count - initial_count)
    }

    fn enumerate_hub_child(
        &mut self,
        hub: HubInfo,
        port: u8,
        speed: Speed,
        address: u8,
    ) -> Result<DeviceInfo, Error> {
        self.split = (speed != Speed::High).then_some(SplitTarget {
            hub_address: hub.address,
            port,
        });
        self.speed = speed;
        self.device_address = 0;
        self.endpoint_zero_max_packet = match speed {
            Speed::High => 64,
            Speed::Full | Speed::Low => 8,
        };

        let mut descriptor = [0u8; 18];
        let prefix = SetupPacket {
            request_type: 0x80,
            request: 6,
            value: 1 << 8,
            index: 0,
            length: 8,
        };
        if self.control_transfer(prefix, &mut descriptor[..8])? != 8
            || descriptor[0] != 18
            || descriptor[1] != 1
            || !matches!(descriptor[7], 8 | 16 | 32 | 64)
        {
            return Err(Error::InvalidDescriptor);
        }
        self.endpoint_zero_max_packet = u16::from(descriptor[7]);

        self.control_transfer(
            SetupPacket {
                request_type: 0,
                request: 5,
                value: u16::from(address),
                index: 0,
                length: 0,
            },
            &mut [],
        )?;
        self.device_address = address;
        delay_ms(self.timebase_hz, self.time, 2);

        let full = SetupPacket {
            request_type: 0x80,
            request: 6,
            value: 1 << 8,
            index: 0,
            length: descriptor.len() as u16,
        };
        if self.control_transfer(full, &mut descriptor)? != descriptor.len() {
            return Err(Error::InvalidDescriptor);
        }
        let info = parse_device_descriptor(descriptor, speed, self.device_address)?;
        self.endpoint_zero_max_packet = u16::from(info.max_packet_size_0);
        Ok(info)
    }

    /// Poll one interrupt-IN keyboard report and return bytes for newly
    /// pressed keys. A USB NAK is normal idle state and produces an empty batch.
    pub fn poll_keyboard(&mut self) -> Result<HidInputBatch, Error> {
        let keyboard = self.keyboard.ok_or(Error::NoDevice)?;
        let target = self.keyboard_target.ok_or(Error::NoDevice)?;
        if !self.connected() {
            self.keyboard = None;
            self.keyboard_target = None;
            return Err(Error::NoDevice);
        }
        self.select_target(target);
        let result = self.channel_transfer(
            self.device_address,
            keyboard.endpoint_in & 0x0f,
            true,
            EndpointType::Interrupt,
            self.keyboard_pid,
            usize::from(keyboard.max_packet_size),
            keyboard.max_packet_size,
            1,
        );
        let actual = match result {
            Ok(actual) => actual,
            Err(Error::Nak) => return Ok(HidInputBatch::new()),
            Err(error) => return Err(error),
        };
        self.keyboard_pid = self.keyboard_pid.toggled();
        match self.keyboard_layout {
            KeyboardLayout::Boot => {
                if actual < HID_REPORT_BYTES {
                    return Err(Error::InvalidDescriptor);
                }
                let mut report = [0u8; HID_REPORT_BYTES];
                unsafe { report.copy_from_slice(&dma_bytes()[..HID_REPORT_BYTES]) };
                let input = decode_hid_report(report, self.keyboard_last);
                self.keyboard_last = report;
                Ok(input)
            }
            KeyboardLayout::AppleReport => {
                let report = unsafe { &dma_bytes()[..actual] };
                match report.first() {
                    Some(1) if report.len() >= 9 => {
                        let mut normalized = [0; HID_REPORT_BYTES];
                        normalized[0] = report[1];
                        normalized[2..7].copy_from_slice(&report[3..8]);
                        let input = decode_hid_report(normalized, self.keyboard_last);
                        self.keyboard_last = normalized;
                        Ok(input)
                    }
                    Some(2) if report.len() >= APPLE_NKRO_REPORT_BYTES => {
                        let mut current = [0; APPLE_NKRO_REPORT_BYTES];
                        current.copy_from_slice(&report[..APPLE_NKRO_REPORT_BYTES]);
                        let input = decode_apple_nkro_report(current, self.keyboard_nkro_last);
                        self.keyboard_nkro_last = current;
                        Ok(input)
                    }
                    Some(_) => Ok(HidInputBatch::new()),
                    None => Err(Error::InvalidDescriptor),
                }
            }
        }
    }

    fn bot_command(&mut self, cdb: &[u8], data_in: bool, data: &mut [u8]) -> Result<(), Error> {
        let target = self.storage_target.ok_or(Error::NoDevice)?;
        self.select_target(target);
        let result = self.bot_command_once(cdb, data_in, data);
        if let Err(error) = result {
            if bot_requires_reset_recovery(error) {
                let _ = self.bot_reset_recovery();
            }
        }
        result
    }

    fn bot_command_once(
        &mut self,
        cdb: &[u8],
        data_in: bool,
        data: &mut [u8],
    ) -> Result<(), Error> {
        const CBW_LENGTH: usize = 31;
        const CSW_LENGTH: usize = 13;
        if cdb.is_empty() || cdb.len() > 16 || data.len() > DMA_BYTES {
            return Err(Error::StorageProtocol);
        }
        let storage = self.mass_storage.ok_or(Error::NoDevice)?;
        let tag = self.storage_tag;
        self.storage_tag = self
            .storage_tag
            .checked_add(1)
            .ok_or(Error::StorageProtocol)?;

        let mut cbw = [0; CBW_LENGTH];
        cbw[0..4].copy_from_slice(&0x4342_5355u32.to_le_bytes());
        cbw[4..8].copy_from_slice(&tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        cbw[12] = if data_in { 0x80 } else { 0 };
        cbw[14] = cdb.len() as u8;
        cbw[15..15 + cdb.len()].copy_from_slice(cdb);
        self.bulk_out(storage.endpoint_out, storage.max_packet_size_out, &cbw)?;
        if !data.is_empty() {
            if data_in {
                let actual = self.bulk_in(storage.endpoint_in, storage.max_packet_size_in, data)?;
                if actual != data.len() {
                    return Err(Error::StorageDataLength {
                        expected: data.len(),
                        actual,
                    });
                }
            } else {
                self.bulk_out(storage.endpoint_out, storage.max_packet_size_out, data)?;
            }
        }
        let mut csw = [0; CSW_LENGTH];
        let csw_length = self.bulk_in(storage.endpoint_in, storage.max_packet_size_in, &mut csw)?;
        if csw_length != CSW_LENGTH {
            return Err(Error::StorageCswLength(csw_length));
        }
        let signature = u32::from_le_bytes(csw[0..4].try_into().unwrap());
        let observed_tag = u32::from_le_bytes(csw[4..8].try_into().unwrap());
        let residue = u32::from_le_bytes(csw[8..12].try_into().unwrap());
        if signature != 0x5342_5355 {
            return Err(Error::StorageCswSignature(signature));
        }
        if observed_tag != tag {
            return Err(Error::StorageCswTag(observed_tag));
        }
        if csw[12] != 0 {
            return Err(Error::StorageCommandFailed(csw[12]));
        }
        if residue != 0 {
            return Err(Error::StorageCswResidue(residue));
        }
        Ok(())
    }

    fn bot_reset_recovery(&mut self) -> Result<(), Error> {
        let storage = self.mass_storage.ok_or(Error::NoDevice)?;
        let target = self.storage_target.ok_or(Error::NoDevice)?;
        self.select_target(target);
        self.control_transfer(
            SetupPacket {
                request_type: 0x21,
                request: 0xff,
                value: 0,
                index: u16::from(storage.interface),
                length: 0,
            },
            &mut [],
        )?;
        for endpoint in [storage.endpoint_in, storage.endpoint_out] {
            self.control_transfer(
                SetupPacket {
                    request_type: 0x02,
                    request: 1,
                    value: 0,
                    index: u16::from(endpoint),
                    length: 0,
                },
                &mut [],
            )?;
        }
        self.storage_pid_in = DataPid::Data0;
        self.storage_pid_out = DataPid::Data0;
        Ok(())
    }

    fn current_target(&self) -> TransferTarget {
        TransferTarget {
            address: self.device_address,
            endpoint_zero_max_packet: self.endpoint_zero_max_packet,
            speed: self.speed,
            split: self.split,
        }
    }

    fn select_target(&mut self, target: TransferTarget) {
        self.device_address = target.address;
        self.endpoint_zero_max_packet = target.endpoint_zero_max_packet;
        self.speed = target.speed;
        self.split = target.split;
    }

    fn bulk_in(
        &mut self,
        endpoint: u8,
        max_packet: u16,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let actual = self.channel_transfer(
            self.device_address,
            endpoint & 0x0f,
            true,
            EndpointType::Bulk,
            self.storage_pid_in,
            output.len(),
            max_packet,
            MAX_NAK_RETRIES,
        )?;
        self.storage_pid_in = advance_pid(self.storage_pid_in, actual, max_packet);
        unsafe { output[..actual].copy_from_slice(&dma_bytes()[..actual]) };
        Ok(actual)
    }

    fn bulk_out(&mut self, endpoint: u8, max_packet: u16, input: &[u8]) -> Result<(), Error> {
        unsafe { dma_bytes()[..input.len()].copy_from_slice(input) };
        let actual = self.channel_transfer(
            self.device_address,
            endpoint & 0x0f,
            false,
            EndpointType::Bulk,
            self.storage_pid_out,
            input.len(),
            max_packet,
            MAX_NAK_RETRIES,
        )?;
        if actual != input.len() {
            return Err(Error::StorageCbwLength(actual));
        }
        self.storage_pid_out = advance_pid(self.storage_pid_out, actual, max_packet);
        Ok(())
    }

    /// Execute one USB control request on the currently addressed endpoint 0.
    /// The returned length is the actual data-stage byte count.
    pub fn control_transfer(
        &mut self,
        setup: SetupPacket,
        data: &mut [u8],
    ) -> Result<usize, Error> {
        let length = usize::from(setup.length);
        if length > data.len() || length > DMA_BYTES {
            return Err(Error::BufferTooSmall);
        }
        let direction_in = setup.request_type & 0x80 != 0;
        unsafe { dma_bytes()[..8].copy_from_slice(&setup.to_bytes()) };
        self.channel_transfer(
            self.device_address,
            0,
            false,
            EndpointType::Control,
            DataPid::Setup,
            8,
            self.endpoint_zero_max_packet,
            MAX_NAK_RETRIES,
        )?;

        let actual = if length == 0 {
            0
        } else {
            if !direction_in {
                unsafe { dma_bytes()[..length].copy_from_slice(&data[..length]) };
            }
            let actual = self.channel_transfer(
                self.device_address,
                0,
                direction_in,
                EndpointType::Control,
                DataPid::Data1,
                length,
                self.endpoint_zero_max_packet,
                MAX_NAK_RETRIES,
            )?;
            if direction_in {
                unsafe { data[..actual].copy_from_slice(&dma_bytes()[..actual]) };
            }
            actual
        };

        self.channel_transfer(
            self.device_address,
            0,
            length == 0 || !direction_in,
            EndpointType::Control,
            DataPid::Data1,
            0,
            self.endpoint_zero_max_packet,
            MAX_NAK_RETRIES,
        )?;
        Ok(actual)
    }

    fn reset_port(&mut self) -> Result<(), Error> {
        if !self.connected() {
            return Err(Error::NoDevice);
        }
        unsafe {
            let port = core_read(self.description, HPRT0);
            core_write(
                self.description,
                HPRT0,
                (port & !HPRT_CHANGE_BITS) | HPRT_POWER | HPRT_RESET,
            );
        }
        delay_ms(self.timebase_hz, self.time, 60);
        unsafe {
            let port = core_read(self.description, HPRT0);
            core_write(
                self.description,
                HPRT0,
                (port & !(HPRT_CHANGE_BITS | HPRT_RESET)) | HPRT_POWER,
            );
        }
        delay_ms(self.timebase_hz, self.time, 20);
        if !self.connected() {
            return Err(Error::NoDevice);
        }
        wait_for(
            self.description,
            HPRT0,
            HPRT_ENABLE,
            true,
            HOST_MODE_TIMEOUT_MS,
            self.timebase_hz,
            self.time,
        )
        .map_err(|_| Error::PortResetTimedOut)
    }

    // Keep the USB transaction tuple visible at the MMIO boundary; grouping
    // these fields would only hide which values are programmed into HCCHAR and
    // HCTSIZ for each control or interrupt transfer.
    #[allow(clippy::too_many_arguments)]
    fn channel_transfer(
        &mut self,
        address: u8,
        endpoint: u8,
        direction_in: bool,
        endpoint_type: EndpointType,
        pid: DataPid,
        length: usize,
        max_packet: u16,
        nak_retries: usize,
    ) -> Result<usize, Error> {
        if length > DMA_BYTES || endpoint > 15 || address > 127 || max_packet == 0 {
            return Err(Error::BufferTooSmall);
        }
        if let Some(split) = self.split {
            return self.split_channel_transfer(
                split,
                address,
                endpoint,
                direction_in,
                endpoint_type,
                pid,
                length,
                max_packet,
                nak_retries,
            );
        }
        let packet_bytes = usize::from(max_packet);
        let packet_count = if length == 0 {
            1
        } else {
            length.div_ceil(packet_bytes)
        };
        let dma_address = DMA.0.get() as usize;

        for _ in 0..nak_retries {
            if direction_in {
                invalidate_range(
                    self.description.cache_line_bytes,
                    dma_address,
                    length.max(1),
                );
            } else {
                clean_range(
                    self.description.cache_line_bytes,
                    dma_address,
                    length.max(1),
                );
            }

            let channel = 0;
            unsafe {
                channel_write(self.description, channel, HCINTMSK, 0);
                channel_write(self.description, channel, HCINT, u32::MAX);
                channel_write(self.description, channel, HCSPLT, 0);
                channel_write(self.description, channel, HCDMA, dma_address as u32);
                channel_write(
                    self.description,
                    channel,
                    HCTSIZ,
                    length as u32
                        | (packet_count as u32) << HCTSIZ_PACKET_SHIFT
                        | (pid as u32) << HCTSIZ_PID_SHIFT,
                );
                let mut character = u32::from(max_packet)
                    | u32::from(endpoint) << HCCHAR_ENDPOINT_SHIFT
                    | (endpoint_type as u32) << HCCHAR_TYPE_SHIFT
                    | u32::from(address) << HCCHAR_ADDRESS_SHIFT
                    | HCCHAR_ENABLE;
                if direction_in {
                    character |= HCCHAR_DIRECTION_IN;
                }
                if self.speed == Speed::Low {
                    character |= HCCHAR_LOW_SPEED;
                }
                channel_write(self.description, channel, HCCHAR, character);
            }

            let started = (self.time)();
            let timeout = ticks_for_ms(self.timebase_hz, TRANSFER_TIMEOUT_MS);
            loop {
                let status = unsafe { channel_read(self.description, channel, HCINT) };
                if status & HCINT_CHANNEL_HALTED != 0 {
                    unsafe { channel_write(self.description, channel, HCINT, status) };
                    if status & HCINT_TRANSFER_COMPLETE != 0 {
                        let remaining =
                            unsafe { channel_read(self.description, channel, HCTSIZ) & 0x7ffff }
                                as usize;
                        let actual = completed_length(direction_in, length, remaining);
                        if direction_in {
                            invalidate_range(
                                self.description.cache_line_bytes,
                                dma_address,
                                actual.max(1),
                            );
                        }
                        return Ok(actual);
                    }
                    if status & HCINT_STALL != 0 {
                        return Err(Error::Stalled);
                    }
                    if status & HCINT_NAK != 0 && status & HCINT_ERRORS == 0 {
                        delay_ms(self.timebase_hz, self.time, 1);
                        break;
                    }
                    return Err(Error::TransferFailed(status));
                }
                if (self.time)().wrapping_sub(started) >= timeout {
                    let _ = halt_channel(self.description, channel, self.timebase_hz, self.time);
                    return Err(Error::TransferTimedOut);
                }
                core::hint::spin_loop();
            }
        }
        Err(Error::Nak)
    }

    #[allow(clippy::too_many_arguments)]
    fn split_channel_transfer(
        &mut self,
        split: SplitTarget,
        address: u8,
        endpoint: u8,
        direction_in: bool,
        endpoint_type: EndpointType,
        mut pid: DataPid,
        length: usize,
        max_packet: u16,
        nak_retries: usize,
    ) -> Result<usize, Error> {
        if length == 0 {
            self.split_packet_transfer(
                split,
                address,
                endpoint,
                direction_in,
                endpoint_type,
                pid,
                0,
                max_packet,
                0,
                nak_retries,
            )?;
            return Ok(0);
        }

        let mut transferred = 0;
        while transferred < length {
            let requested = (length - transferred).min(usize::from(max_packet));
            let actual = self.split_packet_transfer(
                split,
                address,
                endpoint,
                direction_in,
                endpoint_type,
                pid,
                requested,
                max_packet,
                transferred,
                nak_retries,
            )?;
            transferred += actual;
            if actual < requested {
                break;
            }
            pid = pid.toggled();
        }
        Ok(transferred)
    }

    #[allow(clippy::too_many_arguments)]
    fn split_packet_transfer(
        &mut self,
        split: SplitTarget,
        address: u8,
        endpoint: u8,
        direction_in: bool,
        endpoint_type: EndpointType,
        pid: DataPid,
        requested: usize,
        max_packet: u16,
        dma_offset: usize,
        nak_retries: usize,
    ) -> Result<usize, Error> {
        let start_length = if direction_in && requested != 0 {
            usize::from(max_packet)
        } else {
            requested
        };
        if dma_offset.saturating_add(start_length.max(1)) > DMA_BYTES {
            return Err(Error::BufferTooSmall);
        }

        for _ in 0..nak_retries {
            let (start_status, _) = self.run_split_channel(
                split,
                false,
                address,
                endpoint,
                direction_in,
                endpoint_type,
                pid,
                start_length,
                max_packet,
                dma_offset,
            )?;
            if start_status & HCINT_STALL != 0 {
                return Err(Error::Stalled);
            }
            if start_status & HCINT_NAK != 0 && start_status & HCINT_ERRORS == 0 {
                delay_ms(self.timebase_hz, self.time, 1);
                continue;
            }
            if start_status & HCINT_ACK == 0 || start_status & HCINT_ERRORS != 0 {
                return Err(Error::TransferFailed(start_status));
            }

            // A complete split for control/bulk/interrupt traffic is valid
            // from the second microframe after the start split.
            delay_us(self.timebase_hz, self.time, 250);
            for _ in 0..MAX_COMPLETE_SPLIT_RETRIES {
                let complete_length = if direction_in { start_length } else { 0 };
                let (status, actual) = self.run_split_channel(
                    split,
                    true,
                    address,
                    endpoint,
                    direction_in,
                    endpoint_type,
                    pid,
                    complete_length,
                    max_packet,
                    dma_offset,
                )?;
                if status & HCINT_TRANSFER_COMPLETE != 0 {
                    return Ok(if direction_in {
                        actual.min(requested)
                    } else {
                        requested
                    });
                }
                if status & HCINT_STALL != 0 {
                    return Err(Error::Stalled);
                }
                if status & HCINT_NYET != 0 && status & HCINT_ERRORS == 0 {
                    delay_us(self.timebase_hz, self.time, 125);
                    continue;
                }
                if status & HCINT_NAK != 0 && status & HCINT_ERRORS == 0 {
                    delay_ms(self.timebase_hz, self.time, 1);
                    break;
                }
                return Err(Error::TransferFailed(status));
            }
        }
        Err(Error::Nak)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_split_channel(
        &mut self,
        split: SplitTarget,
        complete: bool,
        address: u8,
        endpoint: u8,
        direction_in: bool,
        endpoint_type: EndpointType,
        pid: DataPid,
        length: usize,
        max_packet: u16,
        dma_offset: usize,
    ) -> Result<(u32, usize), Error> {
        let dma_address = DMA.0.get() as usize + dma_offset;
        if direction_in {
            invalidate_range(
                self.description.cache_line_bytes,
                dma_address,
                length.max(1),
            );
        } else {
            clean_range(
                self.description.cache_line_bytes,
                dma_address,
                length.max(1),
            );
        }

        let channel = 0;
        let split_control = split_control(split, complete);
        unsafe {
            channel_write(self.description, channel, HCINTMSK, 0);
            channel_write(self.description, channel, HCINT, u32::MAX);
            channel_write(self.description, channel, HCSPLT, split_control);
            channel_write(self.description, channel, HCDMA, dma_address as u32);
            channel_write(
                self.description,
                channel,
                HCTSIZ,
                length as u32 | 1 << HCTSIZ_PACKET_SHIFT | (pid as u32) << HCTSIZ_PID_SHIFT,
            );
            let mut character = u32::from(max_packet)
                | u32::from(endpoint) << HCCHAR_ENDPOINT_SHIFT
                | (endpoint_type as u32) << HCCHAR_TYPE_SHIFT
                | u32::from(address) << HCCHAR_ADDRESS_SHIFT
                | HCCHAR_ENABLE;
            if endpoint_type == EndpointType::Interrupt {
                character |= 3 << 20;
            }
            if direction_in {
                character |= HCCHAR_DIRECTION_IN;
            }
            if self.speed == Speed::Low {
                character |= HCCHAR_LOW_SPEED;
            }
            channel_write(self.description, channel, HCCHAR, character);
        }

        let started = (self.time)();
        let timeout = ticks_for_ms(self.timebase_hz, TRANSFER_TIMEOUT_MS);
        loop {
            let status = unsafe { channel_read(self.description, channel, HCINT) };
            if status & HCINT_CHANNEL_HALTED != 0 {
                unsafe { channel_write(self.description, channel, HCINT, status) };
                let remaining =
                    unsafe { channel_read(self.description, channel, HCTSIZ) & 0x7ffff } as usize;
                let actual = completed_length(direction_in, length, remaining);
                if direction_in && actual != 0 {
                    invalidate_range(self.description.cache_line_bytes, dma_address, actual);
                }
                return Ok((status, actual));
            }
            if (self.time)().wrapping_sub(started) >= timeout {
                let _ = halt_channel(self.description, channel, self.timebase_hz, self.time);
                return Err(Error::TransferTimedOut);
            }
            core::hint::spin_loop();
        }
    }

    /// Quiesce the host core and release software ownership. Clock gates stay
    /// enabled because other firmware may subsequently take over the OTG port.
    pub fn shutdown(self) {
        unsafe {
            core_write(self.description, GINTMSK, 0);
            let ahbcfg = core_read(self.description, GAHBCFG) & !GAHBCFG_GLOBAL_INTERRUPT;
            core_write(self.description, GAHBCFG, ahbcfg);
            let port = core_read(self.description, HPRT0);
            core_write(
                self.description,
                HPRT0,
                port & !(HPRT_CHANGE_BITS | HPRT_POWER),
            );
        }
        CLAIMED.store(false, Ordering::Release);
        core::mem::forget(self);
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        CLAIMED.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u32)]
enum EndpointType {
    Control = 0,
    Bulk = 2,
    Interrupt = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
enum DataPid {
    Data0 = 0,
    Data1 = 2,
    Setup = 3,
}

impl DataPid {
    const fn toggled(self) -> Self {
        match self {
            Self::Data0 => Self::Data1,
            Self::Data1 => Self::Data0,
            Self::Setup => Self::Setup,
        }
    }
}

fn advance_pid(pid: DataPid, bytes: usize, max_packet: u16) -> DataPid {
    let packets = bytes.div_ceil(usize::from(max_packet));
    if packets % 2 == 0 {
        pid
    } else {
        pid.toggled()
    }
}

fn read_10_cdb(sector: u32) -> [u8; 10] {
    let mut cdb = [0; 10];
    cdb[0] = 0x28;
    cdb[2..6].copy_from_slice(&sector.to_be_bytes());
    cdb[7..9].copy_from_slice(&1u16.to_be_bytes());
    cdb
}

fn write_10_cdb(sector: u32) -> [u8; 10] {
    let mut cdb = read_10_cdb(sector);
    cdb[0] = 0x2a;
    cdb
}

const fn bot_requires_reset_recovery(error: Error) -> bool {
    matches!(
        error,
        Error::TransferTimedOut
            | Error::TransferFailed(_)
            | Error::Stalled
            | Error::Nak
            | Error::StorageProtocol
            | Error::StorageCommandFailed(2)
            | Error::StorageCswSignature(_)
            | Error::StorageCswTag(_)
            | Error::StorageCswResidue(_)
            | Error::StorageCbwLength(_)
            | Error::StorageDataLength { .. }
            | Error::StorageCswLength(_)
    )
}

const fn completed_length(direction_in: bool, requested: usize, remaining: usize) -> usize {
    // CV1800B's DWC2 4.20a buffer-DMA path leaves XFRSIZ unchanged for a
    // successfully completed OUT transaction. Transfer Complete is the OUT
    // acknowledgement; only IN uses XFRSIZ to report a short packet.
    if direction_in {
        requested.saturating_sub(remaining)
    } else {
        requested
    }
}

fn parse_hub_descriptor(descriptor: &[u8]) -> Result<(u8, u16), Error> {
    if descriptor.len() < 7
        || usize::from(descriptor[0]) > descriptor.len()
        || descriptor[1] != USB_DESCRIPTOR_HUB as u8
        || descriptor[2] == 0
        || descriptor[2] > MAX_HUB_PORTS
    {
        return Err(Error::InvalidDescriptor);
    }
    Ok((descriptor[2], u16::from(descriptor[5]) * 2))
}

const fn hub_port_speed(status: u16) -> Speed {
    if status & USB_PORT_STAT_LOW_SPEED != 0 {
        Speed::Low
    } else if status & USB_PORT_STAT_HIGH_SPEED != 0 {
        Speed::High
    } else {
        Speed::Full
    }
}

fn transfer_target_for_child(child: HubChildInfo) -> TransferTarget {
    TransferTarget {
        address: child.device.address,
        endpoint_zero_max_packet: u16::from(child.device.max_packet_size_0),
        speed: child.device.speed,
        split: (child.device.speed != Speed::High).then_some(SplitTarget {
            hub_address: child.parent_hub_address,
            port: child.port,
        }),
    }
}

const fn split_control(target: SplitTarget, complete: bool) -> u32 {
    HCSPLT_ENABLE
        | HCSPLT_TRANSACTION_ALL
        | (target.hub_address as u32) << HCSPLT_HUB_ADDRESS_SHIFT
        | (target.port as u32) & HCSPLT_PORT_MASK
        | if complete { HCSPLT_COMPLETE } else { 0 }
}

fn parse_hid_keyboard_configuration(
    descriptors: &[u8],
    speed: Speed,
) -> Result<(ConfigurationInfo, Option<HidKeyboardInfo>), Error> {
    if descriptors.len() < 9 || descriptors[0] != 9 || descriptors[1] != 2 || descriptors[5] == 0 {
        return Err(Error::InvalidDescriptor);
    }
    let declared = usize::from(u16::from_le_bytes([descriptors[2], descriptors[3]]));
    if declared != descriptors.len() {
        return Err(Error::InvalidDescriptor);
    }

    let mut configuration = ConfigurationInfo {
        value: descriptors[5],
        total_length: declared as u16,
        declared_interfaces: descriptors[4],
        interfaces: [None; MAX_CONFIGURATION_INTERFACES],
    };
    let mut offset = 0;
    let mut current_interface = None;
    let mut keyboard_interface = None;
    let mut keyboard = None;
    while offset < descriptors.len() {
        if descriptors.len() - offset < 2 {
            return Err(Error::InvalidDescriptor);
        }
        let length = usize::from(descriptors[offset]);
        if length < 2 || length > descriptors.len() - offset {
            return Err(Error::InvalidDescriptor);
        }
        match descriptors[offset + 1] {
            4 if length >= 9 => {
                let info = InterfaceInfo {
                    number: descriptors[offset + 2],
                    alternate: descriptors[offset + 3],
                    class: descriptors[offset + 5],
                    subclass: descriptors[offset + 6],
                    protocol: descriptors[offset + 7],
                    hid_report_length: 0,
                    interrupt_in: None,
                    max_packet_size: 0,
                    interval: 0,
                    bulk_in: None,
                    bulk_out: None,
                    bulk_in_max_packet_size: 0,
                    bulk_out_max_packet_size: 0,
                };
                current_interface = configuration.interfaces.iter().position(Option::is_none);
                if let Some(index) = current_interface {
                    configuration.interfaces[index] = Some(info);
                }
                keyboard_interface = (descriptors[offset + 5] == 3
                    && descriptors[offset + 6] == 1
                    && descriptors[offset + 7] == 1)
                    .then_some(descriptors[offset + 2]);
            }
            0x21 if length >= 9 => {
                if let Some(index) = current_interface {
                    if let Some(info) = configuration.interfaces[index].as_mut() {
                        let descriptor_count = usize::from(descriptors[offset + 5]);
                        for descriptor in 0..descriptor_count {
                            let subordinate = offset + 6 + descriptor * 3;
                            if subordinate + 3 > offset + length {
                                return Err(Error::InvalidDescriptor);
                            }
                            if descriptors[subordinate] == 0x22 {
                                info.hid_report_length = u16::from_le_bytes([
                                    descriptors[subordinate + 1],
                                    descriptors[subordinate + 2],
                                ]);
                            }
                        }
                    }
                }
            }
            5 if length >= 7 => {
                let address = descriptors[offset + 2];
                let attributes = descriptors[offset + 3];
                let max_packet =
                    u16::from_le_bytes([descriptors[offset + 4], descriptors[offset + 5]]) & 0x07ff;
                if address & 0x80 != 0
                    && attributes & 0x03 == 3
                    && max_packet >= HID_REPORT_BYTES as u16
                    && usize::from(max_packet) <= DMA_BYTES
                {
                    if let Some(index) = current_interface {
                        if let Some(info) = configuration.interfaces[index].as_mut() {
                            if info.interrupt_in.is_none() {
                                info.interrupt_in = Some(address);
                                info.max_packet_size = max_packet;
                                info.interval = descriptors[offset + 6];
                            }
                        }
                    }
                    if keyboard.is_none() {
                        if let Some(interface) = keyboard_interface {
                            keyboard = Some(HidKeyboardInfo {
                                interface,
                                endpoint_in: address,
                                max_packet_size: max_packet,
                                interval_ms: hid_poll_interval_ms(speed, descriptors[offset + 6]),
                                protocol: HidKeyboardProtocol::Boot,
                            });
                        }
                    }
                }
                if attributes & 0x03 == 2 && max_packet != 0 && usize::from(max_packet) <= DMA_BYTES
                {
                    if let Some(index) = current_interface {
                        if let Some(info) = configuration.interfaces[index].as_mut() {
                            if address & 0x80 != 0 && info.bulk_in.is_none() {
                                info.bulk_in = Some(address);
                                info.bulk_in_max_packet_size = max_packet;
                            } else if address & 0x80 == 0 && info.bulk_out.is_none() {
                                info.bulk_out = Some(address);
                                info.bulk_out_max_packet_size = max_packet;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        offset += length;
    }
    Ok((configuration, keyboard))
}

fn find_mass_storage(configuration: ConfigurationInfo) -> Option<MassStorageInfo> {
    configuration
        .interfaces
        .into_iter()
        .flatten()
        .find_map(|interface| {
            if interface.class != USB_CLASS_MASS_STORAGE
                || interface.subclass != USB_MASS_STORAGE_SCSI
                || interface.protocol != USB_MASS_STORAGE_BULK_ONLY
            {
                return None;
            }
            Some(MassStorageInfo {
                configuration: configuration.value,
                interface: interface.number,
                endpoint_in: interface.bulk_in?,
                endpoint_out: interface.bulk_out?,
                max_packet_size_in: interface.bulk_in_max_packet_size,
                max_packet_size_out: interface.bulk_out_max_packet_size,
                capacity_sectors: None,
                block_size: None,
            })
        })
}

fn is_apple_report_keyboard_descriptor(descriptor: &[u8]) -> bool {
    const ARRAY_REPORT: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15,
        0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
        0x95, 0x05, 0x75, 0x08,
    ];
    const NKRO_REPORT: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x02, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15,
        0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x19, 0x00, 0x29, 0x67, 0x95, 0x68,
        0x81, 0x02,
    ];
    descriptor
        .windows(ARRAY_REPORT.len())
        .any(|window| window == ARRAY_REPORT)
        && descriptor
            .windows(NKRO_REPORT.len())
            .any(|window| window == NKRO_REPORT)
}

fn hid_poll_interval_ms(speed: Speed, interval: u8) -> u16 {
    match speed {
        Speed::High => {
            let exponent = interval.clamp(1, 16) - 1;
            let microframes = 1u32 << exponent;
            microframes.div_ceil(8) as u16
        }
        Speed::Full | Speed::Low => interval.max(1) as u16,
    }
}

fn decode_hid_report(
    report: [u8; HID_REPORT_BYTES],
    previous: [u8; HID_REPORT_BYTES],
) -> HidInputBatch {
    let mut input = HidInputBatch::new();
    for key in report[2..].iter().copied().filter(|key| *key > 3) {
        if previous[2..].contains(&key) {
            continue;
        }
        let (bytes, length) = hid_key_bytes(key, report[0]);
        for byte in &bytes[..length] {
            input.push(*byte);
        }
    }
    input
}

fn decode_apple_nkro_report(
    report: [u8; APPLE_NKRO_REPORT_BYTES],
    previous: [u8; APPLE_NKRO_REPORT_BYTES],
) -> HidInputBatch {
    let mut input = HidInputBatch::new();
    for key in 4u8..=103 {
        let byte = 2 + usize::from(key / 8);
        let mask = 1 << (key % 8);
        if report[byte] & mask == 0 || previous[byte] & mask != 0 {
            continue;
        }
        let (bytes, length) = hid_key_bytes(key, report[1]);
        for byte in &bytes[..length] {
            input.push(*byte);
        }
    }
    input
}

fn hid_key_bytes(key: u8, modifiers: u8) -> ([u8; 3], usize) {
    let shift = modifiers & ((1 << 1) | (1 << 5)) != 0;
    let control = modifiers & ((1 << 0) | (1 << 4)) != 0;
    if (4..=29).contains(&key) {
        let letter = key - 4;
        if control {
            return ([letter + 1, 0, 0], 1);
        }
        return ([if shift { b'A' } else { b'a' } + letter, 0, 0], 1);
    }
    if (30..=39).contains(&key) {
        let index = (key - 30) as usize;
        return (
            [
                if shift {
                    b"!@#$%^&*()"[index]
                } else {
                    b"1234567890"[index]
                },
                0,
                0,
            ],
            1,
        );
    }
    let byte = match key {
        40 => b'\n',
        41 => 0x1b,
        42 | 76 => 0x7f,
        43 => b'\t',
        44 => b' ',
        45 => {
            if shift {
                b'_'
            } else {
                b'-'
            }
        }
        46 => {
            if shift {
                b'+'
            } else {
                b'='
            }
        }
        47 => {
            if shift {
                b'{'
            } else {
                b'['
            }
        }
        48 => {
            if shift {
                b'}'
            } else {
                b']'
            }
        }
        49 => {
            if shift {
                b'|'
            } else {
                b'\\'
            }
        }
        50 => {
            if shift {
                b'~'
            } else {
                b'#'
            }
        }
        51 => {
            if shift {
                b':'
            } else {
                b';'
            }
        }
        52 => {
            if shift {
                b'"'
            } else {
                b'\''
            }
        }
        53 => {
            if shift {
                b'~'
            } else {
                b'`'
            }
        }
        54 => {
            if shift {
                b'<'
            } else {
                b','
            }
        }
        55 => {
            if shift {
                b'>'
            } else {
                b'.'
            }
        }
        56 => {
            if shift {
                b'?'
            } else {
                b'/'
            }
        }
        79 => return ([0x1b, b'[', b'C'], 3),
        80 => return ([0x1b, b'[', b'D'], 3),
        81 => return ([0x1b, b'[', b'B'], 3),
        82 => return ([0x1b, b'[', b'A'], 3),
        _ => return ([0; 3], 0),
    };
    ([byte, 0, 0], 1)
}

fn parse_device_descriptor(
    descriptor: [u8; 18],
    speed: Speed,
    address: u8,
) -> Result<DeviceInfo, Error> {
    if descriptor[0] != 18 || descriptor[1] != 1 || !matches!(descriptor[7], 8 | 16 | 32 | 64) {
        return Err(Error::InvalidDescriptor);
    }
    Ok(DeviceInfo {
        address,
        speed,
        usb_version: u16::from_le_bytes([descriptor[2], descriptor[3]]),
        device_class: descriptor[4],
        vendor_id: u16::from_le_bytes([descriptor[8], descriptor[9]]),
        product_id: u16::from_le_bytes([descriptor[10], descriptor[11]]),
        max_packet_size_0: descriptor[7],
    })
}

fn port_speed(port: u32) -> Result<Speed, Error> {
    match (port & HPRT_SPEED_MASK) >> HPRT_SPEED_SHIFT {
        0 => Ok(Speed::High),
        1 => Ok(Speed::Full),
        2 => Ok(Speed::Low),
        _ => Err(Error::InvalidDescriptor),
    }
}

fn flush_fifos(
    description: Dwc2Description,
    timebase_hz: u64,
    time: fn() -> u64,
) -> Result<(), Error> {
    unsafe {
        core_write(
            description,
            GRSTCTL,
            GRSTCTL_TX_FIFO_FLUSH | GRSTCTL_TX_FIFO_ALL,
        )
    };
    wait_for(
        description,
        GRSTCTL,
        GRSTCTL_TX_FIFO_FLUSH,
        false,
        REGISTER_TIMEOUT_MS,
        timebase_hz,
        time,
    )
    .map_err(|_| Error::CoreResetTimedOut)?;
    unsafe { core_write(description, GRSTCTL, GRSTCTL_RX_FIFO_FLUSH) };
    wait_for(
        description,
        GRSTCTL,
        GRSTCTL_RX_FIFO_FLUSH,
        false,
        REGISTER_TIMEOUT_MS,
        timebase_hz,
        time,
    )
    .map_err(|_| Error::CoreResetTimedOut)
}

fn halt_channel(
    description: Dwc2Description,
    channel: u8,
    timebase_hz: u64,
    time: fn() -> u64,
) -> Result<(), Error> {
    let character = unsafe { channel_read(description, channel, HCCHAR) };
    if character & HCCHAR_ENABLE == 0 {
        unsafe { channel_write(description, channel, HCINT, u32::MAX) };
        return Ok(());
    }
    unsafe {
        channel_write(
            description,
            channel,
            HCCHAR,
            character | HCCHAR_ENABLE | HCCHAR_DISABLE,
        )
    };
    let started = time();
    let timeout = ticks_for_ms(timebase_hz, REGISTER_TIMEOUT_MS);
    while unsafe { channel_read(description, channel, HCCHAR) } & HCCHAR_ENABLE != 0 {
        if time().wrapping_sub(started) >= timeout {
            return Err(Error::TransferTimedOut);
        }
        core::hint::spin_loop();
    }
    unsafe { channel_write(description, channel, HCINT, u32::MAX) };
    Ok(())
}

fn ticks_for_ms(timebase_hz: u64, milliseconds: u64) -> u64 {
    (timebase_hz.saturating_mul(milliseconds).saturating_add(999) / 1_000).max(1)
}

fn delay_ms(timebase_hz: u64, time: fn() -> u64, milliseconds: u64) {
    let started = time();
    let duration = ticks_for_ms(timebase_hz, milliseconds);
    while time().wrapping_sub(started) < duration {
        core::hint::spin_loop();
    }
}

fn delay_us(timebase_hz: u64, time: fn() -> u64, microseconds: u64) {
    let started = time();
    let duration = (timebase_hz
        .saturating_mul(microseconds)
        .saturating_add(999_999)
        / 1_000_000)
        .max(1);
    while time().wrapping_sub(started) < duration {
        core::hint::spin_loop();
    }
}

unsafe fn dma_bytes() -> &'static mut [u8; DMA_BYTES] {
    unsafe { &mut *DMA.0.get() }
}

fn clean_range(line: usize, start: usize, size: usize) {
    cache_range(line, start, size, true)
}

fn invalidate_range(line: usize, start: usize, size: usize) {
    cache_range(line, start, size, false)
}

#[cfg(target_arch = "riscv64")]
fn cache_range(bytes: usize, start: usize, size: usize, clean: bool) {
    let mut line = start & !(bytes - 1);
    let end = start.saturating_add(size).saturating_add(bytes - 1) & !(bytes - 1);
    while line < end {
        unsafe {
            if clean {
                core::arch::asm!(".long 0x0295000b", in("a0") line, options(nostack));
            } else {
                core::arch::asm!(".long 0x02a5000b", in("a0") line, options(nostack));
            }
        }
        line += bytes;
    }
    unsafe { core::arch::asm!(".long 0x0190000b", options(nostack)) };
}

#[cfg(not(target_arch = "riscv64"))]
fn cache_range(_: usize, _: usize, _: usize, _: bool) {
    compiler_fence(Ordering::SeqCst);
}

pub const fn validate_description(description: Dwc2Description) -> bool {
    range_contains(
        description.registers.start,
        description.registers.end,
        HC_BASE + 16 * HC_STRIDE,
    ) && range_contains(description.phy.start, description.phy.end, 0x18)
        && range_contains(
            description.soc_control.start,
            description.soc_control.end,
            CLK_ENABLE_2 + 4,
        )
        && description.irq != 0
        && description.dma_address_bits == 32
        && description.cache_line_bytes == 64
}

const fn range_contains(start: usize, end: usize, bytes: usize) -> bool {
    match start.checked_add(bytes) {
        Some(required_end) => end >= required_end,
        None => false,
    }
}

const fn is_dwc2_core_id(id: u32) -> bool {
    id & 0xffff_0000 == 0x4f54_0000
}

const fn reset_uses_done_handshake(id: u32) -> bool {
    id as u16 >= DWC2_CORE_REVISION_4_20A
}

const fn host_channel_count(hwcfg2: u32) -> u8 {
    (((hwcfg2 >> 14) & 0xf) + 1) as u8
}

fn wait_for(
    description: Dwc2Description,
    register: usize,
    mask: u32,
    asserted: bool,
    timeout_ms: u64,
    timebase_hz: u64,
    time: fn() -> u64,
) -> Result<(), ()> {
    let timeout_ticks = (timebase_hz.saturating_mul(timeout_ms).saturating_add(999) / 1_000).max(1);
    let started = time();
    loop {
        if (unsafe { core_read(description, register) } & mask != 0) == asserted {
            return Ok(());
        }
        if time().wrapping_sub(started) >= timeout_ticks {
            return Err(());
        }
        core::hint::spin_loop();
    }
}

unsafe fn channel_read(description: Dwc2Description, channel: u8, offset: usize) -> u32 {
    unsafe {
        core_read(
            description,
            HC_BASE + usize::from(channel) * HC_STRIDE + offset,
        )
    }
}

unsafe fn channel_write(description: Dwc2Description, channel: u8, offset: usize, value: u32) {
    unsafe {
        core_write(
            description,
            HC_BASE + usize::from(channel) * HC_STRIDE + offset,
            value,
        )
    }
}

unsafe fn core_read(description: Dwc2Description, offset: usize) -> u32 {
    unsafe { read32(description.registers.start + offset) }
}

unsafe fn core_write(description: Dwc2Description, offset: usize, value: u32) {
    unsafe { write32(description.registers.start + offset, value) }
}

unsafe fn phy_read(description: Dwc2Description, offset: usize) -> u32 {
    unsafe { read32(description.phy.start + offset) }
}

unsafe fn phy_write(description: Dwc2Description, offset: usize, value: u32) {
    unsafe { write32(description.phy.start + offset, value) }
}

unsafe fn soc_read(description: Dwc2Description, offset: usize) -> u32 {
    unsafe { read32(description.soc_control.start + offset) }
}

unsafe fn soc_write(description: Dwc2Description, offset: usize, value: u32) {
    unsafe { write32(description.soc_control.start + offset, value) }
}

unsafe fn read32(address: usize) -> u32 {
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

unsafe fn write32(address: usize, value: u32) {
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_hal::AddressRange;

    const VALID: Dwc2Description = Dwc2Description {
        registers: AddressRange::new(0x0434_0000, 0x0435_0000),
        phy: AddressRange::new(0x0300_6000, 0x0300_6058),
        irq: 30,
        soc_control: AddressRange::new(0x0300_0000, 0x0300_a000),
        dma_address_bits: 32,
        cache_line_bytes: 64,
    };

    #[test]
    fn cv1800b_description_covers_every_register() {
        assert!(validate_description(VALID));
        let mut short = VALID;
        short.registers.end = short.registers.start + HPRT0;
        assert!(!validate_description(short));
        short = VALID;
        short.phy.end = short.phy.start + 0x14;
        assert!(!validate_description(short));
    }

    #[test]
    fn recognizes_synopsys_otg_ids_and_decodes_channels() {
        assert!(is_dwc2_core_id(0x4f54_280a));
        assert!(!is_dwc2_core_id(0x5533_0000));
        assert!(!reset_uses_done_handshake(0x4f54_400a));
        assert!(reset_uses_done_handshake(0x4f54_420a));
        assert!(reset_uses_done_handshake(0x4f54_450a));
        assert_eq!(host_channel_count(0), 1);
        assert_eq!(host_channel_count(15 << 14), 16);
    }

    #[test]
    fn parses_usb2_hub_ports_power_delay_and_child_speed() {
        let descriptor = [9, 0x29, 4, 0, 0, 50, 0, 0xff, 0xff];
        assert_eq!(parse_hub_descriptor(&descriptor), Ok((4, 100)));
        assert_eq!(hub_port_speed(USB_PORT_STAT_LOW_SPEED), Speed::Low);
        assert_eq!(hub_port_speed(USB_PORT_STAT_HIGH_SPEED), Speed::High);
        assert_eq!(hub_port_speed(USB_PORT_STAT_ENABLE), Speed::Full);
        let child = HubChildInfo {
            device: DeviceInfo {
                address: 3,
                speed: Speed::Full,
                usb_version: 0x0200,
                device_class: 0,
                vendor_id: 0x1234,
                product_id: 0x5678,
                max_packet_size_0: 64,
            },
            parent_hub_address: 2,
            port: 4,
            port_status: USB_PORT_STAT_CONNECTION | USB_PORT_STAT_ENABLE,
            depth: 2,
        };
        let nested_target = transfer_target_for_child(child);
        assert_eq!(nested_target.address, 3);
        assert_eq!(nested_target.speed, Speed::Full);
        assert_eq!(
            nested_target.split,
            Some(SplitTarget {
                hub_address: 2,
                port: 4,
            })
        );
        assert_eq!(
            transfer_target_for_child(HubChildInfo {
                device: DeviceInfo {
                    speed: Speed::High,
                    ..child.device
                },
                ..child
            })
            .split,
            None
        );
        let target = SplitTarget {
            hub_address: 1,
            port: 1,
        };
        assert_eq!(split_control(target, false), 0x8000_c081);
        assert_eq!(split_control(target, true), 0x8001_c081);
    }

    #[test]
    fn setup_packet_and_device_descriptor_are_little_endian() {
        assert_eq!(
            SetupPacket {
                request_type: 0x80,
                request: 6,
                value: 0x0100,
                index: 0x0203,
                length: 18,
            }
            .to_bytes(),
            [0x80, 6, 0, 1, 3, 2, 18, 0]
        );

        let descriptor = [
            18, 1, 0x10, 0x02, 0, 0, 0, 64, 0x34, 0x12, 0x78, 0x56, 0, 1, 0, 0, 0, 1,
        ];
        let info = parse_device_descriptor(descriptor, Speed::High, 1).unwrap();
        assert_eq!(info.usb_version, 0x0210);
        assert_eq!(info.vendor_id, 0x1234);
        assert_eq!(info.product_id, 0x5678);
        assert_eq!(info.max_packet_size_0, 64);
        assert_eq!(port_speed(0), Ok(Speed::High));
        assert_eq!(port_speed(1 << HPRT_SPEED_SHIFT), Ok(Speed::Full));
        assert_eq!(port_speed(2 << HPRT_SPEED_SHIFT), Ok(Speed::Low));
    }

    #[test]
    fn finds_boot_keyboard_interface_and_interrupt_endpoint() {
        let descriptors = [
            9, 2, 34, 0, 1, 2, 0, 0x80, 50, // configuration
            9, 4, 3, 0, 1, 3, 1, 1, 0, // HID boot-keyboard interface
            9, 0x21, 0x11, 1, 0, 1, 0x22, 63, 0, // HID descriptor
            7, 5, 0x81, 3, 8, 0, 10, // interrupt IN endpoint
        ];
        let (configuration, keyboard) =
            parse_hid_keyboard_configuration(&descriptors, Speed::Full).unwrap();
        assert_eq!(configuration.value, 2);
        assert_eq!(configuration.total_length, 34);
        assert_eq!(configuration.declared_interfaces, 1);
        assert_eq!(
            configuration.interfaces[0],
            Some(InterfaceInfo {
                number: 3,
                alternate: 0,
                class: 3,
                subclass: 1,
                protocol: 1,
                hid_report_length: 63,
                interrupt_in: Some(0x81),
                max_packet_size: 8,
                interval: 10,
                bulk_in: None,
                bulk_out: None,
                bulk_in_max_packet_size: 0,
                bulk_out_max_packet_size: 0,
            })
        );
        assert_eq!(
            keyboard,
            Some(HidKeyboardInfo {
                interface: 3,
                endpoint_in: 0x81,
                max_packet_size: 8,
                interval_ms: 10,
                protocol: HidKeyboardProtocol::Boot,
            })
        );
        assert_eq!(hid_poll_interval_ms(Speed::High, 4), 1);
        assert_eq!(hid_poll_interval_ms(Speed::High, 7), 8);
    }

    #[test]
    fn finds_scsi_bulk_only_mass_storage_endpoints() {
        let descriptors = [
            9, 2, 32, 0, 1, 1, 0, 0x80, 50, // configuration
            9, 4, 0, 0, 2, 8, 6, 0x50, 0, // SCSI bulk-only interface
            7, 5, 0x81, 2, 64, 0, 0, // bulk IN
            7, 5, 0x02, 2, 64, 0, 0, // bulk OUT
        ];
        let (configuration, keyboard) =
            parse_hid_keyboard_configuration(&descriptors, Speed::High).unwrap();
        assert_eq!(keyboard, None);
        assert_eq!(
            find_mass_storage(configuration),
            Some(MassStorageInfo {
                configuration: 1,
                interface: 0,
                endpoint_in: 0x81,
                endpoint_out: 0x02,
                max_packet_size_in: 64,
                max_packet_size_out: 64,
                capacity_sectors: None,
                block_size: None,
            })
        );
        assert_eq!(advance_pid(DataPid::Data0, 512, 64), DataPid::Data0);
        assert_eq!(advance_pid(DataPid::Data0, 31, 64), DataPid::Data1);
        assert_eq!(completed_length(false, 31, 31), 31);
        assert_eq!(completed_length(true, 512, 128), 384);
        assert_eq!(
            read_10_cdb(0x1234_5678),
            [0x28, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 1, 0]
        );
        assert_eq!(
            write_10_cdb(0x1234_5678),
            [0x2a, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 1, 0]
        );
        assert!(!bot_requires_reset_recovery(Error::StorageCommandFailed(1)));
        assert!(bot_requires_reset_recovery(Error::StorageCommandFailed(2)));
    }

    #[test]
    fn boot_reports_emit_only_new_keys_with_terminal_translation() {
        let first = decode_hid_report([2, 0, 4, 30, 0, 0, 0, 0], [0; 8]);
        assert_eq!(first.as_slice(), b"A!");

        let held = decode_hid_report([2, 0, 4, 30, 79, 0, 0, 0], [2, 0, 4, 30, 0, 0, 0, 0]);
        assert_eq!(held.as_slice(), b"\x1b[C");

        let control = decode_hid_report([1, 0, 6, 0, 0, 0, 0, 0], [0; 8]);
        assert_eq!(control.as_slice(), &[3]);
    }

    #[test]
    fn apple_report_keyboard_layout_and_nkro_reports_are_supported() {
        let mut descriptor = [0; 96];
        let array = [
            0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7,
            0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08,
            0x81, 0x01, 0x95, 0x05, 0x75, 0x08,
        ];
        let nkro = [
            0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x02, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7,
            0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x19, 0x00, 0x29, 0x67,
            0x95, 0x68, 0x81, 0x02,
        ];
        descriptor[..array.len()].copy_from_slice(&array);
        descriptor[48..48 + nkro.len()].copy_from_slice(&nkro);
        assert!(is_apple_report_keyboard_descriptor(&descriptor));

        let mut report = [0; APPLE_NKRO_REPORT_BYTES];
        report[0] = 2;
        report[1] = 2;
        report[2] |= 1 << 4;
        assert_eq!(
            decode_apple_nkro_report(report, [0; APPLE_NKRO_REPORT_BYTES]).as_slice(),
            b"A"
        );
        assert!(decode_apple_nkro_report(report, report)
            .as_slice()
            .is_empty());
    }
}
