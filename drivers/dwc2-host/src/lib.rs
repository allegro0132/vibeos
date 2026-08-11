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
const HCINT_ERRORS: u32 = (1 << 2) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10);

const REGISTER_TIMEOUT_MS: u64 = 10;
const HOST_MODE_TIMEOUT_MS: u64 = 110;
const TRANSFER_TIMEOUT_MS: u64 = 250;
const DMA_BYTES: usize = 1_024;
const MAX_NAK_RETRIES: usize = 32;
const HID_REPORT_BYTES: usize = 8;
const HID_INPUT_BYTES: usize = 18;
const DWC2_CORE_REVISION_4_20A: u16 = 0x420a;

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
    keyboard: Option<HidKeyboardInfo>,
    keyboard_pid: DataPid,
    keyboard_last: [u8; HID_REPORT_BYTES],
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
            keyboard: None,
            keyboard_pid: DataPid::Data0,
            keyboard_last: [0; HID_REPORT_BYTES],
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

    pub const fn keyboard(&self) -> Option<HidKeyboardInfo> {
        self.keyboard
    }

    /// Reset the directly attached root-port device and complete USB address
    /// and device-descriptor enumeration through endpoint zero.
    pub fn enumerate_device(&mut self) -> Result<Option<DeviceInfo>, Error> {
        if !self.connected() {
            self.device = None;
            self.keyboard = None;
            self.device_address = 0;
            return Ok(None);
        }

        self.reset_port()?;
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
        self.keyboard = None;
        Ok(Some(info))
    }

    /// Select the first HID boot-keyboard interface exposed by the addressed
    /// device and put it into the fixed eight-byte boot report protocol.
    pub fn configure_hid_keyboard(&mut self) -> Result<Option<HidKeyboardInfo>, Error> {
        if self.device.is_none() || !self.connected() {
            self.keyboard = None;
            return Ok(None);
        }

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
        let Some(keyboard) = keyboard else {
            self.keyboard = None;
            return Ok(None);
        };

        self.control_transfer(
            SetupPacket {
                request_type: 0,
                request: 9,
                value: u16::from(configuration),
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
        self.keyboard_pid = DataPid::Data0;
        self.keyboard_last = [0; HID_REPORT_BYTES];
        Ok(Some(keyboard))
    }

    /// Poll one interrupt-IN boot report and return bytes for newly pressed
    /// keys. A USB NAK is normal idle state and produces an empty batch.
    pub fn poll_keyboard(&mut self) -> Result<HidInputBatch, Error> {
        let keyboard = self.keyboard.ok_or(Error::NoDevice)?;
        if !self.connected() {
            self.keyboard = None;
            return Err(Error::NoDevice);
        }
        let result = self.channel_transfer(
            self.device_address,
            keyboard.endpoint_in & 0x0f,
            true,
            EndpointType::Interrupt,
            self.keyboard_pid,
            HID_REPORT_BYTES,
            keyboard.max_packet_size,
            1,
        );
        let actual = match result {
            Ok(actual) => actual,
            Err(Error::Nak) => return Ok(HidInputBatch::new()),
            Err(error) => return Err(error),
        };
        if actual < HID_REPORT_BYTES {
            return Err(Error::InvalidDescriptor);
        }
        self.keyboard_pid = self.keyboard_pid.toggled();
        let mut report = [0u8; HID_REPORT_BYTES];
        unsafe { report.copy_from_slice(&dma_bytes()[..HID_REPORT_BYTES]) };
        let input = decode_hid_report(report, self.keyboard_last);
        self.keyboard_last = report;
        Ok(input)
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
                        let actual = length.saturating_sub(remaining);
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

#[derive(Clone, Copy)]
#[repr(u32)]
enum EndpointType {
    Control = 0,
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

fn parse_hid_keyboard_configuration(
    descriptors: &[u8],
    speed: Speed,
) -> Result<(u8, Option<HidKeyboardInfo>), Error> {
    if descriptors.len() < 9 || descriptors[0] != 9 || descriptors[1] != 2 || descriptors[5] == 0 {
        return Err(Error::InvalidDescriptor);
    }
    let declared = usize::from(u16::from_le_bytes([descriptors[2], descriptors[3]]));
    if declared != descriptors.len() {
        return Err(Error::InvalidDescriptor);
    }

    let mut offset = 0;
    let mut interface = None;
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
                interface = (descriptors[offset + 5] == 3
                    && descriptors[offset + 6] == 1
                    && descriptors[offset + 7] == 1)
                    .then_some(descriptors[offset + 2]);
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
                    if let Some(interface) = interface {
                        return Ok((
                            descriptors[5],
                            Some(HidKeyboardInfo {
                                interface,
                                endpoint_in: address,
                                max_packet_size: max_packet,
                                interval_ms: hid_poll_interval_ms(speed, descriptors[offset + 6]),
                            }),
                        ));
                    }
                }
            }
            _ => {}
        }
        offset += length;
    }
    Ok((descriptors[5], None))
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
        assert_eq!(configuration, 2);
        assert_eq!(
            keyboard,
            Some(HidKeyboardInfo {
                interface: 3,
                endpoint_in: 0x81,
                max_packet_size: 8,
                interval_ms: 10,
            })
        );
        assert_eq!(hid_poll_interval_ms(Speed::High, 4), 1);
        assert_eq!(hid_poll_interval_ms(Speed::High, 7), 8);
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
}
