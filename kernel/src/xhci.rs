//! Polling XHCI host-controller foundation for QEMU PCI USB devices.
//!
//! Controller-owned memory lives in `.dma` for the kernel lifetime.  All DMA
//! addresses are identity-mapped RAM and all state transitions are serialized
//! by `CONTROLLER`; no component allocation can be published to hardware.

extern crate alloc;

use alloc::vec::Vec;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::pci::Bar;
use crate::sync::SpinLock;

const MAX_SLOTS: usize = 8;
const MAX_DCI: usize = 8;
const RING_TRBS: usize = 64;
const CONTEXT_BYTES: usize = 64 * 33;
const DATA_BYTES: usize = 4096;
const BOT_DATA_OFFSET: usize = 64;
const BOT_CSW_OFFSET: usize = DATA_BYTES - 64;

const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
const PAGESIZE: usize = 0x08;
const CRCR: usize = 0x18;
const DCBAAP: usize = 0x30;
const CONFIG: usize = 0x38;
const PORTSC_BASE: usize = 0x400;
const PORT_STRIDE: usize = 0x10;

const CMD_RUN: u32 = 1 << 0;
const CMD_RESET: u32 = 1 << 1;
const CMD_INTERRUPTER_ENABLE: u32 = 1 << 2;
const STS_HALTED: u32 = 1 << 0;
const STS_CNR: u32 = 1 << 11;

const IMAN: usize = 0x00;
const IMOD: usize = 0x04;
const ERSTSZ: usize = 0x08;
const ERSTBA: usize = 0x10;
const ERDP: usize = 0x18;

const TRB_CYCLE: u32 = 1 << 0;
const TRB_TOGGLE_CYCLE: u32 = 1 << 1;
const TRB_IOC: u32 = 1 << 5;
const TRB_TYPE_SHIFT: u32 = 10;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_DISABLE_SLOT: u32 = 10;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_CONFIGURE_ENDPOINT: u32 = 12;
const TRB_NORMAL: u32 = 1;
const TRB_SETUP_STAGE: u32 = 2;
const TRB_DATA_STAGE: u32 = 3;
const TRB_STATUS_STAGE: u32 = 4;
const TRB_TRANSFER_EVENT: u32 = 32;
const TRB_COMMAND_COMPLETION: u32 = 33;
const TRB_PORT_STATUS_CHANGE: u32 = 34;

const COMPLETION_SUCCESS: u8 = 1;
const COMPLETION_SHORT_PACKET: u8 = 13;
const POLL_BUDGET: usize = 10_000_000;

const PORT_CONNECTED: u32 = 1 << 0;
const PORT_ENABLED: u32 = 1 << 1;
const PORT_RESET: u32 = 1 << 4;
const PORT_CHANGE_BITS: u32 = 0x7f << 17;

#[repr(C)]
#[derive(Clone, Copy)]
struct Trb {
    parameter: u64,
    status: u32,
    control: u32,
}

impl Trb {
    const ZERO: Self = Self { parameter: 0, status: 0, control: 0 };

    const fn trb_type(self) -> u32 {
        (self.control >> TRB_TYPE_SHIFT) & 0x3f
    }

    const fn completion_code(self) -> u8 {
        (self.status >> 24) as u8
    }
}

#[repr(C, align(64))]
struct TrbRing([Trb; RING_TRBS]);

impl TrbRing {
    const fn zero() -> Self { Self([Trb::ZERO; RING_TRBS]) }
}

#[repr(C, align(64))]
struct Context([u8; CONTEXT_BYTES]);

impl Context {
    const fn zero() -> Self { Self([0; CONTEXT_BYTES]) }
}

#[repr(C, align(64))]
struct DataBuffer([u8; DATA_BYTES]);

#[repr(C, align(64))]
struct KeyboardBuffer([u8; 8]);

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct ErstEntry {
    address: u64,
    size: u32,
    reserved: u32,
}

#[repr(C, align(4096))]
struct Dma {
    dcbaa: [u64; MAX_SLOTS + 1],
    command: TrbRing,
    event: TrbRing,
    erst: [ErstEntry; 1],
    input: [Context; MAX_SLOTS],
    device: [Context; MAX_SLOTS],
    transfer: [[TrbRing; MAX_DCI]; MAX_SLOTS],
    data: DataBuffer,
    keyboard: [KeyboardBuffer; MAX_SLOTS],
}

impl Dma {
    const fn zero() -> Self {
        Self {
            dcbaa: [0; MAX_SLOTS + 1],
            command: TrbRing::zero(),
            event: TrbRing::zero(),
            erst: [ErstEntry { address: 0, size: 0, reserved: 0 }],
            input: [const { Context::zero() }; MAX_SLOTS],
            device: [const { Context::zero() }; MAX_SLOTS],
            transfer: [const { [const { TrbRing::zero() }; MAX_DCI] }; MAX_SLOTS],
            data: DataBuffer([0; DATA_BYTES]),
            keyboard: [const { KeyboardBuffer([0; 8]) }; MAX_SLOTS],
        }
    }
}

struct SharedDma(UnsafeCell<Dma>);
unsafe impl Sync for SharedDma {}

#[link_section = ".dma"]
static DMA: SharedDma = SharedDma(UnsafeCell::new(Dma::zero()));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BarMissing,
    BarOutsidePlatform,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointDescriptor {
    address: u8,
    attributes: u8,
    max_packet: u16,
    interval: u8,
}

struct Controller {
    base: usize,
    operational: usize,
    runtime: usize,
    doorbells: usize,
    version: u16,
    max_slots: u8,
    max_ports: u8,
    context_size: usize,
    command_index: usize,
    command_cycle: bool,
    event_index: usize,
    event_cycle: bool,
    connected_ports: u8,
    devices: [Option<DeviceInfo>; MAX_SLOTS],
    transfer_index: [[usize; MAX_DCI]; MAX_SLOTS],
    transfer_cycle: [[bool; MAX_DCI]; MAX_SLOTS],
    bot_tag: u32,
    keyboard_pending: [u64; MAX_SLOTS],
    keyboard_last: [[u8; 8]; MAX_SLOTS],
    irq: u32,
    pending_port_changes: u32,
}

static CONTROLLER: SpinLock<Option<Controller>> = SpinLock::new(None);
static INTERRUPTER_BASE: AtomicUsize = AtomicUsize::new(0);
static IRQ_WAIT: crate::exec::WaitQueue = crate::exec::WaitQueue::new();

pub fn init() -> Result<Option<Info>, Error> {
    let function = match crate::pci::find_xhci() {
        Some(function) => function,
        None => return Ok(None),
    };
    let bar = function.bars[0];
    let base = match bar {
        Bar::Memory32 { address, .. } => address as usize,
        Bar::Memory64 { address, .. } => usize::try_from(address).map_err(|_| Error::BarOutsidePlatform)?,
        _ => return Err(Error::BarMissing),
    };
    if !(crate::platform::PCI_MMIO_START..crate::platform::PCI_MMIO_END).contains(&base) {
        return Err(Error::BarOutsidePlatform);
    }
    function.enable_bus_mastering();
    let mut controller = Controller::initialize(base)?;
    let irq = function.interrupt_line.ok_or(Error::BarOutsidePlatform)?;
    controller.irq = irq;
    let interrupter = controller.runtime + 0x20;
    INTERRUPTER_BASE.store(interrupter, Ordering::Release);
    crate::plic::register(irq, irq_handler, 0).map_err(|_| Error::BarOutsidePlatform)?;
    // Clear a stale IP bit while enabling interrupter zero, then admit the
    // routed INTx source only after its allocation-free top half is published.
    write32(interrupter + IMAN, (1 << 1) | 1);
    write32(
        controller.operational + USBCMD,
        read32(controller.operational + USBCMD) | CMD_INTERRUPTER_ENABLE,
    );
    crate::plic::enable(irq).map_err(|_| Error::BarOutsidePlatform)?;
    let info = controller.info();
    *CONTROLLER.lock() = Some(controller);
    Ok(Some(info))
}

pub fn info() -> Option<Info> {
    CONTROLLER.lock().as_ref().map(Controller::info)
}

pub fn devices() -> Vec<DeviceInfo> {
    CONTROLLER
        .lock()
        .as_ref()
        .map(|controller| controller.devices.iter().flatten().copied().collect())
        .unwrap_or_default()
}

pub fn read_sector(sector: u64) -> Result<[u8; 512], Error> {
    let mut guard = CONTROLLER.lock();
    let controller = guard.as_mut().ok_or(Error::NoMassStorage)?;
    let device = controller
        .devices
        .iter()
        .flatten()
        .copied()
        .find(|device| device.kind == DeviceKind::MassStorage)
        .ok_or(Error::NoMassStorage)?;
    if sector >= device.capacity_sectors || sector > u32::MAX as u64 {
        return Err(Error::StorageOutOfRange);
    }
    let mut cdb = [0u8; 16];
    cdb[0] = 0x28;
    cdb[2..6].copy_from_slice(&(sector as u32).to_be_bytes());
    cdb[7..9].copy_from_slice(&1u16.to_be_bytes());
    controller.bot_command(device, &cdb, 10, true, 512, None)?;
    let mut output = [0u8; 512];
    output.copy_from_slice(&dma().data.0[BOT_DATA_OFFSET..BOT_DATA_OFFSET + 512]);
    Ok(output)
}

pub fn write_sector(sector: u64, bytes: &[u8; 512]) -> Result<(), Error> {
    let mut guard = CONTROLLER.lock();
    let controller = guard.as_mut().ok_or(Error::NoMassStorage)?;
    let device = controller
        .devices
        .iter()
        .flatten()
        .copied()
        .find(|device| device.kind == DeviceKind::MassStorage)
        .ok_or(Error::NoMassStorage)?;
    if sector >= device.capacity_sectors || sector > u32::MAX as u64 {
        return Err(Error::StorageOutOfRange);
    }
    let mut cdb = [0u8; 16];
    cdb[0] = 0x2a;
    cdb[2..6].copy_from_slice(&(sector as u32).to_be_bytes());
    cdb[7..9].copy_from_slice(&1u16.to_be_bytes());
    controller.bot_command(device, &cdb, 10, false, 512, Some(bytes))
}

pub async fn service_task() {
    loop {
        // Register before inspecting the event ring. An IRQ racing the drain
        // advances this waiter's epoch, so awaiting it cannot lose the wake.
        let ready = IRQ_WAIT.wait();
        {
            let mut guard = CONTROLLER.lock();
            if let Some(controller) = guard.as_mut() {
                controller.service_keyboards();
            }
        }
        ready.await;
    }
}

impl Controller {
    fn initialize(base: usize) -> Result<Self, Error> {
        let cap0 = read32(base);
        let cap_length = (cap0 & 0xff) as usize;
        let version = (cap0 >> 16) as u16;
        let hcs1 = read32(base + 0x04);
        let hcs2 = read32(base + 0x08);
        let hcc1 = read32(base + 0x10);
        let max_slots = (hcs1 as u8).min(MAX_SLOTS as u8);
        if max_slots == 0 { return Err(Error::NoSlots); }
        let max_ports = ((hcs1 >> 24) as u8).min(32);
        let scratchpads = (((hcs2 >> 27) & 0x1f) << 5) | ((hcs2 >> 21) & 0x1f);
        if scratchpads != 0 { return Err(Error::ScratchpadsUnsupported); }

        let operational = base + cap_length;
        let doorbells = base + (read32(base + 0x14) as usize & !3);
        let runtime = base + (read32(base + 0x18) as usize & !0x1f);
        let mut controller = Self {
            base,
            operational,
            runtime,
            doorbells,
            version,
            max_slots,
            max_ports,
            context_size: if hcc1 & (1 << 2) != 0 { 64 } else { 32 },
            command_index: 0,
            command_cycle: true,
            event_index: 0,
            event_cycle: true,
            connected_ports: 0,
            devices: [None; MAX_SLOTS],
            transfer_index: [[0; MAX_DCI]; MAX_SLOTS],
            transfer_cycle: [[true; MAX_DCI]; MAX_SLOTS],
            bot_tag: 1,
            keyboard_pending: [0; MAX_SLOTS],
            keyboard_last: [[0; 8]; MAX_SLOTS],
            irq: 0,
            pending_port_changes: 0,
        };

        write32(operational + USBCMD, read32(operational + USBCMD) & !CMD_RUN);
        if !wait_until(|| read32(operational + USBSTS) & STS_HALTED != 0) {
            return Err(Error::ResetTimedOut);
        }
        write32(operational + USBCMD, read32(operational + USBCMD) | CMD_RESET);
        if !wait_until(|| {
            read32(operational + USBCMD) & CMD_RESET == 0
                && read32(operational + USBSTS) & STS_CNR == 0
        }) {
            return Err(Error::ResetTimedOut);
        }
        if read32(operational + PAGESIZE) & 1 == 0 {
            return Err(Error::UnsupportedPageSize);
        }

        controller.initialize_dma();
        write64(operational + DCBAAP, dma().dcbaa.as_ptr() as u64);
        write64(
            operational + CRCR,
            dma().command.0.as_ptr() as u64 | u64::from(controller.command_cycle),
        );
        write32(operational + CONFIG, u32::from(max_slots));

        let interrupter = runtime + 0x20;
        write32(interrupter + ERSTSZ, 1);
        write64(interrupter + ERSTBA, dma().erst.as_ptr() as u64);
        write64(interrupter + ERDP, dma().event.0.as_ptr() as u64);
        write32(interrupter + IMOD, 0);
        // Clear pending and leave interrupts disabled. The first implementation
        // drains the event ring synchronously; INTx is enabled with the async
        // service task once enumeration is established.
        write32(interrupter + IMAN, 1);

        write32(operational + USBCMD, read32(operational + USBCMD) | CMD_RUN);
        if !wait_until(|| read32(operational + USBSTS) & STS_HALTED == 0) {
            return Err(Error::StartTimedOut);
        }

        controller.connected_ports = (1..=max_ports)
            .filter(|port| controller.portsc(*port) & 1 != 0)
            .count()
            .min(u8::MAX as usize) as u8;
        for port in 1..=max_ports {
            if controller.portsc(port) & PORT_CONNECTED == 0 { continue; }
            let device = controller.address_port(port)?;
            let index = device.slot as usize - 1;
            controller.devices[index] = Some(device);
        }
        Ok(controller)
    }

    fn initialize_dma(&mut self) {
        // Safety: init is serialized, no controller is running, and every
        // later access is under CONTROLLER. Hardware sees these buffers only
        // after their addresses and cycle states are fully initialized.
        let dma = unsafe { &mut *DMA.0.get() };
        unsafe { core::ptr::write_bytes(dma as *mut Dma, 0, 1) };
        let command_base = dma.command.0.as_ptr() as u64;
        dma.command.0[RING_TRBS - 1] = Trb {
            parameter: command_base,
            status: 0,
            control: (TRB_LINK << TRB_TYPE_SHIFT) | TRB_TOGGLE_CYCLE | TRB_CYCLE,
        };
        dma.erst[0] = ErstEntry {
            address: dma.event.0.as_ptr() as u64,
            size: RING_TRBS as u32,
            reserved: 0,
        };
    }

    fn info(&self) -> Info {
        Info {
            version: self.version,
            mmio_base: self.base,
            max_slots: self.max_slots,
            max_ports: self.max_ports,
            connected_ports: self.connected_ports,
            addressed_devices: self.devices.iter().flatten().count() as u8,
            irq: self.irq,
        }
    }

    fn portsc(&self, port: u8) -> u32 {
        read32(self.operational + PORTSC_BASE + (port as usize - 1) * PORT_STRIDE)
    }

    fn enable_slot(&mut self) -> Result<u8, Error> {
        let event = self.command(Trb {
            parameter: 0,
            status: 0,
            control: TRB_ENABLE_SLOT << TRB_TYPE_SHIFT,
        })?;
        let slot = (event.control >> 24) as u8;
        if slot == 0 || slot > self.max_slots { return Err(Error::CommandFailed(event.completion_code())); }
        Ok(slot)
    }

    fn address_port(&mut self, port: u8) -> Result<DeviceInfo, Error> {
        let portsc_address =
            self.operational + PORTSC_BASE + (port as usize - 1) * PORT_STRIDE;
        let status = read32(portsc_address);
        write32(portsc_address, (status & !PORT_CHANGE_BITS) | PORT_RESET);
        if !wait_until(|| read32(portsc_address) & PORT_RESET == 0) {
            return Err(Error::PortResetTimedOut);
        }
        let status = read32(portsc_address);
        if status & PORT_ENABLED == 0 { return Err(Error::PortNotEnabled); }
        let speed = ((status >> 10) & 0x0f) as u8;
        let max_packet = match speed {
            1 | 2 => 8,
            3 => 64,
            4..=15 => 512,
            _ => return Err(Error::DescriptorMalformed),
        };

        let slot = self.enable_slot()?;
        if slot == 0 || slot as usize > MAX_SLOTS { return Err(Error::InvalidSlot); }
        self.initialize_slot(slot, port, speed, max_packet);
        let input = dma().input[slot as usize - 1].0.as_ptr() as u64;
        self.command(Trb {
            parameter: input,
            status: 0,
            control: (TRB_ADDRESS_DEVICE << TRB_TYPE_SHIFT) | ((slot as u32) << 24),
        })?;

        let descriptor = self.get_descriptor(slot, 1, 0, 18)?;
        if descriptor.len() != 18 || descriptor[0] != 18 || descriptor[1] != 1 {
            return Err(Error::DescriptorMalformed);
        }
        let mut device = DeviceInfo {
            port,
            slot,
            speed,
            usb_version: u16::from_le_bytes([descriptor[2], descriptor[3]]),
            device_class: descriptor[4],
            vendor_id: u16::from_le_bytes([descriptor[8], descriptor[9]]),
            product_id: u16::from_le_bytes([descriptor[10], descriptor[11]]),
            kind: DeviceKind::Unsupported,
            interface: 0,
            configuration: 0,
            endpoint_in: 0,
            endpoint_out: 0,
            max_packet_in: 0,
            max_packet_out: 0,
            capacity_sectors: 0,
        };
        self.configure_usb_device(&mut device)?;
        if device.kind == DeviceKind::MassStorage {
            device.capacity_sectors = self.read_capacity(&device)?;
        }
        Ok(device)
    }

    fn configure_usb_device(&mut self, device: &mut DeviceInfo) -> Result<(), Error> {
        let header = self.get_descriptor(device.slot, 2, 0, 9)?;
        if header[0] != 9 || header[1] != 2 { return Err(Error::DescriptorMalformed); }
        let total = u16::from_le_bytes([header[2], header[3]]) as usize;
        let configuration = header[5];
        if total < 9 || total > DATA_BYTES || configuration == 0 {
            return Err(Error::DescriptorMalformed);
        }
        let bytes = self.get_descriptor(device.slot, 2, 0, total)?;
        let mut offset = 0usize;
        let mut selected = false;
        let mut active_interface = false;
        let mut endpoint_in = None;
        let mut endpoint_out = None;
        while offset + 2 <= bytes.len() {
            let length = bytes[offset] as usize;
            let descriptor_type = bytes[offset + 1];
            if length < 2 || offset + length > bytes.len() {
                return Err(Error::DescriptorMalformed);
            }
            if descriptor_type == 4 && length >= 9 {
                let class = bytes[offset + 5];
                let subclass = bytes[offset + 6];
                let protocol = bytes[offset + 7];
                active_interface = !selected
                    && ((class == 3 && subclass == 1 && protocol == 1)
                        || (class == 8 && subclass == 6 && protocol == 0x50));
                if active_interface {
                    selected = true;
                    device.interface = bytes[offset + 2];
                    device.kind = if class == 3 {
                        DeviceKind::HidKeyboard
                    } else {
                        DeviceKind::MassStorage
                    };
                }
            } else if descriptor_type == 5 && length >= 7 && active_interface {
                let endpoint = EndpointDescriptor {
                    address: bytes[offset + 2],
                    attributes: bytes[offset + 3],
                    max_packet: u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]) & 0x7ff,
                    interval: bytes[offset + 6],
                };
                if endpoint.address & 0x80 != 0 {
                    endpoint_in.get_or_insert(endpoint);
                } else {
                    endpoint_out.get_or_insert(endpoint);
                }
            }
            offset += length;
        }
        device.configuration = configuration;
        let mut endpoints = [None; 2];
        match device.kind {
            DeviceKind::HidKeyboard => {
                let input = endpoint_in.ok_or(Error::UnsupportedConfiguration)?;
                if input.attributes & 3 != 3 { return Err(Error::UnsupportedConfiguration); }
                device.endpoint_in = endpoint_dci(input.address);
                device.max_packet_in = input.max_packet;
                endpoints[0] = Some(input);
            }
            DeviceKind::MassStorage => {
                let input = endpoint_in.ok_or(Error::UnsupportedConfiguration)?;
                let output = endpoint_out.ok_or(Error::UnsupportedConfiguration)?;
                if input.attributes & 3 != 2 || output.attributes & 3 != 2 {
                    return Err(Error::UnsupportedConfiguration);
                }
                device.endpoint_in = endpoint_dci(input.address);
                device.endpoint_out = endpoint_dci(output.address);
                device.max_packet_in = input.max_packet;
                device.max_packet_out = output.max_packet;
                endpoints = [Some(input), Some(output)];
            }
            DeviceKind::Unsupported => {
                self.set_configuration(device.slot, configuration)?;
                return Ok(());
            }
        }
        self.configure_endpoints(*device, endpoints)?;
        self.set_configuration(device.slot, configuration)?;
        if device.kind == DeviceKind::HidKeyboard {
            // HID Set Protocol(0) selects the fixed boot-keyboard report.
            self.control_no_data(device.slot, 0x21, 11, 0, device.interface as u16)?;
        }
        Ok(())
    }

    fn configure_endpoints(
        &mut self,
        device: DeviceInfo,
        endpoints: [Option<EndpointDescriptor>; 2],
    ) -> Result<(), Error> {
        let index = device.slot as usize - 1;
        let dma = unsafe { dma_mut() };
        unsafe {
            core::ptr::write_bytes(dma.input[index].0.as_mut_ptr(), 0, CONTEXT_BYTES);
            core::ptr::copy_nonoverlapping(
                dma.device[index].0.as_ptr(),
                dma.input[index].0.as_mut_ptr().add(self.context_size),
                self.context_size,
            );
        }
        let mut add_flags = 1u32;
        let mut highest_dci = 1u8;
        for endpoint in endpoints.into_iter().flatten() {
            let dci = endpoint_dci(endpoint.address);
            if dci as usize >= MAX_DCI { return Err(Error::UnsupportedConfiguration); }
            highest_dci = highest_dci.max(dci);
            add_flags |= 1u32 << dci;
            let ring_storage = &mut dma.transfer[index][dci as usize];
            unsafe { core::ptr::write_bytes(ring_storage.0.as_mut_ptr(), 0, RING_TRBS) };
            let ring_base = ring_storage.0.as_ptr() as u64;
            ring_storage.0[RING_TRBS - 1] = Trb {
                parameter: ring_base,
                status: 0,
                control: (TRB_LINK << TRB_TYPE_SHIFT) | TRB_TOGGLE_CYCLE | TRB_CYCLE,
            };
            self.transfer_index[index][dci as usize] = 0;
            self.transfer_cycle[index][dci as usize] = true;
            let ring = dma.transfer[index][dci as usize].0.as_ptr() as u64;
            let direction_in = endpoint.address & 0x80 != 0;
            let transfer_type = endpoint.attributes & 3;
            let endpoint_type = match (transfer_type, direction_in) {
                (2, false) => 2,
                (2, true) => 6,
                (3, false) => 3,
                (3, true) => 7,
                _ => return Err(Error::UnsupportedConfiguration),
            };
            let interval = endpoint_interval(device.speed, endpoint.interval, transfer_type);
            let context = self.context_size * (dci as usize + 1);
            unsafe {
                write_context_u32(
                    dma.input[index].0.as_mut_ptr(),
                    context,
                    0,
                    (interval as u32) << 16,
                );
                write_context_u32(
                    dma.input[index].0.as_mut_ptr(),
                    context,
                    1,
                    (3 << 1) | (endpoint_type << 3) | ((endpoint.max_packet as u32) << 16),
                );
                write_context_u32(dma.input[index].0.as_mut_ptr(), context, 2, ring as u32 | 1);
                write_context_u32(dma.input[index].0.as_mut_ptr(), context, 3, (ring >> 32) as u32);
                write_context_u32(
                    dma.input[index].0.as_mut_ptr(),
                    context,
                    4,
                    endpoint.max_packet as u32
                        | if transfer_type == 3 { (endpoint.max_packet as u32) << 16 } else { 0 },
                );
            }
        }
        let input = dma.input[index].0.as_mut_ptr();
        unsafe {
            write_context_u32(input, 0, 1, add_flags);
            let slot_dw0 = read_context_u32(input, self.context_size, 0);
            write_context_u32(
                input,
                self.context_size,
                0,
                (slot_dw0 & !(0x1f << 27)) | ((highest_dci as u32) << 27),
            );
        }
        self.command(Trb {
            parameter: dma.input[index].0.as_ptr() as u64,
            status: 0,
            control: (TRB_CONFIGURE_ENDPOINT << TRB_TYPE_SHIFT)
                | ((device.slot as u32) << 24),
        })?;
        Ok(())
    }

    fn set_configuration(&mut self, slot: u8, configuration: u8) -> Result<(), Error> {
        self.control_no_data(slot, 0, 9, configuration as u16, 0)
    }

    fn control_no_data(
        &mut self,
        slot: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
    ) -> Result<(), Error> {
        let setup = request_type as u64
            | ((request as u64) << 8)
            | ((value as u64) << 16)
            | ((index as u64) << 32);
        self.transfer(slot, 1, &[
            Trb {
                parameter: setup,
                status: 8,
                control: (TRB_SETUP_STAGE << TRB_TYPE_SHIFT) | (1 << 6),
            },
            Trb {
                parameter: 0,
                status: 0,
                control: (TRB_STATUS_STAGE << TRB_TYPE_SHIFT) | TRB_IOC | (1 << 16),
            },
        ])
    }

    fn bulk_transfer(
        &mut self,
        slot: u8,
        dci: u8,
        address: u64,
        length: usize,
    ) -> Result<(), Error> {
        if length == 0 || length > DATA_BYTES { return Err(Error::StorageProtocol); }
        self.transfer(slot, dci, &[Trb {
            parameter: address,
            status: length as u32,
            control: (TRB_NORMAL << TRB_TYPE_SHIFT) | TRB_IOC,
        }])
    }

    fn read_capacity(&mut self, device: &DeviceInfo) -> Result<u64, Error> {
        let mut tur = [0u8; 16];
        tur[0] = 0x00;
        if self.bot_command(*device, &tur, 6, true, 0, None).is_err() {
            let mut sense = [0u8; 16];
            sense[0] = 0x03;
            sense[4] = 18;
            let _ = self.bot_command(*device, &sense, 6, true, 18, None);
        }
        let cdb = [0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut result = self.bot_command(*device, &cdb, 10, true, 8, None);
        if matches!(result, Err(Error::StorageCommandFailed(_))) {
            let mut sense = [0u8; 16];
            sense[0] = 0x03;
            sense[4] = 18;
            let _ = self.bot_command(*device, &sense, 6, true, 18, None);
            result = self.bot_command(*device, &cdb, 10, true, 8, None);
        }
        result?;
        let data = &dma().data.0[BOT_DATA_OFFSET..BOT_DATA_OFFSET + 8];
        let last_lba = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let block_size = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if block_size != 512 { return Err(Error::StorageBlockSize(block_size)); }
        if last_lba == u32::MAX { return Err(Error::StorageProtocol); }
        Ok(u64::from(last_lba) + 1)
    }

    fn bot_command(
        &mut self,
        device: DeviceInfo,
        cdb: &[u8; 16],
        cdb_length: u8,
        data_in: bool,
        data_length: usize,
        output: Option<&[u8]>,
    ) -> Result<(), Error> {
        const CBW_LENGTH: usize = 31;
        const CSW_LENGTH: usize = 13;
        if cdb_length == 0 || cdb_length > 16 || data_length > BOT_CSW_OFFSET - BOT_DATA_OFFSET {
            return Err(Error::StorageProtocol);
        }
        let tag = self.bot_tag;
        self.bot_tag = self.bot_tag.checked_add(1).ok_or(Error::StorageProtocol)?;
        let buffer = unsafe { &mut dma_mut().data.0 };
        buffer[..CBW_LENGTH].fill(0);
        buffer[0..4].copy_from_slice(&0x4342_5355u32.to_le_bytes());
        buffer[4..8].copy_from_slice(&tag.to_le_bytes());
        buffer[8..12].copy_from_slice(&(data_length as u32).to_le_bytes());
        buffer[12] = if data_in { 0x80 } else { 0 };
        buffer[13] = 0;
        buffer[14] = cdb_length;
        buffer[15..31].copy_from_slice(cdb);
        if let Some(bytes) = output {
            if bytes.len() != data_length { return Err(Error::StorageProtocol); }
            buffer[BOT_DATA_OFFSET..BOT_DATA_OFFSET + data_length].copy_from_slice(bytes);
        } else if data_length != 0 {
            buffer[BOT_DATA_OFFSET..BOT_DATA_OFFSET + data_length].fill(0);
        }
        buffer[BOT_CSW_OFFSET..BOT_CSW_OFFSET + CSW_LENGTH].fill(0);
        let base = buffer.as_ptr() as u64;
        self.bulk_transfer(device.slot, device.endpoint_out, base, CBW_LENGTH)?;
        if data_length != 0 {
            self.bulk_transfer(
                device.slot,
                if data_in { device.endpoint_in } else { device.endpoint_out },
                base + BOT_DATA_OFFSET as u64,
                data_length,
            )?;
        }
        self.bulk_transfer(
            device.slot,
            device.endpoint_in,
            base + BOT_CSW_OFFSET as u64,
            CSW_LENGTH,
        )?;
        let csw = &dma().data.0[BOT_CSW_OFFSET..BOT_CSW_OFFSET + CSW_LENGTH];
        let signature = u32::from_le_bytes(csw[0..4].try_into().unwrap());
        let observed_tag = u32::from_le_bytes(csw[4..8].try_into().unwrap());
        let residue = u32::from_le_bytes(csw[8..12].try_into().unwrap());
        if signature != 0x5342_5355 { return Err(Error::StorageCswSignature(signature)); }
        if observed_tag != tag { return Err(Error::StorageCswTag(observed_tag)); }
        if csw[12] != 0 { return Err(Error::StorageCommandFailed(csw[12])); }
        if residue != 0 { return Err(Error::StorageCswResidue(residue)); }
        Ok(())
    }

    fn initialize_slot(&mut self, slot: u8, port: u8, speed: u8, max_packet: u16) {
        let index = slot as usize - 1;
        // Safety: the slot is bounded above and controller serialization makes
        // these exact context/ring buffers exclusively mutable here.
        let dma = unsafe { dma_mut() };
        unsafe {
            core::ptr::write_bytes(dma.input[index].0.as_mut_ptr(), 0, CONTEXT_BYTES);
            core::ptr::write_bytes(dma.device[index].0.as_mut_ptr(), 0, CONTEXT_BYTES);
            core::ptr::write_bytes(
                dma.transfer[index][1].0.as_mut_ptr(),
                0,
                RING_TRBS,
            );
        }
        let ring_base = dma.transfer[index][1].0.as_ptr() as u64;
        dma.transfer[index][1].0[RING_TRBS - 1] = Trb {
            parameter: ring_base,
            status: 0,
            control: (TRB_LINK << TRB_TYPE_SHIFT) | TRB_TOGGLE_CYCLE | TRB_CYCLE,
        };
        self.transfer_index[index][1] = 0;
        self.transfer_cycle[index][1] = true;

        dma.dcbaa[slot as usize] = dma.device[index].0.as_ptr() as u64;
        let input = dma.input[index].0.as_mut_ptr();
        unsafe {
            // Input Control Context: add Slot and DCI 1 (EP0).
            write_context_u32(input, 0, 1, 0b11);
            // Slot Context: speed, Context Entries=1, root-hub port.
            write_context_u32(
                input,
                self.context_size,
                0,
                ((speed as u32) << 20) | (1 << 27),
            );
            write_context_u32(
                input,
                self.context_size,
                1,
                (port as u32) << 16,
            );
            // EP0 Context: CErr=3, Control endpoint, MPS and dequeue cycle.
            let ep0 = self.context_size * 2;
            write_context_u32(
                input,
                ep0,
                1,
                (3 << 1) | (4 << 3) | ((max_packet as u32) << 16),
            );
            write_context_u32(input, ep0, 2, ring_base as u32 | 1);
            write_context_u32(input, ep0, 3, (ring_base >> 32) as u32);
            write_context_u32(input, ep0, 4, 8);
        }
    }

    fn get_descriptor(
        &mut self,
        slot: u8,
        descriptor_type: u8,
        descriptor_index: u8,
        length: usize,
    ) -> Result<&'static [u8], Error> {
        if length == 0 || length > DATA_BYTES { return Err(Error::DescriptorMalformed); }
        let setup = 0x80u64
            | (6u64 << 8)
            | ((((descriptor_type as u16) << 8 | descriptor_index as u16) as u64) << 16)
            | ((length as u64) << 48);
        unsafe { core::ptr::write_bytes(dma_mut().data.0.as_mut_ptr(), 0, length) };
        let data_address = dma().data.0.as_ptr() as u64;
        let trbs = [
            Trb {
                parameter: setup,
                status: 8,
                control: (TRB_SETUP_STAGE << TRB_TYPE_SHIFT) | (1 << 6) | (3 << 16),
            },
            Trb {
                parameter: data_address,
                status: length as u32,
                control: (TRB_DATA_STAGE << TRB_TYPE_SHIFT) | (1 << 16),
            },
            Trb {
                parameter: 0,
                status: 0,
                control: (TRB_STATUS_STAGE << TRB_TYPE_SHIFT) | TRB_IOC,
            },
        ];
        self.transfer(slot, 1, &trbs)?;
        Ok(unsafe { core::slice::from_raw_parts(dma().data.0.as_ptr(), length) })
    }

    fn transfer(&mut self, slot: u8, dci: u8, trbs: &[Trb]) -> Result<(), Error> {
        let slot_index = slot.checked_sub(1).ok_or(Error::InvalidSlot)? as usize;
        let dci_index = dci as usize;
        if slot_index >= MAX_SLOTS || dci_index == 0 || dci_index >= MAX_DCI {
            return Err(Error::InvalidSlot);
        }
        let mut last = core::ptr::null_mut();
        for trb in trbs {
            let index = self.transfer_index[slot_index][dci_index];
            let cycle = self.transfer_cycle[slot_index][dci_index];
            let pointer = unsafe {
                dma_mut().transfer[slot_index][dci_index]
                    .0
                    .as_mut_ptr()
                    .add(index)
            };
            let mut published = *trb;
            published.control |= u32::from(cycle);
            unsafe { pointer.write_volatile(published) };
            last = pointer;
            let next = index + 1;
            if next == RING_TRBS - 1 {
                unsafe {
                    let link = dma_mut().transfer[slot_index][dci_index]
                        .0
                        .as_mut_ptr()
                        .add(RING_TRBS - 1);
                    let mut value = link.read_volatile();
                    value.control = (value.control & !TRB_CYCLE) | u32::from(cycle);
                    link.write_volatile(value);
                }
                self.transfer_index[slot_index][dci_index] = 0;
                self.transfer_cycle[slot_index][dci_index] = !cycle;
            } else {
                self.transfer_index[slot_index][dci_index] = next;
            }
        }
        io_fence();
        write32(self.doorbells + slot as usize * 4, dci as u32);
        for _ in 0..POLL_BUDGET {
            if let Some(event) = self.next_event() {
                if event.trb_type() == TRB_TRANSFER_EVENT
                    && event.parameter == last as u64
                    && (event.control >> 24) as u8 == slot
                    && ((event.control >> 16) & 0x1f) as u8 == dci
                {
                    return match event.completion_code() {
                        COMPLETION_SUCCESS | COMPLETION_SHORT_PACKET => Ok(()),
                        code => Err(Error::TransferFailed(code)),
                    };
                }
                self.record_async_event(event);
            }
            core::hint::spin_loop();
        }
        Err(Error::TransferTimedOut)
    }

    fn command(&mut self, trb: Trb) -> Result<Trb, Error> {
        let index = self.command_index;
        let pointer = unsafe { dma_mut().command.0.as_mut_ptr().add(index) };
        let mut published = trb;
        published.control |= u32::from(self.command_cycle);
        unsafe { pointer.write_volatile(published) };
        io_fence();
        self.command_index += 1;
        if self.command_index == RING_TRBS - 1 {
            unsafe {
                let link = dma_mut().command.0.as_mut_ptr().add(RING_TRBS - 1);
                let mut value = link.read_volatile();
                value.control = (value.control & !TRB_CYCLE) | u32::from(self.command_cycle);
                link.write_volatile(value);
            }
            self.command_index = 0;
            self.command_cycle = !self.command_cycle;
        }
        write32(self.doorbells, 0);

        for _ in 0..POLL_BUDGET {
            if let Some(event) = self.next_event() {
                if event.trb_type() == TRB_COMMAND_COMPLETION && event.parameter == pointer as u64 {
                    return if event.completion_code() == COMPLETION_SUCCESS {
                        Ok(event)
                    } else {
                        Err(Error::CommandFailed(event.completion_code()))
                    };
                }
                self.record_async_event(event);
            }
            core::hint::spin_loop();
        }
        Err(Error::CommandTimedOut)
    }

    fn service_keyboards(&mut self) {
        while let Some(event) = self.next_event() {
            self.record_async_event(event);
        }
        self.process_port_changes();
        let devices = self.devices;
        for device in devices.into_iter().flatten() {
            if device.kind != DeviceKind::HidKeyboard { continue; }
            let index = device.slot as usize - 1;
            if self.keyboard_pending[index] != 0 { continue; }
            if let Ok(pointer) = self.submit_keyboard(device) {
                self.keyboard_pending[index] = pointer;
            }
        }
    }

    fn submit_keyboard(&mut self, device: DeviceInfo) -> Result<u64, Error> {
        let slot_index = device.slot.checked_sub(1).ok_or(Error::InvalidSlot)? as usize;
        let dci_index = device.endpoint_in as usize;
        if slot_index >= MAX_SLOTS || dci_index == 0 || dci_index >= MAX_DCI {
            return Err(Error::InvalidSlot);
        }
        let index = self.transfer_index[slot_index][dci_index];
        let cycle = self.transfer_cycle[slot_index][dci_index];
        let pointer = unsafe {
            dma_mut().transfer[slot_index][dci_index]
                .0
                .as_mut_ptr()
                .add(index)
        };
        unsafe {
            pointer.write_volatile(Trb {
                parameter: dma().keyboard[slot_index].0.as_ptr() as u64,
                status: 8,
                control: (TRB_NORMAL << TRB_TYPE_SHIFT) | TRB_IOC | u32::from(cycle),
            });
        }
        let next = index + 1;
        if next == RING_TRBS - 1 {
            unsafe {
                let link = dma_mut().transfer[slot_index][dci_index]
                    .0
                    .as_mut_ptr()
                    .add(RING_TRBS - 1);
                let mut value = link.read_volatile();
                value.control = (value.control & !TRB_CYCLE) | u32::from(cycle);
                link.write_volatile(value);
            }
            self.transfer_index[slot_index][dci_index] = 0;
            self.transfer_cycle[slot_index][dci_index] = !cycle;
        } else {
            self.transfer_index[slot_index][dci_index] = next;
        }
        io_fence();
        write32(
            self.doorbells + device.slot as usize * 4,
            device.endpoint_in as u32,
        );
        Ok(pointer as u64)
    }

    fn handle_keyboard_event(&mut self, event: Trb) {
        if event.trb_type() != TRB_TRANSFER_EVENT { return; }
        let slot = (event.control >> 24) as u8;
        let Some(index) = slot.checked_sub(1).map(usize::from) else { return; };
        if index >= MAX_SLOTS || self.keyboard_pending[index] != event.parameter { return; }
        self.keyboard_pending[index] = 0;
        if !matches!(event.completion_code(), COMPLETION_SUCCESS | COMPLETION_SHORT_PACKET) {
            return;
        }
        let report = dma().keyboard[index].0;
        let previous = self.keyboard_last[index];
        self.keyboard_last[index] = report;
        for key in report[2..].iter().copied().filter(|key| *key > 3) {
            if previous[2..].contains(&key) { continue; }
            let (bytes, length) = hid_key_bytes(key, report[0]);
            for byte in &bytes[..length] {
                crate::uart::inject_usb_input(*byte);
            }
        }
    }

    fn record_async_event(&mut self, event: Trb) {
        if event.trb_type() == TRB_PORT_STATUS_CHANGE {
            let port = (event.parameter >> 24) as u8;
            if (1..=self.max_ports).contains(&port) {
                self.pending_port_changes |= 1u32 << (port - 1);
            }
            return;
        }
        self.handle_keyboard_event(event);
    }

    fn process_port_changes(&mut self) {
        let changes = core::mem::take(&mut self.pending_port_changes);
        for port in 1..=self.max_ports {
            if changes & (1u32 << (port - 1)) == 0 { continue; }
            let address = self.operational + PORTSC_BASE + (port as usize - 1) * PORT_STRIDE;
            let status = read32(address);
            // Every change bit is RW1C; writing the observed value clears only
            // causes that were part of this event while preserving port power.
            write32(
                address,
                (status & ((1 << 9) | (7 << 25))) | (status & PORT_CHANGE_BITS),
            );
            let existing = self
                .devices
                .iter()
                .position(|device| device.is_some_and(|device| device.port == port));
            if status & PORT_CONNECTED == 0 {
                if let Some(index) = existing {
                    let slot = self.devices[index].unwrap().slot;
                    let _ = self.command(Trb {
                        parameter: 0,
                        status: 0,
                        control: (TRB_DISABLE_SLOT << TRB_TYPE_SHIFT) | ((slot as u32) << 24),
                    });
                    self.devices[index] = None;
                    self.keyboard_pending[index] = 0;
                    self.keyboard_last[index] = [0; 8];
                    unsafe { dma_mut().dcbaa[slot as usize] = 0 };
                }
            } else if existing.is_none() {
                if let Ok(device) = self.address_port(port) {
                    let index = device.slot as usize - 1;
                    self.devices[index] = Some(device);
                }
            }
        }
        self.connected_ports = (1..=self.max_ports)
            .filter(|port| self.portsc(*port) & PORT_CONNECTED != 0)
            .count() as u8;
    }

    fn next_event(&mut self) -> Option<Trb> {
        let pointer = unsafe { dma().event.0.as_ptr().add(self.event_index) };
        let event = unsafe { pointer.read_volatile() };
        if event.control & TRB_CYCLE != u32::from(self.event_cycle) {
            return None;
        }
        self.event_index += 1;
        if self.event_index == RING_TRBS {
            self.event_index = 0;
            self.event_cycle = !self.event_cycle;
        }
        let next = unsafe { dma().event.0.as_ptr().add(self.event_index) } as u64;
        write64(self.runtime + 0x20 + ERDP, next | (1 << 3));
        Some(event)
    }
}

fn dma() -> &'static Dma {
    unsafe { &*DMA.0.get() }
}

unsafe fn dma_mut() -> &'static mut Dma {
    unsafe { &mut *DMA.0.get() }
}

fn irq_handler(_context: usize, _irq_entry: u64) {
    let interrupter = INTERRUPTER_BASE.load(Ordering::Acquire);
    if interrupter == 0 { return; }
    let iman = read32(interrupter + IMAN);
    if iman & 1 == 0 { return; }
    // IP is RW1C and IE is ordinary RW. Preserve enable while acknowledging
    // only the pending bit; the event-ring consumer clears EHB separately.
    write32(interrupter + IMAN, (iman & (1 << 1)) | 1);
    IRQ_WAIT.wake_all();
}

fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..POLL_BUDGET {
        if condition() { return true; }
        core::hint::spin_loop();
    }
    false
}

unsafe fn write_context_u32(base: *mut u8, context: usize, dword: usize, value: u32) {
    unsafe { (base.add(context + dword * 4) as *mut u32).write_volatile(value) };
}

unsafe fn read_context_u32(base: *const u8, context: usize, dword: usize) -> u32 {
    unsafe { (base.add(context + dword * 4) as *const u32).read_volatile() }
}

const fn endpoint_dci(address: u8) -> u8 {
    let number = address & 0x0f;
    number * 2 + if address & 0x80 != 0 { 1 } else { 0 }
}

fn endpoint_interval(speed: u8, interval: u8, transfer_type: u8) -> u8 {
    if transfer_type != 3 { return 0; }
    match speed {
        // Low/full speed bInterval is in frames; XHCI stores an exponent in
        // 125-us units. Round up so the endpoint is never polled too often.
        1 | 2 => (u32::from(interval.max(1)) * 8)
            .next_power_of_two()
            .trailing_zeros()
            .min(15) as u8,
        // High/SuperSpeed descriptors already encode an exponent starting at
        // one, whereas the endpoint context starts at zero.
        _ => interval.saturating_sub(1).min(15),
    }
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
        let plain = b"1234567890"[index];
        let shifted = b"!@#$%^&*()"[index];
        return ([if shift { shifted } else { plain }, 0, 0], 1);
    }
    let byte = match key {
        40 => b'\n',
        41 => 0x1b,
        42 => 0x7f,
        43 => b'\t',
        44 => b' ',
        45 => if shift { b'_' } else { b'-' },
        46 => if shift { b'+' } else { b'=' },
        47 => if shift { b'{' } else { b'[' },
        48 => if shift { b'}' } else { b']' },
        49 => if shift { b'|' } else { b'\\' },
        50 => if shift { b'~' } else { b'#' },
        51 => if shift { b':' } else { b';' },
        52 => if shift { b'"' } else { b'\'' },
        53 => if shift { b'~' } else { b'`' },
        54 => if shift { b'<' } else { b',' },
        55 => if shift { b'>' } else { b'.' },
        56 => if shift { b'?' } else { b'/' },
        76 => 0x7f,
        79 => return ([0x1b, b'[', b'C'], 3),
        80 => return ([0x1b, b'[', b'D'], 3),
        81 => return ([0x1b, b'[', b'B'], 3),
        82 => return ([0x1b, b'[', b'A'], 3),
        _ => return ([0; 3], 0),
    };
    ([byte, 0, 0], 1)
}

#[inline]
fn read32(address: usize) -> u32 {
    let value = unsafe { (address as *const u32).read_volatile() };
    io_fence();
    value
}

#[inline]
fn write32(address: usize, value: u32) {
    io_fence();
    unsafe { (address as *mut u32).write_volatile(value) };
    io_fence();
}

#[inline]
fn write64(address: usize, value: u64) {
    debug_assert_eq!(address & 7, 0);
    io_fence();
    unsafe { (address as *mut u64).write_volatile(value) };
    io_fence();
}

#[inline]
fn io_fence() {
    unsafe { asm!("fence iorw, iorw", options(nostack, preserves_flags)) };
}
