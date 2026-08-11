//! CV1800B SDIO0 block backend for the Milk-V Duo boot microSD.
//!
//! The first hardware revision deliberately uses one-bit, 25 MHz PIO. This
//! avoids publishing DMA addresses and avoids the board-specific SDR104 tuning
//! sequence until the conservative path has been accepted on real hardware.

extern crate alloc;

use alloc::{format, string::String, sync::Arc};
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use vibeos_driver_sdhci_blk::{Card as HardwareCard, Error as HardwareError};

use crate::cap::{Cap, InvocationLease, Resource, Rights};
use crate::exec::WaitQueue;
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::sync::SpinLock;
use crate::world::Space;

const SDHCI: vibeos_hal::SdhciDescription = crate::platform::SDHCI;
const BASE: usize = SDHCI.registers.start;
const IRQ: u32 = SDHCI.irq;
// The packaged image places a raw VibeOS data partition immediately after the
// 128 MiB FAT boot partition. Expose that partition as logical sector zero so
// existing block acceptance sectors and the journal can never overwrite FIP,
// FIT, or FAT metadata.
const DATA_FIRST_SECTOR: u64 = 262_145;
const DATA_SECTORS: u64 = 8_192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    Offline,
    QueueFull,
    OutOfRange,
    ReadOnly,
    FlushUnsupported,
    TimedOut,
    DriverCancelled,
    DriverFault,
    DriverRestarted,
    DeviceIo,
    Unsupported,
    Protocol,
    Quarantined,
    AuthorityRevoked,
    PermissionDenied,
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Offline => "microSD is offline",
            Self::QueueFull => "microSD request queue is full",
            Self::OutOfRange => "sector is outside the microSD capacity",
            Self::ReadOnly => "microSD is read-only",
            Self::FlushUnsupported => "microSD flush is unsupported",
            Self::TimedOut => "microSD controller timed out",
            Self::DriverCancelled => "microSD driver was cancelled",
            Self::DriverFault => "microSD driver faulted",
            Self::DriverRestarted => "microSD driver session restarted",
            Self::DeviceIo => "microSD reported an I/O error",
            Self::Unsupported => "unsupported microSD card",
            Self::Protocol => "malformed microSD response",
            Self::Quarantined => "microSD controller is quarantined",
            Self::AuthorityRevoked => "microSD capability is absent or revoked",
            Self::PermissionDenied => "microSD capability lacks the required right",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    pub online: bool,
    pub quarantined: bool,
    pub capacity_sectors: u64,
    pub queue_size: u16,
    pub read_only: bool,
    pub supports_flush: bool,
    pub session_epoch: u64,
    pub irq: u32,
    pub used_interrupts: u64,
    pub last_error: Option<BlockError>,
    pub last_command: u8,
    pub interrupt_status: u32,
    pub present_state: u32,
}

pub struct MmioWindow;
impl Resource for MmioWindow {
    fn kind(&self) -> &'static str {
        "cv1800b-sdhci-mmio"
    }
    fn describe(&self) -> String {
        format!("CV1800B SDIO0 @ {BASE:#x}, IRQ {IRQ}")
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct DmaRegion;
impl Resource for DmaRegion {
    fn kind(&self) -> &'static str {
        "pio-region"
    }
    fn describe(&self) -> String {
        String::from("SDHCI PIO (no device-visible DMA)")
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct BlockDevice;
impl BlockDevice {
    fn info(&self) -> BlockInfo {
        let state = HOST.lock();
        BlockInfo {
            online: state.online,
            quarantined: state.quarantined,
            capacity_sectors: state.capacity_sectors,
            queue_size: 1,
            read_only: false,
            supports_flush: true,
            session_epoch: state.epoch,
            irq: IRQ,
            used_interrupts: 0,
            last_error: state.last_error,
            last_command: state.last_command,
            interrupt_status: state.interrupt_status,
            present_state: state.present_state,
        }
    }
}
impl Resource for BlockDevice {
    fn kind(&self) -> &'static str {
        "block-device"
    }
    fn describe(&self) -> String {
        let info = self.info();
        format!(
            "microSD [online {}, sectors {}, PIO, epoch {}]",
            info.online, info.capacity_sectors, info.session_epoch
        )
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct BlockResources {
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub device: Arc<BlockDevice>,
}

pub fn discover() -> Option<BlockResources> {
    Some(BlockResources {
        mmio: Arc::new(MmioWindow),
        dma: Arc::new(DmaRegion),
        device: Arc::new(BlockDevice),
    })
}

pub fn info_with(lease: &InvocationLease<BlockDevice>) -> Result<BlockInfo, BlockError> {
    if !lease.authorizes(Rights::READ) {
        return Err(BlockError::PermissionDenied);
    }
    Ok(lease.with(BlockDevice::info))
}

pub async fn read_with(
    lease: InvocationLease<BlockDevice>,
    sector: u64,
) -> Result<[u8; 512], BlockError> {
    if !lease.authorizes(Rights::READ) {
        return Err(BlockError::PermissionDenied);
    }
    lease.with(|_| ());
    let result = with_card(|card| card.read_sector(sector));
    drop(lease);
    result
}

pub async fn write_with(
    lease: InvocationLease<BlockDevice>,
    sector: u64,
    data: [u8; 512],
) -> Result<(), BlockError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(BlockError::PermissionDenied);
    }
    lease.with(|_| ());
    let result = with_card(|card| card.write_sector(sector, &data));
    drop(lease);
    result
}

pub async fn flush_with(lease: InvocationLease<BlockDevice>) -> Result<(), BlockError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(BlockError::PermissionDenied);
    }
    lease.with(|_| ());
    let result = with_card(Card::flush);
    drop(lease);
    result
}

fn with_card<T>(
    operation: impl FnOnce(&mut Card) -> Result<T, BlockError>,
) -> Result<T, BlockError> {
    if IO_CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(BlockError::QueueFull);
    }
    let domain = crate::heap::current_domain();
    IO_OWNER.store(domain.owner.get(), Ordering::Release);
    IO_ARENA.store(domain.arena.get(), Ordering::Release);
    let mut card = {
        let mut state = HOST.lock();
        if state.quarantined {
            release_io_claim();
            return Err(BlockError::Quarantined);
        }
        if !state.online {
            release_io_claim();
            return Err(BlockError::Offline);
        }
        match state.card.take() {
            Some(card) => card,
            None => {
                release_io_claim();
                return Err(BlockError::Offline);
            }
        }
    };
    let result = operation(&mut card);
    let last_command = card.hardware.last_command();
    let interrupt_status = card.hardware.last_interrupt_status();
    let present_state = card.hardware.present_state();
    let mut state = HOST.lock();
    state.last_command = last_command;
    state.interrupt_status = interrupt_status;
    state.present_state = present_state;
    if state.online {
        state.card = Some(card);
    }
    drop(state);
    release_io_claim();
    result
}

struct Card {
    hardware: HardwareCard,
    capacity_sectors: u64,
}

struct HostState {
    card: Option<Card>,
    capacity_sectors: u64,
    last_command: u8,
    interrupt_status: u32,
    present_state: u32,
    epoch: u64,
    online: bool,
    quarantined: bool,
    last_error: Option<BlockError>,
}

static HOST: SpinLock<HostState> = SpinLock::new_recoverable(HostState {
    card: None,
    capacity_sectors: 0,
    last_command: 0,
    interrupt_status: 0,
    present_state: 0,
    epoch: 0,
    online: false,
    quarantined: false,
    last_error: None,
});
static DRIVER_PARK: WaitQueue = WaitQueue::new();
static IO_CLAIMED: AtomicBool = AtomicBool::new(false);
static IO_OWNER: AtomicU64 = AtomicU64::new(OwnerId::SYSTEM.get());
static IO_ARENA: AtomicU64 = AtomicU64::new(ArenaId::UNTRACKED.get());

fn release_io_claim() {
    IO_OWNER.store(OwnerId::SYSTEM.get(), Ordering::Release);
    IO_ARENA.store(ArenaId::UNTRACKED.get(), Ordering::Release);
    IO_CLAIMED.store(false, Ordering::Release);
}

pub async fn driver_task(space: &'static Space, mmio: Cap, dma: Cap, service: Cap) {
    // Resolve every explicit grant before touching hardware. The retained
    // leases keep the derivation alive for this incarnation.
    let authority = {
        let cspace = space.0.lock();
        (
            cspace.lookup_revocable::<MmioWindow>(mmio, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<DmaRegion>(dma, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<BlockDevice>(service, Rights::READ.union(Rights::WRITE)),
        )
    };
    let (Ok(_mmio), Ok(_pio), Ok(_service)) = authority else {
        return;
    };

    let domain = crate::heap::current_domain();
    if IO_CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    IO_OWNER.store(domain.owner.get(), Ordering::Release);
    IO_ARENA.store(domain.arena.get(), Ordering::Release);
    {
        // Close the previous incarnation before obtaining a second exclusive
        // hardware owner. The shared IO claim prevents a capability request
        // from temporarily carrying the old Card outside HOST.
        let mut state = HOST.lock();
        state.online = false;
        state.card = None;
    }
    let initialized =
        match _mmio.try_with(|_| _pio.try_with(|_| _service.try_with(|_| Card::initialize()))) {
            Ok(Ok(Ok(result))) => result,
            _ => Err(BlockError::AuthorityRevoked),
        };
    {
        let mut state = HOST.lock();
        state.epoch = state.epoch.checked_add(1).expect("SDHCI epoch exhausted");
        match initialized {
            Ok(card) => {
                state.capacity_sectors = card.capacity_sectors;
                state.last_command = card.hardware.last_command();
                state.interrupt_status = card.hardware.last_interrupt_status();
                state.present_state = card.hardware.present_state();
                state.card = Some(card);
                state.online = true;
                state.quarantined = false;
                state.last_error = None;
            }
            Err(error) => {
                state.card = None;
                state.capacity_sectors = 0;
                state.last_command = 0;
                state.interrupt_status = 0;
                state.present_state = 0;
                state.online = false;
                state.last_error = Some(error);
            }
        }
    }
    release_io_claim();
    let _session = DriverSession {
        epoch: HOST.lock().epoch,
    };

    // PIO requests are executed synchronously at the capability invocation
    // boundary. Keep this supervised incarnation alive so cancellation and
    // restart retain the same lifecycle shape as the QEMU backend.
    loop {
        DRIVER_PARK.wait().await;
    }
}

struct DriverSession {
    epoch: u64,
}

impl Drop for DriverSession {
    fn drop(&mut self) {
        let mut state = HOST.lock();
        if state.epoch == self.epoch {
            state.card = None;
            state.online = false;
        }
    }
}

impl Card {
    fn initialize() -> Result<Self, BlockError> {
        // Safety: the board firmware identity-maps both descriptor ranges, and
        // the retained MMIO capability above gives this supervised incarnation
        // exclusive authority to use the controller until it exits.
        let hardware = unsafe {
            HardwareCard::initialize(SDHCI, crate::platform::TIMEBASE_HZ, crate::sbi::time)
        }
        .map_err(map_hardware_error)?;
        let physical_capacity = hardware.info().capacity_sectors;
        let available_sectors = physical_capacity
            .checked_sub(DATA_FIRST_SECTOR)
            .ok_or(BlockError::Unsupported)?;
        if available_sectors < DATA_SECTORS {
            return Err(BlockError::Unsupported);
        }
        Ok(Self {
            hardware,
            capacity_sectors: DATA_SECTORS,
        })
    }

    fn physical_sector(&self, logical_sector: u64) -> Result<u64, BlockError> {
        if logical_sector >= self.capacity_sectors {
            return Err(BlockError::OutOfRange);
        }
        let physical_sector = logical_sector
            .checked_add(DATA_FIRST_SECTOR)
            .ok_or(BlockError::OutOfRange)?;
        if physical_sector >= self.hardware.info().capacity_sectors {
            return Err(BlockError::OutOfRange);
        }
        Ok(physical_sector)
    }

    fn read_sector(&mut self, logical_sector: u64) -> Result<[u8; 512], BlockError> {
        let physical_sector = self.physical_sector(logical_sector)?;
        self.hardware
            .read_sector(physical_sector)
            .map_err(map_hardware_error)
    }

    fn write_sector(&mut self, logical_sector: u64, data: &[u8; 512]) -> Result<(), BlockError> {
        let physical_sector = self.physical_sector(logical_sector)?;
        self.hardware
            .write_sector(physical_sector, data)
            .map_err(map_hardware_error)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.hardware.flush().map_err(map_hardware_error)
    }
}

const fn map_hardware_error(error: HardwareError) -> BlockError {
    match error {
        HardwareError::OutOfRange => BlockError::OutOfRange,
        HardwareError::TimedOut => BlockError::TimedOut,
        HardwareError::DeviceIo => BlockError::DeviceIo,
        HardwareError::Unsupported | HardwareError::InvalidConfiguration => BlockError::Unsupported,
        HardwareError::Protocol => BlockError::Protocol,
    }
}

pub fn inject_fault_after_publish() {}
pub fn inject_timeout() {}
pub fn is_online() -> bool {
    let state = HOST.lock();
    state.online && !state.quarantined
}

/// # Safety
/// The executor guarantees that the faulting domain can never resume.
pub unsafe fn recover_faulted_domain(domain: AllocationDomain) {
    let abandoned_io = IO_CLAIMED.load(Ordering::Acquire)
        && IO_OWNER.load(Ordering::Acquire) == domain.owner.get()
        && IO_ARENA.load(Ordering::Acquire) == domain.arena.get();
    if unsafe { HOST.recover_after_fault(domain) } || abandoned_io {
        let mut state = HOST.lock();
        state.card = None;
        state.online = false;
        drop(state);
        release_io_claim();
    }
}

#[allow(dead_code)]
pub fn debug_waiter_counts() -> (usize, usize, usize) {
    (0, 0, 0)
}
