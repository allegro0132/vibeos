//! CV1800B SDIO0 block backend for the Milk-V Duo boot microSD.
//!
//! The first hardware revision deliberately uses one-bit, 25 MHz PIO. This
//! avoids publishing DMA addresses and avoids the board-specific SDR104 tuning
//! sequence until the conservative path has been accepted on real hardware.

extern crate alloc;

use alloc::{format, string::String, sync::Arc};
use core::any::Any;
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use vibeos_driver_sdhci_blk::{Card as HardwareCard, Error as HardwareError};
use vibeos_storage_device::{MutationFailure, MutationResult};

use crate::cap::{Cap, Resource, Rights};
use crate::exec::WaitQueue;
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::sync::SpinLock;
use crate::world::Space;

const SDHCI: vibeos_hal::SdhciDescription = crate::platform::SDHCI;
const BASE: usize = SDHCI.registers.start;
const IRQ: u32 = SDHCI.irq;
const DATA_SLICE: vibeos_image_policy::BlockSlice = match crate::platform::BLOCK_DATA_SLICE {
    Some(slice) => slice,
    None => panic!("Milk-V Duo firmware must select a data block slice"),
};

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

/// Raw backend entry points used only after the shared block facade validates
/// a capability-scoped request.
pub(crate) fn raw_info() -> BlockInfo {
    BlockDevice.info()
}

pub(crate) async fn raw_read_at(expected_epoch: u64, sector: u64) -> Result<[u8; 512], BlockError> {
    with_card_at(expected_epoch, |card| card.read_sector(sector))
}

pub(crate) async fn raw_read_blocks_at(
    expected_epoch: u64,
    sector: u64,
    block_count: u32,
    output: &mut [u8],
) -> Result<(), BlockError> {
    if block_count != 1 || output.len() != 512 {
        return Err(BlockError::Unsupported);
    }
    output.copy_from_slice(&raw_read_at(expected_epoch, sector).await?);
    Ok(())
}

pub(crate) async fn raw_write_at(
    expected_epoch: u64,
    sector: u64,
    data: [u8; 512],
) -> MutationResult<(), BlockError> {
    let submitted = Cell::new(false);
    with_card_at(expected_epoch, |card| {
        card.write_sector_tracked(sector, &data, || submitted.set(true))
    })
    .map_err(|error| mutation_failure(error, submitted.get()))
}

pub(crate) async fn raw_write_blocks_at(
    expected_epoch: u64,
    sector: u64,
    block_count: u32,
    data: &[u8],
) -> MutationResult<(), BlockError> {
    if block_count != 1 || data.len() != 512 {
        return Err(MutationFailure::not_submitted(BlockError::Unsupported));
    }
    let mut block = [0; 512];
    block.copy_from_slice(data);
    raw_write_at(expected_epoch, sector, block).await
}

pub(crate) async fn raw_flush_at(expected_epoch: u64) -> MutationResult<(), BlockError> {
    let submitted = Cell::new(false);
    with_card_at(expected_epoch, |card| {
        card.flush_tracked(|| submitted.set(true))
    })
    .map_err(|error| mutation_failure(error, submitted.get()))
}

fn mutation_failure(error: BlockError, submitted: bool) -> MutationFailure<BlockError> {
    if submitted {
        MutationFailure::ambiguous(error)
    } else {
        MutationFailure::not_submitted(error)
    }
}

fn with_card_at<T>(
    expected_epoch: u64,
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
        // This is the dispatch linearization point: compare the incarnation
        // while holding the same lock that transfers the Card out of HOST.
        if state.epoch != expected_epoch {
            release_io_claim();
            return Err(BlockError::DriverRestarted);
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
            .checked_sub(DATA_SLICE.first_sector)
            .ok_or(BlockError::Unsupported)?;
        if available_sectors < DATA_SLICE.sector_count || DATA_SLICE.end_sector().is_none() {
            return Err(BlockError::Unsupported);
        }
        Ok(Self {
            hardware,
            capacity_sectors: DATA_SLICE.sector_count,
        })
    }

    fn physical_sector(&self, logical_sector: u64) -> Result<u64, BlockError> {
        if logical_sector >= self.capacity_sectors {
            return Err(BlockError::OutOfRange);
        }
        let physical_sector = logical_sector
            .checked_add(DATA_SLICE.first_sector)
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

    fn write_sector_tracked(
        &mut self,
        logical_sector: u64,
        data: &[u8; 512],
        on_command_published: impl FnOnce(),
    ) -> Result<(), BlockError> {
        let physical_sector = self.physical_sector(logical_sector)?;
        self.hardware
            .write_sector_tracked(physical_sector, data, on_command_published)
            .map_err(map_hardware_error)
    }

    fn flush_tracked(&mut self, on_command_published: impl FnOnce()) -> Result<(), BlockError> {
        self.hardware
            .flush_tracked(on_command_published)
            .map_err(map_hardware_error)
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
