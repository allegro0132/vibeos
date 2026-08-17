//! CV1800B SDIO0 block backend for the Milk-V Duo boot microSD.
//!
//! The first hardware revision deliberately uses one-bit, 25 MHz PIO. This
//! avoids publishing DMA addresses and avoids the board-specific SDR104 tuning
//! sequence until the conservative path has been accepted on real hardware.

extern crate alloc;

use alloc::{format, string::String, sync::Arc, vec};
use core::any::Any;
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use vibeos_driver_sdhci_blk::{
    Card as HardwareCard, Error as HardwareError, MultiBlockWriteMode, SAFE_BLIND_WRITE_BLOCKS,
};

/// Issue one logical batched write as one or more hardware transfers: the
/// blind PIO mode is split into [`SAFE_BLIND_WRITE_BLOCKS`]-sized CMD25
/// bursts (the always-safe, FIFO-verified size used while probing). The
/// publication hook still fires exactly once, before the first published
/// transfer.
fn write_batch_in_mode<H: FnOnce()>(
    hardware: &mut HardwareCard,
    physical_first: u64,
    data: &[u8],
    mode: MultiBlockWriteMode,
    hook: &mut Option<H>,
) -> Result<(), HardwareError> {
    let chunk_bytes = if mode == MultiBlockWriteMode::BlindPio {
        SAFE_BLIND_WRITE_BLOCKS as usize * 512
    } else {
        data.len()
    };
    let mut sector = physical_first;
    for chunk in data.chunks(chunk_bytes) {
        hardware.write_blocks_tracked_with_mode(sector, chunk, mode, || {
            if let Some(hook) = hook.take() {
                hook();
            }
        })?;
        sector += (chunk.len() / 512) as u64;
    }
    Ok(())
}

/// Largest logical-block run one raw batched request may carry, re-exported
/// so the shared block facade can advertise the same bound in its geometry.
pub(crate) use vibeos_driver_sdhci_blk::MAX_TRANSFER_BLOCKS;
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
    IO_BLOCKS_READ.fetch_add(1, Ordering::Relaxed);
    with_card_at(expected_epoch, |card| card.read_sector(sector))
}

pub(crate) async fn raw_read_blocks_at(
    expected_epoch: u64,
    sector: u64,
    block_count: u32,
    output: &mut [u8],
) -> Result<(), BlockError> {
    if block_count == 0 || block_count > MAX_TRANSFER_BLOCKS {
        return Err(BlockError::Unsupported);
    }
    if output.len() != block_count as usize * 512 {
        return Err(BlockError::Protocol);
    }
    IO_BLOCKS_READ.fetch_add(u64::from(block_count), Ordering::Relaxed);
    with_card_at(expected_epoch, |card| card.read_blocks(sector, output))
}

pub(crate) async fn raw_write_at(
    expected_epoch: u64,
    sector: u64,
    data: [u8; 512],
) -> MutationResult<(), BlockError> {
    let submitted = Cell::new(false);
    IO_BLOCKS_WRITTEN.fetch_add(1, Ordering::Relaxed);
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
    if block_count == 0 || block_count > MAX_TRANSFER_BLOCKS {
        return Err(MutationFailure::not_submitted(BlockError::Unsupported));
    }
    if data.len() != block_count as usize * 512 {
        return Err(MutationFailure::not_submitted(BlockError::Protocol));
    }
    let submitted = Cell::new(false);
    IO_BLOCKS_WRITTEN.fetch_add(u64::from(block_count), Ordering::Relaxed);
    with_card_at(expected_epoch, |card| {
        card.write_blocks_tracked(sector, data, || submitted.set(true))
    })
    .map_err(|error| mutation_failure(error, submitted.get()))
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

/// Coarse I/O accounting for hardware bring-up: request count, block volume
/// by direction, and cumulative wall time spent inside the exclusive card
/// claim. A stats line prints every 512 requests so sustained workloads can
/// be attributed to either real device time or time spent elsewhere.
pub(crate) static IO_OPS: AtomicU64 = AtomicU64::new(0);
pub(crate) static IO_BLOCKS_READ: AtomicU64 = AtomicU64::new(0);
pub(crate) static IO_BLOCKS_WRITTEN: AtomicU64 = AtomicU64::new(0);
pub(crate) static IO_BUSY_TICKS: AtomicU64 = AtomicU64::new(0);

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
    let busy_start = crate::sbi::time();
    let result = operation(&mut card);
    let busy_ticks = crate::sbi::time().wrapping_sub(busy_start);
    IO_BUSY_TICKS.fetch_add(busy_ticks, Ordering::Relaxed);
    let ops = IO_OPS.fetch_add(1, Ordering::Relaxed) + 1;
    if ops % 16384 == 0 {
        let busy_ms = IO_BUSY_TICKS.load(Ordering::Relaxed) / (crate::platform::TIMEBASE_HZ / 1000);
        crate::uart::_print(format_args!(
            "  sdhci stats: {ops} ops, {} blk rd, {} blk wr, {busy_ms} ms busy\n",
            IO_BLOCKS_READ.load(Ordering::Relaxed),
            IO_BLOCKS_WRITTEN.load(Ordering::Relaxed),
        ));
    }
    let last_command = card.hardware.last_command();
    let interrupt_status = card.hardware.last_interrupt_status();
    let present_state = card.hardware.present_state();
    if let Err(error) = &result {
        // Bounded first-failure diagnostics: hardware bring-up on this board
        // has twice been set back by silent I/O failures, so the first few
        // errors of a session log the exact command coordinates on UART.
        static LOGGED: AtomicU64 = AtomicU64::new(0);
        if LOGGED.fetch_add(1, Ordering::Relaxed) < 8 {
            crate::uart::_print(format_args!(
                "  sdhci io error: {error:?} after CMD{last_command}, int {interrupt_status:#010x}, present {present_state:#010x}\n"
            ));
        }
    }
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
    /// Set after the first CMD18 failure of this incarnation: the rest of the
    /// session decomposes batched reads into the single-sector command this
    /// exact board has already proven, instead of paying a full poll-budget
    /// timeout on every subsequent batch.
    multiblock_reads_disabled: bool,
    write_batching: WriteBatching,
    /// Consecutive locked-mode batched-write failures; the lock survives
    /// transient card stalls and is only abandoned after several in a row.
    locked_write_failures: u8,
    /// Blind CMD25 burst size currently attempted. SD cards handle one long
    /// sequential burst far better than the same bytes as 4 KiB commands, so
    /// this starts at the full transfer bound and shrinks on evidence.
    blind_chunk_blocks: u32,
    /// Largest blind burst size proven by read-back this session. A burst
    /// larger than this is verified after it completes before the size is
    /// trusted, because a FIFO overflow would corrupt data silently.
    qualified_blind_blocks: u32,
}

/// Session-sticky CMD25 protocol probe state. The CV1800B integration has
/// rejected the standard Auto CMD12 shape on real hardware, so the first
/// batched write walks a ladder of protocol variants, locks onto the first
/// one the controller completes, and otherwise decomposes every later batch
/// into proven single-sector CMD24 writes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteBatching {
    Unprobed,
    Locked(MultiBlockWriteMode),
    Disabled,
}

/// (apply write-stall workarounds first, protocol shape) probe ladder: one
/// baseline attempt reproduces the known stall, then the host workarounds are
/// applied once and every protocol shape is retried under them.
const WRITE_MODE_LADDER: [(bool, MultiBlockWriteMode); 6] = [
    (false, MultiBlockWriteMode::AutoCmd12),
    (true, MultiBlockWriteMode::AutoCmd12),
    (true, MultiBlockWriteMode::ManualCmd12),
    (true, MultiBlockWriteMode::OpenEnded),
    (true, MultiBlockWriteMode::SetBlockCount),
    (true, MultiBlockWriteMode::BlindPio),
];

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
            multiblock_reads_disabled: false,
            write_batching: WriteBatching::Unprobed,
            locked_write_failures: 0,
            blind_chunk_blocks: MAX_TRANSFER_BLOCKS,
            qualified_blind_blocks: SAFE_BLIND_WRITE_BLOCKS,
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

    /// Translate a logical multi-block run into the physical first sector the
    /// hardware driver may be given, validating both endpoints against the
    /// data-slice and card capacities.
    ///
    /// The final lower-bound check is the boot-media invariant this board's
    /// history demands: the FSBL/FIP and the VibeOS FIT live in the physical
    /// sectors below `DATA_SLICE.first_sector`, and a batched write published
    /// with an untranslated (logical) first sector destroys them while every
    /// host and QEMU test stays green. The check is structurally unreachable
    /// today; it exists so no future refactor of this translation can ever
    /// hand the driver a boot-area sector.
    fn physical_block_range(&self, logical_first: u64, byte_len: usize) -> Result<u64, BlockError> {
        if byte_len == 0 || byte_len % 512 != 0 {
            return Err(BlockError::Protocol);
        }
        let block_count = (byte_len / 512) as u64;
        let logical_last = logical_first
            .checked_add(block_count - 1)
            .ok_or(BlockError::OutOfRange)?;
        let physical_first = self.physical_sector(logical_first)?;
        self.physical_sector(logical_last)?;
        if physical_first < DATA_SLICE.first_sector {
            return Err(BlockError::OutOfRange);
        }
        Ok(physical_first)
    }

    fn read_blocks(&mut self, logical_first: u64, output: &mut [u8]) -> Result<(), BlockError> {
        let physical_first = self.physical_block_range(logical_first, output.len())?;
        let block_count = (output.len() / 512) as u64;
        if block_count > 1 && !self.multiblock_reads_disabled {
            match self.hardware.read_blocks(physical_first, output) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    // The failed transfer was aborted by the driver; retry the
                    // request with the single-sector command this board has
                    // already proven before reporting anything upward.
                    self.multiblock_reads_disabled = true;
                    crate::uart::_print(format_args!(
                        "  sdhci: CMD18 x{block_count} failed ({error:?}); single-sector reads for this session\n"
                    ));
                }
            }
        }
        for (index, sector) in output.chunks_exact_mut(512).enumerate() {
            sector.copy_from_slice(
                &self
                    .hardware
                    .read_sector(physical_first + index as u64)
                    .map_err(map_hardware_error)?,
            );
        }
        Ok(())
    }

    fn write_blocks_tracked(
        &mut self,
        logical_first: u64,
        data: &[u8],
        on_command_published: impl FnOnce(),
    ) -> Result<(), BlockError> {
        let physical_first = self.physical_block_range(logical_first, data.len())?;
        let block_count = (data.len() / 512) as u64;
        // The publication hook must fire exactly once even when a batched
        // attempt already published CMD25 before failing: the mutation was
        // submitted to the card either way.
        let mut hook = Some(on_command_published);
        if let WriteBatching::Locked(mode) = self.write_batching {
            if block_count > 1 {
                // A transient failure (for example a long card-internal
                // garbage-collection stall) must not permanently give up the
                // locked mode: retry once, fall back to single-sector for
                // just this request, and disable only on repeated failures.
                for attempt in 1..=2u32 {
                    let result = if mode == MultiBlockWriteMode::BlindPio {
                        self.write_blind(logical_first, physical_first, data, &mut hook)
                    } else {
                        write_batch_in_mode(&mut self.hardware, physical_first, data, mode, &mut hook)
                    };
                    match result {
                        Ok(()) => {
                            self.locked_write_failures = 0;
                            return Ok(());
                        }
                        Err(error) => {
                            crate::uart::_print(format_args!(
                                "  sdhci: locked CMD25 x{block_count} via {mode:?} failed ({error:?}), attempt {attempt}\n"
                            ));
                        }
                    }
                }
                self.locked_write_failures = self.locked_write_failures.saturating_add(1);
                if self.locked_write_failures >= 3 {
                    self.write_batching = WriteBatching::Disabled;
                    crate::uart::_print(format_args!(
                        "  sdhci: repeated locked-mode failures; single-sector writes for this session\n"
                    ));
                }
            }
        } else if block_count > 1 && self.write_batching == WriteBatching::Unprobed {
            let probing = true;
            {
                let state = self.hardware.diagnostic_host_state();
                crate::uart::_print(format_args!(
                    "  sdhci host state: hc1 {:#04x}, blkgap {:#04x}, hc2 {:#06x}, mshc {:#010x}, txrx {:#010x}, phycfg {:#010x}\n",
                    state[0], state[1], state[2], state[3], state[4], state[5]
                ));
            }
            let mut workarounds_applied = false;
            for &(needs_workarounds, mode) in &WRITE_MODE_LADDER {
                if needs_workarounds && !workarounds_applied {
                    workarounds_applied = true;
                    self.hardware.apply_write_stall_workarounds();
                    crate::uart::_print(format_args!(
                        "  sdhci: applied write-stall workarounds (block-gap clear, clock-gate disable)\n"
                    ));
                }
                let attempt =
                    write_batch_in_mode(&mut self.hardware, physical_first, data, mode, &mut hook);
                match attempt {
                    Ok(()) => {
                        if probing && !self.verify_written(logical_first, data) {
                            crate::uart::_print(format_args!(
                                "  sdhci: CMD25 x{block_count} via {mode:?} completed but read-back mismatched; rejecting the mode\n"
                            ));
                            continue;
                        }
                        if self.write_batching != WriteBatching::Locked(mode) {
                            self.write_batching = WriteBatching::Locked(mode);
                            crate::uart::_print(format_args!(
                                "  sdhci: CMD25 x{block_count} ok via {mode:?}; batched writes locked to it\n"
                            ));
                        }
                        return Ok(());
                    }
                    Err(error) => {
                        let interrupt_status = self.hardware.last_interrupt_status();
                        let response = self.hardware.response_word();
                        let present = self.hardware.present_state();
                        crate::uart::_print(format_args!(
                            "  sdhci: CMD25 x{block_count} via {mode:?} failed ({error:?}, int {interrupt_status:#010x}, r1 {response:#010x}, present {present:#010x})\n"
                        ));
                    }
                }
            }
            // Last probe stage: the 1-bit bus is a corner no vendor software
            // exercises for CMD25; try the standard 4-bit width once.
            if probing {
                match self.hardware.enable_four_bit_bus() {
                    Ok(()) => {
                        crate::uart::_print(format_args!(
                            "  sdhci: switched to 4-bit bus; retrying CMD25\n"
                        ));
                        for mode in [
                            MultiBlockWriteMode::AutoCmd12,
                            MultiBlockWriteMode::OpenEnded,
                            MultiBlockWriteMode::BlindPio,
                        ] {
                            let attempt = write_batch_in_mode(
                                &mut self.hardware,
                                physical_first,
                                data,
                                mode,
                                &mut hook,
                            );
                            match attempt {
                                Ok(()) => {
                                    if !self.verify_written(logical_first, data) {
                                        crate::uart::_print(format_args!(
                                            "  sdhci: 4-bit CMD25 x{block_count} via {mode:?} completed but read-back mismatched; rejecting the mode\n"
                                        ));
                                        continue;
                                    }
                                    self.write_batching = WriteBatching::Locked(mode);
                                    crate::uart::_print(format_args!(
                                        "  sdhci: CMD25 x{block_count} ok via {mode:?} on the 4-bit bus; batched writes locked to it\n"
                                    ));
                                    return Ok(());
                                }
                                Err(error) => {
                                    let response = self.hardware.response_word();
                                    let present = self.hardware.present_state();
                                    crate::uart::_print(format_args!(
                                        "  sdhci: 4-bit CMD25 x{block_count} via {mode:?} failed ({error:?}, r1 {response:#010x}, present {present:#010x})\n"
                                    ));
                                }
                            }
                        }
                        self.hardware.disable_four_bit_bus();
                        crate::uart::_print(format_args!(
                            "  sdhci: returned to the 1-bit bus\n"
                        ));
                    }
                    Err(error) => {
                        crate::uart::_print(format_args!(
                            "  sdhci: 4-bit bus switch failed ({error:?}); staying on 1-bit\n"
                        ));
                    }
                }
            }
            if self.write_batching != WriteBatching::Disabled {
                self.write_batching = WriteBatching::Disabled;
                crate::uart::_print(format_args!(
                    "  sdhci: single-sector writes for this session\n"
                ));
            }
        }
        for (index, sector) in data.chunks_exact(512).enumerate() {
            let mut block = [0u8; 512];
            block.copy_from_slice(sector);
            self.hardware
                .write_sector_tracked(physical_first + index as u64, &block, || {
                    if let Some(hook) = hook.take() {
                        hook();
                    }
                })
                .map_err(map_hardware_error)?;
        }
        Ok(())
    }

    /// Batched write through blind CMD25 bursts with adaptive sizing: bursts
    /// larger than the qualified size are read back and compared before the
    /// size is trusted, any mismatch or hardware error shrinks the burst
    /// (floor [`SAFE_BLIND_WRITE_BLOCKS`], which is always safe) and rewrites
    /// the same chunk, so no corruption can persist and no failure at the
    /// floor size is masked.
    fn write_blind(
        &mut self,
        logical_first: u64,
        physical_first: u64,
        data: &[u8],
        hook: &mut Option<impl FnOnce()>,
    ) -> Result<(), HardwareError> {
        let mut offset = 0usize;
        while offset < data.len() {
            let chunk_bytes = (self.blind_chunk_blocks as usize * 512).min(data.len() - offset);
            let chunk = &data[offset..offset + chunk_bytes];
            let attempt = self.hardware.write_blocks_tracked_with_mode(
                physical_first + (offset / 512) as u64,
                chunk,
                MultiBlockWriteMode::BlindPio,
                || {
                    if let Some(hook) = hook.take() {
                        hook();
                    }
                },
            );
            match attempt {
                Ok(()) => {
                    let blocks = (chunk.len() / 512) as u32;
                    if blocks > self.qualified_blind_blocks {
                        if self.verify_written(logical_first + (offset / 512) as u64, chunk) {
                            self.qualified_blind_blocks = blocks;
                            crate::uart::_print(format_args!(
                                "  sdhci: blind CMD25 burst x{blocks} qualified by read-back\n"
                            ));
                        } else {
                            let reduced = (blocks / 2).max(SAFE_BLIND_WRITE_BLOCKS);
                            crate::uart::_print(format_args!(
                                "  sdhci: blind CMD25 burst x{blocks} read-back mismatched; shrinking to x{reduced}\n"
                            ));
                            self.blind_chunk_blocks = reduced;
                            continue;
                        }
                    }
                    offset += chunk.len();
                }
                Err(error) if self.blind_chunk_blocks > SAFE_BLIND_WRITE_BLOCKS => {
                    let reduced = (self.blind_chunk_blocks / 2).max(SAFE_BLIND_WRITE_BLOCKS);
                    crate::uart::_print(format_args!(
                        "  sdhci: blind CMD25 burst x{} failed ({error:?}); shrinking to x{reduced}\n",
                        self.blind_chunk_blocks
                    ));
                    self.blind_chunk_blocks = reduced;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Read the just-written range back through the proven read path and
    /// compare, before a freshly probed write mode is allowed to carry real
    /// storage traffic.
    fn verify_written(&mut self, logical_first: u64, data: &[u8]) -> bool {
        let mut readback = vec![0u8; data.len()];
        match self.read_blocks(logical_first, &mut readback) {
            Ok(()) => readback == data,
            Err(_) => false,
        }
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

pub struct DiagnosticMultiblockReport {
    pub blocks_requested: usize,
    pub blocks_completed: usize,
    pub result: Result<(), BlockError>,
    pub last_command: u8,
    pub interrupt_status: u32,
    pub present_state: u32,
}

/// Diagnostic-only probe for the untested CMD18 multi-block PIO path. Reads
/// raw physical sectors directly, never touching the managed `DATA_SLICE`
/// logical namespace, the `block_device` capability layer, or any automatic
/// boot or I/O path — only an explicit diagnostic vsh command invokes this,
/// once, interactively. Deliberately does not share code with (or get called
/// by) the production read/write path: see docs/MILKV_DUO.md for why that
/// separation matters here.
pub async fn diagnostic_probe_multiblock_read(
    poll_budget: usize,
    block_count: usize,
    physical_sector: u64,
) -> Result<DiagnosticMultiblockReport, BlockError> {
    let block_count = block_count.clamp(1, 256);
    let expected_epoch = raw_info().session_epoch;
    let mut output = vec![0u8; block_count * 512];
    let (blocks_completed, hardware_result) = with_card_at(expected_epoch, |card| {
        Ok(card.hardware.diagnostic_probe_multiblock_read(
            physical_sector,
            &mut output,
            poll_budget,
        ))
    })?;
    let info = raw_info();
    Ok(DiagnosticMultiblockReport {
        blocks_requested: output.len() / 512,
        blocks_completed,
        result: hardware_result.map_err(map_hardware_error),
        last_command: info.last_command,
        interrupt_status: info.interrupt_status,
        present_state: info.present_state,
    })
}
