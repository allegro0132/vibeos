//! CV1800B SDIO0 block backend for the Milk-V Duo boot microSD.
//!
//! The first hardware revision deliberately uses one-bit, 25 MHz PIO. This
//! avoids publishing DMA addresses and avoids the board-specific SDR104 tuning
//! sequence until the conservative path has been accepted on real hardware.

extern crate alloc;

use alloc::{format, string::String, sync::Arc};
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::cap::{Cap, InvocationLease, Resource, Rights};
use crate::exec::WaitQueue;
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::sync::SpinLock;
use crate::world::Space;

const BASE: usize = crate::platform::SDHCI_BASE;
const IRQ: u32 = crate::platform::SDHCI_IRQ;
const SECTOR_SIZE: usize = 512;
const SOURCE_CLOCK_HZ: u32 = 375_000_000;
const INIT_CLOCK_HZ: u32 = 400_000;
const DATA_CLOCK_HZ: u32 = 25_000_000;
const POLL_BUDGET: usize = 5_000_000;
// The packaged image places a raw VibeOS data partition immediately after the
// 128 MiB FAT boot partition. Expose that partition as logical sector zero so
// existing block acceptance sectors and the journal can never overwrite FIP,
// FIT, or FAT metadata.
const DATA_FIRST_SECTOR: u64 = 262_145;
const DATA_SECTORS: u64 = 8_192;

const BLOCK_SIZE: usize = 0x04;
const ARGUMENT: usize = 0x08;
const TRANSFER_MODE: usize = 0x0c;
const COMMAND: usize = 0x0e;
const RESPONSE: usize = 0x10;
const BUFFER: usize = 0x20;
const PRESENT_STATE: usize = 0x24;
const POWER_CONTROL: usize = 0x29;
const CLOCK_CONTROL: usize = 0x2c;
const TIMEOUT_CONTROL: usize = 0x2e;
const SOFTWARE_RESET: usize = 0x2f;
const INT_STATUS: usize = 0x30;
const INT_ENABLE: usize = 0x34;
const SIGNAL_ENABLE: usize = 0x38;
const VENDOR_CTRL: usize = 0x200;
const PHY_TX_RX_DELAY: usize = 0x240;
const PHY_CONFIG: usize = 0x24c;

const INT_COMMAND_COMPLETE: u32 = 1 << 0;
const INT_TRANSFER_COMPLETE: u32 = 1 << 1;
const INT_BUFFER_WRITE_READY: u32 = 1 << 4;
const INT_BUFFER_READ_READY: u32 = 1 << 5;
const INT_ERROR: u32 = 1 << 15;
const INT_ALL: u32 = 0xffff_ffff;

const CMD_RESP_NONE: u16 = 0;
const CMD_RESP_136: u16 = 1;
const CMD_RESP_48: u16 = 2;
const CMD_RESP_48_BUSY: u16 = 3;
const CMD_CRC: u16 = 1 << 3;
const CMD_INDEX: u16 = 1 << 4;
const CMD_DATA: u16 = 1 << 5;

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
            capacity_sectors: state.card.map_or(0, |card| card.capacity_sectors),
            queue_size: 1,
            read_only: false,
            supports_flush: true,
            session_epoch: state.epoch,
            irq: IRQ,
            used_interrupts: 0,
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
        let state = HOST.lock();
        if state.quarantined {
            release_io_claim();
            return Err(BlockError::Quarantined);
        }
        if !state.online {
            release_io_claim();
            return Err(BlockError::Offline);
        }
        match state.card {
            Some(card) => card,
            None => {
                release_io_claim();
                return Err(BlockError::Offline);
            }
        }
    };
    let result = operation(&mut card);
    if result.is_ok() {
        HOST.lock().card = Some(card);
    }
    release_io_claim();
    result
}

#[derive(Clone, Copy)]
struct Card {
    rca: u16,
    high_capacity: bool,
    capacity_sectors: u64,
}

struct HostState {
    card: Option<Card>,
    epoch: u64,
    online: bool,
    quarantined: bool,
}

static HOST: SpinLock<HostState> = SpinLock::new_recoverable(HostState {
    card: None,
    epoch: 0,
    online: false,
    quarantined: false,
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

    let initialized = Card::initialize();
    {
        let mut state = HOST.lock();
        state.epoch = state.epoch.checked_add(1).expect("SDHCI epoch exhausted");
        match initialized {
            Ok(card) => {
                state.card = Some(card);
                state.online = true;
                state.quarantined = false;
            }
            Err(_) => {
                state.card = None;
                state.online = false;
            }
        }
    }

    // PIO requests are executed synchronously at the capability invocation
    // boundary. Keep this supervised incarnation alive so cancellation and
    // restart retain the same lifecycle shape as the QEMU backend.
    loop {
        DRIVER_PARK.wait().await;
    }
}

impl Card {
    fn initialize() -> Result<Self, BlockError> {
        reset_host()?;
        set_clock(INIT_CLOCK_HZ)?;
        write8(POWER_CONTROL, 0x0f);
        write8(TIMEOUT_CONTROL, 0x0e);
        write32(INT_ENABLE, INT_ALL);
        write32(SIGNAL_ENABLE, 0);

        command(0, 0, CMD_RESP_NONE)?;
        let cmd8 = command(8, 0x1aa, CMD_RESP_48 | CMD_CRC | CMD_INDEX)?;
        if cmd8[0] & 0xfff != 0x1aa {
            return Err(BlockError::Unsupported);
        }

        let mut ocr = 0;
        for _ in 0..10_000 {
            command(55, 0, CMD_RESP_48 | CMD_CRC | CMD_INDEX)?;
            ocr = command(41, 0x40ff_8000, CMD_RESP_48)?[0];
            if ocr & (1 << 31) != 0 {
                break;
            }
        }
        if ocr & (1 << 31) == 0 {
            return Err(BlockError::TimedOut);
        }
        let high_capacity = ocr & (1 << 30) != 0;

        command(2, 0, CMD_RESP_136 | CMD_CRC)?;
        let rca_response = command(3, 0, CMD_RESP_48 | CMD_CRC | CMD_INDEX)?[0];
        let rca = (rca_response >> 16) as u16;
        if rca == 0 {
            return Err(BlockError::Protocol);
        }
        let csd = command(9, u32::from(rca) << 16, CMD_RESP_136 | CMD_CRC)?;
        let physical_capacity = capacity_from_csd(csd)?;
        let available_sectors = physical_capacity
            .checked_sub(DATA_FIRST_SECTOR)
            .ok_or(BlockError::Unsupported)?;
        if available_sectors < DATA_SECTORS {
            return Err(BlockError::Unsupported);
        }
        let capacity_sectors = DATA_SECTORS;
        command(
            7,
            u32::from(rca) << 16,
            CMD_RESP_48_BUSY | CMD_CRC | CMD_INDEX,
        )?;
        if !high_capacity {
            command(16, SECTOR_SIZE as u32, CMD_RESP_48 | CMD_CRC | CMD_INDEX)?;
        }
        set_clock(DATA_CLOCK_HZ)?;
        Ok(Self {
            rca,
            high_capacity,
            capacity_sectors,
        })
    }

    fn argument(self, sector: u64) -> Result<u32, BlockError> {
        if sector >= self.capacity_sectors {
            return Err(BlockError::OutOfRange);
        }
        let physical_sector = sector
            .checked_add(DATA_FIRST_SECTOR)
            .ok_or(BlockError::OutOfRange)?;
        let address = if self.high_capacity {
            physical_sector
        } else {
            physical_sector
                .checked_mul(SECTOR_SIZE as u64)
                .ok_or(BlockError::OutOfRange)?
        };
        u32::try_from(address).map_err(|_| BlockError::OutOfRange)
    }

    fn read_sector(&mut self, sector: u64) -> Result<[u8; 512], BlockError> {
        wait_inhibit(true)?;
        clear_interrupts();
        write16(BLOCK_SIZE, SECTOR_SIZE as u16);
        write32(ARGUMENT, self.argument(sector)?);
        write16(TRANSFER_MODE, 1 << 4);
        write16(
            COMMAND,
            command_word(17, CMD_RESP_48 | CMD_CRC | CMD_INDEX | CMD_DATA),
        );
        wait_interrupt(INT_BUFFER_READ_READY)?;
        let mut data = [0u8; SECTOR_SIZE];
        for chunk in data.chunks_exact_mut(4) {
            chunk.copy_from_slice(&read32(BUFFER).to_le_bytes());
        }
        write32(INT_STATUS, INT_BUFFER_READ_READY);
        wait_interrupt(INT_TRANSFER_COMPLETE)?;
        write32(INT_STATUS, INT_TRANSFER_COMPLETE);
        Ok(data)
    }

    fn write_sector(&mut self, sector: u64, data: &[u8; 512]) -> Result<(), BlockError> {
        wait_inhibit(true)?;
        clear_interrupts();
        write16(BLOCK_SIZE, SECTOR_SIZE as u16);
        write32(ARGUMENT, self.argument(sector)?);
        write16(TRANSFER_MODE, 0);
        write16(
            COMMAND,
            command_word(24, CMD_RESP_48 | CMD_CRC | CMD_INDEX | CMD_DATA),
        );
        wait_interrupt(INT_BUFFER_WRITE_READY)?;
        for chunk in data.chunks_exact(4) {
            write32(
                BUFFER,
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            );
        }
        write32(INT_STATUS, INT_BUFFER_WRITE_READY);
        wait_interrupt(INT_TRANSFER_COMPLETE)?;
        write32(INT_STATUS, INT_TRANSFER_COMPLETE);
        self.flush()
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        for _ in 0..10_000 {
            let status = command(
                13,
                u32::from(self.rca) << 16,
                CMD_RESP_48 | CMD_CRC | CMD_INDEX,
            )?[0];
            let state = (status >> 9) & 0xf;
            if status & (1 << 8) != 0 && state == 4 {
                return Ok(());
            }
        }
        Err(BlockError::TimedOut)
    }
}

fn reset_host() -> Result<(), BlockError> {
    write32(SIGNAL_ENABLE, 0);
    write32(INT_ENABLE, 0);
    write8(SOFTWARE_RESET, 1);
    poll_until(|| read8(SOFTWARE_RESET) & 1 == 0)?;
    // CV180X default-speed PHY settings used by the vendor Linux reset hook.
    write32(VENDOR_CTRL, read32(VENDOR_CTRL) | (1 << 1));
    write32(PHY_CONFIG, read32(PHY_CONFIG) | 1);
    write32(PHY_TX_RX_DELAY, 0x0100_0100);
    Ok(())
}

fn set_clock(target: u32) -> Result<(), BlockError> {
    write16(CLOCK_CONTROL, 0);
    let divisor = ((SOURCE_CLOCK_HZ + target.saturating_mul(2) - 1) / target.saturating_mul(2))
        .clamp(1, 0x3ff) as u16;
    let encoded = ((divisor & 0xff) << 8) | ((divisor & 0x300) >> 2);
    write16(CLOCK_CONTROL, encoded | 1);
    poll_until(|| read16(CLOCK_CONTROL) & 2 != 0)?;
    write16(CLOCK_CONTROL, encoded | 1 | 4);
    Ok(())
}

fn command(index: u8, argument: u32, flags: u16) -> Result<[u32; 4], BlockError> {
    wait_inhibit(flags & CMD_DATA != 0 || flags & 3 == CMD_RESP_48_BUSY)?;
    clear_interrupts();
    write32(ARGUMENT, argument);
    write16(TRANSFER_MODE, 0);
    write16(COMMAND, command_word(index, flags));
    wait_interrupt(INT_COMMAND_COMPLETE)?;
    write32(INT_STATUS, INT_COMMAND_COMPLETE);
    if flags & 3 == CMD_RESP_136 {
        Ok([
            (read32(RESPONSE + 12) << 8) | u32::from(read8(RESPONSE + 11)),
            (read32(RESPONSE + 8) << 8) | u32::from(read8(RESPONSE + 7)),
            (read32(RESPONSE + 4) << 8) | u32::from(read8(RESPONSE + 3)),
            read32(RESPONSE) << 8,
        ])
    } else {
        Ok([read32(RESPONSE), 0, 0, 0])
    }
}

fn command_word(index: u8, flags: u16) -> u16 {
    u16::from(index) << 8 | flags
}

fn wait_inhibit(data: bool) -> Result<(), BlockError> {
    let mask = if data { 3 } else { 1 };
    poll_until(|| read32(PRESENT_STATE) & mask == 0)
}

fn wait_interrupt(mask: u32) -> Result<(), BlockError> {
    for _ in 0..POLL_BUDGET {
        let status = read32(INT_STATUS);
        if status & INT_ERROR != 0 {
            write32(INT_STATUS, status);
            return Err(BlockError::DeviceIo);
        }
        if status & mask == mask {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(BlockError::TimedOut)
}

fn clear_interrupts() {
    write32(INT_STATUS, INT_ALL);
}

fn poll_until(mut ready: impl FnMut() -> bool) -> Result<(), BlockError> {
    for _ in 0..POLL_BUDGET {
        if ready() {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(BlockError::TimedOut)
}

fn capacity_from_csd(csd: [u32; 4]) -> Result<u64, BlockError> {
    match unstuff(csd, 126, 2) {
        1 => Ok((u64::from(unstuff(csd, 48, 22)) + 1) * 1024),
        0 => {
            let read_block_len = unstuff(csd, 80, 4);
            let size = u64::from(unstuff(csd, 62, 12)) + 1;
            let multiplier = unstuff(csd, 47, 3) + 2;
            let bytes = size
                .checked_shl(multiplier + read_block_len)
                .ok_or(BlockError::Unsupported)?;
            Ok(bytes / SECTOR_SIZE as u64)
        }
        _ => Err(BlockError::Unsupported),
    }
}

fn unstuff(response: [u32; 4], start: usize, size: usize) -> u32 {
    let offset = 3 - start / 32;
    let shift = start & 31;
    let mut value = response[offset] >> shift;
    if size + shift > 32 {
        value |= response[offset - 1] << (32 - shift);
    }
    value & ((1u32 << size) - 1)
}

#[inline]
fn read8(offset: usize) -> u8 {
    unsafe { ((BASE + offset) as *const u8).read_volatile() }
}
#[inline]
fn read16(offset: usize) -> u16 {
    unsafe { ((BASE + offset) as *const u16).read_volatile() }
}
#[inline]
fn read32(offset: usize) -> u32 {
    unsafe { ((BASE + offset) as *const u32).read_volatile() }
}
#[inline]
fn write8(offset: usize, value: u8) {
    unsafe { ((BASE + offset) as *mut u8).write_volatile(value) }
}
#[inline]
fn write16(offset: usize, value: u16) {
    unsafe { ((BASE + offset) as *mut u16).write_volatile(value) }
}
#[inline]
fn write32(offset: usize, value: u32) {
    unsafe { ((BASE + offset) as *mut u32).write_volatile(value) }
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
