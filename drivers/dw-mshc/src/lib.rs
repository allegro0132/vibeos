#![no_std]
//! Synopsys DesignWare MSHC SD transport (PIO, 512-byte single-block IO).
//! SoC clocks, resets, pinmux and card power are prepared by the embedding
//! firmware. No SDHCI register assumptions or CPU-specific cache operations.
use core::cell::Cell;
use vibeos_hal::AddressRange;
use vibeos_sd_protocol::{capacity_from_csd, sector_argument};

const CTRL: usize = 0x00;
const PWREN: usize = 0x04;
const CLKDIV: usize = 0x08;
const CLKSRC: usize = 0x0c;
const CLKENA: usize = 0x10;
const TMOUT: usize = 0x14;
const CTYPE: usize = 0x18;
const BLKSIZ: usize = 0x1c;
const BYTCNT: usize = 0x20;
const INTMASK: usize = 0x24;
const CMDARG: usize = 0x28;
const CMD: usize = 0x2c;
const RESP0: usize = 0x30;
const RINTSTS: usize = 0x44;
const STATUS: usize = 0x48;
const FIFOTH: usize = 0x4c;
const BMOD: usize = 0x80;
const CMD_START: u32 = 1 << 31;
const CMD_UPDATE_CLOCK: u32 = (1 << 21) | (1 << 13) | CMD_START;
const CMD_DONE: u32 = 1 << 2;
const DATA_OVER: u32 = 1 << 3;
const RESP_TIMEOUT: u32 = 1 << 8;
const ERRORS: u32 = (1 << 1)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (1 << 10)
    | (1 << 11)
    | (1 << 12)
    | (1 << 13)
    | (1 << 15);
const RESP_SHORT: u32 = 1 << 6;
const RESP_LONG: u32 = (1 << 6) | (1 << 7);
const RESP_CRC: u32 = 1 << 8;
const DATA_EXPECT: u32 = 1 << 9;
const DATA_WRITE: u32 = 1 << 10;
const DATA_BUSY: u32 = 1 << 9;
const POLL_LIMIT: usize = 20_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfiguration,
    TimedOut,
    Protocol,
    Unsupported,
    OutOfRange,
    Offline,
}
impl From<Error> for vibeos_hal::block::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidConfiguration => Self::InvalidConfiguration,
            Error::TimedOut => Self::TimedOut,
            Error::Protocol => Self::Protocol,
            Error::Unsupported => Self::Unsupported,
            Error::OutOfRange => Self::OutOfRange,
            Error::Offline => Self::DeviceIo,
        }
    }
}
pub use vibeos_hal::{block::MAX_TRANSFER_BLOCKS, DwMshcDescription as Description};
/// 32-bit FIFO and control accesses. Implementations must preserve ordering.
pub trait Registers {
    fn read(&self, offset: usize) -> u32;
    fn write(&self, offset: usize, value: u32);
}
pub struct Mmio(AddressRange);
impl Mmio {
    /// # Safety
    /// The aperture must remain exclusively owned, mapped as device memory,
    /// and clocked; pinmux/reset/power preparation precedes construction.
    pub const unsafe fn new(range: AddressRange) -> Self {
        assert!(range.start % 4 == 0 && range.len() >= 0x204);
        Self(range)
    }
}
impl Registers for Mmio {
    fn read(&self, offset: usize) -> u32 {
        assert!(offset % 4 == 0 && offset <= self.0.len() - 4);
        unsafe { ((self.0.start + offset) as *const u32).read_volatile() }
    }
    fn write(&self, offset: usize, value: u32) {
        assert!(offset % 4 == 0 && offset <= self.0.len() - 4);
        unsafe { ((self.0.start + offset) as *mut u32).write_volatile(value) }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CardInfo {
    pub capacity_sectors: u64,
    pub high_capacity: bool,
}
pub struct Card<R> {
    registers: R,
    description: Description,
    time: fn() -> u64,
    timeout_ticks: u64,
    rca: u16,
    info: CardInfo,
    online: bool,
    last_command: Cell<u8>,
    last_interrupt: Cell<u32>,
}

pub fn clock_divider(source: u32, target: u32) -> Result<u8, Error> {
    if source == 0 || target == 0 {
        return Err(Error::InvalidConfiguration);
    }
    if source <= target {
        return Ok(0);
    }
    let divider = (source as u64).div_ceil(2 * target as u64);
    u8::try_from(divider).map_err(|_| Error::InvalidConfiguration)
}

impl<R: Registers> Card<R> {
    pub fn initialize(
        registers: R,
        description: Description,
        time: fn() -> u64,
        timebase_hz: u64,
    ) -> Result<Self, Error> {
        if timebase_hz == 0
            || timebase_hz > u64::MAX / 10
            || description.data_clock_hz == 0
            || description.data_clock_hz > 25_000_000
            || description.fifo_depth_words < 2
            || description.fifo_depth_words > 4096
            || description.fifo_offset % 4 != 0
            || description.fifo_offset < 0x100
            || description.registers.len() < description.fifo_offset.saturating_add(4)
        {
            return Err(Error::InvalidConfiguration);
        }
        clock_divider(description.source_clock_hz, 400_000)?;
        clock_divider(description.source_clock_hz, description.data_clock_hz)?;
        let mut card = Self {
            registers,
            description,
            time,
            timeout_ticks: timebase_hz * 10,
            rca: 0,
            info: CardInfo {
                capacity_sectors: 0,
                high_capacity: false,
            },
            online: false,
            last_command: Cell::new(0),
            last_interrupt: Cell::new(0),
        };
        card.registers.write(INTMASK, 0);
        card.registers.write(CTRL, 7); // reset controller, FIFO and DMA; DMA disabled
        card.wait(|| card.registers.read(CTRL) & 7 == 0)?;
        card.registers.write(BMOD, 0);
        card.registers.write(PWREN, 1);
        card.registers.write(TMOUT, u32::MAX);
        card.registers.write(CTYPE, 0);
        let half = u32::from(description.fifo_depth_words) / 2;
        card.registers.write(FIFOTH, ((half - 1) << 16) | half);
        card.set_clock(400_000)?;
        card.command(0, 0, 1 << 15, || {})?;
        if card.command(8, 0x1aa, RESP_SHORT | RESP_CRC, || {})?[0] & 0xfff != 0x1aa {
            return Err(Error::Unsupported);
        }
        let start = (card.time)();
        let mut attempts = 10_000usize;
        loop {
            if attempts == 0 {
                return Err(Error::TimedOut);
            }
            attempts -= 1;
            card.command(55, 0, RESP_SHORT | RESP_CRC, || {})?;
            let ocr = card.command(41, 0x40ff8000, RESP_SHORT, || {})?[0];
            if ocr & (1 << 31) != 0 {
                card.info.high_capacity = ocr & (1 << 30) != 0;
                break;
            }
            if (card.time)().wrapping_sub(start) >= card.timeout_ticks {
                return Err(Error::TimedOut);
            }
        }
        card.command(2, 0, RESP_LONG | RESP_CRC, || {})?;
        card.rca = (card.command(3, 0, RESP_SHORT | RESP_CRC, || {})?[0] >> 16) as u16;
        if card.rca == 0 {
            return Err(Error::Protocol);
        }
        let response = card.command(9, u32::from(card.rca) << 16, RESP_LONG | RESP_CRC, || {})?;
        card.info.capacity_sectors =
            capacity_from_csd([response[3], response[2], response[1], response[0]])
                .map_err(|_| Error::Unsupported)?;
        card.command(7, u32::from(card.rca) << 16, RESP_SHORT | RESP_CRC, || {})?;
        card.wait_not_busy()?;
        if !card.info.high_capacity {
            card.command(16, 512, RESP_SHORT | RESP_CRC, || {})?;
        }
        card.command(55, u32::from(card.rca) << 16, RESP_SHORT | RESP_CRC, || {})?;
        card.command(6, 2, RESP_SHORT | RESP_CRC, || {})?;
        card.registers.write(CTYPE, 1); // four-bit host width after card accepted ACMD6
        card.set_clock(description.data_clock_hz)?;
        card.online = true;
        Ok(card)
    }
    pub fn info(&self) -> CardInfo {
        self.info
    }
    pub fn diagnostics(&self) -> vibeos_hal::block::Diagnostics {
        vibeos_hal::block::Diagnostics {
            command: self.last_command.get(),
            interrupt_status: self.last_interrupt.get(),
            present_state: self.registers.read(STATUS),
        }
    }
    fn validate_blocks(&self, sector: u64, bytes: usize) -> Result<(), Error> {
        if !self.online {
            return Err(Error::Offline);
        }
        if bytes == 0 || bytes % 512 != 0 || bytes / 512 > MAX_TRANSFER_BLOCKS as usize {
            return Err(Error::OutOfRange);
        }
        let end = sector
            .checked_add((bytes / 512) as u64)
            .ok_or(Error::OutOfRange)?;
        if end > self.info.capacity_sectors {
            return Err(Error::OutOfRange);
        }
        sector_argument(self.info.high_capacity, end - 1).map_err(|_| Error::OutOfRange)?;
        Ok(())
    }
    /// Bounded batches use single-block commands; no DMA or caller slice is
    /// retained. Validate the entire request before issuing the first command.
    pub fn read_blocks(&mut self, sector: u64, output: &mut [u8]) -> Result<(), Error> {
        self.validate_blocks(sector, output.len())?;
        for (index, block) in output.chunks_exact_mut(512).enumerate() {
            block.copy_from_slice(&self.read_sector(sector + index as u64)?);
        }
        Ok(())
    }
    /// Publish exactly once, before the first CMD24, even if a later sector or
    /// verification fails. Never retry a failed write or silently keep online.
    pub fn write_blocks_tracked(
        &mut self,
        sector: u64,
        data: &[u8],
        verify: bool,
        published: &mut dyn FnMut(),
    ) -> Result<(), Error> {
        self.validate_blocks(sector, data.len())?;
        let mut submitted = false;
        for (index, bytes) in data.chunks_exact(512).enumerate() {
            let block: &[u8; 512] = bytes.try_into().unwrap();
            let address = sector + index as u64;
            self.write_sector_tracked(address, block, || {
                if !submitted {
                    published();
                    submitted = true;
                }
            })?;
            if verify && self.read_sector(address)? != *block {
                return self.finish(Err(Error::Protocol));
            }
        }
        Ok(())
    }
    pub fn is_online(&self) -> bool {
        self.online
    }
    fn wait(&self, mut ready: impl FnMut() -> bool) -> Result<(), Error> {
        let start = (self.time)();
        for _ in 0..POLL_LIMIT {
            if ready() {
                return Ok(());
            }
            if (self.time)().wrapping_sub(start) >= self.timeout_ticks {
                break;
            }
            core::hint::spin_loop();
        }
        Err(Error::TimedOut)
    }
    fn wait_not_busy(&self) -> Result<(), Error> {
        self.wait(|| self.registers.read(STATUS) & DATA_BUSY == 0)
    }
    fn update_clock(&self) -> Result<(), Error> {
        self.registers.write(RINTSTS, u32::MAX);
        self.registers.write(CMD, CMD_UPDATE_CLOCK);
        self.wait(|| self.registers.read(CMD) & CMD_START == 0)?;
        if self.registers.read(RINTSTS) & ERRORS != 0 {
            return Err(Error::Protocol);
        }
        Ok(())
    }
    fn set_clock(&self, target: u32) -> Result<(), Error> {
        let divider = clock_divider(self.description.source_clock_hz, target)?;
        self.registers.write(CLKENA, 0);
        self.update_clock()?;
        self.registers.write(CLKSRC, 0);
        self.registers.write(CLKDIV, u32::from(divider));
        self.update_clock()?;
        self.registers.write(CLKENA, 1);
        self.update_clock()
    }
    fn check_interrupts(&self) -> Result<u32, Error> {
        let status = self.registers.read(RINTSTS);
        self.last_interrupt.set(status);
        if status & RESP_TIMEOUT != 0 {
            Err(Error::TimedOut)
        } else if status & ERRORS != 0 {
            Err(Error::Protocol)
        } else {
            Ok(status)
        }
    }
    fn command(
        &self,
        index: u8,
        argument: u32,
        flags: u32,
        published: impl FnOnce(),
    ) -> Result<[u32; 4], Error> {
        self.wait_not_busy()?;
        self.registers.write(RINTSTS, u32::MAX);
        self.registers.write(CMDARG, argument);
        self.last_command.set(index);
        // Record submission before the MMIO store: a trap after publication
        // must never make a possibly executed write look safe to retry.
        published();
        self.registers
            .write(CMD, CMD_START | (1 << 13) | flags | u32::from(index));
        self.wait(|| self.registers.read(RINTSTS) & (CMD_DONE | ERRORS) != 0)?;
        self.check_interrupts()?;
        self.registers.write(RINTSTS, CMD_DONE);
        let response = core::array::from_fn(|i| self.registers.read(RESP0 + i * 4));
        // R1/R1b error bits. R2/R3/R6/R7 use different response layouts.
        if matches!(index, 6 | 7 | 13 | 16 | 17 | 24 | 55) && response[0] & 0xfdffe008 != 0 {
            return Err(Error::Protocol);
        }
        Ok(response)
    }
    fn prepare_data(&mut self, sector: u64) -> Result<u32, Error> {
        if !self.online {
            return Err(Error::Offline);
        }
        if sector >= self.info.capacity_sectors {
            return Err(Error::OutOfRange);
        }
        let argument =
            sector_argument(self.info.high_capacity, sector).map_err(|_| Error::OutOfRange)?;
        let result = (|| {
            self.wait_not_busy()?;
            self.registers.write(CTRL, 2);
            self.wait(|| self.registers.read(CTRL) & 2 == 0)?;
            self.registers.write(BLKSIZ, 512);
            self.registers.write(BYTCNT, 512);
            Ok(argument)
        })();
        self.finish(result)
    }
    /// No later IO is admitted after a controller failure until firmware
    /// reconstructs the instance. A possibly published write is never retried.
    fn finish<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.online = false;
        }
        result
    }
    pub fn read_sector(&mut self, sector: u64) -> Result<[u8; 512], Error> {
        let argument = self.prepare_data(sector)?;
        let result = (|| {
            self.command(17, argument, RESP_SHORT | RESP_CRC | DATA_EXPECT, || {})?;
            let mut output = [0; 512];
            for chunk in output.chunks_exact_mut(4) {
                self.wait(|| {
                    self.registers.read(STATUS) & (1 << 2) == 0
                        || self.registers.read(RINTSTS) & ERRORS != 0
                })?;
                self.check_interrupts()?;
                chunk.copy_from_slice(
                    &self
                        .registers
                        .read(self.description.fifo_offset)
                        .to_le_bytes(),
                );
            }
            self.wait_data_end()?;
            Ok(output)
        })();
        self.finish(result)
    }
    pub fn write_sector_tracked(
        &mut self,
        sector: u64,
        data: &[u8; 512],
        published: impl FnOnce(),
    ) -> Result<(), Error> {
        let argument = self.prepare_data(sector)?;
        let result = (|| {
            self.command(
                24,
                argument,
                RESP_SHORT | RESP_CRC | DATA_EXPECT | DATA_WRITE,
                published,
            )?;
            for chunk in data.chunks_exact(4) {
                self.wait(|| {
                    self.registers.read(STATUS) & (1 << 3) == 0
                        || self.registers.read(RINTSTS) & ERRORS != 0
                })?;
                self.check_interrupts()?;
                self.registers.write(
                    self.description.fifo_offset,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                );
            }
            self.wait_data_end()?;
            self.wait_not_busy()?;
            self.ready_for_data()
        })();
        self.finish(result)
    }
    pub fn write_sector(&mut self, sector: u64, data: &[u8; 512]) -> Result<(), Error> {
        self.write_sector_tracked(sector, data, || {})
    }
    fn wait_data_end(&self) -> Result<(), Error> {
        self.wait(|| self.registers.read(RINTSTS) & (DATA_OVER | ERRORS) != 0)?;
        self.check_interrupts()?;
        self.registers.write(RINTSTS, DATA_OVER);
        Ok(())
    }
    fn ready_for_data(&self) -> Result<(), Error> {
        self.ready_for_data_tracked(|| {})
    }
    fn ready_for_data_tracked(&self, published: impl FnOnce()) -> Result<(), Error> {
        let mut published = Some(published);
        let start = (self.time)();
        let mut attempts = 10_000usize;
        loop {
            if attempts == 0 {
                return Err(Error::TimedOut);
            }
            attempts -= 1;
            let r1 = self.command(13, u32::from(self.rca) << 16, RESP_SHORT | RESP_CRC, || {
                if let Some(publish) = published.take() {
                    publish();
                }
            })?[0];
            if r1 & (1 << 8) != 0 && (r1 >> 9) & 15 == 4 {
                return Ok(());
            }
            if (self.time)().wrapping_sub(start) >= self.timeout_ticks {
                return Err(Error::TimedOut);
            }
        }
    }
    pub fn flush(&mut self) -> Result<(), Error> {
        self.flush_tracked(|| {})
    }
    /// Track the first CMD13 submission, matching the PIO block HAL contract.
    pub fn flush_tracked(&mut self, published: impl FnOnce()) -> Result<(), Error> {
        if !self.online {
            return Err(Error::Offline);
        }
        let result = self
            .wait_not_busy()
            .and_then(|_| self.ready_for_data_tracked(published));
        self.finish(result)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::{
        cell::{Cell, RefCell},
        sync::atomic::{AtomicU64, Ordering},
    };
    use std::{rc::Rc, vec::Vec};
    static TIME: AtomicU64 = AtomicU64::new(0);
    fn time() -> u64 {
        TIME.fetch_add(1, Ordering::Relaxed)
    }
    struct Fake {
        writes: Rc<RefCell<Vec<(usize, u32)>>>,
        interrupt: Cell<u32>,
        fail: bool,
        fail_write_number: Cell<usize>,
        write_commands: Cell<usize>,
        busy: Cell<bool>,
        not_ready_polls: Cell<usize>,
        command: Cell<u8>,
    }
    impl Registers for Fake {
        fn read(&self, offset: usize) -> u32 {
            match offset {
                STATUS if self.busy.get() => DATA_BUSY,
                RINTSTS => self.interrupt.get(),
                RESP0 => match self.command.get() {
                    8 => 0x1aa,
                    41 => 0xc0ff8000,
                    3 => 0x10000,
                    9 => 0,
                    13 if self.not_ready_polls.get() != 0 => {
                        self.not_ready_polls.set(self.not_ready_polls.get() - 1);
                        0xe00 // programming state, not ready for data
                    }
                    _ => 0x900,
                },
                0x3c if self.command.get() == 9 => 0x40000000,
                0x200 => 0x04030201,
                _ => 0,
            }
        }
        fn write(&self, offset: usize, value: u32) {
            self.writes.borrow_mut().push((offset, value));
            if offset == RINTSTS {
                self.interrupt.set(self.interrupt.get() & !value);
            }
            if offset == CMD {
                self.command.set((value & 63) as u8);
                if value & 63 == 24 {
                    self.write_commands.set(self.write_commands.get() + 1);
                }
                self.interrupt.set(
                    if self.fail
                        || (value & 63 == 24
                            && self.fail_write_number.get() == self.write_commands.get())
                    {
                        RESP_TIMEOUT
                    } else {
                        CMD_DONE | DATA_OVER
                    },
                );
            }
        }
    }
    fn card(fail: bool) -> Card<Fake> {
        Card {
            registers: Fake {
                writes: Rc::new(RefCell::new(Vec::new())),
                interrupt: Cell::new(0),
                fail,
                fail_write_number: Cell::new(usize::MAX),
                write_commands: Cell::new(0),
                busy: Cell::new(false),
                not_ready_polls: Cell::new(0),
                command: Cell::new(0),
            },
            description: Description {
                registers: AddressRange::new(0, 0x1000),
                irq: 75,
                source_clock_hz: 50_000_000,
                data_clock_hz: 25_000_000,
                fifo_depth_words: 32,
                fifo_offset: 0x200,
            },
            time,
            timeout_ticks: 1000,
            rca: 1,
            info: CardInfo {
                capacity_sectors: 16,
                high_capacity: true,
            },
            online: true,
            last_command: Cell::new(0),
            last_interrupt: Cell::new(0),
        }
    }
    #[test]
    fn initialization_negotiates_sd_and_four_bit_bus_after_acmd6() {
        let initial = card(false);
        let card = Card::initialize(initial.registers, initial.description, time, 1000).unwrap();
        assert_eq!(
            card.info(),
            CardInfo {
                high_capacity: true,
                capacity_sectors: 1024
            }
        );
        let writes = card.registers.writes.borrow();
        let acmd6 = writes
            .iter()
            .position(|&(o, v)| o == CMD && v & 63 == 6)
            .unwrap();
        let host_width = writes
            .iter()
            .position(|&(o, v)| o == CTYPE && v == 1)
            .unwrap();
        assert!(acmd6 < host_width);
        assert!(writes.contains(&(CLKDIV, 63)));
        assert!(writes.contains(&(CLKDIV, 1)));
        assert!(!writes.iter().any(|&(o, v)| o == CTRL && v & (1 << 25) != 0));
    }
    #[test]
    fn dividers_never_exceed_requested_clock() {
        assert_eq!(clock_divider(50_000_000, 400_000), Ok(63));
        assert_eq!(clock_divider(50_000_000, 25_000_000), Ok(1));
        assert_eq!(clock_divider(50_000_000, 50_000_000), Ok(0));
        assert_eq!(clock_divider(u32::MAX, 1), Err(Error::InvalidConfiguration));
        assert_eq!(clock_divider(1, 0), Err(Error::InvalidConfiguration));
    }
    #[test]
    fn out_of_range_never_publishes_mmio() {
        let mut c = card(false);
        assert_eq!(c.write_sector(16, &[0; 512]), Err(Error::OutOfRange));
        assert!(c.registers.writes.borrow().is_empty());
        assert!(c.is_online());
    }
    #[test]
    fn write_publication_precedes_failure_and_disables_further_io() {
        let mut c = card(true);
        let published = Cell::new(0);
        assert_eq!(
            c.write_sector_tracked(0, &[0; 512], || published.set(published.get() + 1)),
            Err(Error::TimedOut)
        );
        assert_eq!(published.get(), 1);
        assert!(!c.is_online());
        assert_eq!(c.write_sector(0, &[0; 512]), Err(Error::Offline));
    }
    #[test]
    fn pio_read_returns_exact_little_endian_sector() {
        let mut c = card(false);
        let data = c.read_sector(15).unwrap();
        assert!(data.chunks_exact(4).all(|x| x == [1, 2, 3, 4]));
        assert!(c.registers.writes.borrow().contains(&(CMDARG, 15)));
    }
    #[test]
    fn pio_write_uses_128_fifo_words_and_checks_card_ready() {
        let mut c = card(false);
        c.write_sector(3, &[0xab; 512]).unwrap();
        let writes = c.registers.writes.borrow();
        assert_eq!(
            writes
                .iter()
                .filter(|&&(o, v)| o == 0x200 && v == 0xabababab)
                .count(),
            128
        );
        assert!(writes.iter().any(|&(o, v)| o == CMD && v & 63 == 13));
    }
    #[test]
    fn tracked_submission_runs_before_the_command_register_store() {
        let mut c = card(false);
        let writes = c.registers.writes.clone();
        c.write_sector_tracked(0, &[0; 512], || {
            assert!(!writes
                .borrow()
                .iter()
                .any(|&(o, v)| o == CMD && v & 63 == 24));
        })
        .unwrap();
        assert!(writes
            .borrow()
            .iter()
            .any(|&(o, v)| o == CMD && v & 63 == 24));
    }
    #[test]
    fn batch_validates_whole_range_and_address_encoding_before_io() {
        for (sector, bytes) in [
            (15, 1024),
            (u64::MAX, 512),
            (0, 0),
            (0, 513),
            (0, 257 * 512),
        ] {
            let mut c = card(false);
            let published = Cell::new(0);
            assert_eq!(
                c.write_blocks_tracked(sector, &std::vec![0;bytes], false, &mut || published
                    .set(1)),
                Err(Error::OutOfRange)
            );
            assert_eq!(published.get(), 0);
            assert!(c.registers.writes.borrow().is_empty());
            assert!(c.is_online());
        }
        let mut c = card(false);
        c.info.capacity_sectors = u64::MAX;
        assert_eq!(
            c.write_blocks_tracked(u32::MAX as u64, &[0; 1024], false, &mut || panic!(
                "published"
            )),
            Err(Error::OutOfRange)
        );
        assert!(c.registers.writes.borrow().is_empty());
        let mut output = [0; 1024];
        let mut c = card(false);
        assert_eq!(c.read_blocks(15, &mut output), Err(Error::OutOfRange));
        assert!(c.registers.writes.borrow().is_empty());
    }
    #[test]
    fn batch_tracks_once_and_verifies_each_sector() {
        let mut c = card(false);
        let mut data = [0; 1024];
        for word in data.chunks_exact_mut(4) {
            word.copy_from_slice(&[1, 2, 3, 4]);
        }
        let mut published = 0;
        c.write_blocks_tracked(14, &data, true, &mut || published += 1)
            .unwrap();
        assert_eq!(published, 1);
        let commands: Vec<_> = c
            .registers
            .writes
            .borrow()
            .iter()
            .filter(|&&(o, _)| o == CMD)
            .map(|&(_, v)| v & 63)
            .collect();
        assert_eq!(commands, [24, 13, 17, 24, 13, 17]);
        let mut output = [0; 1024];
        c.read_blocks(14, &mut output).unwrap();
        assert_eq!(output, data);
    }
    #[test]
    fn mid_batch_failure_is_not_retried_and_retains_submission() {
        let mut c = card(false);
        c.registers.fail_write_number.set(2);
        let mut published = 0;
        assert_eq!(
            c.write_blocks_tracked(0, &[0; 1536], false, &mut || published += 1),
            Err(Error::TimedOut)
        );
        assert_eq!(published, 1);
        assert_eq!(c.registers.write_commands.get(), 2);
        assert!(!c.is_online());
        let diagnostic = c.diagnostics();
        assert_eq!(diagnostic.command, 24);
        assert_eq!(diagnostic.interrupt_status, RESP_TIMEOUT);
        assert_eq!(
            c.write_blocks_tracked(0, &[0; 512], false, &mut || panic!("retry")),
            Err(Error::Offline)
        );
    }
    #[test]
    fn verification_mismatch_quarantines_card_without_retry() {
        let mut c = card(false);
        let mut published = 0;
        assert_eq!(
            c.write_blocks_tracked(0, &[0; 1024], true, &mut || published += 1),
            Err(Error::Protocol)
        );
        assert_eq!(published, 1);
        assert_eq!(c.registers.write_commands.get(), 1);
        assert!(!c.is_online());
    }
    #[test]
    fn busy_failure_before_publication_is_not_reported_as_submitted() {
        let mut c = card(false);
        c.registers.busy.set(true);
        assert_eq!(
            c.write_blocks_tracked(0, &[0; 512], false, &mut || panic!("not submitted")),
            Err(Error::TimedOut)
        );
        assert!(c.registers.writes.borrow().is_empty());
        assert!(!c.is_online());
    }
    #[test]
    fn flush_tracks_before_first_status_command_and_failure_stays_offline() {
        let mut c = card(true);
        let writes = c.registers.writes.clone();
        let mut published = 0;
        assert_eq!(
            c.flush_tracked(|| {
                assert!(!writes.borrow().iter().any(|&(o, _)| o == CMD));
                published += 1;
            }),
            Err(Error::TimedOut)
        );
        assert_eq!(published, 1);
        assert_eq!(c.diagnostics().command, 13);
        assert!(!c.is_online());
        assert_eq!(c.flush_tracked(|| panic!("offline")), Err(Error::Offline));
    }
    #[test]
    fn flush_waits_for_transfer_state_without_republishing() {
        let mut c = card(false);
        c.registers.not_ready_polls.set(2);
        let mut published = 0;
        c.flush_tracked(|| published += 1).unwrap();
        assert_eq!(published, 1);
        assert!(c.is_online());
        let commands: Vec<_> = c
            .registers
            .writes
            .borrow()
            .iter()
            .filter(|&&(o, _)| o == CMD)
            .map(|&(_, v)| v & 63)
            .collect();
        assert_eq!(commands, [13, 13, 13]);
    }
}
