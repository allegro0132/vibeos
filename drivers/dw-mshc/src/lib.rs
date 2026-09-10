#![no_std]
//! Synopsys DesignWare MSHC SD transport (PIO, 512-byte single-block IO).
//! SoC clocks, resets, pinmux and card power are prepared by the embedding
//! firmware. No SDHCI register assumptions or CPU-specific cache operations.
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
pub use vibeos_hal::DwMshcDescription as Description;
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
        self.registers
            .write(CMD, CMD_START | (1 << 13) | flags | u32::from(index));
        published();
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
        let start = (self.time)();
        let mut attempts = 10_000usize;
        loop {
            if attempts == 0 {
                return Err(Error::TimedOut);
            }
            attempts -= 1;
            let r1 = self.command(13, u32::from(self.rca) << 16, RESP_SHORT | RESP_CRC, || {})?[0];
            if r1 & (1 << 8) != 0 && (r1 >> 9) & 15 == 4 {
                return Ok(());
            }
            if (self.time)().wrapping_sub(start) >= self.timeout_ticks {
                return Err(Error::TimedOut);
            }
        }
    }
    pub fn flush(&mut self) -> Result<(), Error> {
        if !self.online {
            return Err(Error::Offline);
        }
        let result = self.wait_not_busy().and_then(|_| self.ready_for_data());
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
    use std::vec::Vec;
    static TIME: AtomicU64 = AtomicU64::new(0);
    fn time() -> u64 {
        TIME.fetch_add(1, Ordering::Relaxed)
    }
    struct Fake {
        writes: RefCell<Vec<(usize, u32)>>,
        interrupt: Cell<u32>,
        fail: bool,
        command: Cell<u8>,
    }
    impl Registers for Fake {
        fn read(&self, offset: usize) -> u32 {
            match offset {
                RINTSTS => self.interrupt.get(),
                RESP0 => match self.command.get() {
                    8 => 0x1aa,
                    41 => 0xc0ff8000,
                    3 => 0x10000,
                    9 => 0,
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
                self.interrupt.set(if self.fail {
                    RESP_TIMEOUT
                } else {
                    CMD_DONE | DATA_OVER
                });
            }
        }
    }
    fn card(fail: bool) -> Card<Fake> {
        Card {
            registers: Fake {
                writes: RefCell::new(Vec::new()),
                interrupt: Cell::new(0),
                fail,
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
}
