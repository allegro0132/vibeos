#![no_std]
//! MT7988 MSDC SDHC/SDXC discovery and capability-scoped single-block PIO I/O.
//! Boot firmware must supply powered 3.3V SD pads and enabled source/core
//! clocks. This driver resets and rediscovers the card, retaining pad tuning.
//! No DMA or implicit write-capable range is exposed. Writes require a trusted
//! session-bound range capability; command publication makes failure ambiguous.
use core::sync::atomic::{AtomicU64, Ordering};
use vibeos_storage_device::{BlockRangeCapability, DeviceId, DeviceSession, MutationFailure};
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

const CFG: usize = 0x00;
const INT: usize = 0x0c;
const INTEN: usize = 0x10;
const FIFO: usize = 0x14;
const RX: usize = 0x1c;
const SDC_CFG: usize = 0x30;
const CMD: usize = 0x34;
const ARG: usize = 0x38;
const STS: usize = 0x3c;
const RESP: usize = 0x40;
const BLOCKS: usize = 0x50;
const CMD_READY: u32 = 1 << 8;
const CMD_TIMEOUT: u32 = 1 << 9;
const CMD_CRC: u32 = 1 << 10;
const DATA_DONE: u32 = 1 << 12;
const DATA_TIMEOUT: u32 = 1 << 14;
const DATA_CRC: u32 = 1 << 15;
const COMMAND_EVENTS: u32 = CMD_READY | CMD_TIMEOUT | CMD_CRC;
const DATA_EVENTS: u32 = DATA_DONE | DATA_TIMEOUT | DATA_CRC;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig,
    NotReady,
    Busy,
    Timeout,
    CommandTimeout(u8),
    CommandCrc(u8),
    CardStatus(u32),
    UnsupportedCard,
    DataTimeout,
    DataCrc,
    ShortTransfer,
    OutOfRange,
    WrongAuthority,
    WriteProtected,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Card {
    pub cid: [u32; 4],
    pub csd: [u32; 4],
    pub rca: u16,
    pub blocks: u64,
    pub ocr: u32,
}
/// Register/time backend. The clock must advance monotonically at `hz`.
/// MMIO implementations own their aperture; mock implementations use no I/O.
pub trait Io {
    fn read(&mut self, offset: usize) -> u32;
    fn write(&mut self, offset: usize, value: u32);
    fn now(&mut self) -> u64;
}
pub struct Mmio {
    base: usize,
    clock: fn() -> u64,
}
impl Mmio {
    /// # Safety
    /// Own the live MSDC controller and map its entire 4 KiB register aperture
    /// Device-nGnRnE. Keep it powered and exclude all other register users.
    pub unsafe fn new(base: usize, clock: fn() -> u64) -> Result<Self, Error> {
        if base == 0 || base & 0xfff != 0 {
            return Err(Error::InvalidConfig);
        }
        Ok(Self { base, clock })
    }
}
impl Io for Mmio {
    fn read(&mut self, offset: usize) -> u32 {
        assert!(offset < 4096 && offset % 4 == 0);
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }
    fn write(&mut self, offset: usize, value: u32) {
        assert!(offset < 4096 && offset % 4 == 0);
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }
    fn now(&mut self) -> u64 {
        (self.clock)()
    }
}

pub struct Host<I: Io> {
    io: I,
    hz: u64,
    card: Option<Card>,
    session: Option<DeviceSession>,
}
impl<I: Io> Host<I> {
    pub fn new(io: I, hz: u64) -> Result<Self, Error> {
        if hz == 0 || hz > u64::MAX / 4 {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            io,
            hz,
            card: None,
            session: None,
        })
    }
    pub fn card(&self) -> Option<Card> {
        self.card
    }
    pub fn session(&self) -> Option<DeviceSession> {
        self.card.and(self.session)
    }
    fn modify(&mut self, reg: usize, clear: u32, set: u32) {
        let value = self.io.read(reg);
        self.io.write(reg, (value & !clear) | set);
    }
    fn wait(&mut self, reg: usize, mask: u32, value: u32) -> Result<(), Error> {
        let start = self.io.now();
        while self.io.read(reg) & mask != value {
            if self.io.now().wrapping_sub(start) >= self.hz {
                return Err(Error::Timeout);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }
    fn command(
        &mut self,
        index: u8,
        arg: u32,
        response: u32,
        data: bool,
    ) -> Result<[u32; 4], Error> {
        self.command_tracked(index, arg, response, data, false, &mut false)
    }
    fn command_tracked(
        &mut self,
        index: u8,
        arg: u32,
        response: u32,
        data: bool,
        write: bool,
        submitted: &mut bool,
    ) -> Result<[u32; 4], Error> {
        self.wait(STS, 3, 0)?;
        self.io.write(INT, COMMAND_EVENTS | DATA_EVENTS);
        self.io.write(BLOCKS, if data { 1 } else { 0 });
        self.io.write(ARG, arg);
        let raw =
            u32::from(index) | (response << 7) | if data { (512 << 16) | (1 << 11) } else { 0 };
        *submitted = true;
        self.io.write(CMD, raw | if write { 1 << 13 } else { 0 });
        let start = self.io.now();
        let events = loop {
            let events = self.io.read(INT) & COMMAND_EVENTS;
            if events != 0 {
                break events;
            }
            if self.io.now().wrapping_sub(start) >= self.hz {
                return Err(Error::CommandTimeout(index));
            }
        };
        self.io.write(INT, events);
        // Error wins even if the controller also latched CMDRDY.
        if events & CMD_TIMEOUT != 0 {
            return Err(Error::CommandTimeout(index));
        }
        if events & CMD_CRC != 0 {
            return Err(Error::CommandCrc(index));
        }
        let mut result = [0; 4];
        if response == 2 {
            for (i, word) in result.iter_mut().enumerate() {
                *word = self.io.read(RESP + (3 - i) * 4);
            }
        } else if response != 0 {
            result[0] = self.io.read(RESP);
        }
        Ok(result)
    }
    fn r1(&mut self, index: u8, arg: u32, busy: bool) -> Result<u32, Error> {
        let status = self.command(index, arg, if busy { 7 } else { 1 }, false)?[0];
        check_r1(status)?;
        if busy {
            self.wait(0x08, 1 << 16, 1 << 16)?;
        }
        Ok(status)
    }
    /// Rediscover a v2 high-capacity SD card at a conservative clock divider.
    /// The MT7988 source clock must be <= 800 MHz: divisor 512 gives <= 391 kHz.
    /// Pads, power, top clocks and tuning are retained from boot firmware.
    /// No old RCA, bus width, card selection or capacity is trusted.
    pub fn initialize_sd(&mut self) -> Result<Card, Error> {
        self.card = None;
        self.session = None;
        if self.io.read(0x9c) & 1 != 0 {
            return Err(Error::Busy);
        }
        self.io.write(INTEN, 0); // PIO polls status, never routes MSDC IRQs.
        self.modify(CFG, 0, 1 << 2);
        self.wait(CFG, 1 << 2, 0)?;
        // 12-bit divider, SDR mode. CKPDN=0 permits clock reconfiguration.
        self.modify(CFG, (1 << 1) | (0x7fff << 8), 1 | (1 << 3) | (512 << 8));
        self.wait(CFG, 1 << 7, 1 << 7)?;
        self.modify(CFG, 0, 1 << 1);
        self.modify(SDC_CFG, (3 << 16) | (0xff << 24), 0xff << 24); // 1-bit bus
        self.modify(FIFO, 0, 1 << 31);
        self.wait(FIFO, 1 << 31, 0)?;
        self.io.write(INT, u32::MAX);
        self.command(0, 0, 0, false)?;
        if self.command(8, 0x1aa, 1, false)?[0] != 0x1aa {
            return Err(Error::UnsupportedCard);
        }
        let start = self.io.now();
        let ocr = loop {
            let app = self.r1(55, 0, false)?;
            if app & (1 << 5) == 0 {
                return Err(Error::UnsupportedCard);
            }
            let ocr = self.command(41, 0x40ff_8000, 3, false)?[0];
            if ocr & (1 << 31) != 0 {
                break ocr;
            }
            if self.io.now().wrapping_sub(start) >= self.hz * 2 {
                return Err(Error::Timeout);
            }
        };
        if ocr & (1 << 30) == 0 || ocr & 0x00ff_8000 == 0 {
            return Err(Error::UnsupportedCard);
        }
        let cid = self.command(2, 0, 2, false)?;
        let r6 = self.command(3, 0, 1, false)?[0];
        if r6 & 0xe000 != 0 {
            return Err(Error::CardStatus(r6));
        }
        let rca = (r6 >> 16) as u16;
        if rca == 0 {
            return Err(Error::UnsupportedCard);
        }
        let csd = self.command(9, u32::from(rca) << 16, 2, false)?;
        let blocks = csd_blocks(csd)?;
        self.r1(7, u32::from(rca) << 16, true)?;
        let status = self.r1(13, u32::from(rca) << 16, false)?;
        if status & 0x1f00 != 0x900 {
            return Err(Error::CardStatus(status));
        }
        let card = Card {
            cid,
            csd,
            rca,
            blocks,
            ocr,
        };
        let identity = cid
            .iter()
            .fold(0u128, |value, word| (value << 32) | u128::from(*word));
        let id = DeviceId::new(identity).ok_or(Error::UnsupportedCard)?;
        let incarnation = NEXT_SESSION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::InvalidConfig)?;
        self.session = Some(DeviceSession::new(id, incarnation).map_err(|_| Error::InvalidConfig)?);
        self.card = Some(card);
        Ok(card)
    }
    /// Read exactly one 512-byte sector. Errors invalidate the selected card;
    /// explicit reinitialization is required before another request can run.
    /// A failed transfer may have changed a prefix of `out`; discard it.
    pub fn read_block(&mut self, lba: u64, out: &mut [u8; 512]) -> Result<(), Error> {
        let card = self.card.ok_or(Error::NotReady)?;
        if lba >= card.blocks || lba > u64::from(u32::MAX) {
            return Err(Error::OutOfRange);
        }
        let result = self.read_inner(lba as u32, out);
        if result.is_err() {
            self.card = None;
        }
        result
    }
    /// Write one sector inside an explicitly provisioned authority. Validation
    /// happens before MMIO. After CMD24 publication, any failure is ambiguous:
    /// callers must reconcile from media, never retry a higher-level mutation
    /// on the assumption that nothing happened. Failure invalidates this host.
    pub fn write_block(
        &mut self,
        authority: BlockRangeCapability,
        relative_lba: u64,
        input: &[u8; 512],
    ) -> Result<(), MutationFailure<Error>> {
        let card = self
            .card
            .ok_or(MutationFailure::not_submitted(Error::NotReady))?;
        if self.session() != Some(authority.session()) {
            return Err(MutationFailure::not_submitted(Error::WrongAuthority));
        }
        let lba = authority
            .range()
            .translate(relative_lba, 1)
            .map_err(|_| MutationFailure::not_submitted(Error::OutOfRange))?;
        if lba >= card.blocks || lba > u64::from(u32::MAX) {
            return Err(MutationFailure::not_submitted(Error::OutOfRange));
        }
        if card.csd[3] & (3 << 12) != 0 {
            return Err(MutationFailure::not_submitted(Error::WriteProtected));
        }
        let mut submitted = false;
        let result = (|| {
            self.modify(FIFO, 0, 1 << 31);
            self.wait(FIFO, 1 << 31, 0)?;
            let status = self.command_tracked(24, lba as u32, 1, true, true, &mut submitted)?[0];
            check_r1(status)?;
            let start = self.io.now();
            let mut count = 0;
            loop {
                let events = self.io.read(INT);
                if events & DATA_TIMEOUT != 0 {
                    return Err(Error::DataTimeout);
                }
                if events & DATA_CRC != 0 {
                    return Err(Error::DataCrc);
                }
                if events & DATA_DONE != 0 {
                    if count != 512 {
                        return Err(Error::ShortTransfer);
                    }
                    self.io.write(INT, DATA_EVENTS);
                    break;
                }
                let occupied = ((self.io.read(FIFO) >> 16) & 255) as usize;
                if occupied > 128 {
                    return Err(Error::Busy);
                }
                for _ in 0..((128 - occupied) / 4).min((512 - count) / 4) {
                    let word = u32::from_le_bytes(input[count..count + 4].try_into().unwrap());
                    self.io.write(0x18, word);
                    count += 4;
                }
                if self.io.now().wrapping_sub(start) >= self.hz * 2 {
                    return Err(Error::DataTimeout);
                }
            }
            self.programming_complete(card.rca)
        })();
        if let Err(error) = result {
            self.card = None;
            return Err(if submitted {
                MutationFailure::ambiguous(error)
            } else {
                MutationFailure::not_submitted(error)
            });
        }
        Ok(())
    }
    /// Status barrier for ordinary SD writes, whose optional cache features
    /// this driver never enables. This is not a power-loss atomicity promise.
    /// Every successful write already performs this barrier before returning.
    pub fn finish_programming(&mut self, authority: BlockRangeCapability) -> Result<(), Error> {
        let card = self.card.ok_or(Error::NotReady)?;
        if self.session() != Some(authority.session()) {
            return Err(Error::WrongAuthority);
        }
        if authority.range().end_block() > card.blocks {
            return Err(Error::OutOfRange);
        }
        let result = self.programming_complete(card.rca);
        if result.is_err() {
            self.card = None;
        }
        result
    }
    fn programming_complete(&mut self, rca: u16) -> Result<(), Error> {
        // DATA_DONE is not sufficient: wait for DAT0 deassertion, then require
        // READY_FOR_DATA and TRAN from CMD13 with no card error bits.
        self.wait(0x08, 1 << 16, 1 << 16)?;
        let start = self.io.now();
        loop {
            let status = self.r1(13, u32::from(rca) << 16, false)?;
            if status & 0x1f00 == 0x900 {
                return Ok(());
            }
            if self.io.now().wrapping_sub(start) >= self.hz * 2 {
                return Err(Error::Timeout);
            }
        }
    }
    fn read_inner(&mut self, lba: u32, out: &mut [u8; 512]) -> Result<(), Error> {
        self.modify(FIFO, 0, 1 << 31);
        self.wait(FIFO, 1 << 31, 0)?;
        let status = self.command(17, lba, 1, true)?[0];
        check_r1(status)?;
        let start = self.io.now();
        let mut count = 0;
        loop {
            let events = self.io.read(INT);
            if events & DATA_TIMEOUT != 0 {
                return Err(Error::DataTimeout);
            }
            if events & DATA_CRC != 0 {
                return Err(Error::DataCrc);
            }
            let available = (self.io.read(FIFO) & 255) as usize;
            for _ in 0..(available / 4).min((512 - count) / 4) {
                let word = self.io.read(RX).to_le_bytes();
                out[count..count + 4].copy_from_slice(&word);
                count += 4;
            }
            if events & DATA_DONE != 0 {
                // Completion may be visible before the final FIFO drain.
                // Only accept the block after all 512 bytes have been read.
                if count == 512 {
                    self.io.write(INT, DATA_EVENTS);
                    return Ok(());
                }
                if self.io.read(FIFO) & 255 == 0 {
                    return Err(Error::ShortTransfer);
                }
            }
            if self.io.now().wrapping_sub(start) >= self.hz * 2 {
                return Err(Error::DataTimeout);
            }
        }
    }
}
fn check_r1(status: u32) -> Result<(), Error> {
    if status & 0xffff_e008 != 0 {
        Err(Error::CardStatus(status))
    } else {
        Ok(())
    }
}
pub fn csd_blocks(csd: [u32; 4]) -> Result<u64, Error> {
    if csd[0] >> 30 != 1 {
        return Err(Error::UnsupportedCard);
    }
    let size = ((csd[1] & 0x3f) << 16) | (csd[2] >> 16);
    Ok((u64::from(size) + 1) * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        regs: [u32; 64],
        tick: u64,
        fifo_words: usize,
        fault: u32,
        command_event: u32,
        hang: bool,
        writes: usize,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                regs: [0; 64],
                tick: 0,
                fifo_words: 0,
                fault: 0,
                command_event: CMD_READY,
                hang: false,
                writes: 0,
            }
        }
    }
    impl Io for Fake {
        fn read(&mut self, reg: usize) -> u32 {
            if reg == FIFO {
                return (self.fifo_words * 4).min(128) as u32;
            }
            if reg == RX {
                assert!(self.fifo_words != 0);
                self.fifo_words -= 1;
                return 0x12345678;
            }
            self.regs[reg / 4]
        }
        fn write(&mut self, reg: usize, value: u32) {
            self.writes += 1;
            if reg == INT {
                self.regs[reg / 4] &= !value;
                return;
            }
            if reg == FIFO {
                return;
            }
            self.regs[reg / 4] = value;
            if reg == CMD {
                assert_eq!(value & 63, 17, "test read must never issue a media write");
                assert_eq!(value & (1 << 13), 0);
                assert_eq!(value >> 16, 512);
                assert_eq!((value >> 11) & 3, 1);
                self.regs[RESP / 4] = 0x900;
                self.regs[INT / 4] = if self.hang {
                    0
                } else {
                    self.command_event | DATA_DONE | self.fault
                };
            }
        }
        fn now(&mut self) -> u64 {
            self.tick += 1;
            self.tick
        }
    }
    fn host(fake: Fake) -> Host<Fake> {
        let mut h = Host::new(fake, 100).unwrap();
        h.card = Some(Card {
            cid: [0; 4],
            csd: [0; 4],
            rca: 1,
            blocks: 4096,
            ocr: 0xc0ff8000,
        });
        h
    }
    #[test]
    fn csd_capacity_and_unsupported_versions() {
        assert_eq!(csd_blocks([1 << 30, 0, 0, 0]), Ok(1024));
        assert_eq!(csd_blocks([1 << 30, 63, 0xffff0000, 0]), Ok(1 << 32));
        assert_eq!(csd_blocks([0; 4]), Err(Error::UnsupportedCard));
        assert_eq!(csd_blocks([2 << 30, 0, 0, 0]), Err(Error::UnsupportedCard));
    }
    #[test]
    fn range_rejection_has_no_io_and_preserves_card() {
        let mut h = host(Fake::new());
        for lba in [4096, u64::MAX] {
            assert_eq!(h.read_block(lba, &mut [0; 512]), Err(Error::OutOfRange));
        }
        assert_eq!(h.io.writes, 0);
        assert!(h.card().is_some());
    }
    #[test]
    fn drains_completion_fifo_and_keeps_exact_sector_bytes() {
        let mut fake = Fake::new();
        fake.fifo_words = 128;
        let mut h = host(fake);
        let mut out = [0; 512];
        h.read_block(1, &mut out).unwrap();
        assert!(out
            .chunks_exact(4)
            .all(|word| word == [0x78, 0x56, 0x34, 0x12]));
        assert_eq!(h.io.fifo_words, 0);
        assert_eq!(h.io.regs[ARG / 4], 1);
    }
    #[test]
    fn errors_win_over_completion_and_require_rediscovery() {
        for (fault, expected) in [
            (DATA_CRC, Error::DataCrc),
            (DATA_TIMEOUT, Error::DataTimeout),
        ] {
            let mut fake = Fake::new();
            fake.fault = fault;
            fake.fifo_words = 128;
            let mut h = host(fake);
            assert_eq!(h.read_block(0, &mut [0; 512]), Err(expected));
            assert_eq!(h.read_block(0, &mut [0; 512]), Err(Error::NotReady));
        }
    }
    #[test]
    fn short_transfer_and_command_deadline_are_bounded() {
        let mut fake = Fake::new();
        fake.fifo_words = 127;
        assert_eq!(
            host(fake).read_block(0, &mut [0; 512]),
            Err(Error::ShortTransfer)
        );
        let mut fake = Fake::new();
        fake.hang = true;
        assert_eq!(
            host(fake).read_block(0, &mut [0; 512]),
            Err(Error::CommandTimeout(17))
        );
        let mut fake = Fake::new();
        fake.command_event = CMD_READY | CMD_CRC;
        assert_eq!(
            host(fake).read_block(0, &mut [0; 512]),
            Err(Error::CommandCrc(17))
        );
    }
    #[test]
    fn card_error_bits_never_look_like_success() {
        assert_eq!(check_r1(0x900), Ok(()));
        for bit in [31, 30, 29, 28, 23, 22, 19, 16, 15, 13, 3] {
            assert_eq!(
                check_r1(0x900 | (1 << bit)),
                Err(Error::CardStatus(0x900 | (1 << bit)))
            );
        }
    }
}

#[cfg(test)]
mod write_tests {
    use super::*;
    use vibeos_storage_device::{BlockRangeProvisioner, MutationCertainty};
    struct WriteIo {
        regs: [u32; 64],
        tick: u64,
        writes: usize,
        sent: usize,
        words: [u32; 128],
        command_timeout: bool,
        early_done: bool,
        data_error: u32,
        busy: bool,
        status_error: bool,
        status_polls: usize,
        published_lba: Option<u32>,
    }
    impl WriteIo {
        fn new() -> Self {
            let mut regs = [0; 64];
            regs[0x08 / 4] = 1 << 16;
            Self {
                regs,
                tick: 0,
                writes: 0,
                sent: 0,
                words: [0; 128],
                command_timeout: false,
                early_done: false,
                data_error: 0,
                busy: false,
                status_error: false,
                status_polls: 0,
                published_lba: None,
            }
        }
    }
    impl Io for WriteIo {
        fn read(&mut self, reg: usize) -> u32 {
            if reg == FIFO {
                return 0;
            } // model drains every word immediately
            if reg == 0x08 && self.busy {
                return 0;
            }
            self.regs[reg / 4]
        }
        fn write(&mut self, reg: usize, value: u32) {
            self.writes += 1;
            match reg {
                INT => self.regs[reg / 4] &= !value,
                FIFO => {}
                0x18 => {
                    assert!(self.sent < 128);
                    self.words[self.sent] = value;
                    self.sent += 1;
                    if self.sent == 128 {
                        self.regs[INT / 4] |= DATA_DONE;
                    }
                }
                CMD => match value & 63 {
                    24 => {
                        assert_eq!(value, 24 | (1 << 7) | (1 << 11) | (1 << 13) | (512 << 16));
                        self.published_lba = Some(self.regs[ARG / 4]);
                        self.regs[RESP / 4] = 0x900;
                        self.regs[INT / 4] = if self.command_timeout {
                            0
                        } else {
                            CMD_READY
                                | self.data_error
                                | if self.early_done { DATA_DONE } else { 0 }
                        };
                    }
                    13 => {
                        self.status_polls += 1;
                        self.regs[INT / 4] = CMD_READY;
                        self.regs[RESP / 4] = if self.status_error {
                            1 << 26
                        } else if self.status_polls < 3 {
                            7 << 9
                        } else {
                            0x900
                        };
                    }
                    other => panic!("unexpected command {other}"),
                },
                _ => self.regs[reg / 4] = value,
            }
        }
        fn now(&mut self) -> u64 {
            self.tick += 1;
            self.tick
        }
    }
    fn setup() -> (Host<WriteIo>, BlockRangeCapability) {
        let mut h = Host::new(WriteIo::new(), 100).unwrap();
        h.card = Some(Card {
            cid: [0; 4],
            csd: [0; 4],
            rca: 1,
            blocks: 4096,
            ocr: 0xc0ff8000,
        });
        h.session = Some(DeviceSession::new(DeviceId::new(1).unwrap(), 7).unwrap());
        let cap = unsafe { BlockRangeProvisioner::new(h.session().unwrap(), 100, 4) }
            .unwrap()
            .derive(0, 4)
            .unwrap();
        (h, cap)
    }
    #[test]
    fn writes_only_translated_range_then_waits_for_programming() {
        let (mut h, cap) = setup();
        h.write_block(cap, 1, &[0xa5; 512]).unwrap();
        assert_eq!(h.io.published_lba, Some(101));
        assert_eq!(h.io.sent, 128);
        assert!(h.io.words.iter().all(|v| *v == 0xa5a5a5a5));
        assert_eq!(
            h.io.status_polls, 3,
            "busy card must not count as durable completion"
        );
        h.finish_programming(cap).unwrap();
        assert_eq!(h.io.status_polls, 4);
    }
    #[test]
    fn wrong_session_range_and_write_protect_are_not_submitted() {
        let (mut h, cap) = setup();
        for offset in [4, u64::MAX] {
            let err = h.write_block(cap, offset, &[0; 512]).unwrap_err();
            assert_eq!(err.certainty(), MutationCertainty::NotSubmitted);
            assert_eq!(*err.error(), Error::OutOfRange);
        }
        for (device, incarnation) in [(1, 8), (2, 7)] {
            let session = DeviceSession::new(DeviceId::new(device).unwrap(), incarnation).unwrap();
            let wrong = unsafe { BlockRangeProvisioner::new(session, 100, 4) }
                .unwrap()
                .derive(0, 4)
                .unwrap();
            assert_eq!(
                h.write_block(wrong, 0, &[0; 512]),
                Err(MutationFailure::not_submitted(Error::WrongAuthority))
            );
        }
        h.card.as_mut().unwrap().csd[3] = 1 << 12;
        assert_eq!(
            h.write_block(cap, 0, &[0; 512]),
            Err(MutationFailure::not_submitted(Error::WriteProtected))
        );
        assert_eq!(h.io.writes, 0);
    }
    #[test]
    fn post_submission_errors_are_ambiguous_and_quarantine_host() {
        for kind in 0..5 {
            let (mut h, cap) = setup();
            match kind {
                0 => h.io.command_timeout = true,
                1 => {
                    h.io.early_done = true;
                    h.io.data_error = DATA_CRC;
                }
                2 => h.io.early_done = true,
                3 => h.io.busy = true,
                _ => h.io.status_error = true,
            }
            let err = h.write_block(cap, 0, &[0; 512]).unwrap_err();
            assert_eq!(err.certainty(), MutationCertainty::Ambiguous);
            assert!(h.card().is_none() && h.session().is_none());
            assert_eq!(
                h.write_block(cap, 0, &[0; 512]),
                Err(MutationFailure::not_submitted(Error::NotReady))
            );
        }
    }
    #[test]
    fn controller_busy_before_command_is_not_submitted() {
        let (mut h, cap) = setup();
        h.io.regs[STS / 4] = 3;
        let err = h.write_block(cap, 0, &[0; 512]).unwrap_err();
        assert_eq!(err.certainty(), MutationCertainty::NotSubmitted);
        assert_eq!(h.io.published_lba, None);
    }
}
