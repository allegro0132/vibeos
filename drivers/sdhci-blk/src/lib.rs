#![no_std]

//! Conservative SDHCI PIO block driver for the CV1800B SDIO0 controller.
//!
//! This crate owns SoC clock/pad/power setup, SD card discovery and the SDHCI
//! command/data path. It intentionally implements one-bit, 25 MHz PIO only:
//! no device-visible DMA address is ever published.

use vibeos_hal::SdhciDescription;

const SECTOR_SIZE: usize = 512;
const POLL_BUDGET: usize = 5_000_000;

/// Wall-clock deadline for command/data waits, in seconds of the caller's
/// timebase. Iteration budgets are the wrong unit here: an SD card performing
/// internal garbage collection may legitimately stall a write for over a
/// second, and a spin-count budget of a fraction of that converts routine
/// card housekeeping into spurious TimedOut failures under sustained load.
const WAIT_DEADLINE_SECONDS: u64 = 10;

const BLOCK_SIZE: usize = 0x04;
const HOST_CONTROL: usize = 0x28;
const BLOCK_GAP_CONTROL: usize = 0x2a;
const HOST_CONTROL2: usize = 0x3e;
const BLOCK_COUNT: usize = 0x06;
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
const INT_ALL: u32 = u32::MAX;

const CMD_RESP_NONE: u16 = 0;
const CMD_RESP_136: u16 = 1;
const CMD_RESP_48: u16 = 2;
const CMD_RESP_48_BUSY: u16 = 3;
const CMD_CRC: u16 = 1 << 3;
const CMD_INDEX: u16 = 1 << 4;
const CMD_DATA: u16 = 1 << 5;
const CMD_TYPE_ABORT: u16 = 3 << 6;

const SRST_CMD: u8 = 1 << 1;
const SRST_DAT: u8 = 1 << 2;

/// Poll budget for the best-effort abort sequence after a failed data
/// transfer. Deliberately much smaller than [`POLL_BUDGET`]: the abort runs on
/// a path that has already timed out once, and CMD12 plus a CMD/DAT line reset
/// complete in microseconds on a live controller.
const ABORT_POLL_BUDGET: usize = 100_000;

// TRANSFER_MODE bits used by the multi-block PIO path. Block Count Enable
// tells the controller to honor `BLOCK_COUNT`; Auto CMD12 Enable makes the
// controller issue CMD12 (STOP_TRANSMISSION) itself after the last block, so
// the PIO drain loop below never has to race a manually issued stop command
// against the controller's own end-of-transfer bookkeeping.
const TM_BLOCK_COUNT_ENABLE: u16 = 1 << 1;
const TM_AUTO_CMD12_ENABLE: u16 = 1 << 2;
const TM_READ: u16 = 1 << 4;
const TM_MULTI_BLOCK: u16 = 1 << 5;

/// Largest single multi-block PIO transfer this driver will issue. Bounded
/// well under the 16-bit `BLOCK_COUNT` register limit so one request cannot
/// monopolize the controller (and this hart, since transfers are
/// synchronous/PIO) for an unbounded real-time duration.
pub const MAX_TRANSFER_BLOCKS: u32 = 256;

/// Blind burst size that is always safe: one 4 KiB page, hardware-verified
/// by read-back against the controller FIFO. Larger blind bursts are legal
/// (up to [`MAX_TRANSFER_BLOCKS`]) but must be qualified by the caller with
/// its own read-back before being trusted, since a FIFO overflow would
/// corrupt data silently.
pub const SAFE_BLIND_WRITE_BLOCKS: u32 = 8;

/// SDMA buffer-boundary field of `BLOCK_SIZE` pinned to its maximum, matching
/// the Linux sdhci PIO path (`SDHCI_MAKE_BLKSZ(7, ...)`). PIO transfers should
/// ignore it, but the CV1800B integration has not been proven to.
const BLOCK_SIZE_BOUNDARY: u16 = 7 << 12;

/// How a multi-block write publishes and terminates its CMD25 transfer.
/// The CV1800B's WRITE_MULTIPLE path is not yet proven on hardware, so the
/// kernel ladder can try each protocol shape in turn and lock onto the one
/// the controller actually completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiBlockWriteMode {
    /// Block Count Enable + Auto CMD12 (the standard SDHCI shape).
    AutoCmd12,
    /// Block Count Enable, then a manually issued CMD12 after
    /// TRANSFER_COMPLETE.
    ManualCmd12,
    /// Open-ended CMD25 (no Block Count Enable); CMD12 ends the transfer.
    OpenEnded,
    /// CMD23 (SET_BLOCK_COUNT) immediately before a Block Count Enable CMD25;
    /// the card stops by itself and no CMD12 is sent.
    SetBlockCount,
    /// Auto CMD12 shape, but the data feed does not require the (observed
    /// broken) buffer-write-ready signal: each block waits for it briefly and
    /// is then pushed regardless. TRANSFER_COMPLETE and the caller's
    /// read-back verification judge whether the data actually landed.
    BlindPio,
}

const PINMUX_OFFSET: usize = 0x1000;
const CLKGEN_OFFSET: usize = 0x2000;
const TOP_SD_PWRSW_CTRL: usize = 0x1f4;
const CLK_ENABLE_0: usize = CLKGEN_OFFSET;
const CLK_BYPASS_0: usize = CLKGEN_OFFSET + 0x30;
const CLK_DIV_SD0: usize = CLKGEN_OFFSET + 0x70;
const SD0_CLOCKS: u32 = (1 << 18) | (1 << 19) | (1 << 20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    OutOfRange,
    TimedOut,
    DeviceIo,
    Unsupported,
    Protocol,
    InvalidConfiguration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardInfo {
    pub capacity_sectors: u64,
    pub high_capacity: bool,
}

/// An initialized card and its exclusively owned SDHCI controller.
pub struct Card {
    description: SdhciDescription,
    timebase_hz: u64,
    time: fn() -> u64,
    rca: u16,
    high_capacity: bool,
    capacity_sectors: u64,
    last_command: u8,
    last_interrupt_status: u32,
}

impl Card {
    /// Initialize the described CV1800B SDIO0 controller and attached card.
    ///
    /// # Safety
    /// `description.registers` and `description.soc_control` must be mapped,
    /// writable MMIO ranges for the CV1800B SDIO0 instance and its TOP block.
    /// The caller must hold exclusive ownership of both ranges for the full
    /// lifetime of the returned card. `time` must be a monotonic counter at
    /// `timebase_hz`, and the ranges must remain identity mapped and strongly
    /// ordered while any method on the card is executing.
    pub unsafe fn initialize(
        description: SdhciDescription,
        timebase_hz: u64,
        time: fn() -> u64,
    ) -> Result<Self, Error> {
        validate_description(description, timebase_hz)?;
        let mut card = Self {
            description,
            timebase_hz,
            time,
            rca: 0,
            high_capacity: false,
            capacity_sectors: 0,
            last_command: 0,
            last_interrupt_status: 0,
        };
        card.prepare_soc_hardware();
        card.reset_host()?;
        card.set_clock(description.init_clock_hz)?;
        card.write8(POWER_CONTROL, 0x0f);
        card.power_on_card();
        card.write8(TIMEOUT_CONTROL, 0x0e);
        card.write32(INT_ENABLE, INT_ALL);
        card.write32(SIGNAL_ENABLE, 0);

        card.command(0, 0, CMD_RESP_NONE)?;
        let cmd8 = card.command(8, 0x1aa, CMD_RESP_48 | CMD_CRC | CMD_INDEX)?;
        if cmd8[0] & 0xfff != 0x1aa {
            return Err(Error::Unsupported);
        }

        let mut ocr = 0;
        for _ in 0..10_000 {
            card.command(55, 0, CMD_RESP_48 | CMD_CRC | CMD_INDEX)?;
            ocr = card.command(41, 0x40ff_8000, CMD_RESP_48)?[0];
            if ocr & (1 << 31) != 0 {
                break;
            }
        }
        if ocr & (1 << 31) == 0 {
            return Err(Error::TimedOut);
        }
        card.high_capacity = ocr & (1 << 30) != 0;
        card.command(2, 0, CMD_RESP_136 | CMD_CRC)?;
        let rca_response = card.command(3, 0, CMD_RESP_48 | CMD_CRC | CMD_INDEX)?[0];
        card.rca = (rca_response >> 16) as u16;
        if card.rca == 0 {
            return Err(Error::Protocol);
        }
        let csd = card.command(9, u32::from(card.rca) << 16, CMD_RESP_136 | CMD_CRC)?;
        card.capacity_sectors = capacity_from_csd(csd)?;
        card.command(
            7,
            u32::from(card.rca) << 16,
            CMD_RESP_48_BUSY | CMD_CRC | CMD_INDEX,
        )?;
        if !card.high_capacity {
            card.command(16, SECTOR_SIZE as u32, CMD_RESP_48 | CMD_CRC | CMD_INDEX)?;
        }
        card.set_clock(description.data_clock_hz)?;
        Ok(card)
    }

    pub const fn info(&self) -> CardInfo {
        CardInfo {
            capacity_sectors: self.capacity_sectors,
            high_capacity: self.high_capacity,
        }
    }

    pub const fn irq(&self) -> u32 {
        self.description.irq
    }
    pub const fn last_command(&self) -> u8 {
        self.last_command
    }
    pub const fn last_interrupt_status(&self) -> u32 {
        self.last_interrupt_status
    }
    pub fn present_state(&self) -> u32 {
        self.read32(PRESENT_STATE)
    }

    pub fn read_sector(&mut self, physical_sector: u64) -> Result<[u8; 512], Error> {
        validate_sector(self.capacity_sectors, physical_sector)?;
        self.wait_inhibit(true)?;
        self.last_command = 17;
        self.last_interrupt_status = 0;
        self.clear_interrupts();
        self.write16(BLOCK_SIZE, SECTOR_SIZE as u16);
        self.write32(
            ARGUMENT,
            sector_argument(self.high_capacity, physical_sector)?,
        );
        self.write16(TRANSFER_MODE, 1 << 4);
        self.write16(
            COMMAND,
            command_word(17, CMD_RESP_48 | CMD_CRC | CMD_INDEX | CMD_DATA),
        );
        let mut data = [0u8; SECTOR_SIZE];
        self.complete_read_transfer(&mut data)?;
        Ok(data)
    }

    pub fn write_sector(&mut self, physical_sector: u64, data: &[u8; 512]) -> Result<(), Error> {
        self.write_sector_tracked(physical_sector, data, || {})
    }

    /// Write one sector and report the exact point at which CMD24 is
    /// published to the controller.
    ///
    /// `on_command_published` runs after all request validation and the
    /// command/data inhibit wait have succeeded, immediately before the
    /// volatile store to the SDHCI `COMMAND` register. Once the callback has
    /// run, an error from this method must therefore be treated as potentially
    /// having changed the card.
    pub fn write_sector_tracked(
        &mut self,
        physical_sector: u64,
        data: &[u8; 512],
        on_command_published: impl FnOnce(),
    ) -> Result<(), Error> {
        validate_sector(self.capacity_sectors, physical_sector)?;
        self.wait_inhibit(true)?;
        self.last_command = 24;
        self.last_interrupt_status = 0;
        self.clear_interrupts();
        self.write16(BLOCK_SIZE, SECTOR_SIZE as u16);
        self.write32(
            ARGUMENT,
            sector_argument(self.high_capacity, physical_sector)?,
        );
        self.write16(TRANSFER_MODE, 0);
        self.publish_command(
            command_word(24, CMD_RESP_48 | CMD_CRC | CMD_INDEX | CMD_DATA),
            on_command_published,
        );
        self.complete_write_transfer(data)?;
        self.flush()
    }

    /// Read `output.len() / 512` contiguous sectors starting at
    /// `physical_sector` in one CMD18 (READ_MULTIPLE_BLOCK) transfer, falling
    /// back to the single-sector CMD17 path for exactly one block.
    ///
    /// `output.len()` must be a positive, exact multiple of 512 bytes and
    /// resolve to at most [`MAX_TRANSFER_BLOCKS`] blocks.
    pub fn read_blocks(&mut self, physical_sector: u64, output: &mut [u8]) -> Result<(), Error> {
        let block_count = validate_block_range(self.capacity_sectors, physical_sector, output.len())?;
        if block_count == 1 {
            output.copy_from_slice(&self.read_sector(physical_sector)?);
            return Ok(());
        }
        self.wait_inhibit(true)?;
        self.last_command = 18;
        self.last_interrupt_status = 0;
        self.clear_interrupts();
        self.write16(BLOCK_SIZE, SECTOR_SIZE as u16);
        self.write16(BLOCK_COUNT, block_count);
        self.write32(
            ARGUMENT,
            sector_argument(self.high_capacity, physical_sector)?,
        );
        self.write16(
            TRANSFER_MODE,
            TM_BLOCK_COUNT_ENABLE | TM_AUTO_CMD12_ENABLE | TM_MULTI_BLOCK | TM_READ,
        );
        self.write16(
            COMMAND,
            command_word(18, CMD_RESP_48 | CMD_CRC | CMD_INDEX | CMD_DATA),
        );
        self.complete_read_transfer(output)
    }

    /// Write `data.len() / 512` contiguous sectors starting at
    /// `physical_sector` in one CMD25 (WRITE_MULTIPLE_BLOCK) transfer.
    pub fn write_blocks(&mut self, physical_sector: u64, data: &[u8]) -> Result<(), Error> {
        self.write_blocks_tracked(physical_sector, data, || {})
    }

    /// Write multiple sectors and report the exact point at which CMD25 (or,
    /// for exactly one block, CMD24) is published to the controller. See
    /// [`Self::write_sector_tracked`] for the ambiguous-mutation contract.
    pub fn write_blocks_tracked(
        &mut self,
        physical_sector: u64,
        data: &[u8],
        on_command_published: impl FnOnce(),
    ) -> Result<(), Error> {
        self.write_blocks_tracked_with_mode(
            physical_sector,
            data,
            MultiBlockWriteMode::AutoCmd12,
            on_command_published,
        )
    }

    /// As [`Self::write_blocks_tracked`], but with an explicit CMD25 protocol
    /// shape so a caller can probe which termination scheme this controller
    /// actually completes. Exactly one block still uses CMD24.
    pub fn write_blocks_tracked_with_mode(
        &mut self,
        physical_sector: u64,
        data: &[u8],
        mode: MultiBlockWriteMode,
        on_command_published: impl FnOnce(),
    ) -> Result<(), Error> {
        let block_count = validate_block_range(self.capacity_sectors, physical_sector, data.len())?;
        if block_count == 1 {
            let mut sector = [0u8; SECTOR_SIZE];
            sector.copy_from_slice(data);
            return self.write_sector_tracked(physical_sector, &sector, on_command_published);
        }
        self.wait_inhibit(true)?;
        // Every observed CMD25 stall on the CV1800B shows "no buffer space"
        // (PRESENT_STATE bit 10 clear) before any data was written, while
        // CMD24 succeeds whenever a CMD/DAT software reset happened to run
        // first. Clear the data path so the write FIFO accounting starts
        // from a known-empty state.
        self.reset_command_and_data_lines();
        self.wait_inhibit(true)?;
        if mode == MultiBlockWriteMode::SetBlockCount {
            self.command(23, u32::from(block_count), CMD_RESP_48 | CMD_CRC | CMD_INDEX)?;
            self.wait_inhibit(true)?;
        }
        self.last_command = 25;
        self.last_interrupt_status = 0;
        self.clear_interrupts();
        self.write16(BLOCK_SIZE, BLOCK_SIZE_BOUNDARY | SECTOR_SIZE as u16);
        let transfer_mode = match mode {
            MultiBlockWriteMode::AutoCmd12 | MultiBlockWriteMode::BlindPio => {
                TM_BLOCK_COUNT_ENABLE | TM_AUTO_CMD12_ENABLE | TM_MULTI_BLOCK
            }
            MultiBlockWriteMode::ManualCmd12 | MultiBlockWriteMode::SetBlockCount => {
                TM_BLOCK_COUNT_ENABLE | TM_MULTI_BLOCK
            }
            MultiBlockWriteMode::OpenEnded => TM_MULTI_BLOCK,
        };
        if transfer_mode & TM_BLOCK_COUNT_ENABLE != 0 {
            self.write16(BLOCK_COUNT, block_count);
        }
        self.write32(
            ARGUMENT,
            sector_argument(self.high_capacity, physical_sector)?,
        );
        self.write16(TRANSFER_MODE, transfer_mode);
        self.publish_command(
            command_word(25, CMD_RESP_48 | CMD_CRC | CMD_INDEX | CMD_DATA),
            on_command_published,
        );
        let result = self.terminate_write_transfer(data, mode);
        if result.is_err() {
            self.abort_data_transfer();
        }
        // Deliberately no CMD13 flush here, unlike the single-sector path:
        // durability barriers are the storage contract's explicit Flush
        // operation, and waiting out the card's programming after every
        // burst serializes its internal pipeline. The next command's
        // inhibit wait already honors a still-busy card.
        result
    }

    fn terminate_write_transfer(
        &mut self,
        data: &[u8],
        mode: MultiBlockWriteMode,
    ) -> Result<(), Error> {
        match mode {
            MultiBlockWriteMode::BlindPio => self.feed_write_blocks_blind(data)?,
            _ => self.feed_write_blocks(data)?,
        }
        match mode {
            MultiBlockWriteMode::OpenEnded => {
                self.stop_transmission()?;
                self.wait_transfer_complete()
            }
            MultiBlockWriteMode::ManualCmd12 => {
                self.wait_transfer_complete()?;
                self.command(12, 0, CMD_RESP_48_BUSY | CMD_CRC | CMD_INDEX)
                    .map(|_| ())
            }
            MultiBlockWriteMode::AutoCmd12
            | MultiBlockWriteMode::SetBlockCount
            | MultiBlockWriteMode::BlindPio => self.wait_transfer_complete(),
        }
    }

    /// Feed write data around this integration's buffer-write-ready defect:
    /// the signal never fires for an empty FIFO (so the transfer start sees
    /// no edge), but does fire on every full-to-space transition once the
    /// FIFO has been saturated. The first [`SAFE_BLIND_WRITE_BLOCKS`] blocks
    /// (hardware-verified to fit the FIFO) are therefore pushed blind, and
    /// every later block strictly waits for the now-live ready signal — real
    /// flow control, so card throttling back-pressures the feed instead of
    /// overflowing the FIFO. Callers still qualify each larger burst size by
    /// read-back before trusting it.
    fn feed_write_blocks_blind(&mut self, data: &[u8]) -> Result<(), Error> {
        for (index, chunk) in data.chunks_exact(SECTOR_SIZE).enumerate() {
            if index >= SAFE_BLIND_WRITE_BLOCKS as usize {
                self.wait_interrupt(INT_BUFFER_WRITE_READY)?;
            }
            for word in chunk.chunks_exact(4) {
                self.write32(
                    BUFFER,
                    u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
                );
            }
            self.write32(INT_STATUS, INT_BUFFER_WRITE_READY);
        }
        Ok(())
    }

    /// Software-reset the CMD and DAT state machines (clearing the shared
    /// data FIFO) while the bus is idle. Best-effort: on live hardware the
    /// bits self-clear within microseconds, and a controller that cannot
    /// complete the reset will fail the next interrupt wait loudly anyway.
    fn reset_command_and_data_lines(&self) {
        self.write8(SOFTWARE_RESET, SRST_CMD | SRST_DAT);
        let _ = self.poll_until_with_budget(ABORT_POLL_BUDGET, || {
            self.read8(SOFTWARE_RESET) & (SRST_CMD | SRST_DAT) == 0
        });
    }

    /// Publish CMD12 as an SDHCI abort-class command while a data transfer is
    /// still active: only the command inhibit is awaited, because the DAT
    /// lines legitimately stay busy until the card processes the stop.
    fn stop_transmission(&mut self) -> Result<(), Error> {
        self.poll_until(|| self.read32(PRESENT_STATE) & 1 == 0)?;
        self.write32(ARGUMENT, 0);
        self.write16(
            COMMAND,
            command_word(12, CMD_RESP_48_BUSY | CMD_CRC | CMD_INDEX) | CMD_TYPE_ABORT,
        );
        self.wait_interrupt(INT_COMMAND_COMPLETE)?;
        self.write32(INT_STATUS, INT_COMMAND_COMPLETE);
        Ok(())
    }

    /// Diagnostic-only probe for the untested CMD18 (READ_MULTIPLE_BLOCK)
    /// path. Unlike [`Self::read_blocks`] (which this driver's production
    /// callers never invoke), this always issues a genuine multi-block
    /// transfer — no single-block fallback — so it exercises exactly the
    /// register sequence a real batched read would use.
    ///
    /// Uses a caller-supplied `poll_budget` instead of the production
    /// [`POLL_BUDGET`], so a controller that stops asserting
    /// `BUFFER_READ_READY` after the first block reports back in a bounded,
    /// short amount of time instead of spinning for the production budget on
    /// every remaining block. Returns the number of blocks whose data was
    /// successfully drained before any error (or all of them, on success)
    /// alongside the terminal result, so a caller can tell exactly where a
    /// stuck transfer stopped making progress.
    ///
    /// This method is never called by any automatic boot or I/O path in this
    /// workspace; it exists solely for a human to invoke once, interactively,
    /// from a diagnostic shell while watching the result.
    pub fn diagnostic_probe_multiblock_read(
        &mut self,
        physical_sector: u64,
        output: &mut [u8],
        poll_budget: usize,
    ) -> (usize, Result<(), Error>) {
        let block_count =
            match validate_block_range(self.capacity_sectors, physical_sector, output.len()) {
                Ok(block_count) => block_count,
                Err(error) => return (0, Err(error)),
            };
        if let Err(error) = self.wait_inhibit_with_budget(true, poll_budget) {
            return (0, Err(error));
        }
        self.last_command = 18;
        self.last_interrupt_status = 0;
        self.clear_interrupts();
        self.write16(BLOCK_SIZE, SECTOR_SIZE as u16);
        self.write16(BLOCK_COUNT, block_count);
        let argument = match sector_argument(self.high_capacity, physical_sector) {
            Ok(argument) => argument,
            Err(error) => return (0, Err(error)),
        };
        self.write32(ARGUMENT, argument);
        self.write16(
            TRANSFER_MODE,
            TM_BLOCK_COUNT_ENABLE | TM_AUTO_CMD12_ENABLE | TM_MULTI_BLOCK | TM_READ,
        );
        self.write16(
            COMMAND,
            command_word(18, CMD_RESP_48 | CMD_CRC | CMD_INDEX | CMD_DATA),
        );
        let mut completed = 0usize;
        for chunk in output.chunks_exact_mut(SECTOR_SIZE) {
            if let Err(error) = self.wait_interrupt_with_budget(INT_BUFFER_READ_READY, poll_budget) {
                self.abort_data_transfer();
                return (completed, Err(error));
            }
            for word in chunk.chunks_exact_mut(4) {
                word.copy_from_slice(&self.read32(BUFFER).to_le_bytes());
            }
            self.write32(INT_STATUS, INT_BUFFER_READ_READY);
            completed += 1;
        }
        if let Err(error) = self.wait_interrupt_with_budget(INT_TRANSFER_COMPLETE, poll_budget) {
            self.abort_data_transfer();
            return (completed, Err(error));
        }
        self.write32(INT_STATUS, INT_TRANSFER_COMPLETE);
        (completed, Ok(()))
    }

    /// Drain a published read data command and clear its completion, aborting
    /// the transfer if the controller stops making progress. Handles both the
    /// single-sector CMD17 case (`output` is one sector) and CMD18.
    fn complete_read_transfer(&mut self, output: &mut [u8]) -> Result<(), Error> {
        let result = (|| {
            for chunk in output.chunks_exact_mut(SECTOR_SIZE) {
                self.wait_interrupt(INT_BUFFER_READ_READY)?;
                for word in chunk.chunks_exact_mut(4) {
                    word.copy_from_slice(&self.read32(BUFFER).to_le_bytes());
                }
                self.write32(INT_STATUS, INT_BUFFER_READ_READY);
            }
            self.wait_interrupt(INT_TRANSFER_COMPLETE)?;
            self.write32(INT_STATUS, INT_TRANSFER_COMPLETE);
            Ok(())
        })();
        if result.is_err() {
            self.abort_data_transfer();
        }
        result
    }

    /// Feed a published write data command and clear its completion, aborting
    /// the transfer if the controller stops making progress. Handles both the
    /// single-sector CMD24 case (`data` is one sector) and CMD25.
    fn complete_write_transfer(&mut self, data: &[u8]) -> Result<(), Error> {
        let result = self
            .feed_write_blocks(data)
            .and_then(|()| self.wait_transfer_complete());
        if result.is_err() {
            self.abort_data_transfer();
        }
        result
    }

    fn feed_write_blocks(&mut self, data: &[u8]) -> Result<(), Error> {
        for chunk in data.chunks_exact(SECTOR_SIZE) {
            self.wait_interrupt(INT_BUFFER_WRITE_READY)?;
            for word in chunk.chunks_exact(4) {
                self.write32(
                    BUFFER,
                    u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
                );
            }
            self.write32(INT_STATUS, INT_BUFFER_WRITE_READY);
        }
        Ok(())
    }

    fn wait_transfer_complete(&mut self) -> Result<(), Error> {
        self.wait_interrupt(INT_TRANSFER_COMPLETE)?;
        self.write32(INT_STATUS, INT_TRANSFER_COMPLETE);
        Ok(())
    }

    /// Best-effort recovery after a data transfer failed mid-flight: publish
    /// CMD12 (STOP_TRANSMISSION) as an SDHCI abort command so the card leaves
    /// its data state, then software-reset the controller's CMD and DAT lines.
    ///
    /// Without this, a card abandoned mid CMD18/CMD25 keeps driving the data
    /// lines and can stay unreachable across a warm reboot — the card is not
    /// power-cycled by a SoC reset, so even the boot ROM's next attempt to
    /// load the FSBL from it can fail. Errors here are deliberately swallowed:
    /// this path only runs after a primary failure, and the caller's error is
    /// the one worth reporting. The pre-abort `last_command` and
    /// `last_interrupt_status` diagnostics are preserved for that reason.
    fn abort_data_transfer(&mut self) {
        let failed_command = self.last_command;
        let failed_interrupt_status = self.last_interrupt_status;
        // Clear a stuck command inhibit first so the CMD12 store below is not
        // ignored by a controller still executing the failed command.
        self.write8(SOFTWARE_RESET, SRST_CMD);
        let _ = self.poll_until_with_budget(ABORT_POLL_BUDGET, || {
            self.read8(SOFTWARE_RESET) & SRST_CMD == 0
        });
        self.clear_interrupts();
        self.write32(ARGUMENT, 0);
        self.write16(TRANSFER_MODE, 0);
        self.write16(
            COMMAND,
            command_word(12, CMD_RESP_48_BUSY | CMD_CRC | CMD_INDEX) | CMD_TYPE_ABORT,
        );
        let _ = self.wait_interrupt_with_budget(INT_COMMAND_COMPLETE, ABORT_POLL_BUDGET);
        self.write8(SOFTWARE_RESET, SRST_CMD | SRST_DAT);
        let _ = self.poll_until_with_budget(ABORT_POLL_BUDGET, || {
            self.read8(SOFTWARE_RESET) & (SRST_CMD | SRST_DAT) == 0
        });
        self.clear_interrupts();
        self.last_command = failed_command;
        self.last_interrupt_status = failed_interrupt_status;
    }

    /// First response word of the most recent command (the R1 card status for
    /// CMD25), for stall diagnostics.
    pub fn response_word(&self) -> u32 {
        self.read32(RESPONSE)
    }

    /// Switch the card (ACMD6) and host to 4-bit bus width. On failure the
    /// bus is left in its previous 1-bit state.
    pub fn enable_four_bit_bus(&mut self) -> Result<(), Error> {
        self.command(55, u32::from(self.rca) << 16, CMD_RESP_48 | CMD_CRC | CMD_INDEX)?;
        self.command(6, 2, CMD_RESP_48 | CMD_CRC | CMD_INDEX)?;
        self.write8(HOST_CONTROL, self.read8(HOST_CONTROL) | (1 << 1));
        Ok(())
    }

    /// Best-effort return to the proven 1-bit bus: the card is switched back
    /// first (while the host still matches), then the host.
    pub fn disable_four_bit_bus(&mut self) {
        let _ = self.command(55, u32::from(self.rca) << 16, CMD_RESP_48 | CMD_CRC | CMD_INDEX);
        let _ = self.command(6, 0, CMD_RESP_48 | CMD_CRC | CMD_INDEX);
        self.write8(HOST_CONTROL, self.read8(HOST_CONTROL) & !(1 << 1));
    }

    /// Raw host-state registers relevant to the unexplained CMD25 stall, for
    /// bounded one-line UART diagnostics from the kernel.
    pub fn diagnostic_host_state(&self) -> [u32; 6] {
        [
            u32::from(self.read8(HOST_CONTROL)),
            u32::from(self.read8(BLOCK_GAP_CONTROL)),
            u32::from(self.read16(HOST_CONTROL2)),
            self.read32(VENDOR_CTRL),
            self.read32(PHY_TX_RX_DELAY),
            self.read32(PHY_CONFIG),
        ]
    }

    /// Host-side workarounds for the observed "CMD25 accepted but the write
    /// data phase never starts" stall: clear any stop-at-block-gap request
    /// left by earlier firmware and disable the vendor controller's automatic
    /// card-clock gating (`MSHC_CTRL` bit 0, the same bit the vendor tuning
    /// loop sets before it streams tuning blocks).
    pub fn apply_write_stall_workarounds(&mut self) {
        self.write8(BLOCK_GAP_CONTROL, 0);
        self.write32(VENDOR_CTRL, self.read32(VENDOR_CTRL) | 1);
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        self.flush_tracked(|| {})
    }

    /// Wait for the card to become ready and report when the first CMD13 is
    /// published to the controller.
    ///
    /// The callback runs exactly once, immediately before the first volatile
    /// `COMMAND` register store. It is not run when the pre-command inhibit
    /// wait fails. Further CMD13 polls do not invoke it again: after the first
    /// publication the flush request has already crossed its submission
    /// boundary.
    pub fn flush_tracked(&mut self, on_command_published: impl FnOnce()) -> Result<(), Error> {
        let mut on_command_published = Some(on_command_published);
        for _ in 0..10_000 {
            let argument = u32::from(self.rca) << 16;
            let flags = CMD_RESP_48 | CMD_CRC | CMD_INDEX;
            let status = if let Some(on_command_published) = on_command_published.take() {
                self.command_tracked(13, argument, flags, on_command_published)?[0]
            } else {
                self.command(13, argument, flags)?[0]
            };
            if status & (1 << 8) != 0 && (status >> 9) & 0xf == 4 {
                return Ok(());
            }
        }
        Err(Error::TimedOut)
    }

    fn prepare_soc_hardware(&self) {
        self.soc_write32(CLK_ENABLE_0, self.soc_read32(CLK_ENABLE_0) | SD0_CLOCKS);
        self.soc_write32(CLK_BYPASS_0, self.soc_read32(CLK_BYPASS_0) & !(1 << 6));
        self.soc_write32(CLK_DIV_SD0, 0x0004_0009);
        self.write8(POWER_CONTROL, 0);
        self.set_sd_pad_function(3);
        self.set_sd_pad_bias(false);
        self.soc_write32(
            TOP_SD_PWRSW_CTRL,
            (self.soc_read32(TOP_SD_PWRSW_CTRL) & !0xf) | 0xe,
        );
        self.delay_ms(30);
    }

    fn power_on_card(&self) {
        self.soc_write32(
            TOP_SD_PWRSW_CTRL,
            (self.soc_read32(TOP_SD_PWRSW_CTRL) & !0xf) | 0x9,
        );
        self.delay_ms(1);
        self.set_sd_pad_function(0);
        self.set_sd_pad_bias(true);
        self.delay_ms(5);
    }

    fn set_sd_pad_function(&self, function: u8) {
        self.soc_write8(PINMUX_OFFSET + 0x18, 0);
        self.soc_write8(PINMUX_OFFSET + 0x1c, 0);
        for offset in [0x00, 0x04, 0x08, 0x0c, 0x10, 0x14] {
            self.soc_write8(PINMUX_OFFSET + offset, function);
        }
    }

    fn set_sd_pad_bias(&self, online: bool) {
        self.set_pad_pull(PINMUX_OFFSET + 0x900, true);
        self.set_pad_pull(PINMUX_OFFSET + 0x904, false);
        self.set_pad_pull(PINMUX_OFFSET + 0xa00, false);
        for offset in [0xa04, 0xa08, 0xa0c, 0xa10, 0xa14] {
            self.set_pad_pull(PINMUX_OFFSET + offset, online);
        }
    }

    fn set_pad_pull(&self, offset: usize, pull_up: bool) {
        let mut value = self.soc_read8(offset) & !((1 << 2) | (1 << 3));
        value |= if pull_up { 1 << 2 } else { 1 << 3 };
        self.soc_write8(offset, value);
    }

    fn delay_ms(&self, milliseconds: u64) {
        let ticks = milliseconds.saturating_mul(self.timebase_hz) / 1_000;
        let deadline = (self.time)().saturating_add(ticks);
        while (self.time)() < deadline {
            core::hint::spin_loop();
        }
    }

    fn reset_host(&self) -> Result<(), Error> {
        self.write32(SIGNAL_ENABLE, 0);
        self.write32(INT_ENABLE, 0);
        self.write8(SOFTWARE_RESET, 1);
        self.poll_until(|| self.read8(SOFTWARE_RESET) & 1 == 0)?;
        self.write32(
            VENDOR_CTRL,
            self.read32(VENDOR_CTRL) | (1 << 1) | (1 << 8) | (1 << 9),
        );
        self.write32(PHY_CONFIG, self.read32(PHY_CONFIG) | 1);
        self.write32(PHY_TX_RX_DELAY, 0x0100_0100);
        Ok(())
    }

    fn set_clock(&self, target: u32) -> Result<(), Error> {
        let encoded = encode_clock_divisor(self.description.source_clock_hz, target)?;
        self.write16(CLOCK_CONTROL, 0);
        self.write16(CLOCK_CONTROL, encoded | 1);
        self.poll_until(|| self.read16(CLOCK_CONTROL) & 2 != 0)?;
        self.write16(CLOCK_CONTROL, encoded | 1 | 4);
        Ok(())
    }

    fn command(&mut self, index: u8, argument: u32, flags: u16) -> Result<[u32; 4], Error> {
        self.command_tracked(index, argument, flags, || {})
    }

    fn command_tracked(
        &mut self,
        index: u8,
        argument: u32,
        flags: u16,
        on_command_published: impl FnOnce(),
    ) -> Result<[u32; 4], Error> {
        self.wait_inhibit(flags & CMD_DATA != 0 || flags & 3 == CMD_RESP_48_BUSY)?;
        self.last_command = index;
        self.last_interrupt_status = 0;
        self.clear_interrupts();
        self.write32(ARGUMENT, argument);
        self.write16(TRANSFER_MODE, 0);
        self.publish_command(command_word(index, flags), on_command_published);
        self.wait_interrupt(INT_COMMAND_COMPLETE)?;
        self.write32(INT_STATUS, INT_COMMAND_COMPLETE);
        if flags & 3 == CMD_RESP_136 {
            Ok([
                (self.read32(RESPONSE + 12) << 8) | u32::from(self.read8(RESPONSE + 11)),
                (self.read32(RESPONSE + 8) << 8) | u32::from(self.read8(RESPONSE + 7)),
                (self.read32(RESPONSE + 4) << 8) | u32::from(self.read8(RESPONSE + 3)),
                self.read32(RESPONSE) << 8,
            ])
        } else {
            Ok([self.read32(RESPONSE), 0, 0, 0])
        }
    }

    #[inline]
    fn publish_command(&self, command: u16, on_command_published: impl FnOnce()) {
        on_command_published();
        self.write16(COMMAND, command);
    }

    fn wait_inhibit(&self, data: bool) -> Result<(), Error> {
        let mask = if data { 3 } else { 1 };
        let deadline = self.wait_deadline();
        loop {
            if self.read32(PRESENT_STATE) & mask == 0 {
                return Ok(());
            }
            if (self.time)() >= deadline {
                return Err(Error::TimedOut);
            }
            core::hint::spin_loop();
        }
    }

    fn wait_deadline(&self) -> u64 {
        (self.time)().saturating_add(WAIT_DEADLINE_SECONDS.saturating_mul(self.timebase_hz))
    }

    fn wait_inhibit_with_budget(&self, data: bool, budget: usize) -> Result<(), Error> {
        let mask = if data { 3 } else { 1 };
        self.poll_until_with_budget(budget, || self.read32(PRESENT_STATE) & mask == 0)
    }

    fn wait_interrupt(&mut self, mask: u32) -> Result<(), Error> {
        let deadline = self.wait_deadline();
        loop {
            let status = self.read32(INT_STATUS);
            if status & INT_ERROR != 0 {
                self.last_interrupt_status = status;
                self.write32(INT_STATUS, status);
                return Err(Error::DeviceIo);
            }
            if status & mask == mask {
                return Ok(());
            }
            if (self.time)() >= deadline {
                self.last_interrupt_status = status;
                return Err(Error::TimedOut);
            }
            core::hint::spin_loop();
        }
    }

    /// As [`Self::wait_interrupt`], but polls at most `budget` times instead
    /// of the production [`POLL_BUDGET`]. Used only by the diagnostic
    /// multi-block probe so a controller that never asserts a later
    /// interrupt reports back quickly instead of spinning for the full
    /// production budget.
    fn wait_interrupt_with_budget(&mut self, mask: u32, budget: usize) -> Result<(), Error> {
        for _ in 0..budget {
            let status = self.read32(INT_STATUS);
            if status & INT_ERROR != 0 {
                self.last_interrupt_status = status;
                self.write32(INT_STATUS, status);
                return Err(Error::DeviceIo);
            }
            if status & mask == mask {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        self.last_interrupt_status = self.read32(INT_STATUS);
        Err(Error::TimedOut)
    }

    fn clear_interrupts(&self) {
        self.write32(INT_STATUS, INT_ALL);
    }
    fn poll_until(&self, ready: impl FnMut() -> bool) -> Result<(), Error> {
        self.poll_until_with_budget(POLL_BUDGET, ready)
    }
    fn poll_until_with_budget(&self, budget: usize, mut ready: impl FnMut() -> bool) -> Result<(), Error> {
        for _ in 0..budget {
            if ready() {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::TimedOut)
    }

    #[inline]
    fn address(&self, offset: usize) -> usize {
        self.description.registers.start + offset
    }
    #[inline]
    fn soc_address(&self, offset: usize) -> usize {
        self.description.soc_control.start + offset
    }
    #[inline]
    fn read8(&self, offset: usize) -> u8 {
        unsafe { (self.address(offset) as *const u8).read_volatile() }
    }
    #[inline]
    fn read16(&self, offset: usize) -> u16 {
        unsafe { (self.address(offset) as *const u16).read_volatile() }
    }
    #[inline]
    fn read32(&self, offset: usize) -> u32 {
        unsafe { (self.address(offset) as *const u32).read_volatile() }
    }
    #[inline]
    fn write8(&self, offset: usize, value: u8) {
        unsafe { (self.address(offset) as *mut u8).write_volatile(value) }
    }
    #[inline]
    fn write16(&self, offset: usize, value: u16) {
        unsafe { (self.address(offset) as *mut u16).write_volatile(value) }
    }
    #[inline]
    fn write32(&self, offset: usize, value: u32) {
        unsafe { (self.address(offset) as *mut u32).write_volatile(value) }
    }
    #[inline]
    fn soc_read8(&self, offset: usize) -> u8 {
        unsafe { (self.soc_address(offset) as *const u8).read_volatile() }
    }
    #[inline]
    fn soc_write8(&self, offset: usize, value: u8) {
        unsafe { (self.soc_address(offset) as *mut u8).write_volatile(value) }
    }
    #[inline]
    fn soc_read32(&self, offset: usize) -> u32 {
        unsafe { (self.soc_address(offset) as *const u32).read_volatile() }
    }
    #[inline]
    fn soc_write32(&self, offset: usize, value: u32) {
        unsafe { (self.soc_address(offset) as *mut u32).write_volatile(value) }
    }
}

fn validate_description(description: SdhciDescription, timebase_hz: u64) -> Result<(), Error> {
    if description.registers.len() < 0x250
        || description.soc_control.len() < 0x3000
        || description.source_clock_hz == 0
        || description.init_clock_hz == 0
        || description.data_clock_hz == 0
        || description.bus_width != 1
        || timebase_hz == 0
    {
        Err(Error::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn encode_clock_divisor(source: u32, target: u32) -> Result<u16, Error> {
    if source == 0 || target == 0 {
        return Err(Error::InvalidConfiguration);
    }
    let source = u64::from(source);
    let twice_target = u64::from(target) * 2;
    let divisor = source.div_ceil(twice_target).clamp(1, 0x3ff) as u16;
    Ok(((divisor & 0xff) << 8) | ((divisor & 0x300) >> 2))
}

fn command_word(index: u8, flags: u16) -> u16 {
    u16::from(index) << 8 | flags
}

fn sector_argument(high_capacity: bool, physical_sector: u64) -> Result<u32, Error> {
    let address = if high_capacity {
        physical_sector
    } else {
        physical_sector
            .checked_mul(SECTOR_SIZE as u64)
            .ok_or(Error::OutOfRange)?
    };
    u32::try_from(address).map_err(|_| Error::OutOfRange)
}

const fn validate_sector(capacity_sectors: u64, physical_sector: u64) -> Result<(), Error> {
    if physical_sector < capacity_sectors {
        Ok(())
    } else {
        Err(Error::OutOfRange)
    }
}

/// Validate a `byte_len`-sized transfer starting at `physical_sector` and
/// return its block count. `byte_len` must be a positive exact multiple of
/// 512 bytes, the whole range must lie within `capacity_sectors`, and the
/// block count must fit both the 16-bit `BLOCK_COUNT` register and
/// [`MAX_TRANSFER_BLOCKS`].
fn validate_block_range(
    capacity_sectors: u64,
    physical_sector: u64,
    byte_len: usize,
) -> Result<u16, Error> {
    if byte_len == 0 || byte_len % SECTOR_SIZE != 0 {
        return Err(Error::InvalidConfiguration);
    }
    let block_count = (byte_len / SECTOR_SIZE) as u64;
    if block_count > u64::from(MAX_TRANSFER_BLOCKS) {
        return Err(Error::InvalidConfiguration);
    }
    let last_sector = physical_sector
        .checked_add(block_count - 1)
        .ok_or(Error::OutOfRange)?;
    validate_sector(capacity_sectors, last_sector)?;
    Ok(block_count as u16)
}

fn capacity_from_csd(csd: [u32; 4]) -> Result<u64, Error> {
    match unstuff(csd, 126, 2) {
        1 => Ok((u64::from(unstuff(csd, 48, 22)) + 1) * 1024),
        0 => {
            let read_block_len = unstuff(csd, 80, 4);
            let size = u64::from(unstuff(csd, 62, 12)) + 1;
            let multiplier = unstuff(csd, 47, 3) + 2;
            let bytes = size
                .checked_shl(multiplier + read_block_len)
                .ok_or(Error::Unsupported)?;
            Ok(bytes / SECTOR_SIZE as u64)
        }
        _ => Err(Error::Unsupported),
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use vibeos_hal::AddressRange;

    const TEST_MMIO_WORDS: usize = 0x100;

    fn fake_card(registers: &mut [u32; TEST_MMIO_WORDS]) -> Card {
        let start = registers.as_mut_ptr() as usize;
        Card {
            description: SdhciDescription {
                registers: AddressRange::new(start, start + core::mem::size_of_val(registers)),
                irq: 0,
                // None of the command-path tests touch SoC control registers.
                soc_control: AddressRange::new(start, start + core::mem::size_of_val(registers)),
                source_clock_hz: 1,
                bus_width: 1,
                init_clock_hz: 1,
                data_clock_hz: 1,
            },
            timebase_hz: 1,
            // Advances one tick per read so deadline-based waits terminate
            // quickly against plain-memory registers that never change.
            time: || {
                use core::sync::atomic::{AtomicU64, Ordering};
                static TICKS: AtomicU64 = AtomicU64::new(0);
                TICKS.fetch_add(1, Ordering::Relaxed)
            },
            rca: 1,
            high_capacity: true,
            capacity_sectors: 1,
            last_command: 0,
            last_interrupt_status: 0,
        }
    }

    fn read_test_command(registers: &[u32; TEST_MMIO_WORDS]) -> u16 {
        let address = registers.as_ptr() as usize + COMMAND;
        // The test buffer is live, aligned for a u16 access at COMMAND, and
        // models the volatile MMIO cell used by the production path.
        unsafe { (address as *const u16).read_volatile() }
    }

    #[test]
    fn clock_divisor_matches_cv1800b_rates() {
        assert_eq!(encode_clock_divisor(375_000_000, 25_000_000), Ok(0x0800));
        assert_eq!(encode_clock_divisor(375_000_000, 400_000), Ok(0xd540));
        assert_eq!(
            encode_clock_divisor(0, 400_000),
            Err(Error::InvalidConfiguration)
        );
    }

    #[test]
    fn parses_sd_hc_csd_capacity() {
        let mut csd = [0u32; 4];
        csd[0] |= 1 << 30;
        let c_size = 0x3fff_u32;
        csd[2] |= c_size << 16;
        csd[1] |= c_size >> 16;
        assert_eq!(capacity_from_csd(csd), Ok((u64::from(c_size) + 1) * 1024));
    }

    #[test]
    fn converts_sector_address_for_both_card_types() {
        assert_eq!(sector_argument(true, 12_345), Ok(12_345));
        assert_eq!(sector_argument(false, 12_345), Ok(12_345 * 512));
        assert_eq!(sector_argument(false, u64::MAX), Err(Error::OutOfRange));
        assert_eq!(
            sector_argument(true, u64::from(u32::MAX) + 1),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn rejects_sectors_outside_discovered_capacity() {
        assert_eq!(validate_sector(1024, 1023), Ok(()));
        assert_eq!(validate_sector(1024, 1024), Err(Error::OutOfRange));
        assert_eq!(validate_sector(0, 0), Err(Error::OutOfRange));
    }

    #[test]
    fn validate_block_range_accepts_in_bounds_multi_block_runs() {
        assert_eq!(validate_block_range(1024, 0, 512), Ok(1));
        assert_eq!(validate_block_range(1024, 0, 4096), Ok(8));
        assert_eq!(validate_block_range(1024, 1016, 4096), Ok(8));
    }

    #[test]
    fn validate_block_range_rejects_malformed_or_out_of_range_requests() {
        assert_eq!(
            validate_block_range(1024, 0, 0),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            validate_block_range(1024, 0, 511),
            Err(Error::InvalidConfiguration)
        );
        assert_eq!(
            validate_block_range(1024, 0, 513),
            Err(Error::InvalidConfiguration)
        );
        // Crosses the end of the discovered card capacity.
        assert_eq!(validate_block_range(1024, 1017, 4096), Err(Error::OutOfRange));
        // Exceeds MAX_TRANSFER_BLOCKS even though it would otherwise fit.
        assert_eq!(
            validate_block_range(
                u64::from(MAX_TRANSFER_BLOCKS) + 1,
                0,
                (u64::from(MAX_TRANSFER_BLOCKS) as usize + 1) * SECTOR_SIZE
            ),
            Err(Error::InvalidConfiguration)
        );
    }

    #[test]
    fn read_blocks_of_exactly_one_block_uses_the_single_sector_command() {
        let mut registers = [0u32; TEST_MMIO_WORDS];
        let mut card = fake_card(&mut registers);
        let mut output = [0u8; SECTOR_SIZE];
        // As with the other command-path tests, plain memory cannot emulate
        // INT_STATUS write-one-to-clear, so this deliberately fails at the
        // first interrupt wait; the command it records before doing so is
        // still the single-block CMD17, not CMD18.
        assert_eq!(card.read_blocks(0, &mut output), Err(Error::DeviceIo));
        assert_eq!(card.last_command(), 17);
        assert_abort_published(&registers);
    }

    #[test]
    fn tracked_multi_block_write_publishes_once_immediately_before_cmd25_store() {
        let mut registers = [0u32; TEST_MMIO_WORDS];
        let mut card = fake_card(&mut registers);
        card.capacity_sectors = 8;
        let command_address = registers.as_ptr() as usize + COMMAND;
        let publications = Cell::new(0);

        // As with the single-sector tracked write test, plain memory cannot
        // emulate INT_STATUS write-one-to-clear, so this deliberately fails at
        // the first interrupt wait, after the COMMAND store.
        assert_eq!(
            card.write_blocks_tracked(0, &[0u8; SECTOR_SIZE * 8], || {
                assert_eq!(
                    unsafe { (command_address as *const u16).read_volatile() },
                    0
                );
                publications.set(publications.get() + 1);
            }),
            Err(Error::DeviceIo)
        );
        assert_eq!(publications.get(), 1);
        assert_eq!(card.last_command(), 25);
        assert_abort_published(&registers);
    }

    #[test]
    fn diagnostic_probe_publishes_cmd18_with_block_count_and_reports_zero_progress_on_failure() {
        let mut registers = [0u32; TEST_MMIO_WORDS];
        let mut card = fake_card(&mut registers);
        card.capacity_sectors = 8;
        let mut output = [0u8; SECTOR_SIZE * 2];

        // As with the other command-path tests, plain memory cannot emulate
        // INT_STATUS write-one-to-clear, so this deliberately fails at the
        // first interrupt wait, before any block data has been drained.
        assert_eq!(
            card.diagnostic_probe_multiblock_read(0, &mut output, 10),
            (0, Err(Error::DeviceIo))
        );
        assert_eq!(card.last_command(), 18);
        assert_abort_published(&registers);
        let block_count_address = registers.as_ptr() as usize + BLOCK_COUNT;
        assert_eq!(
            unsafe { (block_count_address as *const u16).read_volatile() },
            2
        );
    }

    #[test]
    fn diagnostic_probe_rejects_malformed_requests_without_touching_hardware() {
        let mut registers = [0u32; TEST_MMIO_WORDS];
        let mut card = fake_card(&mut registers);
        let mut odd_length = [0u8; SECTOR_SIZE + 1];
        assert_eq!(
            card.diagnostic_probe_multiblock_read(0, &mut odd_length, 10),
            (0, Err(Error::InvalidConfiguration))
        );
        assert_eq!(read_test_command(&registers), 0);
    }

    #[test]
    fn tracked_write_does_not_publish_on_pre_command_failures() {
        let mut registers = [0u32; TEST_MMIO_WORDS];
        let mut card = fake_card(&mut registers);
        let publications = Cell::new(0);

        assert_eq!(
            card.write_sector_tracked(1, &[0u8; SECTOR_SIZE], || {
                publications.set(publications.get() + 1);
            }),
            Err(Error::OutOfRange)
        );
        assert_eq!(publications.get(), 0);
        assert_eq!(read_test_command(&registers), 0);

        // A busy command/data path is also rejected before CMD24 publication.
        registers[PRESENT_STATE / 4] = 3;
        assert_eq!(
            card.write_sector_tracked(0, &[0u8; SECTOR_SIZE], || {
                publications.set(publications.get() + 1);
            }),
            Err(Error::TimedOut)
        );
        assert_eq!(publications.get(), 0);
        assert_eq!(read_test_command(&registers), 0);
    }

    #[test]
    fn tracked_write_publishes_once_immediately_before_cmd24_store() {
        let mut registers = [0u32; TEST_MMIO_WORDS];
        let mut card = fake_card(&mut registers);
        let command_address = registers.as_ptr() as usize + COMMAND;
        let publications = Cell::new(0);

        // Plain memory cannot emulate INT_STATUS write-one-to-clear, so the
        // request intentionally fails at the first interrupt wait, after the
        // COMMAND store. That is exactly the ambiguity boundary under test.
        assert_eq!(
            card.write_sector_tracked(0, &[0u8; SECTOR_SIZE], || {
                assert_eq!(
                    unsafe { (command_address as *const u16).read_volatile() },
                    0
                );
                publications.set(publications.get() + 1);
            }),
            Err(Error::DeviceIo)
        );
        assert_eq!(publications.get(), 1);
        assert_eq!(card.last_command(), 24);
        assert_abort_published(&registers);
    }

    /// After any failed data transfer, the driver must publish the CMD12
    /// abort and request a CMD/DAT line reset — otherwise the card can be
    /// left mid-transfer, unreachable even to the boot ROM across a warm
    /// reboot.
    fn assert_abort_published(registers: &[u32; TEST_MMIO_WORDS]) {
        assert_eq!(
            read_test_command(registers),
            command_word(12, CMD_RESP_48_BUSY | CMD_CRC | CMD_INDEX) | CMD_TYPE_ABORT
        );
        let reset_address = registers.as_ptr() as usize + SOFTWARE_RESET;
        assert_eq!(
            unsafe { (reset_address as *const u8).read_volatile() },
            SRST_CMD | SRST_DAT
        );
    }

    #[test]
    fn manual_cmd12_write_mode_omits_auto_cmd12_and_sets_linux_block_size() {
        let mut registers = [0u32; TEST_MMIO_WORDS];
        let mut card = fake_card(&mut registers);
        card.capacity_sectors = 8;
        // Fails at the first buffer wait in plain memory; the register
        // programming before that point is what this test pins down.
        assert_eq!(
            card.write_blocks_tracked_with_mode(
                0,
                &[0u8; SECTOR_SIZE * 2],
                MultiBlockWriteMode::ManualCmd12,
                || {},
            ),
            Err(Error::DeviceIo)
        );
        assert_eq!(card.last_command(), 25);
        let block_size_address = registers.as_ptr() as usize + BLOCK_SIZE;
        assert_eq!(
            unsafe { (block_size_address as *const u16).read_volatile() },
            BLOCK_SIZE_BOUNDARY | SECTOR_SIZE as u16
        );
        assert_abort_published(&registers);
    }

    #[test]
    fn set_block_count_write_mode_issues_cmd23_before_the_transfer() {
        let mut registers = [0u32; TEST_MMIO_WORDS];
        let mut card = fake_card(&mut registers);
        card.capacity_sectors = 8;
        // Plain memory fails the CMD23 command wait itself, which proves the
        // pre-transfer CMD23 publication happens before any CMD25 state.
        assert_eq!(
            card.write_blocks_tracked_with_mode(
                0,
                &[0u8; SECTOR_SIZE * 2],
                MultiBlockWriteMode::SetBlockCount,
                || {},
            ),
            Err(Error::DeviceIo)
        );
        assert_eq!(card.last_command(), 23);
        assert_eq!(
            read_test_command(&registers),
            command_word(23, CMD_RESP_48 | CMD_CRC | CMD_INDEX)
        );
    }

    #[test]
    fn failed_read_preserves_failing_command_diagnostics_across_the_abort() {
        let mut registers = [0u32; TEST_MMIO_WORDS];
        let mut card = fake_card(&mut registers);
        assert_eq!(card.read_sector(0).unwrap_err(), Error::DeviceIo);
        // The abort issues CMD12 and its own interrupt waits, but the
        // diagnostics still describe the CMD17 that actually failed.
        assert_eq!(card.last_command(), 17);
        assert_ne!(card.last_interrupt_status(), 0);
        assert_abort_published(&registers);
    }

    #[test]
    fn tracked_flush_publishes_once_immediately_before_cmd13_store() {
        let mut registers = [0u32; TEST_MMIO_WORDS];
        let mut card = fake_card(&mut registers);
        let command_address = registers.as_ptr() as usize + COMMAND;
        let publications = Cell::new(0);

        assert_eq!(
            card.flush_tracked(|| {
                assert_eq!(
                    unsafe { (command_address as *const u16).read_volatile() },
                    0
                );
                publications.set(publications.get() + 1);
            }),
            Err(Error::DeviceIo)
        );
        assert_eq!(publications.get(), 1);
        assert_eq!(
            read_test_command(&registers),
            command_word(13, CMD_RESP_48 | CMD_CRC | CMD_INDEX)
        );
    }
}
