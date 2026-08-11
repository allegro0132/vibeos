#![no_std]

//! Conservative SDHCI PIO block driver for the CV1800B SDIO0 controller.
//!
//! This crate owns SoC clock/pad/power setup, SD card discovery and the SDHCI
//! command/data path. It intentionally implements one-bit, 25 MHz PIO only:
//! no device-visible DMA address is ever published.

use vibeos_hal::SdhciDescription;

const SECTOR_SIZE: usize = 512;
const POLL_BUDGET: usize = 5_000_000;

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
const INT_ALL: u32 = u32::MAX;

const CMD_RESP_NONE: u16 = 0;
const CMD_RESP_136: u16 = 1;
const CMD_RESP_48: u16 = 2;
const CMD_RESP_48_BUSY: u16 = 3;
const CMD_CRC: u16 = 1 << 3;
const CMD_INDEX: u16 = 1 << 4;
const CMD_DATA: u16 = 1 << 5;

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
        self.wait_interrupt(INT_BUFFER_READ_READY)?;
        let mut data = [0u8; SECTOR_SIZE];
        for chunk in data.chunks_exact_mut(4) {
            chunk.copy_from_slice(&self.read32(BUFFER).to_le_bytes());
        }
        self.write32(INT_STATUS, INT_BUFFER_READ_READY);
        self.wait_interrupt(INT_TRANSFER_COMPLETE)?;
        self.write32(INT_STATUS, INT_TRANSFER_COMPLETE);
        Ok(data)
    }

    pub fn write_sector(&mut self, physical_sector: u64, data: &[u8; 512]) -> Result<(), Error> {
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
        self.write16(
            COMMAND,
            command_word(24, CMD_RESP_48 | CMD_CRC | CMD_INDEX | CMD_DATA),
        );
        self.wait_interrupt(INT_BUFFER_WRITE_READY)?;
        for chunk in data.chunks_exact(4) {
            self.write32(
                BUFFER,
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            );
        }
        self.write32(INT_STATUS, INT_BUFFER_WRITE_READY);
        self.wait_interrupt(INT_TRANSFER_COMPLETE)?;
        self.write32(INT_STATUS, INT_TRANSFER_COMPLETE);
        self.flush()
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        for _ in 0..10_000 {
            let status = self.command(
                13,
                u32::from(self.rca) << 16,
                CMD_RESP_48 | CMD_CRC | CMD_INDEX,
            )?[0];
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
        self.wait_inhibit(flags & CMD_DATA != 0 || flags & 3 == CMD_RESP_48_BUSY)?;
        self.last_command = index;
        self.last_interrupt_status = 0;
        self.clear_interrupts();
        self.write32(ARGUMENT, argument);
        self.write16(TRANSFER_MODE, 0);
        self.write16(COMMAND, command_word(index, flags));
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

    fn wait_inhibit(&self, data: bool) -> Result<(), Error> {
        let mask = if data { 3 } else { 1 };
        self.poll_until(|| self.read32(PRESENT_STATE) & mask == 0)
    }

    fn wait_interrupt(&mut self, mask: u32) -> Result<(), Error> {
        for _ in 0..POLL_BUDGET {
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
    fn poll_until(&self, mut ready: impl FnMut() -> bool) -> Result<(), Error> {
        for _ in 0..POLL_BUDGET {
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
}
