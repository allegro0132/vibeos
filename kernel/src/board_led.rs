//! Milk-V Duo board-status LED.
//!
//! The blue user LED is active-high on GPIOC24. The stock boot firmware does
//! not promise to leave either its audio-pad pinmux or GPIO direction latch in
//! a useful state, so VibeOS takes explicit ownership after enabling Sv39.

const PINMUX_PAD_AUD_AOUTR: usize = crate::platform::SOC_CONTROL_BASE + 0x1000 + 0x12c;
const PINMUX_FUNCTION_MASK: u32 = 0x7;
const PINMUX_XGPIOC24: u32 = 3;

const GPIO_DATA: usize = crate::platform::GPIOC_BASE;
const GPIO_DIRECTION: usize = crate::platform::GPIOC_BASE + 0x04;
const GPIO_EXTERNAL: usize = crate::platform::GPIOC_BASE + 0x50;
const BLUE_LED: u32 = 1 << 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlueLedInfo {
    pub pinmux: u32,
    pub direction: u32,
    pub data: u32,
    pub external: u32,
}

impl BlueLedInfo {
    pub fn configured(self) -> bool {
        self.pinmux & PINMUX_FUNCTION_MASK == PINMUX_XGPIOC24 && self.direction & BLUE_LED != 0
    }

    pub fn on(self) -> bool {
        self.configured() && self.data & BLUE_LED != 0 && self.external & BLUE_LED != 0
    }
}

/// Select GPIOC24, preload a high output latch, and only then enable output.
///
/// Preloading avoids a visible low glitch while the direction changes. All
/// unrelated pinmux and GPIO bank bits are retained.
pub fn init() -> BlueLedInfo {
    update_bits(PINMUX_PAD_AUD_AOUTR, PINMUX_FUNCTION_MASK, PINMUX_XGPIOC24);
    set_bits(GPIO_DATA, BLUE_LED);
    set_bits(GPIO_DIRECTION, BLUE_LED);
    info()
}

pub fn info() -> BlueLedInfo {
    BlueLedInfo {
        pinmux: read32(PINMUX_PAD_AUD_AOUTR),
        direction: read32(GPIO_DIRECTION),
        data: read32(GPIO_DATA),
        external: read32(GPIO_EXTERNAL),
    }
}

fn set_bits(address: usize, bits: u32) {
    write32(address, read32(address) | bits);
}

fn update_bits(address: usize, mask: u32, value: u32) {
    write32(address, (read32(address) & !mask) | (value & mask));
}

#[inline]
fn read32(address: usize) -> u32 {
    unsafe { (address as *const u32).read_volatile() }
}

#[inline]
fn write32(address: usize, value: u32) {
    unsafe { (address as *mut u32).write_volatile(value) }
}
