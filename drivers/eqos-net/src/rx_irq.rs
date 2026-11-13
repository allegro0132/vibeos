//! GMAC4/5 RX interrupt register operations, separate from scheduler policy.
//! Encodings: Linux stmmac dwmac4_dma.h / dwmac4_lib.c. These operations do not
//! register a handler or authorize sleep. The adapter must publish its waiter
//! before arming and recheck both the event generation and RX descriptor OWN.
use crate::mdio::Registers;

pub const ENABLE: usize = 0x1134;
pub const WATCHDOG: usize = 0x1138;
pub const STATUS: usize = 0x1160;
const RX_COMPLETE: u32 = 1 << 6;
const RX_EVENTS: u32 = RX_COMPLETE | (1 << 7) | (1 << 8) | (1 << 9);
pub const FATAL_EVENTS: u32 = (1 << 12) | (1 << 13);
const NORMAL_SUMMARY: u32 = 1 << 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Revision {
    Gmac400,
    Gmac410OrLater,
}
impl Revision {
    fn normal_enable(self) -> u32 {
        match self {
            Self::Gmac400 => 1 << 16,
            Self::Gmac410OrLater => 1 << 15,
        }
    }
}

/// RX watchdog units are 256 CSR clock cycles. Round up; never silently clamp
/// an unrepresentable request. Zero disables the timer, not the IRQ source.
pub fn watchdog_ticks(csr_hz: u64, microseconds: u32) -> Option<u8> {
    if csr_hz == 0 {
        return None;
    }
    let ticks = (u128::from(csr_hz) * u128::from(microseconds)).div_ceil(256_000_000);
    u8::try_from(ticks).ok()
}

/// Mask only RX completion, preserving TX interrupt enables and shared summary.
/// All enable-register writers must be serialized by the adapter, including
/// its top half. No mutable controller engine may be borrowed by an ISR.
pub fn mask(io: &mut impl Registers) {
    let value = io.read(ENABLE);
    io.write(ENABLE, value & !RX_COMPLETE);
    let _ = io.read(ENABLE); // Flush posted MMIO before PLIC completion.
}

/// Top-half primitive: mask before sampling/acknowledging RX causes. Return the
/// full status for fault policy, but never clear TX causes or fatal-bus errors.
pub fn mask_and_acknowledge(io: &mut impl Registers) -> u32 {
    mask(io);
    let status = io.read(STATUS);
    let rx = status & RX_EVENTS;
    if rx != 0 {
        io.write(STATUS, rx | (status & NORMAL_SUMMARY));
        let _ = io.read(STATUS);
    }
    status
}

/// Arm after a budgeted drain. False means an RX or fatal event is already pending, so
/// keep polling with RX masked. True still requires the adapter's descriptor
/// and wake-generation recheck before sleeping: this is not a sleep decision.
/// This function does not clear status, including when an arrival races arming.
pub fn arm_and_check(io: &mut impl Registers, revision: Revision) -> bool {
    let value = io.read(ENABLE);
    let enabled = value | RX_COMPLETE | revision.normal_enable();
    io.write(ENABLE, enabled);
    if io.read(ENABLE) & (RX_COMPLETE | revision.normal_enable())
        != RX_COMPLETE | revision.normal_enable()
        || io.read(STATUS) & (RX_EVENTS | FATAL_EVENTS) != 0
    {
        mask(io);
        return false;
    }
    true
}
