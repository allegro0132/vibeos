//! Read-only shared root decoding. This is a rate snapshot, not a clock lease.
//! The owner must keep the 24 MHz oscillator, PLL and dividers stable throughout
//! the read and every dependent device invocation. No clocks are reprogrammed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bank {
    SysCrg,
    Syscon,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedClock;

pub(crate) fn pll(
    r: &mut impl FnMut(Bank, usize) -> u32,
    zero: bool,
) -> Result<u64, UnsupportedClock> {
    let (mode, fb, post, pre, mask) = if zero {
        (
            r(Bank::Syscon, 0x18),
            r(Bank::Syscon, 0x1c) & 0xfff,
            r(Bank::Syscon, 0x20),
            r(Bank::Syscon, 0x24) & 63,
            3 << 24,
        )
    } else {
        let mode = r(Bank::Syscon, 0x2c);
        (
            mode,
            (mode >> 17) & 0xfff,
            r(Bank::Syscon, 0x30),
            r(Bank::Syscon, 0x34) & 63,
            3 << 15,
        )
    };
    if mode & mask != mask || post & (1 << 27) != 0 || pre == 0 || fb < 8 {
        return Err(UnsupportedClock);
    }
    let divisor = u64::from(pre) * (1 << ((post >> 28) & 3));
    let numerator = 24_000_000u64 * u64::from(fb);
    if numerator % divisor != 0 {
        return Err(UnsupportedClock);
    }
    Ok(numerator / divisor)
}

/// Decode BUS_ROOT -> AXI_CFG0 -> STG_AXIAHB. Fractional/powered-down PLLs,
/// invalid dividers and non-integral rates are rejected. Does not touch PLL0:
/// security clients need no GMAC GTX/PTP clock. Physical clock presence and
/// reset readiness still require platform ownership and hardware validation.
pub fn stg_axiahb_hz(mut read: impl FnMut(Bank, usize) -> u32) -> Result<u32, UnsupportedClock> {
    let bus = if read(Bank::SysCrg, 5 * 4) & (1 << 24) != 0 {
        pll(&mut read, false)?
    } else {
        24_000_000
    };
    let axi = divide(bus, read(Bank::SysCrg, 7 * 4) & 0x00ff_ffff, 3)?;
    let stg = divide(axi, read(Bank::SysCrg, 8 * 4) & 0x00ff_ffff, 2)?;
    if !(20_000_000..=300_000_000).contains(&stg) {
        return Err(UnsupportedClock);
    }
    Ok(stg as u32)
}
fn divide(rate: u64, divisor: u32, max: u32) -> Result<u64, UnsupportedClock> {
    if divisor == 0 || divisor > max || rate % u64::from(divisor) != 0 {
        return Err(UnsupportedClock);
    }
    Ok(rate / u64::from(divisor))
}
