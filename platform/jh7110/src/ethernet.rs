//! GMAC0 platform preparation for boards wired to external RGMII RX-derived
//! TX clock (Mars). Shared PLLs/bus dividers are inspected, never rewritten.
//! Clock topology follows the pinned SDK; Mars TX parent follows upstream DTS.
use vibeos_hal::AddressRange;
const GATE: u32 = 1 << 31;
const MUX: u32 = 1 << 24;
const RESET: usize = 0x38;
const STATUS: usize = 0x3c;
const MAC_RESETS: u32 = 3; // AON reset IDs 160 (AXI), 161 (AHB)
const GTX: usize = 108 * 4;
const PTP: usize = 109 * 4;
const GTXC: usize = 111 * 4;
const POLLS: usize = 100_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bank {
    SysCrg,
    Syscon,
    AonCrg,
    AonSyscon,
    AonPins,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidResources,
    UnsupportedClock,
    TimedOut,
    Readback,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prepared {
    pub csr_hz: u32,
    pub gtx_hz: u32,
    pub ptp_hz: u32,
    pub gtx_divider: u8,
    pub ptp_divider: u8,
}
pub trait Registers {
    fn read(&mut self, bank: Bank, offset: usize) -> u32;
    fn write(&mut self, bank: Bank, offset: usize, value: u32);
    fn ticks(&mut self) -> u64;
}
fn root_read(r: &mut impl Registers, bank: crate::clock::Bank, offset: usize) -> u32 {
    r.read(
        match bank {
            crate::clock::Bank::SysCrg => Bank::SysCrg,
            crate::clock::Bank::Syscon => Bank::Syscon,
        },
        offset,
    )
}
fn exact_div(rate: u64, divisor: u32, maximum: u32) -> Result<u64, Error> {
    if divisor == 0 || divisor > maximum || rate % u64::from(divisor) != 0 {
        return Err(Error::UnsupportedClock);
    }
    Ok(rate / u64::from(divisor))
}
/// Decode actual running roots; reject fractional, powered-down or malformed
/// clock configurations before making any writes. 24 MHz oscillator is a
/// board prerequisite. CSR comes from STG_AXI/AHB, never the 125 MHz GTX clock.
pub fn clock_plan(r: &mut impl Registers) -> Result<Prepared, Error> {
    let gmac = crate::clock::pll(&mut |b, o| root_read(r, b, o), true)
        .map_err(|_| Error::UnsupportedClock)?;
    let gtx_divider = gmac / 125_000_000;
    if gmac % 125_000_000 != 0 || !(1..=15).contains(&gtx_divider) {
        return Err(Error::UnsupportedClock);
    }
    let csr = crate::clock::stg_axiahb_hz(|b, o| root_read(r, b, o))
        .map_err(|_| Error::UnsupportedClock)?;
    let ptp_parent = exact_div(gmac, r.read(Bank::SysCrg, 99 * 4) & 0x00ff_ffff, 7)?;
    let ptp_divider = ptp_parent.div_ceil(125_000_000);
    if !(1..=31).contains(&ptp_divider) || ptp_parent % ptp_divider != 0 {
        return Err(Error::UnsupportedClock);
    }
    Ok(Prepared {
        csr_hz: csr as u32,
        gtx_hz: 125_000_000,
        ptp_hz: (ptp_parent / ptp_divider) as u32,
        gtx_divider: gtx_divider as u8,
        ptp_divider: ptp_divider as u8,
    })
}
fn update(r: &mut impl Registers, b: Bank, o: usize, mask: u32, value: u32) -> Result<(), Error> {
    let old = r.read(b, o);
    r.write(b, o, (old & !mask) | (value & mask));
    if r.read(b, o) & mask != value & mask {
        return Err(Error::Readback);
    }
    Ok(())
}
fn wait_reset(r: &mut impl Registers, released: bool, ticks: u64) -> Result<(), Error> {
    let start = r.ticks();
    for _ in 0..POLLS {
        if r.read(Bank::AonCrg, STATUS) & MAC_RESETS == if released { MAC_RESETS } else { 0 } {
            return Ok(());
        }
        if r.ticks().wrapping_sub(start) >= ticks {
            break;
        }
        core::hint::spin_loop();
    }
    Err(Error::TimedOut)
}
/// Caller must already have stopped any previous MAC/DMA instance. Prepare only
/// GMAC0; board supplies TX pad drive (two-bit encoding). External RGMII-derived
/// TX follows the negotiated PHY speed, so no shared PLL rate change is needed.
/// Preflight failure writes nothing. Later failures request reset and gate TX;
/// cleanup is not proof of DMA quiescence and must never authorize pool reuse.
pub fn prepare(r: &mut impl Registers, tx_drive: u8, timebase_hz: u64) -> Result<Prepared, Error> {
    if tx_drive > 3 || !(1_000..=1_000_000_000).contains(&timebase_hz) {
        return Err(Error::InvalidResources);
    }
    let plan = clock_plan(r)?;
    // AON pin control is shared. Require boot firmware to have released it;
    // never reset the entire GPIO/RTC domain to configure five MAC TX pads.
    if r.read(Bank::AonCrg, RESET) & 4 != 0 || r.read(Bank::AonCrg, STATUS) & 4 == 0 {
        return Err(Error::InvalidResources);
    }
    let result = (|| {
        update(r, Bank::AonCrg, 0x08, GATE, GATE)?;
        update(r, Bank::AonCrg, 0x0c, GATE, GATE)?;
        update(r, Bank::AonCrg, RESET, MAC_RESETS, MAC_RESETS)?;
        wait_reset(r, false, timebase_hz.div_ceil(10))?;
        update(r, Bank::AonCrg, 0x14, GATE, 0)?;
        update(r, Bank::SysCrg, GTXC, GATE, 0)?;
        update(r, Bank::SysCrg, GTX, GATE, 0)?;
        update(
            r,
            Bank::SysCrg,
            GTX,
            0x00ff_ffff,
            u32::from(plan.gtx_divider),
        )?;
        update(
            r,
            Bank::SysCrg,
            PTP,
            GATE | 0x00ff_ffff,
            GATE | u32::from(plan.ptp_divider),
        )?;
        update(r, Bank::AonSyscon, 0x0c, 7 << 18, 1 << 18)?; // RGMII interface
        update(r, Bank::AonCrg, 0x10, 0x00ff_ffff, 1)?; // external clock, no division
        update(r, Bank::AonCrg, 0x14, MUX, MUX)?;
        update(r, Bank::AonCrg, 0x1c, MUX, 0)?; // RX from RGMII RX input
        update(r, Bank::AonCrg, 0x18, 1 << 30, 0)?;
        update(r, Bank::AonCrg, 0x20, 1 << 30, 0)?;
        for offset in [0x78, 0x7c, 0x80, 0x84, 0x88] {
            update(r, Bank::AonPins, offset, 3, u32::from(tx_drive))?;
        }
        update(r, Bank::SysCrg, GTX, GATE, GATE)?;
        update(r, Bank::SysCrg, GTXC, GATE, GATE)?;
        update(r, Bank::AonCrg, 0x14, GATE, GATE)?;
        update(r, Bank::AonCrg, RESET, MAC_RESETS, 0)?;
        wait_reset(r, true, timebase_hz.div_ceil(10))?;
        Ok(plan)
    })();
    if result.is_err() {
        let _ = update(r, Bank::AonCrg, RESET, MAC_RESETS, MAC_RESETS);
        let _ = update(r, Bank::AonCrg, 0x14, GATE, 0);
        for offset in [GTXC, GTX, PTP] {
            let _ = update(r, Bank::SysCrg, offset, GATE, 0);
        }
    }
    result
}
pub struct Mmio {
    ranges: [AddressRange; 5],
    time: fn() -> u64,
}
impl Mmio {
    /// # Safety
    /// Ranges are the mapped JH7110 banks and exclusively serialized for this
    /// operation. Shared clocks remain stable; prior GMAC DMA is already stopped.
    pub unsafe fn new(ranges: [AddressRange; 5], time: fn() -> u64) -> Result<Self, Error> {
        for (r, (base, size)) in ranges.iter().zip([
            (0x13020000, 0x10000),
            (0x13030000, 0x1000),
            (0x17000000, 0x10000),
            (0x17010000, 0x1000),
            (0x17020000, 0x10000),
        ]) {
            if *r != AddressRange::new(base, base + size) {
                return Err(Error::InvalidResources);
            }
        }
        Ok(Self { ranges, time })
    }
    fn address(&self, b: Bank, o: usize) -> usize {
        let r = self.ranges[b as usize];
        assert!(o % 4 == 0 && o <= r.len() - 4);
        r.start + o
    }
}
fn fence() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
    #[cfg(not(target_arch = "riscv64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
impl Registers for Mmio {
    fn read(&mut self, b: Bank, o: usize) -> u32 {
        fence();
        let v = unsafe { (self.address(b, o) as *const u32).read_volatile() };
        fence();
        v
    }
    fn write(&mut self, b: Bank, o: usize, v: u32) {
        fence();
        unsafe { (self.address(b, o) as *mut u32).write_volatile(v) };
        fence();
    }
    fn ticks(&mut self) -> u64 {
        (self.time)()
    }
}
