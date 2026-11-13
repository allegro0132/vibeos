//! SDIO1 clock/reset/pad preparation, based on the pinned Mars SDK.
//! Own only the slot resources; never rewrite PLLs, shared bus dividers or SDIO0.
use core::marker::PhantomData;
use vibeos_hal::AddressRange;

const GATE: u32 = 1 << 31;
const RESET: usize = 0x300;
const RESET_STATUS: usize = 0x310;
const SLOT_RESET: u32 = 1 << 1; // reset ID 65, SYS group 2
const AHB: usize = 92 * 4;
const CARD: usize = 94 * 4;
const POLL_LIMIT: usize = 10_000_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bank {
    Crg,
    Syscon,
    Pins,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidResources,
    InvalidPins,
    UnsupportedClock,
    TimedOut,
}
/// Clock/CMD/DAT0/DAT1/DAT2/DAT3 GPIO routing. Initial implementation supports
/// SYS GPIO7..12; the board specifies the signal order, not the SoC module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pins(pub [u8; 6]);
impl Pins {
    fn valid(self) -> bool {
        self.0
            .iter()
            .enumerate()
            .all(|(i, &pin)| (7..=12).contains(&pin) && !self.0[..i].contains(&pin))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prepared {
    pub parent_hz: u32,
    pub source_hz: u32,
    pub divider: u8,
}
/// Implementations serialize all accesses and preserve device ordering.
pub trait Registers {
    fn read(&mut self, bank: Bank, offset: usize) -> u32;
    fn write(&mut self, bank: Bank, offset: usize, value: u32);
    fn ticks(&mut self) -> u64;
}
pub struct Mmio {
    ranges: [AddressRange; 3],
    time: fn() -> u64,
    _exclusive: PhantomData<core::cell::Cell<()>>,
}
impl Mmio {
    /// # Safety
    /// Caller exclusively owns the mapped JH7110 SYS CRG/SYSCON/IOMUX resources.
    /// Shared root clocks stay immutable throughout preparation. No other hart
    /// or firmware agent may use/reconfigure SDIO1 or its pins concurrently.
    pub unsafe fn new(
        crg: AddressRange,
        syscon: AddressRange,
        pins: AddressRange,
        time: fn() -> u64,
    ) -> Result<Self, Error> {
        let ranges = [crg, syscon, pins];
        for (range, minimum) in ranges.iter().zip([0x314, 0x38, 0x2b4]) {
            if range.start % 4 != 0
                || range
                    .end
                    .checked_sub(range.start)
                    .filter(|&n| n >= minimum)
                    .is_none()
            {
                return Err(Error::InvalidResources);
            }
        }
        for i in 0..3 {
            for j in 0..i {
                if ranges[i].start < ranges[j].end && ranges[j].start < ranges[i].end {
                    return Err(Error::InvalidResources);
                }
            }
        }
        Ok(Self {
            ranges,
            time,
            _exclusive: PhantomData,
        })
    }
    fn address(&self, bank: Bank, offset: usize) -> usize {
        let range = self.ranges[bank as usize];
        assert!(offset % 4 == 0 && offset <= range.len() - 4);
        range.start + offset
    }
}
fn fence() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
    // Host tests use Registers models; this fallback does not emulate MMIO.
    #[cfg(not(target_arch = "riscv64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
impl Registers for Mmio {
    fn read(&mut self, bank: Bank, offset: usize) -> u32 {
        fence();
        let value = unsafe { (self.address(bank, offset) as *const u32).read_volatile() };
        fence();
        value
    }
    fn write(&mut self, bank: Bank, offset: usize, value: u32) {
        fence();
        unsafe {
            (self.address(bank, offset) as *mut u32).write_volatile(value);
        }
        fence();
    }
    fn ticks(&mut self) -> u64 {
        (self.time)()
    }
}
fn update(r: &mut impl Registers, bank: Bank, offset: usize, mask: u32, value: u32) {
    let old = r.read(bank, offset);
    r.write(bank, offset, (old & !mask) | (value & mask));
}
/// Decode the running integer PLL2 and AXI_CFG0 tree. Fractional/unknown modes
/// are rejected rather than borrowing the SDK's nominal-frequency fallback.
/// Paired boot firmware must establish a supported integer PLL configuration.
pub fn clock_plan(r: &mut impl Registers) -> Result<Prepared, Error> {
    if r.read(Bank::Crg, 9 * 4) & GATE == 0 || r.read(Bank::Crg, 8 * 4) & 3 == 0 {
        return Err(Error::UnsupportedClock);
    }
    let root = if r.read(Bank::Crg, 5 * 4) & (1 << 24) == 0 {
        24_000_000u64
    } else {
        let mode = r.read(Bank::Syscon, 0x2c);
        let post = r.read(Bank::Syscon, 0x30);
        let pre = r.read(Bank::Syscon, 0x34) & 63;
        let fb = (mode >> 17) & 0xfff;
        if mode & (3 << 15) != 3 << 15 || post & (1 << 27) != 0 || pre == 0 || fb == 0 {
            return Err(Error::UnsupportedClock);
        }
        (24_000_000u64 * u64::from(fb)) / (u64::from(pre) * (1u64 << ((post >> 28) & 3)))
    };
    let axi_div = r.read(Bank::Crg, 7 * 4) & 3;
    if axi_div == 0 {
        return Err(Error::UnsupportedClock);
    }
    let parent = root / u64::from(axi_div);
    let divider = parent.div_ceil(50_000_000);
    if !(1..=15).contains(&divider) || parent / divider < 400_000 {
        return Err(Error::UnsupportedClock);
    }
    Ok(Prepared {
        parent_hz: u32::try_from(parent).map_err(|_| Error::UnsupportedClock)?,
        source_hz: (parent / divider) as u32,
        divider: divider as u8,
    })
}
fn wait_reset(r: &mut impl Registers, released: bool, timeout: u64) -> Result<(), Error> {
    let start = r.ticks();
    for _ in 0..POLL_LIMIT {
        if (r.read(Bank::Crg, RESET_STATUS) & SLOT_RESET != 0) == released {
            return Ok(());
        }
        if r.ticks().wrapping_sub(start) >= timeout {
            break;
        }
        core::hint::spin_loop();
    }
    Err(Error::TimedOut)
}
fn delay(r: &mut impl Registers, ticks: u64) -> Result<(), Error> {
    let start = r.ticks();
    for _ in 0..POLL_LIMIT {
        if r.ticks().wrapping_sub(start) >= ticks {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(Error::TimedOut)
}
fn route(r: &mut impl Registers, gpio: u8, signal: usize) {
    let (mux, shift) = if gpio <= 9 {
        (0x2b0, 2 + 3 * (gpio - 7))
    } else {
        (0x29c, 2 + 3 * (gpio - 10))
    };
    update(r, Bank::Pins, mux, 7 << shift, 0);
    let shift = u32::from(gpio % 4) * 8;
    let group = usize::from(gpio / 4) * 4;
    let dout = [55, 57, 58, 59, 60, 61][signal];
    let doen = [0, 19, 20, 21, 22, 23][signal];
    update(r, Bank::Pins, 0x40 + group, 0x7f << shift, dout << shift);
    update(r, Bank::Pins, group, 0x3f << shift, doen << shift);
    if signal != 0 {
        let din = 43 + signal;
        let shift = (din % 4) * 8;
        update(
            r,
            Bank::Pins,
            0x80 + (din / 4) * 4,
            0x7f << shift,
            (u32::from(gpio) + 2) << shift,
        );
    }
    // CLK: input + pull-up + drive 2 + slew; CMD/DAT: input + pull-up + drive 1.
    update(
        r,
        Bank::Pins,
        0x120 + usize::from(gpio) * 4,
        0xff,
        if signal == 0 { 0x2d } else { 0x0b },
    );
}
/// Prepare SDIO1 while it is held in reset, then allow the board-supplied
/// post-power-on settling interval. Returns the actual source rate for MSHC.
/// Preflight failures make no writes. Later failures request reset and disable
/// the card clock. A missing reset acknowledgment is not proof of quiescence;
/// the caller must not construct a controller engine.
/// A retry may repeat preparation; an earlier controller instance must be gone.
pub fn prepare(
    r: &mut impl Registers,
    pins: Pins,
    timebase_hz: u64,
    settle_ms: u32,
) -> Result<Prepared, Error> {
    if !pins.valid() {
        return Err(Error::InvalidPins);
    }
    if timebase_hz < 1000 {
        return Err(Error::InvalidResources);
    }
    let settle_ticks = timebase_hz
        .checked_mul(u64::from(settle_ms))
        .ok_or(Error::InvalidResources)?
        .div_ceil(1000);
    let plan = clock_plan(r)?;
    let result = (|| {
        update(r, Bank::Crg, AHB, GATE, GATE);
        update(r, Bank::Crg, RESET, SLOT_RESET, SLOT_RESET);
        wait_reset(r, false, timebase_hz.div_ceil(10))?;
        update(r, Bank::Crg, CARD, GATE, 0);
        update(r, Bank::Crg, CARD, 15, u32::from(plan.divider));
        for (signal, &gpio) in pins.0.iter().enumerate() {
            route(r, gpio, signal);
        }
        update(r, Bank::Crg, CARD, GATE, GATE);
        update(r, Bank::Crg, RESET, SLOT_RESET, 0);
        wait_reset(r, true, timebase_hz.div_ceil(10))?;
        delay(r, settle_ticks)?;
        Ok(plan)
    })();
    if result.is_err() {
        update(r, Bank::Crg, RESET, SLOT_RESET, SLOT_RESET);
        update(r, Bank::Crg, CARD, GATE, 0);
    }
    result
}
