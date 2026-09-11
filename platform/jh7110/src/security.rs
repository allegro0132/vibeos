//! Shared SEC_TOP clock/reset lifecycle. This domain includes TRNG, crypto
//! and security DMA; it must never be reset by an independently owned TRNG.
//! Parent STG_AXI/AHB clocks are an owner prerequisite, not reprogrammed here.
use vibeos_hal::AddressRange;
const HCLK: usize = 0x3c; // (vendor clock ID 205 - SYS_REG_END 190) * 4
const MISC: usize = 0x40; // clock ID 206
const RESET: usize = 0x74;
const STATUS: usize = 0x78;
const GATE: u32 = 1 << 31;
const SEC: u32 = 1 << 3; // vendor reset ID 131 in STG group 4
const POLLS: usize = 100_000;

pub trait Registers {
    fn read(&mut self, offset: usize) -> u32;
    fn write(&mut self, offset: usize, value: u32);
    fn ticks(&mut self) -> u64;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidResources,
    InvalidTimebase,
    NotReady,
    Readback,
    TimedOut,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    New,
    Ready,
    Stopped,
    Faulted,
}
pub struct Domain<R> {
    io: R,
    timeout_ticks: u64,
    state: State,
}
impl<R: Registers> Domain<R> {
    /// # Safety
    /// The caller exclusively owns ALL SEC_TOP clients (TRNG/crypto/security
    /// DMA), with no live operations/buffers/IRQs. It holds the parent STG bus
    /// clock and serializes STG CRG RMW with other platform operations for this
    /// object's lifetime. A BSP reset description alone is not this authority.
    pub unsafe fn new_exclusive(io: R, timebase_hz: u64) -> Result<Self, Error> {
        if !(1000..=1_000_000_000).contains(&timebase_hz) {
            return Err(Error::InvalidTimebase);
        }
        Ok(Self {
            io,
            timeout_ticks: timebase_hz.div_ceil(1000),
            state: State::New,
        })
    }
    fn update(&mut self, offset: usize, mask: u32, bits: u32) -> Result<(), Error> {
        let value = (self.io.read(offset) & !mask) | bits;
        self.io.write(offset, value);
        if self.io.read(offset) & mask != bits {
            return Err(Error::Readback);
        }
        Ok(())
    }
    fn clocks(&mut self, on: bool) -> Result<(), Error> {
        for offset in [HCLK, MISC] {
            self.update(offset, GATE, if on { GATE } else { 0 })?;
        }
        Ok(())
    }
    fn reset(&mut self, asserted: bool) -> Result<(), Error> {
        self.update(RESET, SEC, if asserted { SEC } else { 0 })?;
        let expected = if asserted { 0 } else { SEC };
        let started = self.io.ticks();
        for _ in 0..POLLS {
            if self.io.read(STATUS) & SEC == expected {
                return Ok(());
            }
            if self.io.ticks().wrapping_sub(started) >= self.timeout_ticks {
                break;
            }
        }
        Err(Error::TimedOut)
    }
    /// All child drivers must still be stopped. No action is retried on error.
    /// An error retains ownership; only stop() may attempt subsequent recovery.
    pub fn prepare(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::New | State::Stopped) {
            return Err(Error::NotReady);
        }
        self.state = State::Faulted;
        self.clocks(true)?;
        self.reset(true)?;
        self.reset(false)?;
        self.state = State::Ready;
        Ok(())
    }
    /// # Safety
    /// All child invocations have ceased and cannot resume; buffers remain
    /// retained until this returns Ok. No other client may be admitted during
    /// this call. A failed reset is not proof that security DMA stopped.
    pub unsafe fn stop(&mut self) -> Result<(), Error> {
        if self.state == State::Stopped {
            return Ok(());
        }
        self.state = State::Faulted;
        self.clocks(true)?; // reset acknowledgement requires running clocks
        self.reset(true)?;
        self.clocks(false)?;
        self.state = State::Stopped;
        Ok(())
    }
    pub fn ready(&self) -> bool {
        self.state == State::Ready
    }
}

pub struct Mmio {
    base: usize,
    time: fn() -> u64,
}
impl Mmio {
    /// # Safety
    /// This exact STG aperture is identity mapped with device attributes for
    /// the lifetime of this view. The caller owns/serializes its register IO.
    pub unsafe fn new(range: AddressRange, time: fn() -> u64) -> Result<Self, Error> {
        if range != AddressRange::new(0x10230000, 0x10240000) {
            return Err(Error::InvalidResources);
        }
        Ok(Self {
            base: range.start,
            time,
        })
    }
    fn address(&self, offset: usize) -> *mut u32 {
        assert!(matches!(offset, HCLK | MISC | RESET | STATUS));
        (self.base + offset) as *mut u32
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
    fn read(&mut self, offset: usize) -> u32 {
        fence();
        let value = unsafe { self.address(offset).read_volatile() };
        fence();
        value
    }
    fn write(&mut self, offset: usize, value: u32) {
        assert!(offset != STATUS);
        fence();
        unsafe { self.address(offset).write_volatile(value) };
        fence();
    }
    fn ticks(&mut self) -> u64 {
        (self.time)()
    }
}
