#![no_std]
//! JH7110 TRNG command transport. No entropy estimate or cryptographic
//! qualification is implied by successfully reading conditioned output.
//! Firmware owns clocks/shared reset and must mask the PLIC source while this
//! polling instance owns ISTAT. No concurrent interrupt acknowledgement allowed.
//! Register references and deliberate restrictions are recorded in
//! `boards/milkv-mars/trng-reference.json` in the workspace.

const CTRL: usize = 0;
const STAT: usize = 4;
const MODE: usize = 8;
const SMODE: usize = 12;
const IE: usize = 16;
const ISTAT: usize = 20;
const RANDOM: usize = 32;
const REQUESTS: usize = 96;
const AGE: usize = 100;
const BUSY: u32 = 3 << 30;
const NONCE: u32 = 1 << 2;
const R256: u32 = 1 << 3;
const MISSION: u32 = 1 << 8;
const SEEDED: u32 = 1 << 9;
const LOCKUP: u32 = 1 << 4;
const EVENTS: u32 = 3 | LOCKUP;

/// Implementations must provide ordered 32-bit accesses and a monotonically
/// wrapping tick counter. Exclusive ownership is required for all methods.
pub trait Registers {
    fn read(&mut self, offset: usize) -> u32;
    fn write(&mut self, offset: usize, value: u32);
    fn ticks(&mut self) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidBudget,
    NotReady,
    TimedOut,
    Mode,
    Protocol,
    Lockup,
    RepeatedOutput,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    New,
    Ready,
    Faulted,
}

pub struct Trng<R> {
    io: R,
    ticks_per_ms: u64,
    polls: u32,
    state: State,
    previous: Option<[u8; 32]>,
}
impl<R: Registers> Trng<R> {
    pub fn new(io: R, timebase_hz: u64, max_polls: u32) -> Result<Self, Error> {
        if !(1000..=1_000_000_000).contains(&timebase_hz) || !(1..=1_000_000).contains(&max_polls) {
            return Err(Error::InvalidBudget);
        }
        Ok(Self {
            io,
            ticks_per_ms: timebase_hz.div_ceil(1000),
            polls: max_polls,
            state: State::New,
            previous: None,
        })
    }
    fn events(&mut self) -> Result<u32, Error> {
        let events = self.io.read(ISTAT);
        if events & LOCKUP != 0 {
            return Err(Error::Lockup);
        }
        if events & !EVENTS != 0 {
            return Err(Error::Protocol);
        }
        Ok(events)
    }
    fn mode(&mut self, seeded: bool) -> Result<(), Error> {
        let value = self.io.read(STAT);
        let mask = BUSY | NONCE | R256 | MISSION | if seeded { SEEDED } else { 0 };
        let expected = R256 | MISSION | if seeded { SEEDED } else { 0 };
        if value & mask != expected {
            return Err(Error::Mode);
        }
        Ok(())
    }
    fn wait(&mut self, event: u32, ms: u64) -> Result<(), Error> {
        let start = self.io.ticks();
        for _ in 0..self.polls {
            let flags = self.events()?;
            let idle = self.io.read(STAT) & BUSY == 0;
            if event != 0 && flags & (3 ^ event) != 0 {
                return Err(Error::Protocol);
            }
            if idle && (event == 0 || flags & event != 0) {
                return Ok(());
            }
            if self.io.ticks().wrapping_sub(start) >= self.ticks_per_ms * ms {
                break;
            }
        }
        Err(Error::TimedOut)
    }
    fn clear(&mut self, events: u32) -> Result<(), Error> {
        self.io.write(ISTAT, events);
        if self.events()? != 0 {
            return Err(Error::Protocol);
        }
        Ok(())
    }
    fn command(&mut self, command: u32, event: u32) -> Result<(), Error> {
        self.wait(0, 100)?;
        let stale = self.events()?;
        self.clear(stale)?;
        self.io.write(CTRL, command);
        self.wait(event, 1)?;
        self.mode(true)?;
        Ok(())
    }
    fn fault<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.state = State::Faulted;
            // Disable interrupts, but retain diagnostics and ownership. This
            // is not reset/stop proof and must not reset the shared SEC block.
            self.io.write(IE, 0);
        }
        result
    }
    /// Caller must have exclusive ownership after platform reset/clock setup.
    /// Mission mode must already be selected, nonce/test mode must be off.
    /// A failed instance never retries; reset/replacement requires its owner.
    pub fn initialize(&mut self) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::NotReady);
        }
        let result = (|| {
            self.wait(0, 100)?;
            let security = self.io.read(SMODE);
            if security & (MISSION | NONCE) != MISSION {
                return Err(Error::Mode);
            }
            self.io.write(IE, 0);
            self.io.write(REQUESTS, 0);
            self.io.write(AGE, 0);
            let mode = self.io.read(MODE) | R256;
            self.io.write(MODE, mode);
            if self.io.read(MODE) != mode || self.io.read(REQUESTS) != 0 || self.io.read(AGE) != 0 {
                return Err(Error::Protocol);
            }
            self.mode(false)?;
            self.clear(3)?;
            // Match the documented interrupt-status enable path. The PLIC
            // source stays masked; this instance polls and acknowledges it.
            self.io.write(IE, (1 << 31) | EVENTS);
            if self.io.read(IE) != (1 << 31) | EVENTS {
                return Err(Error::Protocol);
            }
            self.command(2, 2)?;
            self.clear(2)?;
            self.state = State::Ready;
            Ok(())
        })();
        self.fault(result)
    }
    /// Produce one complete 256-bit conditioned block. No caller memory is
    /// changed on failure. Every request reseeds from the hardware source;
    /// hardware-quality validation still needs separate physical evidence.
    pub fn read_block(&mut self) -> Result<[u8; 32], Error> {
        if self.state != State::Ready {
            return Err(Error::NotReady);
        }
        let result = (|| {
            self.command(2, 2)?;
            self.clear(2)?;
            self.command(1, 1)?;
            let mut block = [0; 32];
            for (i, bytes) in block.chunks_exact_mut(4).enumerate() {
                bytes.copy_from_slice(&self.io.read(RANDOM + 4 * i).to_le_bytes());
            }
            if self.events()? != 1 {
                return Err(Error::Protocol);
            }
            self.mode(true)?;
            self.clear(1)?;
            // Cheap stuck-output rejection, not a statistical health test or
            // an entropy credit. Keep history across software reseeds.
            if block == [0; 32] || block == [255; 32] || self.previous == Some(block) {
                return Err(Error::RepeatedOutput);
            }
            self.previous = Some(block);
            Ok(block)
        })();
        self.fault(result)
    }
}
