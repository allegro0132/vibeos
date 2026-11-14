//! PCA9555 status lamps on I2C2 mux channel 0. The caller chooses meaning/timing.
use core::sync::atomic::{AtomicU32, Ordering};
const EXPANDER: u8 = 0x20;
/// Expander registers for pins 8..=15: output latch, direction (1 = input).
const OUTPUT_PORT1: u8 = 0x03;
const CONFIG_PORT1: u8 = 0x07;
const RED: u8 = 1 << 7;
const BLUE: u8 = 1 << 6;

/// Bit 31: the expander answered and both lamps are outputs. Bits 0..=7: the
/// latch last written to its port 1. Bits 8..=15: failed updates (saturating).
static STATE: AtomicU32 = AtomicU32::new(0);
const READY: u32 = 1 << 31;

/// Take over the bus pins, select the expander, make both lamp pins outputs
/// (the others are kept as they are) and light `red` and `blue`.
fn attach(red: bool, blue: bool) -> Result<u8, ()> {
    super::i2c::with_channel(0, |bus| {
        let latch = (bus.read(EXPANDER, OUTPUT_PORT1)? & !(RED | BLUE))
            | if red { RED } else { 0 }
            | if blue { BLUE } else { 0 };
        // Latch before direction, so the pins come up showing the right state.
        bus.write(EXPANDER, &[OUTPUT_PORT1, latch])?;
        let config = bus.read(EXPANDER, CONFIG_PORT1)?;
        bus.write(EXPANDER, &[CONFIG_PORT1, config & !(RED | BLUE)])?;
        if bus.read(EXPANDER, CONFIG_PORT1)? & (RED | BLUE) != 0
            || bus.read(EXPANDER, OUTPUT_PORT1)? != latch
        {
            return Err(());
        }
        Ok(latch)
    })
}
/// Show `red` and `blue`. Writes only on a change; after a failure the next
/// call starts over from the bus.
pub fn show(red: bool, blue: bool) {
    let state = STATE.load(Ordering::Relaxed);
    let errors = state & 0xff00;
    let fail = || STATE.store(errors.saturating_add(0x100).min(0xff00), Ordering::Relaxed);
    if state & READY == 0 {
        match attach(red, blue) {
            Ok(latch) => STATE.store(READY | errors | u32::from(latch), Ordering::Relaxed),
            Err(()) => fail(),
        }
        return;
    }
    let old = state as u8;
    let latch = (old & !(RED | BLUE)) | if red { RED } else { 0 } | if blue { BLUE } else { 0 };
    if latch == old {
        return;
    }
    match super::i2c::with_channel(0, |bus| bus.write(EXPANDER, &[OUTPUT_PORT1, latch])) {
        Ok(()) => STATE.store(READY | errors | u32::from(latch), Ordering::Relaxed),
        Err(()) => fail(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub ready: bool,
    pub red: bool,
    pub blue: bool,
    pub failed_updates: u8,
}
pub fn state() -> State {
    let value = STATE.load(Ordering::Relaxed);
    State {
        ready: value & READY != 0,
        red: value as u8 & RED != 0,
        blue: value as u8 & BLUE != 0,
        failed_updates: (value >> 8) as u8,
    }
}
