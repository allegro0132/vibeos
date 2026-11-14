//! Electrical controls for both BPI-R4 Pro SFP cages and the shared GDM2 media mux.
//! Requires the board Device mappings and exclusive control-plane ownership.
//! No network roles, executor tasks, console output or product configuration here.
use super::serdes;
use core::{
    ptr::{read_volatile, write_volatile},
    sync::atomic::{AtomicU32, Ordering},
};
use vibeos_ethernet::sfp as identity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Cage {
    Sfp1,
    Sfp2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    PcsReadback,
    MuxReadback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    Absent,
    Bus,
    Changed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signals {
    pub present: Option<bool>,
    pub los: Option<bool>,
    pub tx_disabled: Option<bool>,
    pub channel: u8,
    pub configured: bool,
    pub path_ready: bool,
}
pub fn signals(cage: Cage) -> Signals {
    let c = &CAGES[cage as usize];
    let mask = 1 << cage as usize;
    Signals {
        present: pin(c.present, false).map(|absent| !absent),
        los: pin(c.los, false),
        tx_disabled: pin(c.disable, true),
        channel: c.channel,
        configured: ENABLED.load(Ordering::Relaxed) & mask != 0,
        path_ready: PATH_READY.load(Ordering::Relaxed) & mask != 0,
    }
}
pub fn read_identity(cage: Cage, bytes: &mut [u8; 96]) -> Result<(), ProbeError> {
    let before = signals(cage).present;
    if before == Some(false) {
        return Err(ProbeError::Absent);
    }
    super::i2c::with_channel(CAGES[cage as usize].channel, |bus| {
        bus.read_block(0x50, 0, bytes)
    })
    .map_err(|_| ProbeError::Bus)?;
    if signals(cage).present != before {
        return Err(ProbeError::Changed);
    }
    Ok(())
}
struct Pins {
    channel: u8,
    present: u8,
    los: u8,
    disable: u8,
}
const CAGES: [Pins; 2] = [
    Pins {
        channel: 1,
        present: 69,
        los: 70,
        disable: 21,
    },
    Pins {
        channel: 2,
        present: 1,
        los: 2,
        disable: 0,
    },
];
/// Read only a pin already muxed as GPIO, with the expected direction.
/// Unknown is distinct from absent: firmware must not infer a module from
/// a pin still owned by another peripheral.
fn pin(pin: u8, output: bool) -> Option<bool> {
    let pin = usize::from(pin);
    unsafe {
        let mode = read_volatile((0x1001_f300 + pin / 8 * 16) as *const u32);
        let direction = read_volatile((0x1001_f000 + pin / 32 * 16) as *const u32);
        if mode >> (pin % 8 * 4) & 15 != 0 || (direction >> (pin % 32) & 1 != 0) != output {
            return None;
        }
        let bank = if output { 0x1001_f100 } else { 0x1001_f200 };
        Some(read_volatile((bank + pin / 32 * 16) as *const u32) >> (pin % 32) & 1 != 0)
    }
}
static ENABLED: AtomicU32 = AtomicU32::new(0);
static PATH_READY: AtomicU32 = AtomicU32::new(0);
static QUALIFIED: AtomicU32 = AtomicU32::new(0);
fn modify(address: usize, clear: u32, set: u32) {
    unsafe {
        write_volatile(
            address as *mut u32,
            (read_volatile(address as *const u32) & !clear) | set,
        );
    }
}
fn gpio(pin: u8, output: Option<bool>) {
    let p = usize::from(pin);
    let bit = 1 << (p % 32);
    // Latch before selecting GPIO/output, so TX never glitches on.
    if let Some(high) = output {
        modify(0x1001_f100 + p / 32 * 16, bit, if high { bit } else { 0 });
    }
    modify(
        0x1001_f000 + p / 32 * 16,
        bit,
        if output.is_some() { bit } else { 0 },
    );
    modify(0x1001_f300 + p / 8 * 16, 15 << (p % 8 * 4), 0);
}
pub fn init() {
    for c in &CAGES {
        gpio(c.disable, Some(true));
        gpio(c.present, None);
        gpio(c.los, None);
    }
    // IOCFG_TL input enable for pins 1,2,69,70.
    modify(0x11f0_0030, 0, (1 << 14) | (1 << 11) | (1 << 1) | (1 << 2));
}
pub fn direct_selected() -> bool {
    ENABLED.load(Ordering::Relaxed) & 2 != 0
}
pub fn configure(lan: bool, wan: bool, boot: bool) -> Result<(), Error> {
    let next = u32::from(lan) | u32::from(wan) << 1;
    let previous = ENABLED.swap(next, Ordering::Relaxed);
    PATH_READY.fetch_and(!1, Ordering::Relaxed);
    PATH_READY.fetch_or(next & 1, Ordering::Relaxed);
    for (i, c) in CAGES.iter().enumerate() {
        if next & (1 << i) == 0 || (next ^ previous) & (1 << i) != 0 {
            gpio(c.disable, Some(true));
            QUALIFIED.fetch_and(!(1 << i), Ordering::Relaxed);
        }
    }
    if !boot && (next ^ previous) & 2 != 0 {
        direct_mode()?;
    }
    Ok(())
}
/// Called after PHY firmware/clock setup at boot and with withdrawn flows on
/// a media change. Only GDM2 is closed; the external switch's lane is untouched.
pub fn direct_mode() -> Result<(), Error> {
    unsafe {
        write_volatile(0x1510_1500 as *mut u32, 0x2071_7777);
    }
    if direct_selected() {
        PATH_READY.fetch_and(!2, Ordering::Relaxed);
        if !serdes::initialize() {
            gpio(CAGES[1].disable, Some(true));
            QUALIFIED.fetch_and(!2, Ordering::Relaxed);
            return Err(Error::PcsReadback);
        }
        modify(0x11d1_0084, 3, 2);
        // PCS owns link status in 10GBASE-R mode, never force a false link.
        modify(0x1511_000c, (1 << 31) | (1 << 27), 0);
        if unsafe { read_volatile(0x11d1_0084 as *const u32) } & 3 != 2 {
            return Err(Error::MuxReadback);
        }
        PATH_READY.fetch_or(2, Ordering::Relaxed);
    } else {
        modify(0x11d1_0084, 3, 0);
        modify(0x1511_000c, 0, (1 << 31) | (1 << 27));
    }
    unsafe {
        write_volatile(0x1510_1500 as *mut u32, 0x2071_0000);
    }
    Ok(())
}
pub fn link(cage: Cage) -> bool {
    let index = cage as usize;
    let c = &CAGES[index];
    if QUALIFIED.load(Ordering::Relaxed) & (1 << index) == 0
        || pin(c.present, false) != Some(false)
        || pin(c.los, false) != Some(false)
    {
        return false;
    }
    if index == 1 {
        // XGMAC1 status occupies the upper half; PCS link is bit 8 there.
        unsafe { read_volatile(0x1511_000c as *const u32) & (1 << 24) != 0 }
    } else {
        true
    } // Caller also samples the switch's actual MAC link.
}

/// Own one poller and call every 500 ms; first observation waits a full interval.
#[derive(Default)]
pub struct Poller {
    present: u32,
}
impl Poller {
    pub const fn new() -> Self {
        Self { present: 0 }
    }
    pub fn poll(&mut self) {
        for (i, c) in CAGES.iter().enumerate() {
            let mask = 1 << i;
            let inserted = pin(c.present, false) == Some(false);
            let enabled =
                ENABLED.load(Ordering::Relaxed) & PATH_READY.load(Ordering::Relaxed) & mask != 0;
            if !inserted || !enabled {
                gpio(c.disable, Some(true));
                QUALIFIED.fetch_and(!mask, Ordering::Relaxed);
                self.present &= !mask;
                continue;
            }
            // Wait an entire polling interval after insertion for power-up.
            if self.present & mask == 0 {
                self.present |= mask;
                continue;
            }
            if QUALIFIED.load(Ordering::Relaxed) & mask != 0 {
                continue;
            }
            let mut bytes = [0; 96];
            let identified =
                super::i2c::with_channel(c.channel, |bus| bus.read_block(0x50, 0, &mut bytes))
                    .is_ok()
                    && identity::parse(&bytes).is_ok_and(|id| id.ethernet_10g)
                    && pin(c.present, false) == Some(false);
            if identified {
                gpio(c.disable, Some(false));
                QUALIFIED.fetch_or(mask, Ordering::Relaxed);
            }
        }
    }
}
