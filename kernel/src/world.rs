//! The v0.1 userland: a handful of async components wired together with
//! capabilities and typed channels. This module *is* the system image.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

use crate::cap::{self, Cap, CSpace, Resource, Rights};
use crate::chan::Endpoint;
use crate::dev::ConsoleDev;
use crate::exec;
use crate::sync::SpinLock;

/// A capability space is itself a resource. Holding a cap on a space with
/// `REVOKE` is what lets a supervisor claw authority back from a component.
pub struct Space(pub SpinLock<CSpace>);

impl Space {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Space(SpinLock::new(CSpace::new(name))))
    }
}

impl Resource for Space {
    fn kind(&self) -> &'static str {
        "cspace"
    }
    fn describe(&self) -> String {
        let cs = self.0.lock();
        format!("{} [{} caps]", cs.name, cs.list().len())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// One telemetry reading. The channel is typed, so "the protocol" is this
/// struct rather than a byte format both ends have to agree about by hand.
#[derive(Clone, Copy)]
pub struct Reading {
    pub seq: u64,
    pub millicelsius: i32,
}

pub struct World {
    pub spaces: BTreeMap<&'static str, Arc<Space>>,
    /// init's handles onto everything it created.
    pub console: Cap,
    pub telemetry: Cap,
    pub guest_space: Cap,
}

static WORLD: SpinLock<Option<Arc<World>>> = SpinLock::new(None);

pub fn world() -> Arc<World> {
    WORLD.lock().as_ref().expect("world not built").clone()
}

pub fn build() {
    let console = ConsoleDev::new();
    let telemetry: Arc<Endpoint<Reading>> = Endpoint::new("telemetry", 8);

    let init = Space::new("init");
    let sensor = Space::new("sensor");
    let logger = Space::new("logger");
    let guest = Space::new("guest");

    // init is the root of authority: it mints the only unattenuated caps, then
    // hands out strictly weaker copies. Nothing else can widen what it gets.
    let mut cs = init.0.lock();
    let c_console = cs.mint(console.clone(), Rights::ALL);
    let c_telemetry = cs.mint(telemetry.clone(), Rights::ALL);
    let c_guest_space = cs.mint(guest.clone(), Rights::READ.union(Rights::REVOKE));
    cs.mint(sensor.clone(), Rights::READ);
    cs.mint(logger.clone(), Rights::READ);

    // A sensor can talk but never listen.
    let sensor_tx = cap::grant(&cs, c_telemetry, Rights::SEND, &mut sensor.0.lock()).unwrap();
    // A logger can listen and print, but can never forge a reading.
    let logger_rx = cap::grant(&cs, c_telemetry, Rights::RECV, &mut logger.0.lock()).unwrap();
    let logger_con = cap::grant(&cs, c_console, Rights::WRITE, &mut logger.0.lock()).unwrap();
    // The guest gets a console it can lose.
    let guest_con = cap::grant(&cs, c_console, Rights::WRITE, &mut guest.0.lock()).unwrap();
    drop(cs);

    *WORLD.lock() = Some(Arc::new(World {
        spaces: BTreeMap::from([
            ("init", init),
            ("sensor", sensor.clone()),
            ("logger", logger.clone()),
            ("guest", guest.clone()),
        ]),
        console: c_console,
        telemetry: c_telemetry,
        guest_space: c_guest_space,
    }));

    // Components are *handed* their handles at spawn. That is their whole
    // authority — there is no other way for them to reach anything.
    exec::spawn("sensor", sensor_task(sensor, sensor_tx));
    exec::spawn("logger", logger_task(logger, logger_rx, logger_con));
    exec::spawn("guest", guest_task(guest, guest_con));
}

/// Samples a (fake) thermometer and publishes it. Holds SEND and nothing else —
/// asking the very same endpoint for RECV is refused.
async fn sensor_task(space: Arc<Space>, tx: Cap) {
    let mut seq = 0u64;
    loop {
        exec::sleep_ms(1200).await;
        seq += 1;
        let ep = match space.0.lock().lookup_as::<Endpoint<Reading>>(tx, Rights::SEND) {
            Ok(ep) => ep,
            Err(e) => {
                crate::println!("[sensor] denied: {}", e);
                return;
            }
        };
        ep.send(Reading { seq, millicelsius: 21_500 + ((seq as i32 * 37) % 900) }).await;
    }
}

/// Consumes telemetry and renders it. Holds RECV on the channel and WRITE on
/// the console — it cannot inject fake readings, because it has no SEND.
async fn logger_task(space: Arc<Space>, rx: Cap, con: Cap) {
    loop {
        let resolved = {
            let cs = space.0.lock();
            match (
                cs.lookup_as::<Endpoint<Reading>>(rx, Rights::RECV),
                cs.lookup_as::<ConsoleDev>(con, Rights::WRITE),
            ) {
                (Ok(a), Ok(b)) => Some((a, b)),
                _ => None,
            }
        };
        let Some((ep, console)) = resolved else {
            crate::println!("[logger] lost its capabilities; exiting");
            return;
        };
        let r = ep.recv().await;
        console.write(&format!(
            "[logger] reading #{} = {}.{:03} C\n",
            r.seq,
            r.millicelsius / 1000,
            (r.millicelsius % 1000).unsigned_abs()
        ));
    }
}

/// A component whose authority the operator can pull at runtime. Run
/// `revoke guest` in the shell and watch this task start failing — with no
/// change to its code, no signal, and no restart.
async fn guest_task(space: Arc<Space>, con: Cap) {
    let mut n = 0u64;
    loop {
        exec::sleep_ms(2500).await;
        n += 1;
        let resolved = space.0.lock().lookup_as::<ConsoleDev>(con, Rights::WRITE);
        match resolved {
            Ok(console) => console.write(&format!("[guest]  heartbeat {}\n", n)),
            Err(e) => {
                crate::println!("[guest]  console denied: {} -- guest is now mute", e);
                return;
            }
        }
    }
}
