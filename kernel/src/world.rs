//! The v0.1 userland: a handful of async components wired together with
//! capabilities and typed channels. This module *is* the system image.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;
use core::future::Future;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::{self, CSpace, Cap, Resource, Rights};
use crate::chan::Endpoint;
use crate::dev::{ConsoleDev, MemoryRegion};
use crate::heap::{self, OwnerId};
use crate::sync::SpinLock;
use crate::{exec, HEAP};

const BACKGROUND_MEMORY_BUDGET: usize = 64 * 1024;
pub const SHELL_MEMORY_BUDGET: usize = 256 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ComponentId(u64);

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "component:{}", self.0)
    }
}

static NEXT_COMPONENT_ID: AtomicU64 = AtomicU64::new(1);

fn next_component_id() -> ComponentId {
    let id = NEXT_COMPONENT_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("ComponentId space exhausted");
    ComponentId(id)
}

/// A point-in-time view of the allocation account owned by a component.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryAccount {
    pub owner: ComponentId,
    pub budget_bytes: usize,
    pub live_bytes: usize,
    pub peak_bytes: usize,
    pub denials: u64,
}

/// One supervised unit: stable component identity, current task, authority,
/// declared memory budget, and observable lifecycle state.
pub struct Component {
    id: ComponentId,
    name: String,
    instance: SpinLock<ComponentInstance>,
    memory_owner: OwnerId,
}

struct ComponentInstance {
    generation: u64,
    task: exec::TaskHandle,
    space: Arc<Space>,
    cspace: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ComponentSnapshot {
    pub id: ComponentId,
    pub generation: u64,
    pub name: String,
    pub task_id: exec::TaskId,
    pub cspace: String,
    pub state: exec::TaskState,
    pub terminal_reason: Option<&'static str>,
    pub polls: u64,
    pub memory: MemoryAccount,
}

impl Component {
    pub fn snapshot(&self) -> ComponentSnapshot {
        let mut system_owner = heap::enter_owner(OwnerId::SYSTEM);
        let (generation, task_id, state, polls, cspace) = {
            let instance = self.instance.lock();
            (
                instance.generation,
                instance.task.id(),
                instance.task.state(),
                instance.task.polls(),
                instance.cspace.clone(),
            )
        };
        let account = HEAP
            .account_stats(self.memory_owner)
            .expect("a component allocation owner must remain registered");
        debug_assert_eq!(account.owner, self.memory_owner);
        let snapshot = ComponentSnapshot {
            id: self.id,
            generation,
            name: self.name.clone(),
            task_id,
            cspace,
            state,
            terminal_reason: state.terminal_reason(),
            polls,
            memory: MemoryAccount {
                owner: self.id,
                budget_bytes: account.quota_bytes,
                live_bytes: account.live_bytes,
                peak_bytes: account.peak_bytes,
                denials: account.denials,
            },
        };
        system_owner.restore();
        snapshot
    }

    pub fn memory_owner(&self) -> OwnerId {
        self.memory_owner
    }

    pub fn space(&self) -> Arc<Space> {
        self.instance.lock().space.clone()
    }

    /// Cooperatively stop the current task incarnation without conflating
    /// lifecycle control with capability revocation.
    pub fn cancel(&self) -> exec::CancelOutcome {
        let task = self.instance.lock().task.clone();
        task.cancel()
    }

    /// Bind a join to the task incarnation that was current at this call.
    /// A later restart may replace the task, but cannot silently retarget an
    /// already-created supervisor wait to the new generation.
    pub fn join_current(&self) -> (u64, exec::Join) {
        let instance = self.instance.lock();
        (instance.generation, instance.task.join())
    }
}

/// A capability space is itself a resource. Holding a cap on a space with
/// `REVOKE` is what lets a supervisor claw authority back from a component.
pub struct Space(pub SpinLock<CSpace>);

impl Space {
    pub(crate) fn new(name: &str) -> Arc<Self> {
        let mut system_owner = heap::enter_owner(OwnerId::SYSTEM);
        let space = Arc::new(Space(SpinLock::new(CSpace::new(name))));
        system_owner.restore();
        space
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
    components: SpinLock<BTreeMap<ComponentId, Arc<Component>>>,
    /// init's handles onto everything it created.
    pub console: Cap,
    pub telemetry: Cap,
    pub guest_space: Cap,
    /// The space compiled programs run with, and init's handle on it.
    pub prog_space: Cap,
    pub prog_console: Cap,
    /// The region compiled programs allocate arrays from, as `prog` holds it.
    pub prog_memory: Cap,
    /// init's own handle on the same region, for reporting.
    pub region: Cap,
}

impl World {
    /// Spawn and register a task under a stable component identity.
    pub fn spawn_component(
        &self,
        name: &str,
        space: Arc<Space>,
        memory_budget: usize,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> Arc<Component> {
        assert!(
            memory_budget > 0,
            "a component memory budget must be nonzero"
        );
        // Component records, scheduler envelopes, CSpaces, and the registry are
        // supervisor infrastructure. Only polling/destroying `fut` runs under
        // the component owner installed by the executor.
        let mut system_owner = heap::enter_owner(OwnerId::SYSTEM);
        {
            let components = self.components.lock();
            assert!(
                !components.values().any(|component| component.name == name),
                "duplicate component name"
            );
            assert!(
                !components
                    .values()
                    .any(|component| Arc::ptr_eq(&component.space(), &space)),
                "a CSpace may have only one component owner"
            );
        }
        let id = next_component_id();
        let memory_owner = OwnerId::new(id.0);
        HEAP.register_owner(memory_owner, memory_budget)
            .expect("a fresh component allocation owner must register");
        let cspace = space.0.lock().name.clone();
        let task = exec::spawn_tracked_owned(memory_owner, name, fut);
        let component = Arc::new(Component {
            id,
            name: String::from(name),
            instance: SpinLock::new(ComponentInstance {
                generation: 1,
                task,
                space,
                cspace,
            }),
            memory_owner,
        });
        let mut components = self.components.lock();
        // There is no yield between the two checks on the single-hart executor,
        // but keep the insertion assertion as the registry invariant.
        let old = components.insert(id, component.clone());
        debug_assert!(old.is_none());
        drop(components);
        system_owner.restore();
        component
    }

    /// Remove a terminal test/supervisor record. Normal owners are unregistered
    /// only after Drop returned their account to zero; fault owners remain
    /// registered until M3.12 performs incarnation-wide raw reclamation.
    pub(crate) fn remove_terminal_component(&self, id: ComponentId) -> bool {
        let component = self.components.lock().get(&id).cloned();
        let Some(component) = component else {
            return false;
        };
        let snapshot = component.snapshot();
        if snapshot.state == exec::TaskState::Running {
            return false;
        }

        let normal = matches!(
            snapshot.state,
            exec::TaskState::Exited | exec::TaskState::Cancelled
        );
        // A component may legally hand an owned payload to another component.
        // Pointer provenance keeps that payload charged to its creator, so the
        // account cannot be retired until the last escaped allocation is gone.
        if normal && snapshot.memory.live_bytes != 0 {
            return false;
        }
        if normal {
            HEAP.unregister_owner(component.memory_owner())
                .expect("a normally terminated component must have no live allocations");
        }
        self.components.lock().remove(&id).is_some()
    }

    /// Stable component order for `ps` and tests. Clone under the registry lock
    /// so callers never hold it while inspecting a component or its CSpace.
    pub fn components(&self) -> Vec<Arc<Component>> {
        let mut system_owner = heap::enter_owner(OwnerId::SYSTEM);
        let components = self.components.lock().values().cloned().collect();
        system_owner.restore();
        components
    }

    /// Resolve a CSpace to its owning component by object identity, not by two
    /// strings that merely happen to match. `shell` intentionally owns `init`.
    pub fn component_for_space(&self, space: &Arc<Space>) -> Option<Arc<Component>> {
        self.components()
            .into_iter()
            .find(|component| Arc::ptr_eq(&component.space(), space))
    }

    pub fn component_named(&self, name: &str) -> Option<Arc<Component>> {
        self.components()
            .into_iter()
            .find(|component| component.name == name)
    }
}

static WORLD: SpinLock<Option<Arc<World>>> = SpinLock::new(None);

pub fn world() -> Arc<World> {
    WORLD.lock().as_ref().expect("world not built").clone()
}

pub fn build() {
    let console = ConsoleDev::new();
    // 4096 i64s: enough for real programs, small enough that a runaway one hits
    // the bound rather than the heap.
    let region = MemoryRegion::new("prog-arena", 4096);
    let telemetry: Arc<Endpoint<Reading>> = Endpoint::new("telemetry", 8);

    let init = Space::new("init");
    let sensor = Space::new("sensor");
    let logger = Space::new("logger");
    let guest = Space::new("guest");
    let prog = Space::new("prog");

    // init is the root of authority: it mints the only unattenuated caps, then
    // hands out strictly weaker copies. Nothing else can widen what it gets.
    let mut cs = init.0.lock();
    let c_console = cs.mint(console.clone(), Rights::ALL);
    let c_telemetry = cs.mint(telemetry.clone(), Rights::ALL);
    let c_guest_space = cs.mint(guest.clone(), Rights::READ.union(Rights::REVOKE));
    let c_prog_space = cs.mint(prog.clone(), Rights::READ.union(Rights::REVOKE));
    cs.mint(sensor.clone(), Rights::READ);
    cs.mint(logger.clone(), Rights::READ);

    // A sensor can talk but never listen.
    let sensor_tx = cap::grant(&cs, c_telemetry, Rights::SEND, &mut sensor.0.lock()).unwrap();
    // A logger can listen and print, but can never forge a reading.
    let logger_rx = cap::grant(&cs, c_telemetry, Rights::RECV, &mut logger.0.lock()).unwrap();
    let logger_con = cap::grant(&cs, c_console, Rights::WRITE, &mut logger.0.lock()).unwrap();
    // The guest gets a console it can lose.
    let guest_con = cap::grant(&cs, c_console, Rights::WRITE, &mut guest.0.lock()).unwrap();
    // Compiled programs get a console and nothing else. Machine code emitted by
    // the in-kernel compiler reaches the outside world only through this cap.
    let prog_con = cap::grant(&cs, c_console, Rights::WRITE, &mut prog.0.lock()).unwrap();
    // Memory is granted the same way as the console, and `revoke prog` takes
    // both -- an operator revoking a component means all of its authority.
    let c_region = cs.mint(region.clone(), Rights::ALL);
    let init_region = c_region;
    let prog_mem = cap::grant(
        &cs,
        c_region,
        Rights::READ.union(Rights::WRITE),
        &mut prog.0.lock(),
    )
    .unwrap();
    drop(cs);

    let world = Arc::new(World {
        spaces: BTreeMap::from([
            ("init", init),
            ("sensor", sensor.clone()),
            ("logger", logger.clone()),
            ("guest", guest.clone()),
            ("prog", prog),
        ]),
        components: SpinLock::new(BTreeMap::new()),
        console: c_console,
        telemetry: c_telemetry,
        guest_space: c_guest_space,
        prog_space: c_prog_space,
        prog_console: prog_con,
        prog_memory: prog_mem,
        region: init_region,
    });

    // Components are *handed* their handles at spawn. That is their whole
    // authority — there is no other way for them to reach anything.
    world.spawn_component(
        "sensor",
        sensor.clone(),
        BACKGROUND_MEMORY_BUDGET,
        sensor_task(sensor, sensor_tx),
    );
    world.spawn_component(
        "logger",
        logger.clone(),
        BACKGROUND_MEMORY_BUDGET,
        logger_task(logger, logger_rx, logger_con),
    );
    world.spawn_component(
        "guest",
        guest.clone(),
        BACKGROUND_MEMORY_BUDGET,
        guest_task(guest, guest_con),
    );

    *WORLD.lock() = Some(world);
}

/// Samples a (fake) thermometer and publishes it. Holds SEND and nothing else —
/// asking the very same endpoint for RECV is refused.
async fn sensor_task(space: Arc<Space>, tx: Cap) {
    let mut seq = 0u64;
    loop {
        exec::sleep_ms(3000).await;
        seq += 1;
        let ep = match space
            .0
            .lock()
            .lookup_as::<Endpoint<Reading>>(tx, Rights::SEND)
        {
            Ok(ep) => ep,
            Err(e) => {
                crate::println!("[sensor] denied: {}", e);
                return;
            }
        };
        ep.send(Reading {
            seq,
            millicelsius: 21_500 + ((seq as i32 * 37) % 900),
        })
        .await;
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
        console.write_bg(&format!(
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
        exec::sleep_ms(9000).await;
        n += 1;
        let resolved = space.0.lock().lookup_as::<ConsoleDev>(con, Rights::WRITE);
        match resolved {
            Ok(console) => console.write_bg(&format!("[guest]  heartbeat {}\n", n)),
            Err(e) => {
                crate::println!("[guest]  console denied: {} -- guest is now mute", e);
                return;
            }
        }
    }
}
