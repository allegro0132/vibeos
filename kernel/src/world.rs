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
use crate::heap::{self, AllocationDomain, ArenaId, OwnerId};
use crate::sync::SpinLock;
use crate::virtio_blk;
use crate::{exec, HEAP};

const BACKGROUND_MEMORY_BUDGET: usize = 64 * 1024;
// The interactive compiler's conform program now charges its future envelope
// and every transient AST/code buffer to the shell owner. Keep enough headroom
// for that audited workload while retaining a hard component quota.
pub const SHELL_MEMORY_BUDGET: usize = 512 * 1024;

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
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
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
    cspace: String,
    space: Arc<Space>,
    template: Option<ComponentTemplate>,
    instance: SpinLock<ComponentInstance>,
    memory_owner: OwnerId,
    memory_budget: usize,
}

struct ComponentInstance {
    generation: u64,
    task: exec::TaskHandle,
}

/// The only component programs admitted to restart supervision. Keeping this
/// list sealed is part of the fault-arena safety argument: these tasks pass
/// only pointer-free messages, never publish component-owned allocations, and
/// register only against SYSTEM-owned endpoints or the global timer registry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ComponentTemplate {
    Sensor,
    Logger,
    Guest,
    VirtioBlk,
    FaultProbe,
}

enum ComponentGrants {
    Sensor(Cap),
    Logger { rx: Cap, console: Cap },
    Guest(Cap),
    VirtioBlk { mmio: Cap, dma: Cap, service: Cap },
    FaultProbe,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RestartError {
    NotFound,
    NotRestartable,
    StillRunning,
    GenerationExhausted,
}

impl fmt::Display for RestartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no such component",
            Self::NotRestartable => "component has no audited restart template",
            Self::StillRunning => "component is still running; cancel it first",
            Self::GenerationExhausted => "component generation space exhausted",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RestartReport {
    pub component: ComponentId,
    pub old_generation: u64,
    pub new_generation: u64,
    pub old_task: exec::TaskId,
    pub new_task: exec::TaskId,
    pub retired_caps: usize,
}

/// Non-owning access used only by the sealed component templates. `Component`
/// and the boot-static World route retain the `Arc<Space>` until the task is
/// terminal, so a fault cannot strand an extra strong reference each cycle.
#[derive(Clone, Copy)]
struct SpaceRef(*const Space);

unsafe impl Send for SpaceRef {}

impl SpaceRef {
    fn new(space: &Arc<Space>) -> Self {
        Self(Arc::as_ptr(space))
    }

    fn get(self) -> &'static Space {
        // Safety: SpaceRef is constructed only for a supervised task, and the
        // Component's stable Arc outlives every incarnation of that task.
        unsafe { &*self.0 }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ComponentSnapshot {
    pub id: ComponentId,
    pub generation: u64,
    pub arena: ArenaId,
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
        let (generation, arena, task_id, state, polls) = {
            let instance = self.instance.lock();
            (
                instance.generation,
                instance.task.arena(),
                instance.task.id(),
                instance.task.state(),
                instance.task.polls(),
            )
        };
        let account = HEAP
            .account_stats(self.memory_owner)
            .expect("a component allocation owner must remain registered");
        debug_assert_eq!(account.owner, self.memory_owner);
        let snapshot = ComponentSnapshot {
            id: self.id,
            generation,
            arena,
            name: self.name.clone(),
            task_id,
            cspace: self.cspace.clone(),
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
        self.space.clone()
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

static FAULT_PROBE_DROPS: AtomicU64 = AtomicU64::new(0);

struct FaultProbeDrop;

impl Drop for FaultProbeDrop {
    fn drop(&mut self) {
        FAULT_PROBE_DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

pub(crate) fn fault_probe_drop_count() -> u64 {
    FAULT_PROBE_DROPS.load(Ordering::SeqCst)
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
    /// init's client authority on the discovered block service. The transport
    /// and DMA roots remain private supervisor grants.
    pub block: Option<Cap>,
    pub block_space: Option<Cap>,
    block_mmio: Option<Cap>,
    block_dma: Option<Cap>,
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
        self.spawn_component_inner(name, space, memory_budget, None, fut)
    }

    fn spawn_component_inner(
        &self,
        name: &str,
        space: Arc<Space>,
        memory_budget: usize,
        template: Option<ComponentTemplate>,
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
        let task = match template {
            Some(_) => {
                let arena = HEAP
                    .create_arena(memory_owner)
                    .expect("a fresh component arena must register");
                // Safety: only sealed ComponentTemplate futures enter tracked
                // arenas. Their IPC payloads are pointer-free and no owning
                // reference into the arena is published to SYSTEM or a peer.
                unsafe {
                    exec::spawn_reclaimable_owned(
                        AllocationDomain::new(memory_owner, arena),
                        name,
                        fut,
                    )
                }
            }
            None => exec::spawn_tracked_owned(memory_owner, name, fut),
        };
        let component = Arc::new(Component {
            id,
            name: String::from(name),
            cspace,
            space,
            template,
            instance: SpinLock::new(ComponentInstance {
                generation: 1,
                task,
            }),
            memory_owner,
            memory_budget,
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

    fn grant_template(&self, template: ComponentTemplate, space: &Arc<Space>) -> ComponentGrants {
        let init = self.spaces["init"].clone();
        let init = init.0.lock();
        let mut target = space.0.lock();
        match template {
            ComponentTemplate::Sensor => ComponentGrants::Sensor(
                cap::grant(&init, self.telemetry, Rights::SEND, &mut target)
                    .expect("init retains the telemetry grant root"),
            ),
            ComponentTemplate::Logger => ComponentGrants::Logger {
                rx: cap::grant(&init, self.telemetry, Rights::RECV, &mut target)
                    .expect("init retains the telemetry grant root"),
                console: cap::grant(&init, self.console, Rights::WRITE, &mut target)
                    .expect("init retains the console grant root"),
            },
            ComponentTemplate::Guest => ComponentGrants::Guest(
                cap::grant(&init, self.console, Rights::WRITE, &mut target)
                    .expect("init retains the console grant root"),
            ),
            ComponentTemplate::VirtioBlk => ComponentGrants::VirtioBlk {
                mmio: cap::grant(
                    &init,
                    self.block_mmio.expect("block MMIO root exists"),
                    Rights::READ.union(Rights::WRITE),
                    &mut target,
                )
                .expect("init retains the block MMIO grant root"),
                dma: cap::grant(
                    &init,
                    self.block_dma.expect("block DMA root exists"),
                    Rights::READ.union(Rights::WRITE),
                    &mut target,
                )
                .expect("init retains the block DMA grant root"),
                service: cap::grant(
                    &init,
                    self.block.expect("block service root exists"),
                    Rights::READ.union(Rights::WRITE),
                    &mut target,
                )
                .expect("init retains the block service grant root"),
            },
            ComponentTemplate::FaultProbe => ComponentGrants::FaultProbe,
        }
    }

    fn spawn_template_task(
        &self,
        component: &Component,
        template: ComponentTemplate,
    ) -> exec::TaskHandle {
        let grants = self.grant_template(template, &component.space);
        let space = SpaceRef::new(&component.space);
        let arena = HEAP
            .create_arena(component.memory_owner)
            .expect("a restarted component needs a fresh arena");
        let domain = AllocationDomain::new(component.memory_owner, arena);
        match grants {
            // Safety: this match is the sealed audited factory. Reading is POD;
            // none of these tasks exports arena-backed Vec/Box/Arc payloads.
            ComponentGrants::Sensor(tx) => unsafe {
                exec::spawn_reclaimable_owned(domain, &component.name, sensor_task(space, tx))
            },
            ComponentGrants::Logger { rx, console } => unsafe {
                exec::spawn_reclaimable_owned(
                    domain,
                    &component.name,
                    logger_task(space, rx, console),
                )
            },
            ComponentGrants::Guest(console) => unsafe {
                exec::spawn_reclaimable_owned(domain, &component.name, guest_task(space, console))
            },
            ComponentGrants::VirtioBlk { mmio, dma, service } => unsafe {
                exec::spawn_reclaimable_owned(
                    domain,
                    &component.name,
                    virtio_blk::driver_task(space.get(), mmio, dma, service),
                )
            },
            ComponentGrants::FaultProbe => unsafe {
                exec::spawn_reclaimable_owned(
                    domain,
                    &component.name,
                    fault_probe_task(space, component.memory_budget),
                )
            },
        }
    }

    pub(crate) fn spawn_fault_probe(
        &self,
        name: &'static str,
        memory_budget: usize,
    ) -> Arc<Component> {
        let space = Space::new(name);
        self.spawn_component_inner(
            name,
            space.clone(),
            memory_budget,
            Some(ComponentTemplate::FaultProbe),
            fault_probe_task(SpaceRef::new(&space), memory_budget),
        )
    }

    /// Replace a terminal task incarnation while retaining stable component,
    /// memory-owner, Space, and supervisor-route identities.
    pub fn restart_component(&self, name: &str) -> Result<RestartReport, RestartError> {
        let component = self.component_named(name).ok_or(RestartError::NotFound)?;
        let template = component.template.ok_or(RestartError::NotRestartable)?;
        let before = component.snapshot();
        if before.state == exec::TaskState::Running {
            return Err(RestartError::StillRunning);
        }
        let new_generation = before
            .generation
            .checked_add(1)
            .ok_or(RestartError::GenerationExhausted)?;

        match before.state {
            exec::TaskState::Exited | exec::TaskState::Cancelled => HEAP
                .close_empty_arena(before.arena)
                .expect("a normally terminated audited arena must be empty"),
            exec::TaskState::Faulted => {
                debug_assert!(HEAP.arena_stats(before.arena).is_none());
            }
            exec::TaskState::Running => unreachable!(),
        }

        // `reset` retires every old derivation while preserving incremented
        // slot generations. A stale cap therefore cannot alias a fresh grant
        // even though the stable Space wrapper is reused. Fault teardown has
        // already recovered any abandoned guard before publishing Faulted.
        let retired_caps = component.space.0.lock().reset();
        let task = self.spawn_template_task(&component, template);
        let new_task = task.id();

        let mut instance = component.instance.lock();
        debug_assert_eq!(instance.generation, before.generation);
        debug_assert_eq!(instance.task.id(), before.task_id);
        instance.generation = new_generation;
        instance.task = task;
        drop(instance);

        Ok(RestartReport {
            component: before.id,
            old_generation: before.generation,
            new_generation,
            old_task: before.task_id,
            new_task,
            retired_caps,
        })
    }

    /// Remove a terminal test/supervisor record once its allocation domain is
    /// empty (normal Drop) or has been raw-reclaimed (audited fault arena).
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
        let reclaimed_fault = snapshot.state == exec::TaskState::Faulted
            && snapshot.arena.is_tracked()
            && HEAP.arena_stats(snapshot.arena).is_none()
            && snapshot.memory.live_bytes == 0;
        if !(normal || reclaimed_fault) {
            // An ordinary untracked fault is intentionally leaked. Keep its
            // owner record observable instead of silently consuming an owner
            // slot that can never be unregistered soundly.
            return false;
        }
        if normal && snapshot.arena.is_tracked() {
            HEAP.close_empty_arena(snapshot.arena)
                .expect("a normal terminal arena must be empty");
        }
        if reclaimed_fault {
            // Fault teardown recovered the abandoned guard before publishing
            // Faulted; this safe lifecycle operation only consumes that state.
            component.space.0.lock().reset();
        }
        HEAP.unregister_owner(component.memory_owner())
            .expect("a reaped component must have no live allocation domain");
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

    /// Recover the stable CSpace lock abandoned by one audited fault domain.
    ///
    /// This is deliberately part of the executor's pre-publication teardown,
    /// rather than `restart_component` or removal. A safe lifecycle caller may
    /// itself hold a Space guard; letting it force-unlock that guard would
    /// create overlapping mutable access. At this boundary the faulting task
    /// is permanently detached and no supervisor can observe `Faulted` yet.
    ///
    /// # Safety
    ///
    /// `domain` must be the tracked domain currently being torn down by the
    /// single-hart executor, after every task in it has become unable to resume
    /// and before its terminal state is published.
    pub(crate) unsafe fn recover_faulted_domain(&self, domain: AllocationDomain) {
        assert!(
            domain.arena.is_tracked(),
            "only a tracked component domain can abandon its CSpace lock"
        );

        // Iterate the registry in place: this callback runs at the raw fault
        // boundary and must not allocate or clone the component collection.
        let components = self.components.lock();
        let mut recovered = false;
        for component in components.values() {
            if component.memory_owner != domain.owner {
                continue;
            }
            let owns_domain = component.instance.lock().task.allocation_domain() == domain;
            if !owns_domain {
                continue;
            }
            assert!(!recovered, "an allocation domain must identify one component");
            // Safety: the exact current incarnation was found above, and the
            // executor contract supplied by this method's caller makes it
            // terminal before this direct lock-state recovery.
            let _ = unsafe { component.space.0.recover_after_fault(domain) };
            recovered = true;
        }
        assert!(recovered, "faulted allocation domain has no component owner");
    }
}

static WORLD: SpinLock<Option<Arc<World>>> = SpinLock::new(None);

pub fn world() -> Arc<World> {
    WORLD.lock().as_ref().expect("world not built").clone()
}

/// Restart only faulted block-driver incarnations, with a bounded exponential
/// backoff. Explicit cancellation is an operator decision and is never
/// converted into an automatic restart.
pub fn start_block_supervisor() {
    let world = world();
    let Some(component) = world.component_named("virtio-blk") else {
        return;
    };
    exec::spawn("supervisor:virtio-blk", async move {
        let mut attempts = 0u32;
        loop {
            let (generation, join) = component.join_current();
            let exit = join.await;
            match exit.state() {
                exec::TaskState::Faulted if attempts < 3 => {
                    exec::sleep_ms(10u64 << attempts).await;
                    attempts += 1;
                    if world.restart_component("virtio-blk").is_err() {
                        return;
                    }
                }
                exec::TaskState::Cancelled | exec::TaskState::Exited => {
                    // Cancellation itself never authorizes restart. Keep the
                    // stable supervisor alive so an explicit later restart is
                    // supervised just like the boot incarnation.
                    loop {
                        if component.snapshot().generation > generation {
                            break;
                        }
                        exec::sleep_ms(100).await;
                    }
                }
                exec::TaskState::Faulted | exec::TaskState::Running => return,
            }
        }
    });
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
    let block_resources = virtio_blk::discover();
    let block_space = block_resources.as_ref().map(|_| Space::new("virtio-blk"));

    // init is the root of authority: it mints the only unattenuated caps, then
    // hands out strictly weaker copies. Nothing else can widen what it gets.
    let mut cs = init.0.lock();
    let c_console = cs.mint(console.clone(), Rights::ALL);
    let c_telemetry = cs.mint(telemetry.clone(), Rights::ALL);
    let c_guest_space = cs.mint(guest.clone(), Rights::READ.union(Rights::REVOKE));
    let c_prog_space = cs.mint(prog.clone(), Rights::READ.union(Rights::REVOKE));
    let c_block_space = block_space
        .as_ref()
        .map(|space| cs.mint(space.clone(), Rights::READ.union(Rights::REVOKE)));
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

    let (block_root, block_mmio_root, block_dma_root, block_grants) =
        match (block_resources, block_space.as_ref()) {
            (Some(resources), Some(space)) => {
                let mmio_root = cs.mint(resources.mmio, Rights::ALL);
                let dma_root = cs.mint(resources.dma, Rights::ALL);
                let service_root = cs.mint(resources.device, Rights::ALL);
                let mut target = space.0.lock();
                let grants = (
                    cap::grant(
                        &cs,
                        mmio_root,
                        Rights::READ.union(Rights::WRITE),
                        &mut target,
                    )
                    .unwrap(),
                    cap::grant(
                        &cs,
                        dma_root,
                        Rights::READ.union(Rights::WRITE),
                        &mut target,
                    )
                    .unwrap(),
                    cap::grant(
                        &cs,
                        service_root,
                        Rights::READ.union(Rights::WRITE),
                        &mut target,
                    )
                    .unwrap(),
                );
                drop(target);
                (Some(service_root), Some(mmio_root), Some(dma_root), Some(grants))
            }
            (None, None) => (None, None, None, None),
            _ => unreachable!("block resources and CSpace are constructed together"),
        };
    drop(cs);

    let mut spaces = BTreeMap::from([
        ("init", init),
        ("sensor", sensor.clone()),
        ("logger", logger.clone()),
        ("guest", guest.clone()),
        ("prog", prog),
    ]);
    if let Some(space) = block_space.as_ref() {
        spaces.insert("virtio-blk", space.clone());
    }

    let world = Arc::new(World {
        spaces,
        components: SpinLock::new(BTreeMap::new()),
        console: c_console,
        telemetry: c_telemetry,
        guest_space: c_guest_space,
        prog_space: c_prog_space,
        prog_console: prog_con,
        prog_memory: prog_mem,
        region: init_region,
        block: block_root,
        block_space: c_block_space,
        block_mmio: block_mmio_root,
        block_dma: block_dma_root,
    });

    // Components are *handed* their handles at spawn. That is their whole
    // authority — there is no other way for them to reach anything.
    world.spawn_component_inner(
        "sensor",
        sensor.clone(),
        BACKGROUND_MEMORY_BUDGET,
        Some(ComponentTemplate::Sensor),
        sensor_task(SpaceRef::new(&sensor), sensor_tx),
    );
    world.spawn_component_inner(
        "logger",
        logger.clone(),
        BACKGROUND_MEMORY_BUDGET,
        Some(ComponentTemplate::Logger),
        logger_task(SpaceRef::new(&logger), logger_rx, logger_con),
    );
    world.spawn_component_inner(
        "guest",
        guest.clone(),
        BACKGROUND_MEMORY_BUDGET,
        Some(ComponentTemplate::Guest),
        guest_task(SpaceRef::new(&guest), guest_con),
    );

    if let (Some(space), Some((mmio, dma, service))) = (block_space, block_grants) {
        world.spawn_component_inner(
            "virtio-blk",
            space.clone(),
            BACKGROUND_MEMORY_BUDGET,
            Some(ComponentTemplate::VirtioBlk),
            virtio_blk::driver_task(SpaceRef::new(&space).get(), mmio, dma, service),
        );
    }

    *WORLD.lock() = Some(world);
}

/// Samples a (fake) thermometer and publishes it. Holds SEND and nothing else —
/// asking the very same endpoint for RECV is refused.
async fn sensor_task(space: SpaceRef, tx: Cap) {
    let mut seq = 0u64;
    loop {
        exec::sleep_ms(3000).await;
        seq += 1;
        let ep = match space
            .get()
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
async fn logger_task(space: SpaceRef, rx: Cap, con: Cap) {
    loop {
        let resolved = {
            let cs = space.get().0.lock();
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
async fn guest_task(space: SpaceRef, con: Cap) {
    let mut n = 0u64;
    loop {
        exec::sleep_ms(9000).await;
        n += 1;
        let resolved = space
            .get()
            .0
            .lock()
            .lookup_as::<ConsoleDev>(con, Rights::WRITE);
        match resolved {
            Ok(console) => console.write_bg(&format!("[guest]  heartbeat {}\n", n)),
            Err(e) => {
                crate::println!("[guest]  console denied: {} -- guest is now mute", e);
                return;
            }
        }
    }
}

/// Audited target-only probe for M3.12. It leaves a live Vec and a destructor
/// bomb behind, then quota-faults while holding the generation's CSpace lock.
/// Restart must recover the lock and raw-reclaim the arena without running Drop.
async fn fault_probe_task(space: SpaceRef, memory_budget: usize) {
    let _must_not_drop = FaultProbeDrop;
    let mut held = Vec::new();
    held.resize(512, 0xA5);
    let _abandoned_cspace = space.get().0.lock();
    held.resize(memory_budget.saturating_mul(2), 0x5A);
    panic!("fault probe unexpectedly stayed within its allocation quota");
}
