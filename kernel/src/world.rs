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

use crate::block_device;
use crate::cap::{self, CSpace, Cap, Resource, Rights};
use crate::chan::Endpoint;
use crate::dev::{ConsoleDev, MemoryRegion};
use crate::durable_cspace;
use crate::heap::{self, AllocationDomain, ArenaId, OwnerId};
use crate::net::{Endpoint as NetEndpoint, StampedPacket};
use crate::net_device;
use crate::saved_program;
use crate::store;
use crate::sync::SpinLock;
#[cfg(feature = "qemu-virt")]
use crate::virtio_rng;
use crate::{exec, HEAP};

const BACKGROUND_MEMORY_BUDGET: usize = 64 * 1024;
#[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
const SSH_TEST_MEMORY_BUDGET: usize = 256 * 1024;
// The interactive compiler and bounded full-journal object recovery charge
// their transient buffers to the shell owner. Keep the documented store
// working-set floor plus client/future headroom while retaining a hard quota.
pub const SHELL_MEMORY_BUDGET: usize = store::STORE_CLIENT_MEMORY_BUDGET;

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
    BlockDriver,
    NetDriver,
    #[cfg(feature = "qemu-virt")]
    VirtioRng,
    #[cfg(feature = "ssh-security-test")]
    SshSecurityTest,
    #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
    SshTest,
    #[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
    Ipv4Stack,
    StoreFaultProbe,
    FaultProbe,
}

enum ComponentGrants {
    Sensor(Cap),
    Logger {
        rx: Cap,
        console: Cap,
    },
    Guest(Cap),
    BlockDriver {
        mmio: Cap,
        dma: Cap,
        service: Cap,
    },
    NetDriver {
        mmio: Cap,
        dma: Cap,
        outbound: Cap,
        inbound: Cap,
        control: Cap,
    },
    #[cfg(feature = "qemu-virt")]
    VirtioRng {
        mmio: Cap,
        dma: Cap,
        source: Cap,
    },
    #[cfg(feature = "ssh-security-test")]
    SshSecurityTest {
        random: Cap,
        signer_read: Cap,
        signer_invoke: Cap,
        policy: Cap,
    },
    #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
    SshTest {
        outbound: Cap,
        inbound: Cap,
        control: Cap,
        random: Cap,
        signer_read: Cap,
        signer_invoke: Cap,
        policy: Cap,
    },
    #[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
    Ipv4Stack {
        outbound: Cap,
        inbound: Cap,
        control: Cap,
    },
    StoreFaultProbe(Cap),
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
pub struct Space(pub Arc<SpinLock<CSpace>>);

impl Space {
    pub(crate) fn new(name: &str) -> Arc<Self> {
        let mut system_owner = heap::enter_owner(OwnerId::SYSTEM);
        let space = Arc::new(Space(Arc::new(SpinLock::new_recoverable(CSpace::new(
            name,
        )))));
        system_owner.restore();
        space
    }

    pub(crate) fn new_persistent(name: &str, space_id: crate::durable::SpaceId) -> Arc<Self> {
        let mut system_owner = heap::enter_owner(OwnerId::SYSTEM);
        let space = Arc::new(Space(Arc::new(SpinLock::new_recoverable(
            CSpace::new_persistent(name, space_id),
        ))));
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
    #[cfg(not(feature = "legacy-shell"))]
    pub vsh_console: Cap,
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
    /// init's authority on the capability-addressed persistent object service.
    pub store: Option<Cap>,
    /// init's explicit operation capability for the fixed durable `hello`
    /// program. The program's console/memory grants come from a separate private
    /// supervisor policy CSpace, never from the legacy `prog` handles.
    pub saved_program: Option<Cap>,
    /// init's explicit authority on the persistent-test CSpace lifecycle.
    pub durable_cspace: Option<Cap>,
    durable_cspace_service: Option<Arc<durable_cspace::DurableCSpaceService>>,
    pub block_space: Option<Cap>,
    block_mmio: Option<Cap>,
    block_dma: Option<Cap>,
    /// init sees only these directional packet interfaces and the control
    /// service. The MMIO/DMA roots live in the private policy CSpace below.
    pub net_outbound: Option<Cap>,
    pub net_inbound: Option<Cap>,
    pub net_control: Option<Cap>,
    net_policy: Option<Arc<Space>>,
    net_mmio: Option<Cap>,
    net_dma: Option<Cap>,
    net_outbound_root: Option<Cap>,
    net_inbound_root: Option<Cap>,
    net_control_root: Option<Cap>,
    #[cfg(any(feature = "qemu-virt", feature = "milkv-ssh-acceptance"))]
    rng_policy: Option<Arc<Space>>,
    #[cfg(feature = "qemu-virt")]
    rng_mmio: Option<Cap>,
    #[cfg(feature = "qemu-virt")]
    rng_dma: Option<Cap>,
    #[cfg(any(feature = "qemu-virt", feature = "milkv-ssh-acceptance"))]
    rng_source_root: Option<Cap>,
    #[cfg(any(
        feature = "ssh-security-test",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance"
    ))]
    ssh_security_policy: Option<Arc<Space>>,
    #[cfg(any(
        feature = "ssh-security-test",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance"
    ))]
    ssh_signer_root: Option<Cap>,
    #[cfg(any(
        feature = "ssh-security-test",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance"
    ))]
    ssh_authorized_policy_root: Option<Cap>,
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
            // Unsealed control tasks (currently the UART shell and one
            // self-test survivor) stay on their creation hart. The shell is
            // therefore also the explicit boot-hart initiator for SMP/IPI
            // acceptance commands instead of being stealable mid-session.
            None => exec::spawn_pinned_owned(memory_owner, name, fut),
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
        #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
        if template == ComponentTemplate::SshTest {
            let mut target = space.0.lock();
            let (outbound, inbound, control) = {
                let policy = self
                    .net_policy
                    .as_ref()
                    .expect("network policy CSpace exists")
                    .0
                    .lock();
                (
                    cap::grant(
                        &policy,
                        self.net_outbound_root
                            .expect("network outbound endpoint root exists"),
                        Rights::SEND,
                        &mut target,
                    )
                    .expect("network policy retains the outbound grant root"),
                    cap::grant(
                        &policy,
                        self.net_inbound_root
                            .expect("network inbound endpoint root exists"),
                        Rights::RECV,
                        &mut target,
                    )
                    .expect("network policy retains the inbound grant root"),
                    cap::grant(
                        &policy,
                        self.net_control_root.expect("network control root exists"),
                        Rights::READ.union(Rights::INVOKE),
                        &mut target,
                    )
                    .expect("network policy retains the control grant root"),
                )
            };
            let random = {
                let policy = self
                    .rng_policy
                    .as_ref()
                    .expect("entropy policy CSpace exists")
                    .0
                    .lock();
                cap::grant(
                    &policy,
                    self.rng_source_root
                        .expect("entropy source grant root exists"),
                    Rights::READ,
                    &mut target,
                )
                .expect("entropy policy retains the source grant root")
            };
            let security = self
                .ssh_security_policy
                .as_ref()
                .expect("SSH security policy CSpace exists")
                .0
                .lock();
            return ComponentGrants::SshTest {
                outbound,
                inbound,
                control,
                random,
                signer_read: cap::grant(
                    &security,
                    self.ssh_signer_root.expect("SSH signer grant root exists"),
                    Rights::READ,
                    &mut target,
                )
                .expect("SSH policy retains the signer grant root"),
                signer_invoke: cap::grant(
                    &security,
                    self.ssh_signer_root.expect("SSH signer grant root exists"),
                    Rights::INVOKE,
                    &mut target,
                )
                .expect("SSH policy retains the signer grant root"),
                policy: cap::grant(
                    &security,
                    self.ssh_authorized_policy_root
                        .expect("SSH authorized-policy grant root exists"),
                    Rights::READ,
                    &mut target,
                )
                .expect("SSH policy retains the authorized-key grant root"),
            };
        }

        #[cfg(feature = "ssh-security-test")]
        if template == ComponentTemplate::SshSecurityTest {
            let mut target = space.0.lock();
            let random = {
                let policy = self
                    .rng_policy
                    .as_ref()
                    .expect("entropy policy CSpace exists")
                    .0
                    .lock();
                cap::grant(
                    &policy,
                    self.rng_source_root
                        .expect("entropy source grant root exists"),
                    Rights::READ,
                    &mut target,
                )
                .expect("entropy policy retains the source grant root")
            };
            let policy = self
                .ssh_security_policy
                .as_ref()
                .expect("SSH security policy CSpace exists")
                .0
                .lock();
            return ComponentGrants::SshSecurityTest {
                random,
                signer_read: cap::grant(
                    &policy,
                    self.ssh_signer_root.expect("SSH signer grant root exists"),
                    Rights::READ,
                    &mut target,
                )
                .expect("SSH policy retains the signer grant root"),
                signer_invoke: cap::grant(
                    &policy,
                    self.ssh_signer_root.expect("SSH signer grant root exists"),
                    Rights::INVOKE,
                    &mut target,
                )
                .expect("SSH policy retains the signer grant root"),
                policy: cap::grant(
                    &policy,
                    self.ssh_authorized_policy_root
                        .expect("SSH authorized-policy grant root exists"),
                    Rights::READ,
                    &mut target,
                )
                .expect("SSH policy retains the authorized-key grant root"),
            };
        }

        #[cfg(feature = "qemu-virt")]
        if template == ComponentTemplate::VirtioRng {
            let policy = self
                .rng_policy
                .as_ref()
                .expect("entropy policy CSpace exists");
            let policy = policy.0.lock();
            let mut target = space.0.lock();
            return ComponentGrants::VirtioRng {
                mmio: cap::grant(
                    &policy,
                    self.rng_mmio.expect("entropy MMIO root exists"),
                    Rights::READ.union(Rights::WRITE),
                    &mut target,
                )
                .expect("entropy policy retains the MMIO grant root"),
                dma: cap::grant(
                    &policy,
                    self.rng_dma.expect("entropy DMA root exists"),
                    Rights::READ.union(Rights::WRITE),
                    &mut target,
                )
                .expect("entropy policy retains the DMA grant root"),
                source: cap::grant(
                    &policy,
                    self.rng_source_root
                        .expect("entropy source grant root exists"),
                    Rights::READ,
                    &mut target,
                )
                .expect("entropy policy retains the source grant root"),
            };
        }

        if template == ComponentTemplate::NetDriver {
            let policy = self
                .net_policy
                .as_ref()
                .expect("network policy CSpace exists");
            let policy = policy.0.lock();
            let mut target = space.0.lock();
            return ComponentGrants::NetDriver {
                mmio: cap::grant(
                    &policy,
                    self.net_mmio.expect("network MMIO root exists"),
                    Rights::READ.union(Rights::WRITE),
                    &mut target,
                )
                .expect("network policy retains the MMIO grant root"),
                dma: cap::grant(
                    &policy,
                    self.net_dma.expect("network DMA root exists"),
                    Rights::READ.union(Rights::WRITE),
                    &mut target,
                )
                .expect("network policy retains the DMA grant root"),
                outbound: cap::grant(
                    &policy,
                    self.net_outbound_root
                        .expect("network outbound endpoint root exists"),
                    Rights::RECV,
                    &mut target,
                )
                .expect("network policy retains the outbound grant root"),
                inbound: cap::grant(
                    &policy,
                    self.net_inbound_root
                        .expect("network inbound endpoint root exists"),
                    Rights::SEND,
                    &mut target,
                )
                .expect("network policy retains the inbound grant root"),
                control: cap::grant(
                    &policy,
                    self.net_control_root.expect("network control root exists"),
                    Rights::READ,
                    &mut target,
                )
                .expect("network policy retains the control grant root"),
            };
        }

        #[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
        if template == ComponentTemplate::Ipv4Stack {
            let policy = self
                .net_policy
                .as_ref()
                .expect("network policy CSpace exists");
            let policy = policy.0.lock();
            let mut target = space.0.lock();
            return ComponentGrants::Ipv4Stack {
                outbound: cap::grant(
                    &policy,
                    self.net_outbound_root
                        .expect("network outbound endpoint root exists"),
                    Rights::SEND,
                    &mut target,
                )
                .expect("network policy retains the outbound grant root"),
                inbound: cap::grant(
                    &policy,
                    self.net_inbound_root
                        .expect("network inbound endpoint root exists"),
                    Rights::RECV,
                    &mut target,
                )
                .expect("network policy retains the inbound grant root"),
                control: cap::grant(
                    &policy,
                    self.net_control_root.expect("network control root exists"),
                    Rights::READ.union(Rights::INVOKE),
                    &mut target,
                )
                .expect("network policy retains the control grant root"),
            };
        }

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
            ComponentTemplate::BlockDriver => ComponentGrants::BlockDriver {
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
            ComponentTemplate::NetDriver => {
                unreachable!("network grants come from the private policy CSpace")
            }
            #[cfg(feature = "qemu-virt")]
            ComponentTemplate::VirtioRng => {
                unreachable!("entropy grants come from the private policy CSpace")
            }
            #[cfg(feature = "ssh-security-test")]
            ComponentTemplate::SshSecurityTest => {
                unreachable!("SSH security-test grants come from private policy CSpaces")
            }
            #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
            ComponentTemplate::SshTest => {
                unreachable!("SSH test grants come from private policy CSpaces")
            }
            #[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
            ComponentTemplate::Ipv4Stack => {
                unreachable!("TCP echo grants come from the private policy CSpace")
            }
            ComponentTemplate::StoreFaultProbe => ComponentGrants::StoreFaultProbe(
                cap::grant(
                    &init,
                    self.store.expect("store service root exists"),
                    Rights::READ.union(Rights::WRITE),
                    &mut target,
                )
                .expect("init retains the object-store grant root"),
            ),
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
            ComponentGrants::BlockDriver { mmio, dma, service } => unsafe {
                exec::spawn_reclaimable_owned(
                    domain,
                    &component.name,
                    block_device::driver_task(space.get(), mmio, dma, service),
                )
            },
            ComponentGrants::NetDriver {
                mmio,
                dma,
                outbound,
                inbound,
                control,
            } => unsafe {
                exec::spawn_reclaimable_owned(
                    domain,
                    &component.name,
                    net_device::driver_task(space.get(), mmio, dma, outbound, inbound, control),
                )
            },
            #[cfg(feature = "qemu-virt")]
            ComponentGrants::VirtioRng { mmio, dma, source } => unsafe {
                exec::spawn_reclaimable_owned(
                    domain,
                    &component.name,
                    virtio_rng::driver_task(space.get(), mmio, dma, source),
                )
            },
            #[cfg(feature = "ssh-security-test")]
            ComponentGrants::SshSecurityTest {
                random,
                signer_read,
                signer_invoke,
                policy,
            } => unsafe {
                exec::spawn_reclaimable_owned(
                    domain,
                    &component.name,
                    crate::ssh_security_test::task(
                        space.get(),
                        random,
                        signer_read,
                        signer_invoke,
                        policy,
                    ),
                )
            },
            #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
            ComponentGrants::SshTest {
                outbound,
                inbound,
                control,
                random,
                signer_read,
                signer_invoke,
                policy,
            } => unsafe {
                exec::spawn_reclaimable_owned(
                    domain,
                    &component.name,
                    crate::ssh_platform::task(
                        space.get(),
                        outbound,
                        inbound,
                        control,
                        random,
                        signer_read,
                        signer_invoke,
                        policy,
                    ),
                )
            },
            #[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
            ComponentGrants::Ipv4Stack {
                outbound,
                inbound,
                control,
            } => unsafe {
                exec::spawn_reclaimable_owned(
                    domain,
                    &component.name,
                    crate::netstack_platform::task(space.get(), outbound, inbound, control),
                )
            },
            ComponentGrants::StoreFaultProbe(service) => unsafe {
                exec::spawn_reclaimable_owned(
                    domain,
                    &component.name,
                    store_fault_probe_task(space, service),
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

    pub(crate) fn spawn_store_fault_probe(
        &self,
        name: &'static str,
        memory_budget: usize,
    ) -> Option<Arc<Component>> {
        let store_root = self.store?;
        let space = Space::new(name);
        let service = {
            let init = self.spaces["init"].0.lock();
            cap::grant(
                &init,
                store_root,
                Rights::READ.union(Rights::WRITE),
                &mut space.0.lock(),
            )
            .expect("init retains the object-store grant root")
        };
        Some(self.spawn_component_inner(
            name,
            space.clone(),
            memory_budget,
            Some(ComponentTemplate::StoreFaultProbe),
            store_fault_probe_task(SpaceRef::new(&space), service),
        ))
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
    /// strings that merely happen to match. The test shell owns `init`; the
    /// default `vsh` component owns the separate least-authority `vsh` space.
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
            assert!(
                !recovered,
                "an allocation domain must identify one component"
            );
            // Safety: the exact current incarnation was found above, and the
            // executor contract supplied by this method's caller makes it
            // terminal before this direct lock-state recovery.
            let _ = unsafe { component.space.0.recover_after_fault(domain) };
            recovered = true;
        }
        assert!(
            recovered,
            "faulted allocation domain has no component owner"
        );
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
    let durable_cspace = world.durable_cspace_service.clone();
    exec::spawn("supervisor:virtio-blk", async move {
        let mut attempts = 0u32;
        let mut recovery_operation =
            durable_cspace
                .as_ref()
                .and_then(|service| match service.begin_boot_recovery() {
                    Ok(operation) => Some(operation),
                    Err(_) => {
                        service.fail_closed();
                        None
                    }
                });
        let mut recovery_pending = recovery_operation.is_some();

        // Reuse the pre-existing supervisor task instead of consuming new
        // TaskIds. While the recovery gate waits for an online device, driver
        // terminal state remains higher priority and uses the same bounded
        // restart budget as steady-state supervision. Every transient scan
        // failure returns the gate to WaitingBlock and starts at sector zero.
        while recovery_pending {
            let snapshot = component.snapshot();
            match snapshot.state {
                exec::TaskState::Running if block_device::is_online() => {
                    let service = durable_cspace
                        .as_ref()
                        .expect("a pending durable recovery has a service");
                    match service.recover_after_block_online().await {
                        Ok(()) => {
                            if service.activate_dependent().await.is_err() {
                                recovery_operation
                                    .take()
                                    .expect("pending recovery has an exact claim")
                                    .fail();
                            } else {
                                recovery_operation
                                    .take()
                                    .expect("pending recovery has an exact claim")
                                    .finish();
                            }
                            recovery_pending = false;
                        }
                        Err(_)
                            if service.state()
                                == durable_cspace::DurableCSpaceState::WaitingBlock => {}
                        Err(_) => {
                            recovery_operation
                                .take()
                                .expect("pending recovery has an exact claim")
                                .fail();
                            recovery_pending = false;
                        }
                    }
                }
                exec::TaskState::Running => {}
                exec::TaskState::Faulted if attempts < 3 => {
                    exec::sleep_ms(10u64 << attempts).await;
                    attempts += 1;
                    if world.restart_component("virtio-blk").is_err() {
                        if let Some(operation) = recovery_operation.take() {
                            operation.fail();
                        }
                        return;
                    }
                }
                exec::TaskState::Faulted => {
                    if let Some(operation) = recovery_operation.take() {
                        operation.fail();
                    }
                    return;
                }
                exec::TaskState::Cancelled | exec::TaskState::Exited => {
                    // Preserve the operator's decision. An explicit restart
                    // changes the generation and this loop then resumes.
                    exec::sleep_ms(100).await;
                }
            }
            if recovery_pending {
                exec::sleep_ms(1).await;
            }
        }

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

/// Restart only faulted network-driver incarnations, with the same bounded
/// exponential policy as the block driver. Cancellation remains an explicit
/// operator decision and is never mistaken for a crash.
pub fn start_net_supervisor() {
    let world = world();
    let Some(component) = world.component_named("virtio-net") else {
        return;
    };
    exec::spawn("supervisor:virtio-net", async move {
        let mut attempts = 0u32;
        loop {
            let (generation, join) = component.join_current();
            let exit = join.await;
            match exit.state() {
                exec::TaskState::Faulted if attempts < 3 => {
                    exec::sleep_ms(10u64 << attempts).await;
                    attempts += 1;
                    if world.restart_component("virtio-net").is_err() {
                        return;
                    }
                }
                exec::TaskState::Cancelled | exec::TaskState::Exited => loop {
                    if component.snapshot().generation > generation {
                        break;
                    }
                    exec::sleep_ms(100).await;
                },
                exec::TaskState::Faulted | exec::TaskState::Running => return,
            }
        }
    });
}

/// Restart only faulted entropy-driver incarnations. A failed or unconfirmed
/// device reset remains quarantined inside the driver and cannot be converted
/// into synthetic output by the supervisor.
#[cfg(feature = "qemu-virt")]
pub fn start_rng_supervisor() {
    let world = world();
    let Some(component) = world.component_named("virtio-rng") else {
        return;
    };
    exec::spawn("supervisor:virtio-rng", async move {
        let mut attempts = 0u32;
        loop {
            let (generation, join) = component.join_current();
            let exit = join.await;
            match exit.state() {
                exec::TaskState::Faulted if attempts < 3 => {
                    exec::sleep_ms(10u64 << attempts).await;
                    attempts += 1;
                    if world.restart_component("virtio-rng").is_err() {
                        return;
                    }
                }
                exec::TaskState::Cancelled | exec::TaskState::Exited => loop {
                    if component.snapshot().generation > generation {
                        break;
                    }
                    exec::sleep_ms(100).await;
                },
                exec::TaskState::Faulted | exec::TaskState::Running => return,
            }
        }
    });
}

/// Restart only faulted TCP-stack incarnations. Stack generations are rebound
/// by the fresh task before it consumes ingress, so cancellation remains an
/// operator decision while an audited fault can safely recover service.
#[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
pub fn start_ipv4_stack_supervisor() {
    let world = world();
    let Some(component) = world.component_named(crate::netstack_platform::COMPONENT_NAME) else {
        return;
    };
    exec::spawn("supervisor:ipv4-stack", async move {
        let mut attempts = 0u32;
        loop {
            let (generation, join) = component.join_current();
            let exit = join.await;
            match exit.state() {
                exec::TaskState::Faulted if attempts < 3 => {
                    exec::sleep_ms(10u64 << attempts).await;
                    attempts += 1;
                    if world
                        .restart_component(crate::netstack_platform::COMPONENT_NAME)
                        .is_err()
                    {
                        return;
                    }
                }
                exec::TaskState::Cancelled | exec::TaskState::Exited => loop {
                    if component.snapshot().generation > generation {
                        break;
                    }
                    exec::sleep_ms(100).await;
                },
                exec::TaskState::Faulted | exec::TaskState::Running => return,
            }
        }
    });
}

/// Restart only faulted SSH acceptance-server incarnations. A fresh template
/// receives newly derived network, entropy, signer, and authorization grants;
/// explicit cancellation remains an operator decision.
#[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
pub fn start_ssh_test_supervisor() {
    let world = world();
    let Some(component) = world.component_named("ssh-test") else {
        return;
    };
    exec::spawn("supervisor:ssh-test", async move {
        let mut attempts = 0u32;
        loop {
            let (generation, join) = component.join_current();
            let exit = join.await;
            match exit.state() {
                exec::TaskState::Faulted if attempts < 3 => {
                    exec::sleep_ms(10u64 << attempts).await;
                    attempts += 1;
                    if world.restart_component("ssh-test").is_err() {
                        return;
                    }
                }
                exec::TaskState::Cancelled | exec::TaskState::Exited => loop {
                    if component.snapshot().generation > generation {
                        break;
                    }
                    exec::sleep_ms(100).await;
                },
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
    #[cfg(not(feature = "legacy-shell"))]
    let vsh = Space::new("vsh");
    let sensor = Space::new("sensor");
    let logger = Space::new("logger");
    let guest = Space::new("guest");
    let prog = Space::new("prog");
    let block_resources = block_device::discover();
    let saved_program_policy = block_resources
        .as_ref()
        .map(|_| Space::new("saved-program-policy"));
    let saved_program_space = block_resources
        .as_ref()
        .map(|_| Space::new_persistent("saved-program", crate::program::program_space_id()));
    let block_space = block_resources.as_ref().map(|_| Space::new("virtio-blk"));
    let net_resources = net_device::discover();
    let net_space = net_resources.as_ref().map(|_| Space::new("virtio-net"));
    let net_policy = net_resources
        .as_ref()
        .map(|_| Space::new("virtio-net-policy"));
    #[cfg(feature = "qemu-virt")]
    let rng_resources = virtio_rng::discover();
    #[cfg(all(feature = "milkv-duo", feature = "milkv-ssh-acceptance"))]
    let rng_resources = Some(crate::ssh_acceptance_rng::provision());
    #[cfg(feature = "qemu-virt")]
    let rng_space = rng_resources.as_ref().map(|_| Space::new("virtio-rng"));
    #[cfg(feature = "qemu-virt")]
    let rng_policy = rng_resources
        .as_ref()
        .map(|_| Space::new("virtio-rng-policy"));
    #[cfg(all(feature = "milkv-duo", feature = "milkv-ssh-acceptance"))]
    let rng_policy = rng_resources
        .as_ref()
        .map(|_| Space::new("ssh-acceptance-random-policy"));
    #[cfg(feature = "ssh-security-test")]
    let ssh_security_test_space = rng_resources
        .as_ref()
        .map(|_| Space::new("ssh-security-test"));
    #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
    let ssh_test_space = net_resources
        .as_ref()
        .zip(rng_resources.as_ref())
        .map(|_| Space::new("ssh-test"));
    #[cfg(any(
        feature = "ssh-security-test",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance"
    ))]
    let ssh_security_policy = rng_resources
        .as_ref()
        .map(|_| Space::new("ssh-security-policy"));
    #[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
    let tcp_echo_space = net_resources
        .as_ref()
        .map(|_| Space::new(crate::netstack_platform::COMPONENT_NAME));
    let store_backend = block_resources
        .as_ref()
        .map(|_| Space::new("store-backend"));
    let persistent_test = block_resources
        .as_ref()
        .map(|_| Space::new_persistent("persistent-test", durable_cspace::persistent_space_id()));

    // A saved program's ephemeral boot-resource authority is rooted in an
    // explicit supervisor-only CSpace. The canonical artifact manifest permits
    // exactly console WRITE and memory READ|WRITE; no `prog` CSpace cap is used.
    let (saved_console_policy, saved_memory_policy) = match saved_program_policy.as_ref() {
        Some(policy) => {
            let mut policy = policy.0.lock();
            (
                Some(policy.mint(console.clone(), Rights::ALL)),
                Some(policy.mint(region.clone(), Rights::ALL)),
            )
        }
        None => (None, None),
    };

    // init is the root of authority: it mints the only unattenuated caps, then
    // hands out strictly weaker copies. Nothing else can widen what it gets.
    let mut cs = init.0.lock();
    let c_console = cs.mint(console.clone(), Rights::ALL);
    #[cfg(not(feature = "legacy-shell"))]
    let vsh_console = cap::grant(&cs, c_console, Rights::WRITE, &mut vsh.0.lock()).unwrap();
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
                (
                    Some(service_root),
                    Some(mmio_root),
                    Some(dma_root),
                    Some(grants),
                )
            }
            (None, None) => (None, None, None, None),
            _ => unreachable!("block resources and CSpace are constructed together"),
        };
    let (
        net_outbound,
        net_inbound,
        net_control,
        net_mmio_root,
        net_dma_root,
        net_outbound_root,
        net_inbound_root,
        net_control_root,
        net_grants,
    ) = match (net_resources, net_space.as_ref(), net_policy.as_ref()) {
        (Some(resources), Some(driver_space), Some(policy_space)) => {
            let outbound: Arc<NetEndpoint<StampedPacket>> =
                NetEndpoint::new("net-outbound", crate::net_device::FRONTEND_QUEUE_DEPTH);
            let inbound: Arc<NetEndpoint<StampedPacket>> =
                NetEndpoint::new("net-inbound", crate::net_device::FRONTEND_QUEUE_DEPTH);
            let mut policy = policy_space.0.lock();
            let mmio_root = policy.mint(resources.mmio, Rights::ALL);
            let dma_root = policy.mint(resources.dma, Rights::ALL);
            let outbound_root = policy.mint(outbound, Rights::ALL);
            let inbound_root = policy.mint(inbound, Rights::ALL);
            let control_root = policy.mint(resources.control, Rights::ALL_VOLATILE);

            // Diagnostic images expose the directional raw-L2 API to init.
            // Protocol acceptance images make their stack the sole client:
            // init must not race ingress, inject frames, or fault the device
            // underneath either TCP or SSH session state.
            #[cfg(not(any(
                feature = "tcp-echo",
                feature = "net-shell",
                feature = "ssh-test",
                feature = "milkv-ssh-acceptance"
            )))]
            let (init_outbound, init_inbound, init_control) = (
                Some(cap::grant(&policy, outbound_root, Rights::SEND, &mut cs).unwrap()),
                Some(cap::grant(&policy, inbound_root, Rights::RECV, &mut cs).unwrap()),
                Some(
                    cap::grant(
                        &policy,
                        control_root,
                        Rights::READ.union(Rights::WRITE).union(Rights::INVOKE),
                        &mut cs,
                    )
                    .unwrap(),
                ),
            );
            #[cfg(any(
                feature = "tcp-echo",
                feature = "net-shell",
                feature = "ssh-test",
                feature = "milkv-ssh-acceptance"
            ))]
            let (init_outbound, init_inbound, init_control) = (None, None, None);

            let mut target = driver_space.0.lock();
            let grants = (
                cap::grant(
                    &policy,
                    mmio_root,
                    Rights::READ.union(Rights::WRITE),
                    &mut target,
                )
                .unwrap(),
                cap::grant(
                    &policy,
                    dma_root,
                    Rights::READ.union(Rights::WRITE),
                    &mut target,
                )
                .unwrap(),
                cap::grant(&policy, outbound_root, Rights::RECV, &mut target).unwrap(),
                cap::grant(&policy, inbound_root, Rights::SEND, &mut target).unwrap(),
                cap::grant(&policy, control_root, Rights::READ, &mut target).unwrap(),
            );
            drop(target);
            drop(policy);
            (
                init_outbound,
                init_inbound,
                init_control,
                Some(mmio_root),
                Some(dma_root),
                Some(outbound_root),
                Some(inbound_root),
                Some(control_root),
                Some(grants),
            )
        }
        (None, None, None) => (None, None, None, None, None, None, None, None, None),
        _ => unreachable!("network resources and CSpaces are constructed together"),
    };
    #[cfg(feature = "qemu-virt")]
    let (rng_mmio_root, rng_dma_root, rng_source_root, rng_grants) =
        match (rng_resources, rng_space.as_ref(), rng_policy.as_ref()) {
            (Some(resources), Some(driver_space), Some(policy_space)) => {
                let mut policy = policy_space.0.lock();
                let mmio_root = policy.mint(resources.mmio, Rights::ALL);
                let dma_root = policy.mint(resources.dma, Rights::ALL);
                let source_root = policy.mint(resources.source, Rights::ALL);
                let mut target = driver_space.0.lock();
                let grants = (
                    cap::grant(
                        &policy,
                        mmio_root,
                        Rights::READ.union(Rights::WRITE),
                        &mut target,
                    )
                    .unwrap(),
                    cap::grant(
                        &policy,
                        dma_root,
                        Rights::READ.union(Rights::WRITE),
                        &mut target,
                    )
                    .unwrap(),
                    cap::grant(&policy, source_root, Rights::READ, &mut target).unwrap(),
                );
                drop(target);
                drop(policy);
                (
                    Some(mmio_root),
                    Some(dma_root),
                    Some(source_root),
                    Some(grants),
                )
            }
            (None, None, None) => (None, None, None, None),
            _ => unreachable!("entropy resources and CSpaces are constructed together"),
        };
    #[cfg(all(feature = "milkv-duo", feature = "milkv-ssh-acceptance"))]
    let rng_source_root = match (rng_resources, rng_policy.as_ref()) {
        (Some(resources), Some(policy_space)) => {
            let mut policy = policy_space.0.lock();
            Some(policy.mint(resources.source, Rights::ALL))
        }
        (None, None) => None,
        _ => unreachable!("acceptance entropy resource and policy are constructed together"),
    };
    #[cfg(any(
        feature = "ssh-security-test",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance"
    ))]
    let (ssh_signer_root, ssh_authorized_policy_root) = match ssh_security_policy.as_ref() {
        Some(security_space) => {
            let resources = crate::ssh_test_fixture::provision();
            let mut security = security_space.0.lock();
            let signer_root = security.mint(resources.signer, Rights::ALL_VOLATILE);
            let authorized_policy_root = security.mint(resources.policy, Rights::ALL);
            (Some(signer_root), Some(authorized_policy_root))
        }
        None => (None, None),
    };
    #[cfg(feature = "ssh-security-test")]
    let ssh_security_test_grants = ssh_security_test_space.as_ref().map(|test_space| {
        let entropy = rng_policy
            .as_ref()
            .expect("SSH security test requires the entropy policy")
            .0
            .lock();
        let security = ssh_security_policy
            .as_ref()
            .expect("SSH security test requires the security policy")
            .0
            .lock();
        let mut target = test_space.0.lock();
        (
            cap::grant(
                &entropy,
                rng_source_root.expect("SSH security test requires the entropy root"),
                Rights::READ,
                &mut target,
            )
            .unwrap(),
            cap::grant(
                &security,
                ssh_signer_root.expect("SSH security test requires the signer root"),
                Rights::READ,
                &mut target,
            )
            .unwrap(),
            cap::grant(
                &security,
                ssh_signer_root.expect("SSH security test requires the signer root"),
                Rights::INVOKE,
                &mut target,
            )
            .unwrap(),
            cap::grant(
                &security,
                ssh_authorized_policy_root
                    .expect("SSH security test requires the authorized-policy root"),
                Rights::READ,
                &mut target,
            )
            .unwrap(),
        )
    });
    #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
    let ssh_test_grants = ssh_test_space.as_ref().map(|test_space| {
        let network = net_policy
            .as_ref()
            .expect("SSH test requires the network policy")
            .0
            .lock();
        let entropy = rng_policy
            .as_ref()
            .expect("SSH test requires the entropy policy")
            .0
            .lock();
        let security = ssh_security_policy
            .as_ref()
            .expect("SSH test requires the security policy")
            .0
            .lock();
        let mut target = test_space.0.lock();
        (
            cap::grant(
                &network,
                net_outbound_root.expect("SSH test requires the outbound root"),
                Rights::SEND,
                &mut target,
            )
            .unwrap(),
            cap::grant(
                &network,
                net_inbound_root.expect("SSH test requires the inbound root"),
                Rights::RECV,
                &mut target,
            )
            .unwrap(),
            cap::grant(
                &network,
                net_control_root.expect("SSH test requires the network control root"),
                Rights::READ.union(Rights::INVOKE),
                &mut target,
            )
            .unwrap(),
            cap::grant(
                &entropy,
                rng_source_root.expect("SSH test requires the entropy root"),
                Rights::READ,
                &mut target,
            )
            .unwrap(),
            cap::grant(
                &security,
                ssh_signer_root.expect("SSH test requires the signer root"),
                Rights::READ,
                &mut target,
            )
            .unwrap(),
            cap::grant(
                &security,
                ssh_signer_root.expect("SSH test requires the signer root"),
                Rights::INVOKE,
                &mut target,
            )
            .unwrap(),
            cap::grant(
                &security,
                ssh_authorized_policy_root.expect("SSH test requires the authorized-policy root"),
                Rights::READ,
                &mut target,
            )
            .unwrap(),
        )
    });
    #[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
    let tcp_echo_grants = match (
        net_policy.as_ref(),
        tcp_echo_space.as_ref(),
        net_outbound_root,
        net_inbound_root,
        net_control_root,
    ) {
        (Some(policy_space), Some(stack_space), Some(outbound), Some(inbound), Some(control)) => {
            let policy = policy_space.0.lock();
            let mut target = stack_space.0.lock();
            Some((
                cap::grant(&policy, outbound, Rights::SEND, &mut target).unwrap(),
                cap::grant(&policy, inbound, Rights::RECV, &mut target).unwrap(),
                cap::grant(
                    &policy,
                    control,
                    Rights::READ.union(Rights::INVOKE),
                    &mut target,
                )
                .unwrap(),
            ))
        }
        (None, None, None, None, None) => None,
        _ => unreachable!("TCP echo grants exist exactly when a network device exists"),
    };
    let (store_root, durable_cspace_root, durable_cspace_service, saved_program_root) = match (
        block_root,
        store_backend.as_ref(),
        persistent_test.as_ref(),
        saved_program_space.as_ref(),
        saved_program_policy.as_ref(),
        saved_console_policy,
        saved_memory_policy,
    ) {
        (
            Some(block),
            Some(backend),
            Some(persistent),
            Some(saved_target),
            Some(saved_policy),
            Some(saved_console),
            Some(saved_memory),
        ) => {
            // The store receives only block read/write authority in a private
            // backend CSpace. Its public service cap discloses neither the
            // device nor stable object identifiers.
            let block_grant = cap::grant(
                &cs,
                block,
                Rights::READ.union(Rights::WRITE),
                &mut backend.0.lock(),
            )
            .unwrap();
            let service = crate::store_platform::new_service(backend.clone(), block_grant);
            let journal = service.authority_journal();
            let store_cap = cs.mint(service, Rights::ALL);
            let saved = saved_program::SavedProgramService::new(
                journal.clone(),
                saved_target.clone(),
                saved_policy.clone(),
                saved_console,
                saved_memory,
            );
            let durable = durable_cspace::DurableCSpaceService::new(
                journal,
                persistent.clone(),
                saved.clone(),
            );
            let durable_cap = cs.mint(durable.clone(), Rights::READ.union(Rights::WRITE));
            let saved_cap = cs.mint(saved, Rights::READ.union(Rights::WRITE));
            (
                Some(store_cap),
                Some(durable_cap),
                Some(durable),
                Some(saved_cap),
            )
        }
        (None, None, None, None, None, None, None) => (None, None, None, None),
        _ => unreachable!("store backend exists exactly when a block device exists"),
    };
    drop(cs);

    let mut spaces = BTreeMap::from([
        ("init", init),
        ("sensor", sensor.clone()),
        ("logger", logger.clone()),
        ("guest", guest.clone()),
        ("prog", prog),
    ]);
    #[cfg(not(feature = "legacy-shell"))]
    spaces.insert("vsh", vsh);
    if let Some(space) = block_space.as_ref() {
        spaces.insert("virtio-blk", space.clone());
    }
    if let Some(space) = net_space.as_ref() {
        spaces.insert("virtio-net", space.clone());
    }
    if let Some(space) = net_policy.as_ref() {
        spaces.insert("virtio-net-policy", space.clone());
    }
    #[cfg(feature = "qemu-virt")]
    if let Some(space) = rng_space.as_ref() {
        spaces.insert("virtio-rng", space.clone());
    }
    #[cfg(feature = "qemu-virt")]
    if let Some(space) = rng_policy.as_ref() {
        spaces.insert("virtio-rng-policy", space.clone());
    }
    #[cfg(all(feature = "milkv-duo", feature = "milkv-ssh-acceptance"))]
    if let Some(space) = rng_policy.as_ref() {
        spaces.insert("ssh-acceptance-random-policy", space.clone());
    }
    #[cfg(feature = "ssh-security-test")]
    if let Some(space) = ssh_security_test_space.as_ref() {
        spaces.insert("ssh-security-test", space.clone());
    }
    #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
    if let Some(space) = ssh_test_space.as_ref() {
        spaces.insert("ssh-test", space.clone());
    }
    #[cfg(any(
        feature = "ssh-security-test",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance"
    ))]
    if let Some(space) = ssh_security_policy.as_ref() {
        spaces.insert("ssh-security-policy", space.clone());
    }
    #[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
    if let Some(space) = tcp_echo_space.as_ref() {
        spaces.insert(crate::netstack_platform::COMPONENT_NAME, space.clone());
    }
    if let Some(space) = store_backend.as_ref() {
        spaces.insert("store-backend", space.clone());
    }
    if let Some(space) = persistent_test.as_ref() {
        spaces.insert("persistent-test", space.clone());
    }
    if let Some(space) = saved_program_policy.as_ref() {
        spaces.insert("saved-program-policy", space.clone());
    }
    if let Some(space) = saved_program_space.as_ref() {
        spaces.insert("saved-program", space.clone());
    }

    let world = Arc::new(World {
        spaces,
        components: SpinLock::new(BTreeMap::new()),
        console: c_console,
        #[cfg(not(feature = "legacy-shell"))]
        vsh_console,
        telemetry: c_telemetry,
        guest_space: c_guest_space,
        prog_space: c_prog_space,
        prog_console: prog_con,
        prog_memory: prog_mem,
        region: init_region,
        block: block_root,
        store: store_root,
        saved_program: saved_program_root,
        durable_cspace: durable_cspace_root,
        durable_cspace_service,
        block_space: c_block_space,
        block_mmio: block_mmio_root,
        block_dma: block_dma_root,
        net_outbound,
        net_inbound,
        net_control,
        net_policy,
        net_mmio: net_mmio_root,
        net_dma: net_dma_root,
        net_outbound_root,
        net_inbound_root,
        net_control_root,
        #[cfg(any(feature = "qemu-virt", feature = "milkv-ssh-acceptance"))]
        rng_policy,
        #[cfg(feature = "qemu-virt")]
        rng_mmio: rng_mmio_root,
        #[cfg(feature = "qemu-virt")]
        rng_dma: rng_dma_root,
        #[cfg(any(feature = "qemu-virt", feature = "milkv-ssh-acceptance"))]
        rng_source_root,
        #[cfg(any(
            feature = "ssh-security-test",
            feature = "ssh-test",
            feature = "milkv-ssh-acceptance"
        ))]
        ssh_security_policy,
        #[cfg(any(
            feature = "ssh-security-test",
            feature = "ssh-test",
            feature = "milkv-ssh-acceptance"
        ))]
        ssh_signer_root,
        #[cfg(any(
            feature = "ssh-security-test",
            feature = "ssh-test",
            feature = "milkv-ssh-acceptance"
        ))]
        ssh_authorized_policy_root,
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
            Some(ComponentTemplate::BlockDriver),
            block_device::driver_task(SpaceRef::new(&space).get(), mmio, dma, service),
        );
    }

    if let (Some(space), Some((mmio, dma, outbound, inbound, control))) = (net_space, net_grants) {
        world.spawn_component_inner(
            "virtio-net",
            space.clone(),
            BACKGROUND_MEMORY_BUDGET,
            Some(ComponentTemplate::NetDriver),
            net_device::driver_task(
                SpaceRef::new(&space).get(),
                mmio,
                dma,
                outbound,
                inbound,
                control,
            ),
        );
    }

    #[cfg(feature = "qemu-virt")]
    if let (Some(space), Some((mmio, dma, source))) = (rng_space, rng_grants) {
        world.spawn_component_inner(
            "virtio-rng",
            space.clone(),
            BACKGROUND_MEMORY_BUDGET,
            Some(ComponentTemplate::VirtioRng),
            virtio_rng::driver_task(SpaceRef::new(&space).get(), mmio, dma, source),
        );
    }

    #[cfg(feature = "ssh-security-test")]
    if let (Some(space), Some((random, signer_read, signer_invoke, policy))) =
        (ssh_security_test_space, ssh_security_test_grants)
    {
        world.spawn_component_inner(
            "ssh-security-test",
            space.clone(),
            BACKGROUND_MEMORY_BUDGET,
            Some(ComponentTemplate::SshSecurityTest),
            crate::ssh_security_test::task(
                SpaceRef::new(&space).get(),
                random,
                signer_read,
                signer_invoke,
                policy,
            ),
        );
    }

    #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
    if let (
        Some(space),
        Some((outbound, inbound, control, random, signer_read, signer_invoke, policy)),
    ) = (ssh_test_space, ssh_test_grants)
    {
        world.spawn_component_inner(
            "ssh-test",
            space.clone(),
            SSH_TEST_MEMORY_BUDGET,
            Some(ComponentTemplate::SshTest),
            crate::ssh_platform::task(
                SpaceRef::new(&space).get(),
                outbound,
                inbound,
                control,
                random,
                signer_read,
                signer_invoke,
                policy,
            ),
        );
    }

    #[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
    if let (Some(space), Some((outbound, inbound, control))) = (tcp_echo_space, tcp_echo_grants) {
        world.spawn_component_inner(
            crate::netstack_platform::COMPONENT_NAME,
            space.clone(),
            BACKGROUND_MEMORY_BUDGET,
            Some(ComponentTemplate::Ipv4Stack),
            crate::netstack_platform::task(SpaceRef::new(&space).get(), outbound, inbound, control),
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

/// Audited target-only probe for M3.12 and M6.3. It leaves a live Vec, a sealed
/// code-pool allocation, and a destructor bomb behind, then quota-faults while
/// holding the generation's CSpace lock. Restart must recover the lock and both
/// allocation domains without running Drop.
async fn fault_probe_task(space: SpaceRef, memory_budget: usize) {
    let _must_not_drop = FaultProbeDrop;
    let mut code = crate::code_pool::WritableCode::allocate(1)
        .expect("fault probe must reserve one code-pool page");
    code.words_mut()[0] = 0x0000_8067; // ret
    let _abandoned_code = code.seal();
    let mut held = Vec::new();
    held.resize(512, 0xA5);
    let _abandoned_cspace = space.get().0.lock();
    held.resize(memory_budget.saturating_mul(2), 0x5A);
    panic!("fault probe unexpectedly stayed within its allocation quota");
}

/// Audited M4.2 probe. It allocates the normal recovery/transaction working
/// set, then faults after taking the store claim and before the first write.
/// Raw teardown must reclaim both the caller arena and the abandoned claim.
async fn store_fault_probe_task(space: SpaceRef, service: Cap) {
    const MARKER: &[u8] = b"VIBEOS-STORE-FAULT-PROBE-v1";
    let mut payload: Vec<u8> = (0..900)
        .map(|index| ((index * 29 + 7) % 251) as u8)
        .collect();
    payload[..MARKER.len()].copy_from_slice(MARKER);
    let kind = store::journal_object_kind(0xF042).expect("fault-probe object kind is non-zero");
    let lease = space
        .get()
        .0
        .lock()
        .lookup_lease::<store::StoreService>(service, Rights::WRITE)
        .expect("store fault probe receives an explicit write grant");
    let result =
        store::put_with_static_fault_before_write(lease, space.get(), kind, &payload).await;
    panic!("injected store fault unexpectedly returned: {result:?}");
}
