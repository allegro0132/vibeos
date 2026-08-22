//! C5.3 native-async driver shared by two sealed image roots.
//!
//! The direct QEMU fixture retains its acceptance-only pin and cleanup-free
//! start envelope. The formal command feature instead retains the opaque
//! projection produced by `component-image-adapter` and can start only through
//! a VSH-managed cleanup lease. Both use the same exact driver and SYSTEM
//! pending-operation shadow while the validation-only profile and runtime
//! readiness bits remain inert.

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
use super::native_pending_shadow_model::ExactRevokeDecision;
use super::native_pending_shadow_model::{
    exact_backend_cancel_then_release, BackendEffect, ExactBackendAction,
    ExactBackendPendingKind as PendingKind, ExactBackendReturn, ExactCancelCause, ExactCancelPlan,
    ExactCleanupDecision, ExactContinuation, ExactContinuationCleanup, ExactHostFunction,
    ExactInputSpillReceipt, ExactInstanceIdentity, ExactLedgerError, ExactLedgerPhase,
    ExactLedgerSnapshot, ExactNativeLeaseBranch, ExactNativeLeaseContinuationReceipt,
    ExactNativeLeaseError, ExactNativeLeaseLedger, ExactOperationLedger, ExactResidualCancelPlan,
    ExactResourceRevokePlan, ExactResourceState, ExactRuntimeCleanup, ExactRuntimeToken,
    ExactStreamResource, InputSpill, OutputStaging, DRIVER_CHUNK_BYTES, EXACT_NATIVE_LEASE_LIMIT,
};
use super::*;
use crate::instance::{
    FaultContinuationAbandonReceipt, InstanceContinuationConsumed, InstanceContinuationToken,
};

#[cfg(all(
    feature = "wasm-c53-native-async-qemu-acceptance",
    not(feature = "ssh-native-async-command")
))]
use vibeos_component_admission::admit_native_async_acceptance_candidate;
#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
use vibeos_component_admission::AdmittedNativeAsyncAcceptanceCandidate;
#[cfg(not(all(
    feature = "wasm-c53-native-async-qemu-acceptance",
    feature = "ssh-native-async-command"
)))]
use vibeos_component_format::{ProfileIdentity, ProfileStage};
#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
use vibeos_component_host::STREAM_BUFFER_CHUNKS;
use vibeos_component_host::{StreamCloseObservation, StreamTerminalDispatch};
#[cfg(all(
    feature = "ssh-native-async-command",
    not(feature = "wasm-c53-native-async-qemu-acceptance")
))]
use vibeos_component_image_adapter::project_native_async_command;
#[cfg(feature = "ssh-native-async-command")]
use vibeos_component_image_adapter::NativeAsyncCommandProjection;
use vibeos_component_runtime::decode::ComponentPlan;
use vibeos_component_runtime::native_async_acceptance::{
    Component as NativeComponent, Error as NativeError, FinalizeError as NativeFinalizeError,
    HostRequest as NativeHostRequest, HostToken as NativeHostToken, Invocation as NativeInvocation,
    Poll as NativePoll, WaitRegistration as NativeWaitRegistration, WaitToken as NativeWaitToken,
};
#[cfg(feature = "ssh-native-async-command")]
use vibeos_image_policy::C53_NATIVE_ASYNC_COMMAND;
#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
use vibeos_image_policy::C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
const NATIVE_LIFECYCLE_HEALTHY: u8 = 0;
#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
const NATIVE_LIFECYCLE_FAILED: u8 = 1;

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
static NATIVE_LIFECYCLE_HEALTH: AtomicU8 = AtomicU8::new(NATIVE_LIFECYCLE_HEALTHY);
static NATIVE_POLICY_GATE: AtomicU8 = AtomicU8::new(POLICY_CLOSED);
static IMAGE_ROOT: AtomicPtr<NativeImageRoot> = AtomicPtr::new(ptr::null_mut());
#[cfg(feature = "ssh-native-async-command")]
static LIFECYCLE: NativeImageComponentLifecycle = NativeImageComponentLifecycle;

struct NativeImageRoot {
    #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
    admitted: AdmittedNativeAsyncAcceptanceCandidate,
    #[cfg(feature = "ssh-native-async-command")]
    projection: NativeAsyncCommandProjection,
    #[cfg(feature = "ssh-native-async-command")]
    ssh_policy: SshExecComponentPolicy,
    incarnation: NonZeroU64,
}

impl NativeImageRoot {
    fn validated_plan(&self) -> Result<ComponentPlan<'_>, ()> {
        #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
        {
            return self.admitted.validated_plan().map_err(|_| ());
        }
        #[cfg(all(
            feature = "ssh-native-async-command",
            not(feature = "wasm-c53-native-async-qemu-acceptance")
        ))]
        {
            self.projection.validated_plan().map_err(|_| ())
        }
    }

    fn entrypoint(&self) -> &str {
        #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
        {
            return self.admitted.entrypoint();
        }
        #[cfg(all(
            feature = "ssh-native-async-command",
            not(feature = "wasm-c53-native-async-qemu-acceptance")
        ))]
        {
            self.projection.manifest().entrypoint()
        }
    }

    fn memory_bytes(&self) -> usize {
        #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
        {
            return self.admitted.limits().memory_bytes;
        }
        #[cfg(all(
            feature = "ssh-native-async-command",
            not(feature = "wasm-c53-native-async-qemu-acceptance")
        ))]
        {
            self.projection.manifest().memory_bytes()
        }
    }

    fn total_fuel(&self) -> u64 {
        #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
        {
            return self.admitted.limits().total_fuel;
        }
        #[cfg(all(
            feature = "ssh-native-async-command",
            not(feature = "wasm-c53-native-async-qemu-acceptance")
        ))]
        {
            self.projection.manifest().total_fuel()
        }
    }

    fn poll_quantum(&self) -> u64 {
        #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
        {
            return self.admitted.limits().poll_quantum;
        }
        #[cfg(all(
            feature = "ssh-native-async-command",
            not(feature = "wasm-c53-native-async-qemu-acceptance")
        ))]
        {
            self.projection.manifest().poll_quantum()
        }
    }

    fn resource_limit(&self) -> u16 {
        #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
        {
            return self.admitted.limits().resources;
        }
        #[cfg(all(
            feature = "ssh-native-async-command",
            not(feature = "wasm-c53-native-async-qemu-acceptance")
        ))]
        {
            self.projection.manifest().resource_limit()
        }
    }
}

pub(super) fn lifecycle_is_healthy() -> bool {
    #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
    {
        return NATIVE_LIFECYCLE_HEALTH.load(Ordering::Acquire) == NATIVE_LIFECYCLE_HEALTHY;
    }
    #[cfg(all(
        feature = "ssh-native-async-command",
        not(feature = "wasm-c53-native-async-qemu-acceptance")
    ))]
    {
        super::lifecycle_is_healthy()
    }
}

pub(super) fn lifecycle_poll_permit() -> (&'static AtomicU8, u8) {
    #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
    {
        return (&NATIVE_LIFECYCLE_HEALTH, NATIVE_LIFECYCLE_HEALTHY);
    }
    #[cfg(all(
        feature = "ssh-native-async-command",
        not(feature = "wasm-c53-native-async-qemu-acceptance")
    ))]
    {
        super::lifecycle_poll_permit()
    }
}

pub(super) fn lifecycle_fail_stop() {
    CONTROL.reject_prepared_publications();
    NATIVE_POLICY_GATE.store(POLICY_FAILED, Ordering::Release);
    #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
    NATIVE_LIFECYCLE_HEALTH.store(NATIVE_LIFECYCLE_FAILED, Ordering::Release);
    #[cfg(all(
        feature = "ssh-native-async-command",
        not(feature = "wasm-c53-native-async-qemu-acceptance")
    ))]
    super::lifecycle_fail_stop();
    CONTROL.request_fail_stop_wake();
}

#[cfg(feature = "ssh-native-async-command")]
pub(super) fn policy_gate_passed() -> bool {
    lifecycle_is_healthy() && NATIVE_POLICY_GATE.load(Ordering::Acquire) == POLICY_PASSED
}

pub(super) fn init() {
    if !IMAGE_ROOT.load(Ordering::Acquire).is_null() {
        lifecycle_fail_stop();
        panic!("native async image root initialized twice");
    }
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let root = match build_image_root() {
        Ok(root) => Box::new(root),
        Err(()) => {
            lifecycle_fail_stop();
            system.restore();
            panic!("native async image admission failed");
        }
    };
    let pointer = Box::into_raw(root);
    if IMAGE_ROOT
        .compare_exchange(
            ptr::null_mut(),
            pointer,
            Ordering::Release,
            Ordering::Acquire,
        )
        .is_err()
    {
        unsafe { drop(Box::from_raw(pointer)) };
        lifecycle_fail_stop();
        system.restore();
        panic!("native async image root publication raced");
    }
    let root = unsafe { &*pointer };
    if !revalidate_image_root(root) {
        lifecycle_fail_stop();
        system.restore();
        panic!("native async image root failed publication revalidation");
    }
    #[cfg(feature = "ssh-native-async-command")]
    if NATIVE_POLICY_GATE
        .compare_exchange(
            POLICY_CLOSED,
            POLICY_PASSED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        lifecycle_fail_stop();
        system.restore();
        panic!("native async command policy publication raced");
    }
    system.restore();
}

fn image_root() -> Option<&'static NativeImageRoot> {
    unsafe { IMAGE_ROOT.load(Ordering::Acquire).as_ref() }
}

pub(super) fn root_ready() -> bool {
    image_root().is_some_and(revalidate_image_root)
}

pub(super) fn command_name() -> &'static str {
    #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
    {
        return C53_NATIVE_ASYNC_QEMU_ACCEPTANCE.command_name();
    }
    #[cfg(all(
        feature = "ssh-native-async-command",
        not(feature = "wasm-c53-native-async-qemu-acceptance")
    ))]
    {
        C53_NATIVE_ASYNC_COMMAND.command_name()
    }
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
fn start_with_io(io: InstalledComponentIo) -> Result<ManagedComponentToken, ComponentTerminal> {
    start_image_instance_with_input(
        StartPolicyGate::None,
        PayloadMode::NativeAsyncAcceptance,
        ComponentStartInput::NativeAsyncAcceptance(Some(io)),
    )
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
fn admission_mode(mode: ComponentStreamMode) -> CommandStreamMode {
    match mode {
        ComponentStreamMode::Required => CommandStreamMode::Required,
        ComponentStreamMode::Optional => CommandStreamMode::Optional,
        ComponentStreamMode::Closed => CommandStreamMode::Closed,
    }
}

#[cfg(all(
    feature = "wasm-c53-native-async-qemu-acceptance",
    not(feature = "ssh-native-async-command")
))]
fn build_image_root() -> Result<NativeImageRoot, ()> {
    let pin = C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;
    let world = WorldContract::parse(pin.wit_source(), pin.world()).map_err(|_| ())?;
    let artifact =
        ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).map_err(|_| ())?;
    let identity = artifact.identity();
    if identity.as_bytes() != &pin.expected_sha256() {
        return Err(());
    }
    let limits = pin.limits();
    let admitted = admit_native_async_acceptance_candidate(
        artifact,
        &AdmissionPolicy {
            command_name: pin.command_name(),
            entrypoint: pin.entrypoint(),
            min_args: pin.min_args(),
            max_args: pin.max_args(),
            exact_world: &world,
            profile: pin.profile(),
            trust: ArtifactTrust::ImagePinned(identity),
            limits: InstanceLimits {
                memory_bytes: limits.memory_bytes,
                total_fuel: limits.total_fuel,
                poll_quantum: limits.poll_quantum,
                resources: limits.resources,
            },
            stdin: admission_mode(pin.stdin()),
            stdout: admission_mode(pin.stdout()),
            stderr: admission_mode(pin.stderr()),
            interfaces: &[],
        },
        &CallerAuthority { offers: &[] },
    )
    .map_err(|_| ())?;
    let root = NativeImageRoot {
        admitted,
        incarnation: NonZeroU64::new(1).expect("one is nonzero"),
    };
    if revalidate_image_root(&root) {
        Ok(root)
    } else {
        Err(())
    }
}

#[cfg(all(
    feature = "wasm-c53-native-async-qemu-acceptance",
    not(feature = "ssh-native-async-command")
))]
fn revalidate_image_root(root: &NativeImageRoot) -> bool {
    let pin = C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;
    if root.incarnation.get() != 1
        || root.admitted.identity().as_bytes() != &pin.expected_sha256()
        || root.admitted.command_name() != pin.command_name()
        || root.admitted.profile() != ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
        || root.admitted.profile().stage != ProfileStage::ValidationOnly
        || root.admitted.profile().execution_enabled()
        || root.admitted.world() != pin.world()
        || root.admitted.entrypoint() != pin.entrypoint()
        || root.admitted.min_args() != pin.min_args()
        || root.admitted.max_args() != pin.max_args()
        || root.admitted.stdin() != admission_mode(pin.stdin())
        || root.admitted.stdout() != admission_mode(pin.stdout())
        || root.admitted.stderr() != admission_mode(pin.stderr())
        || root.admitted.limits().memory_bytes != pin.limits().memory_bytes
        || root.admitted.limits().total_fuel != pin.limits().total_fuel
        || root.admitted.limits().poll_quantum != pin.limits().poll_quantum
        || root.admitted.limits().resources != pin.limits().resources
    {
        return false;
    }
    root.validated_plan().is_ok_and(|plan| {
        plan.profile() == ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
            && !plan.runtime_ready()
            && !plan.native_async_runtime_ready()
            && plan.native_async_execution_plan().is_some()
    })
}

#[cfg(all(
    feature = "ssh-native-async-command",
    not(feature = "wasm-c53-native-async-qemu-acceptance")
))]
fn build_image_root() -> Result<NativeImageRoot, ()> {
    let pin = C53_NATIVE_ASYNC_COMMAND;
    let projection = project_native_async_command(pin).map_err(|_| ())?;
    let limits = pin.limits();
    let ssh_policy = SshExecComponentPolicy::from_image_pin(
        pin.command_name(),
        pin.abi(),
        ComponentArtifactIdentity::new(pin.expected_sha256()),
        pin.world(),
        pin.entrypoint(),
        pin.min_args(),
        pin.max_args(),
        vsh_stream(pin.stdin()),
        vsh_stream(pin.stdout()),
        vsh_stream(pin.stderr()),
        limits.memory_bytes,
        limits.total_fuel,
        limits.poll_quantum,
        limits.resources,
        Vec::new(),
    )
    .map_err(|_| ())?;
    let root = NativeImageRoot {
        projection,
        ssh_policy,
        incarnation: NonZeroU64::new(1).expect("one is nonzero"),
    };
    if revalidate_image_root(&root) {
        Ok(root)
    } else {
        Err(())
    }
}

#[cfg(all(
    feature = "ssh-native-async-command",
    not(feature = "wasm-c53-native-async-qemu-acceptance")
))]
fn revalidate_image_root(root: &NativeImageRoot) -> bool {
    let pin = C53_NATIVE_ASYNC_COMMAND;
    let manifest = root.projection.manifest();
    root.incarnation.get() == 1
        && manifest.name() == pin.command_name()
        && manifest.abi() == pin.abi()
        && manifest.artifact().as_bytes() == &pin.expected_sha256()
        && manifest.world() == pin.world()
        && manifest.entrypoint() == pin.entrypoint()
        && manifest.min_args() == pin.min_args()
        && manifest.max_args() == pin.max_args()
        && manifest.stdin() == vsh_stream(pin.stdin())
        && manifest.stdout() == vsh_stream(pin.stdout())
        && manifest.stderr() == vsh_stream(pin.stderr())
        && manifest.memory_bytes() == pin.limits().memory_bytes
        && manifest.total_fuel() == pin.limits().total_fuel
        && manifest.poll_quantum() == pin.limits().poll_quantum
        && manifest.resource_limit() == pin.limits().resources
        && manifest.requirements().is_empty()
        && root.ssh_policy.admits_manifest(manifest)
        && root.validated_plan().is_ok_and(|plan| {
            plan.profile() == ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
                && plan.profile().stage == ProfileStage::ValidationOnly
                && !plan.profile().execution_enabled()
                && !plan.runtime_ready()
                && !plan.native_async_runtime_ready()
                && plan.native_async_execution_plan().is_some()
        })
}

#[cfg(all(
    feature = "wasm-c53-native-async-qemu-acceptance",
    feature = "ssh-native-async-command"
))]
fn build_image_root() -> Result<NativeImageRoot, ()> {
    Err(())
}

#[cfg(all(
    feature = "wasm-c53-native-async-qemu-acceptance",
    feature = "ssh-native-async-command"
))]
fn revalidate_image_root(_root: &NativeImageRoot) -> bool {
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DriverIdentity {
    key: ControlKey,
    instance: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
}

impl DriverIdentity {
    fn exact(
        self,
    ) -> Option<
        ExactInstanceIdentity<InstanceToken, TaskId, AllocationDomain, RegistryStreamBindings>,
    > {
        Some(ExactInstanceIdentity {
            control: self.key.encode()?.get(),
            control_generation: self.key.generation,
            instance: self.instance,
            task: self.task,
            domain: self.domain,
            bindings: self.streams,
        })
    }
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
const TARGET_AUDIT_IDLE: u8 = 0;
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
const TARGET_AUDIT_STARTED: u8 = 1;
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
const TARGET_AUDIT_SHADOW_RETIRED: u8 = 2;
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
const TARGET_AUDIT_TERMINAL: u8 = 3;
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
const TARGET_AUDIT_REAPER_NOTIFIED: u8 = 4;
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
const TARGET_AUDIT_ACKNOWLEDGED: u8 = 5;
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
const TARGET_NATIVE_FIXTURE_BYTES: u64 = (13 * 1024 + 73) as u64;

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct TargetManagedIdentity {
    driver: DriverIdentity,
    managed: ManagedComponentToken,
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
struct TargetManagedAudit {
    watermark: u64,
    stage: u8,
    identity: Option<TargetManagedIdentity>,
    terminal: Option<ComponentTerminal>,
    input_bytes: u64,
    output_bytes: u64,
    normal_eof: u64,
    normal_close: u64,
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
impl TargetManagedAudit {
    const fn new() -> Self {
        Self {
            watermark: 0,
            stage: TARGET_AUDIT_IDLE,
            identity: None,
            terminal: None,
            input_bytes: 0,
            output_bytes: 0,
            normal_eof: 0,
            normal_close: 0,
        }
    }

    fn clear_active(&mut self) {
        self.stage = TARGET_AUDIT_IDLE;
        self.identity = None;
        self.terminal = None;
        self.input_bytes = 0;
        self.output_bytes = 0;
        self.normal_eof = 0;
        self.normal_close = 0;
    }
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
#[derive(Clone, Copy)]
pub(super) struct TargetManagedReport {
    passed: bool,
    starts: u64,
    shadow_retires: u64,
    terminals: u64,
    cspace_resets: u64,
    reaper_notifies: u64,
    acknowledgements: u64,
    input_bytes: u64,
    output_bytes: u64,
    normal_eof: u64,
    normal_close: u64,
    pending_shadows: usize,
    registry_occupied: usize,
    registry_header_mismatches: usize,
    control_live: usize,
    stream_bindings: usize,
    cleanup_shadows: usize,
    reaper_slots: usize,
    reaper_waiters: usize,
    route_exact: bool,
    gates_open: bool,
    lease_current: usize,
    lease_peak: u8,
    lease_limit: u8,
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
static TARGET_MANAGED_AUDIT: [SpinLock<TargetManagedAudit>; CONTROL_SLOTS] =
    [const { SpinLock::new(TargetManagedAudit::new()) }; CONTROL_SLOTS];
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
static TARGET_MANAGED_STARTS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
static TARGET_MANAGED_SHADOW_RETIRES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
static TARGET_MANAGED_TERMINALS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
static TARGET_MANAGED_CSPACE_RESETS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
static TARGET_MANAGED_REAPER_NOTIFIES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
static TARGET_MANAGED_ACKNOWLEDGEMENTS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
static TARGET_MANAGED_COMPLETIONS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
fn target_managed_slot(key: ControlKey) -> Option<&'static SpinLock<TargetManagedAudit>> {
    TARGET_MANAGED_AUDIT.get(key.slot as usize)
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
pub(super) fn target_record_managed_start(
    key: ControlKey,
    instance: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    managed: ManagedComponentToken,
) -> bool {
    let Some(slot) = target_managed_slot(key) else {
        return false;
    };
    let mut audit = slot.lock();
    if audit.stage != TARGET_AUDIT_IDLE
        || audit.identity.is_some()
        || key.generation <= audit.watermark
    {
        return false;
    }
    audit.watermark = key.generation;
    audit.stage = TARGET_AUDIT_STARTED;
    audit.identity = Some(TargetManagedIdentity {
        driver: DriverIdentity {
            key,
            instance,
            task,
            domain,
            streams,
        },
        managed,
    });
    TARGET_MANAGED_STARTS.fetch_add(1, Ordering::AcqRel);
    true
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
fn target_record_input_bytes(identity: DriverIdentity, bytes: usize) -> bool {
    let Some(slot) = target_managed_slot(identity.key) else {
        return false;
    };
    let mut audit = slot.lock();
    if audit.stage != TARGET_AUDIT_STARTED
        || audit.identity.map(|stored| stored.driver) != Some(identity)
    {
        return false;
    }
    let Some(total) = audit.input_bytes.checked_add(bytes as u64) else {
        return false;
    };
    audit.input_bytes = total;
    true
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
fn target_record_output_bytes(identity: DriverIdentity, bytes: usize) -> bool {
    let Some(slot) = target_managed_slot(identity.key) else {
        return false;
    };
    let mut audit = slot.lock();
    if audit.stage != TARGET_AUDIT_STARTED
        || audit.identity.map(|stored| stored.driver) != Some(identity)
    {
        return false;
    }
    let Some(total) = audit.output_bytes.checked_add(bytes as u64) else {
        return false;
    };
    audit.output_bytes = total;
    true
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
fn target_record_normal_eof(identity: DriverIdentity) -> bool {
    let Some(slot) = target_managed_slot(identity.key) else {
        return false;
    };
    let mut audit = slot.lock();
    if audit.stage != TARGET_AUDIT_STARTED
        || audit.identity.map(|stored| stored.driver) != Some(identity)
        || audit.normal_eof != 0
    {
        return false;
    }
    audit.normal_eof = 1;
    true
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
fn target_record_normal_close(identity: DriverIdentity) -> bool {
    let Some(slot) = target_managed_slot(identity.key) else {
        return false;
    };
    let mut audit = slot.lock();
    if audit.stage != TARGET_AUDIT_STARTED
        || audit.identity.map(|stored| stored.driver) != Some(identity)
        || audit.normal_close != 0
    {
        return false;
    }
    audit.normal_close = 1;
    true
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
fn target_record_shadow_retired(identity: DriverIdentity) -> bool {
    let Some(slot) = target_managed_slot(identity.key) else {
        return false;
    };
    let mut audit = slot.lock();
    if audit.stage != TARGET_AUDIT_STARTED
        || audit.identity.map(|stored| stored.driver) != Some(identity)
    {
        return false;
    }
    audit.stage = TARGET_AUDIT_SHADOW_RETIRED;
    TARGET_MANAGED_SHADOW_RETIRES.fetch_add(1, Ordering::AcqRel);
    true
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
pub(super) fn target_record_managed_terminal(
    key: ControlKey,
    instance: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    terminal: ComponentTerminal,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance,
        task,
        domain,
        streams,
    };
    let Some(slot) = target_managed_slot(key) else {
        return false;
    };
    let mut audit = slot.lock();
    if audit.stage != TARGET_AUDIT_SHADOW_RETIRED
        || audit.identity.map(|stored| stored.driver) != Some(identity)
        || audit.terminal.is_some()
    {
        return false;
    }
    audit.stage = TARGET_AUDIT_TERMINAL;
    audit.terminal = Some(terminal);
    TARGET_MANAGED_TERMINALS.fetch_add(1, Ordering::AcqRel);
    // The parent invokes this hook only after `finalize_with_space` returned
    // its exact next CSpace incarnation, which is the reset linearization.
    TARGET_MANAGED_CSPACE_RESETS.fetch_add(1, Ordering::AcqRel);
    true
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
pub(super) fn target_record_reaper_notified(
    key: ControlKey,
    instance: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    managed: ManagedComponentToken,
    terminal: ComponentTerminal,
) -> bool {
    let expected = TargetManagedIdentity {
        driver: DriverIdentity {
            key,
            instance,
            task,
            domain,
            streams,
        },
        managed,
    };
    let Some(slot) = target_managed_slot(key) else {
        return false;
    };
    let mut audit = slot.lock();
    if audit.stage != TARGET_AUDIT_TERMINAL
        || audit.identity != Some(expected)
        || audit.terminal != Some(terminal)
    {
        return false;
    }
    audit.stage = TARGET_AUDIT_REAPER_NOTIFIED;
    TARGET_MANAGED_REAPER_NOTIFIES.fetch_add(1, Ordering::AcqRel);
    true
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
pub(super) fn target_record_managed_acknowledgement(
    key: ControlKey,
    managed: ManagedComponentToken,
    terminal: ComponentTerminal,
) -> bool {
    let Some(slot) = target_managed_slot(key) else {
        return false;
    };
    let mut audit = slot.lock();
    if audit.stage != TARGET_AUDIT_REAPER_NOTIFIED
        || audit
            .identity
            .is_none_or(|stored| stored.managed != managed)
        || audit.terminal != Some(terminal)
    {
        return false;
    }
    audit.stage = TARGET_AUDIT_ACKNOWLEDGED;
    TARGET_MANAGED_ACKNOWLEDGEMENTS.fetch_add(1, Ordering::AcqRel);
    true
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
pub(super) fn target_pending_shadow_residue() -> usize {
    PENDING_LEDGERS
        .iter()
        .enumerate()
        .filter(|(index, ledger)| {
            let operation_live = {
                ledger.lock().phase()
                    != super::native_pending_shadow_model::ExactLedgerPhase::Retired
            };
            let lease_live = { !LEASE_LEDGERS[*index].lock().is_retired() };
            operation_live || lease_live
        })
        .count()
}

#[cfg(any(
    feature = "ssh-native-async-qemu-acceptance",
    feature = "ssh-native-async-revoke-qemu-acceptance"
))]
fn target_lease_evidence() -> (usize, u8, u8, bool) {
    let mut current = 0usize;
    let mut peak = 0u8;
    let mut exact = true;
    for ledger in &LEASE_LEDGERS {
        let metrics = ledger.lock().metrics();
        current = current.saturating_add(usize::from(metrics.current()));
        peak = peak.max(metrics.peak());
        exact &= metrics.limit() == EXACT_NATIVE_LEASE_LIMIT
            && metrics.peak() <= metrics.limit()
            && metrics.current() <= metrics.limit();
    }
    (current, peak, EXACT_NATIVE_LEASE_LIMIT, exact)
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
#[allow(clippy::too_many_arguments)]
pub(super) fn target_completion_report(
    status: u32,
    route_exact: bool,
    gates_open: bool,
    pending_shadows: usize,
    registry_occupied: usize,
    registry_header_mismatches: usize,
    control_live: usize,
    stream_bindings: usize,
    cleanup_shadows: usize,
    reaper_slots: usize,
    reaper_waiters: usize,
) -> TargetManagedReport {
    let starts = TARGET_MANAGED_STARTS.load(Ordering::Acquire);
    let shadow_retires = TARGET_MANAGED_SHADOW_RETIRES.load(Ordering::Acquire);
    let terminals = TARGET_MANAGED_TERMINALS.load(Ordering::Acquire);
    let cspace_resets = TARGET_MANAGED_CSPACE_RESETS.load(Ordering::Acquire);
    let reaper_notifies = TARGET_MANAGED_REAPER_NOTIFIES.load(Ordering::Acquire);
    let acknowledgements = TARGET_MANAGED_ACKNOWLEDGEMENTS.load(Ordering::Acquire);
    let completions = TARGET_MANAGED_COMPLETIONS.load(Ordering::Acquire);
    let (lease_current, lease_peak, lease_limit, lease_exact) = target_lease_evidence();
    let mut active = 0usize;
    let mut acknowledged = None;
    let mut acknowledged_count = 0usize;
    for (index, slot) in TARGET_MANAGED_AUDIT.iter().enumerate() {
        let audit = slot.lock();
        if audit.stage != TARGET_AUDIT_IDLE {
            active += 1;
        }
        if audit.stage == TARGET_AUDIT_ACKNOWLEDGED {
            acknowledged_count += 1;
            acknowledged.get_or_insert(index);
        }
    }

    let (input_bytes, output_bytes, normal_eof, normal_close, successful_terminal) = acknowledged
        .map(|index| {
            let audit = TARGET_MANAGED_AUDIT[index].lock();
            (
                audit.input_bytes,
                audit.output_bytes,
                audit.normal_eof,
                audit.normal_close,
                audit.terminal == Some(ComponentTerminal::Success),
            )
        })
        .unwrap_or((0, 0, 0, 0, false));
    let passed = active == 1
        && acknowledged_count == 1
        && status == 0
        && route_exact
        && gates_open
        && successful_terminal
        && input_bytes == TARGET_NATIVE_FIXTURE_BYTES
        && output_bytes == TARGET_NATIVE_FIXTURE_BYTES
        && normal_eof == 1
        && normal_close == 1
        && pending_shadows == 0
        && registry_occupied == 0
        && registry_header_mismatches == 0
        && control_live == 0
        && stream_bindings == 0
        && cleanup_shadows == 0
        && reaper_slots == 0
        && reaper_waiters == 0
        && starts == shadow_retires
        && starts == terminals
        && starts == cspace_resets
        && starts == reaper_notifies
        && starts == acknowledgements
        && acknowledgements == completions.saturating_add(1);
    let passed = passed && lease_exact && lease_current == 0 && lease_peak <= lease_limit;

    if passed {
        TARGET_MANAGED_AUDIT[acknowledged.expect("checked target acknowledgement")]
            .lock()
            .clear_active();
        TARGET_MANAGED_COMPLETIONS.fetch_add(1, Ordering::AcqRel);
    }

    TargetManagedReport {
        passed,
        starts,
        shadow_retires,
        terminals,
        cspace_resets,
        reaper_notifies,
        acknowledgements,
        input_bytes,
        output_bytes,
        normal_eof,
        normal_close,
        pending_shadows,
        registry_occupied,
        registry_header_mismatches,
        control_live,
        stream_bindings,
        cleanup_shadows,
        reaper_slots,
        reaper_waiters,
        route_exact,
        gates_open,
        lease_current,
        lease_peak,
        lease_limit,
    }
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
pub(super) fn target_report_passed(report: TargetManagedReport) -> bool {
    report.passed
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
pub(super) fn publish_target_report(report: TargetManagedReport) {
    let result = if report.passed { "PASS" } else { "FAIL" };
    crate::println!(
        "WASM_C53_NATIVE_SSH_ACCEPTANCE {} starts={} shadow_retires={} terminals={} cspace_resets={} reaper_notifies={} acks={} input_bytes={} output_bytes={} normal_eof={} normal_close={} pending_shadows={} registry_occupied={} registry_header_mismatches={} control_live={} stream_bindings={} cleanup_shadows={} reaper_slots={} reaper_waiters={} route_exact={} gates_open={} lease_current={} lease_peak={} lease_limit={}",
        result,
        report.starts,
        report.shadow_retires,
        report.terminals,
        report.cspace_resets,
        report.reaper_notifies,
        report.acknowledgements,
        report.input_bytes,
        report.output_bytes,
        report.normal_eof,
        report.normal_close,
        report.pending_shadows,
        report.registry_occupied,
        report.registry_header_mismatches,
        report.control_live,
        report.stream_bindings,
        report.cleanup_shadows,
        report.reaper_slots,
        report.reaper_waiters,
        usize::from(report.route_exact),
        usize::from(report.gates_open),
        report.lease_current,
        report.lease_peak,
        report.lease_limit,
    );
}

impl ExactRuntimeToken for NativeHostToken {
    fn strictly_after(self, previous: Self) -> bool {
        NativeHostToken::strictly_after(self, previous)
    }
}

type NativeOperationLedger = ExactOperationLedger<
    InstanceToken,
    TaskId,
    AllocationDomain,
    RegistryStreamBindings,
    NativeHostToken,
    HostOperationToken,
    InstanceContinuationToken,
>;
type NativeLeaseLedger = ExactNativeLeaseLedger<
    InstanceToken,
    TaskId,
    AllocationDomain,
    RegistryStreamBindings,
    NativeWaitToken,
    InstanceContinuationToken,
>;
type NativeLeaseContinuation = ExactNativeLeaseContinuationReceipt<
    InstanceToken,
    TaskId,
    AllocationDomain,
    RegistryStreamBindings,
    InstanceContinuationToken,
>;
type NativeLedgerSnapshot = ExactLedgerSnapshot<
    InstanceToken,
    TaskId,
    AllocationDomain,
    RegistryStreamBindings,
    NativeHostToken,
    HostOperationToken,
    InstanceContinuationToken,
>;
type NativeInputSpillReceipt =
    ExactInputSpillReceipt<InstanceToken, TaskId, AllocationDomain, RegistryStreamBindings>;
type NativeCancelPlan = ExactCancelPlan<
    InstanceToken,
    TaskId,
    AllocationDomain,
    RegistryStreamBindings,
    NativeHostToken,
    HostOperationToken,
    InstanceContinuationToken,
>;
type NativeBackendReturn = ExactBackendReturn<
    InstanceToken,
    TaskId,
    AllocationDomain,
    RegistryStreamBindings,
    NativeHostToken,
    HostOperationToken,
    InstanceContinuationToken,
>;
type NativeResidualCancelPlan = ExactResidualCancelPlan<
    InstanceToken,
    TaskId,
    AllocationDomain,
    RegistryStreamBindings,
    NativeHostToken,
    HostOperationToken,
    InstanceContinuationToken,
>;
type NativeResourceRevokePlan =
    ExactResourceRevokePlan<InstanceToken, TaskId, AllocationDomain, RegistryStreamBindings>;

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_TARGET_EVENT: u64 = 1;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_BACKEND_STDIN_FIRST_BYTES: usize = 257;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_BACKEND_STDIN_SECOND_BYTES: usize = DRIVER_CHUNK_BYTES - C54_BACKEND_STDIN_FIRST_BYTES;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_CANONICAL_SLICE_BYTES: usize = 99;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_FIRST_BACKEND_TAIL_BYTES: usize =
    C54_BACKEND_STDIN_FIRST_BYTES - 2 * C54_CANONICAL_SLICE_BYTES;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_REVOKE_CANONICAL_COMMITS: u8 = 9;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_REVOKE_CANONICAL_TOTAL_BYTES: usize = C54_BACKEND_STDIN_FIRST_BYTES
    + (C54_REVOKE_CANONICAL_COMMITS as usize - 3) * C54_CANONICAL_SLICE_BYTES;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_REVOKE_INPUT_SPILL_BYTES: usize = C54_BACKEND_STDIN_SECOND_BYTES
    - (C54_REVOKE_CANONICAL_COMMITS as usize - 3) * C54_CANONICAL_SLICE_BYTES;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_SENT_OUTPUT_PREFIXES: u8 = 8;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_SENT_OUTPUT_TOTAL_BYTES: usize = C54_BACKEND_STDIN_FIRST_BYTES
    + (C54_SENT_OUTPUT_PREFIXES as usize - 3) * C54_CANONICAL_SLICE_BYTES;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_LINEARIZED_OUTPUT_BYTES: usize = C54_CANONICAL_SLICE_BYTES;
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const _: () = {
    assert!(C54_BACKEND_STDIN_FIRST_BYTES == 257);
    assert!(C54_BACKEND_STDIN_SECOND_BYTES == 767);
    assert!(C54_CANONICAL_SLICE_BYTES == 99);
    assert!(C54_REVOKE_INPUT_SPILL_BYTES == 173);
    assert!(C54_FIRST_BACKEND_TAIL_BYTES == 59);
    assert!(C54_REVOKE_CANONICAL_TOTAL_BYTES == 851);
    assert!(C54_SENT_OUTPUT_TOTAL_BYTES == 752);
    assert!(C54_REVOKE_CANONICAL_COMMITS == C54_SENT_OUTPUT_PREFIXES + 1);
    assert!(
        C54_REVOKE_CANONICAL_TOTAL_BYTES == C54_SENT_OUTPUT_TOTAL_BYTES + C54_CANONICAL_SLICE_BYTES
    );
};
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_HEALTHY_MAGIC: &[u8] = b"VIBE-C54-HEALTHY\n";
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_LINEARIZED_MAGIC: &[u8] = b"VIBE-C54-LINEARIZED\n";
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_RAW_INVOKING_MAGIC: &[u8] = b"VIBE-C54-RAW-INVOKING\n";
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
const C54_RAW_LINEARIZED_MAGIC: &[u8] = b"VIBE-C54-RAW-LINEARIZED\n";

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum C54Scenario {
    Undecided,
    Healthy,
    LinearizedGuard,
    RawInvoking,
    RawLinearized,
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum C54WorkerKind {
    ConsumedPending,
    InvokingDeferred,
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct C54ManagedIdentity {
    driver: DriverIdentity,
    managed: ManagedComponentToken,
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
#[derive(Clone, Copy)]
struct C54WorkerRequest {
    kind: C54WorkerKind,
    identity: DriverIdentity,
    continuation: Option<InstanceContinuationToken>,
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
struct C54TargetAudit {
    primary: Option<C54ManagedIdentity>,
    replacement: Option<C54ManagedIdentity>,
    scenario: C54Scenario,
    drain_open: bool,
    worker_request: Option<C54WorkerRequest>,
    worker_complete: bool,
    cancel_plan: Option<NativeCancelPlan>,
    stale_snapshot: Option<NativeLedgerSnapshot>,
    stale_continuation: Option<InstanceContinuationToken>,
    starts: u64,
    shadow_retires: u64,
    claims: u64,
    pending_claims: u64,
    deferred_claims: u64,
    cap_revokes: u64,
    backend_cancels: u64,
    core_already_consumed: u64,
    consumed_deltas: u64,
    runtime_cancel_acks: u64,
    cancel_idles: u64,
    canonical_total: u64,
    canonical_first: u64,
    canonical_second: u64,
    canonical_commits: u8,
    sent_output_total: u64,
    sent_output_prefixes: u8,
    waiting_ops: u64,
    cancelled_terminals: u64,
    terminals: u64,
    cspace_resets: u64,
    reaper_notifies: u64,
    acknowledgements: u64,
    ssh_completions: u64,
    late_wake_stale: u64,
    restart_stale_claim: u64,
    restart_stale_backend: u64,
    replacement_success: u64,
    backend_effects: u64,
    raw_faults: u64,
    raw_reclaims: u64,
    raw_phase: Option<ExactLedgerPhase>,
    failed: bool,
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
impl C54TargetAudit {
    const fn new() -> Self {
        Self {
            primary: None,
            replacement: None,
            scenario: C54Scenario::Undecided,
            drain_open: false,
            worker_request: None,
            worker_complete: false,
            cancel_plan: None,
            stale_snapshot: None,
            stale_continuation: None,
            starts: 0,
            shadow_retires: 0,
            claims: 0,
            pending_claims: 0,
            deferred_claims: 0,
            cap_revokes: 0,
            backend_cancels: 0,
            core_already_consumed: 0,
            consumed_deltas: 0,
            runtime_cancel_acks: 0,
            cancel_idles: 0,
            canonical_total: 0,
            canonical_first: 0,
            canonical_second: 0,
            canonical_commits: 0,
            sent_output_total: 0,
            sent_output_prefixes: 0,
            waiting_ops: 0,
            cancelled_terminals: 0,
            terminals: 0,
            cspace_resets: 0,
            reaper_notifies: 0,
            acknowledgements: 0,
            ssh_completions: 0,
            late_wake_stale: 0,
            restart_stale_claim: 0,
            restart_stale_backend: 0,
            replacement_success: 0,
            backend_effects: 0,
            raw_faults: 0,
            raw_reclaims: 0,
            raw_phase: None,
            failed: false,
        }
    }

    fn is_primary(&self, identity: DriverIdentity) -> bool {
        self.primary.is_some_and(|target| target.driver == identity)
    }

    fn is_replacement(&self, identity: DriverIdentity) -> bool {
        self.replacement
            .is_some_and(|target| target.driver == identity)
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
static C54_TARGET: SpinLock<C54TargetAudit> = SpinLock::new(C54TargetAudit::new());
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
static C54_WORK_READY: OneShotWaitQueue = OneShotWaitQueue::new();
#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
static C54_WORK_COMPLETE: OneShotWaitQueue = OneShotWaitQueue::new();

static PENDING_LEDGERS: [SpinLock<NativeOperationLedger>; CONTROL_SLOTS] =
    [const { SpinLock::new(NativeOperationLedger::new()) }; CONTROL_SLOTS];
static LEASE_LEDGERS: [SpinLock<NativeLeaseLedger>; CONTROL_SLOTS] =
    [const { SpinLock::new(NativeLeaseLedger::new()) }; CONTROL_SLOTS];
static SHADOW_KIND_INSTALLS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

const fn pending_kind_index(kind: PendingKind) -> usize {
    match kind {
        PendingKind::ReadWaiting => 0,
        PendingKind::ReadPrepared => 1,
        PendingKind::WriteWaiting => 2,
        PendingKind::TerminalWaiting => 3,
    }
}

fn record_shadow_kind_install(kind: PendingKind) {
    SHADOW_KIND_INSTALLS[pending_kind_index(kind)].fetch_add(1, Ordering::AcqRel);
}

fn shadow_kind_install_counts() -> [u64; 4] {
    core::array::from_fn(|index| SHADOW_KIND_INSTALLS[index].load(Ordering::Acquire))
}

fn ledger_slot(key: ControlKey) -> Option<&'static SpinLock<NativeOperationLedger>> {
    PENDING_LEDGERS.get(key.slot as usize)
}

fn lease_slot(key: ControlKey) -> Option<&'static SpinLock<NativeLeaseLedger>> {
    LEASE_LEDGERS.get(key.slot as usize)
}

fn with_ledger<T>(
    identity: DriverIdentity,
    operation: impl FnOnce(&mut NativeOperationLedger) -> Result<T, ExactLedgerError>,
) -> Result<T, ExactLedgerError> {
    if identity.exact().is_none() {
        return Err(ExactLedgerError::IdentityMismatch);
    }
    let Some(slot) = ledger_slot(identity.key) else {
        return Err(ExactLedgerError::IdentityMismatch);
    };
    operation(&mut slot.lock())
}

fn with_leases<T>(
    identity: DriverIdentity,
    operation: impl FnOnce(&mut NativeLeaseLedger) -> Result<T, ExactNativeLeaseError>,
) -> Result<T, ExactNativeLeaseError> {
    if identity.exact().is_none() {
        return Err(ExactNativeLeaseError::IdentityMismatch);
    }
    let Some(slot) = lease_slot(identity.key) else {
        return Err(ExactNativeLeaseError::IdentityMismatch);
    };
    operation(&mut slot.lock())
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_policy_exact(policy: SshExecComponentSessionPolicy) -> bool {
    policy.command_name() == command_name()
        && ssh_exec_policy(policy.profile()) == Some(policy)
        && policy_gate_passed()
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_fail(reason: &'static str) {
    let publish = {
        let mut audit = C54_TARGET.lock();
        let publish = !audit.failed;
        audit.failed = true;
        publish
    };
    if publish {
        crate::println!("WASM_C54_NATIVE_REVOKE FAIL reason={}", reason);
    }
    lifecycle_fail_stop();
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) fn target_revoke_fail(reason: &'static str) {
    c54_fail(reason);
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) fn target_record_revoke_start(
    key: ControlKey,
    instance: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    managed: ManagedComponentToken,
) -> bool {
    let identity = C54ManagedIdentity {
        driver: DriverIdentity {
            key,
            instance,
            task,
            domain,
            streams,
        },
        managed,
    };
    let (starts, primary, stale) = {
        let audit = C54_TARGET.lock();
        (
            audit.starts,
            audit.primary,
            audit.stale_snapshot.map(|snapshot| {
                (
                    audit.primary.expect("stale snapshot has a primary").driver,
                    snapshot,
                )
            }),
        )
    };
    match starts {
        0 => {
            let mut audit = C54_TARGET.lock();
            if audit.starts != 0 || audit.primary.is_some() || audit.failed {
                return false;
            }
            audit.primary = Some(identity);
            audit.starts = 1;
            audit.drain_open = false;
            true
        }
        1 => {
            let Some((old_identity, stale_snapshot)) = stale else {
                return false;
            };
            if primary.is_none()
                || primary == Some(identity)
                || with_ledger(old_identity, |ledger| {
                    ledger.claim_revoke(
                        old_identity
                            .exact()
                            .ok_or(ExactLedgerError::IdentityMismatch)?,
                        ExactStreamResource::StdoutWriter,
                    )
                }) != Err(ExactLedgerError::StaleGeneration)
                || with_ledger(old_identity, |ledger| {
                    ledger.begin_backend(stale_snapshot, ExactBackendAction::Resume)
                }) != Err(ExactLedgerError::StaleGeneration)
            {
                return false;
            }
            let mut audit = C54_TARGET.lock();
            if audit.starts != 1
                || audit.scenario != C54Scenario::Healthy
                || audit.acknowledgements != 1
                || audit.ssh_completions != 1
                || audit.replacement.is_some()
                || audit.failed
            {
                return false;
            }
            audit.replacement = Some(identity);
            audit.starts = 2;
            audit.restart_stale_claim = 1;
            audit.restart_stale_backend = 1;
            audit.drain_open = true;
            true
        }
        _ => false,
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) fn target_stdout_drain_permitted(policy: SshExecComponentSessionPolicy) -> bool {
    if !c54_policy_exact(policy) {
        return false;
    }
    let audit = C54_TARGET.lock();
    // Close from admission so the permit check and the later stdout consume
    // cannot straddle a target transition. Eight canonical output prefixes
    // fill the backend queue with 752 bytes; the ninth 99-byte operation opens
    // the gate monotonically after registering its real stream wake.
    !audit.failed && audit.drain_open
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) fn target_stdin_chunk_limit(
    policy: SshExecComponentSessionPolicy,
    accepted_bytes: usize,
) -> Result<usize, &'static str> {
    if !c54_policy_exact(policy) {
        return Err("native revoke stdin policy changed");
    }
    let audit = C54_TARGET.lock();
    if audit.failed {
        return Err("native revoke stdin audit failed");
    }
    match accepted_bytes {
        0 => Ok(C54_BACKEND_STDIN_FIRST_BYTES),
        C54_BACKEND_STDIN_FIRST_BYTES => Ok(C54_BACKEND_STDIN_SECOND_BYTES),
        _ => Ok(DRIVER_CHUNK_BYTES),
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_select_scenario(identity: DriverIdentity, input: &[u8]) -> bool {
    {
        let audit = C54_TARGET.lock();
        if audit.is_replacement(identity) && !audit.failed {
            return true;
        }
        if audit.is_primary(identity) && audit.scenario != C54Scenario::Undecided && !audit.failed {
            return true;
        }
    }
    let scenario = if input.starts_with(C54_HEALTHY_MAGIC) {
        C54Scenario::Healthy
    } else if input.starts_with(C54_LINEARIZED_MAGIC) {
        C54Scenario::LinearizedGuard
    } else if input.starts_with(C54_RAW_INVOKING_MAGIC) {
        C54Scenario::RawInvoking
    } else if input.starts_with(C54_RAW_LINEARIZED_MAGIC) {
        C54Scenario::RawLinearized
    } else {
        return false;
    };
    let mut audit = C54_TARGET.lock();
    if !audit.is_primary(identity)
        || audit.scenario != C54Scenario::Undecided
        || audit.canonical_commits != 0
        || audit.failed
    {
        return false;
    }
    audit.scenario = scenario;
    true
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_record_input_progress(identity: DriverIdentity, progress: usize) -> bool {
    let mut audit = C54_TARGET.lock();
    if audit.is_replacement(identity) && !audit.failed {
        return true;
    }
    if !audit.is_primary(identity) || audit.failed || audit.scenario == C54Scenario::Undecided {
        return false;
    }
    let expected = match audit.canonical_commits {
        0 | 1 => C54_CANONICAL_SLICE_BYTES,
        2 => C54_FIRST_BACKEND_TAIL_BYTES,
        3.. if audit.canonical_commits < C54_REVOKE_CANONICAL_COMMITS => C54_CANONICAL_SLICE_BYTES,
        _ => return false,
    };
    if progress != expected {
        return false;
    }
    match audit.canonical_commits {
        0 => audit.canonical_first = progress as u64,
        1 => audit.canonical_second = progress as u64,
        _ => {}
    }
    let Some(total) = audit.canonical_total.checked_add(progress as u64) else {
        return false;
    };
    let Some(commits) = audit.canonical_commits.checked_add(1) else {
        return false;
    };
    audit.canonical_total = total;
    audit.canonical_commits = commits;
    true
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_record_sent_output_prefix(identity: DriverIdentity, progress: usize) -> bool {
    let mut audit = C54_TARGET.lock();
    if audit.is_replacement(identity) && !audit.failed {
        return true;
    }
    if !audit.is_primary(identity)
        || audit.scenario != C54Scenario::Healthy
        || audit.failed
        || audit.sent_output_prefixes >= C54_SENT_OUTPUT_PREFIXES
        || audit.canonical_commits != audit.sent_output_prefixes.saturating_add(1)
    {
        return false;
    }
    let expected = if audit.sent_output_prefixes == 2 {
        C54_FIRST_BACKEND_TAIL_BYTES
    } else {
        C54_CANONICAL_SLICE_BYTES
    };
    if progress != expected {
        return false;
    }
    let Some(total) = audit.sent_output_total.checked_add(progress as u64) else {
        return false;
    };
    audit.sent_output_total = total;
    audit.sent_output_prefixes += 1;
    true
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_is_healthy_primary(identity: DriverIdentity) -> bool {
    let audit = C54_TARGET.lock();
    audit.is_primary(identity) && audit.scenario == C54Scenario::Healthy && !audit.failed
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_record_cap_revoke(identity: DriverIdentity) -> bool {
    let mut audit = C54_TARGET.lock();
    if !audit.is_primary(identity) || audit.scenario != C54Scenario::Healthy || audit.failed {
        return false;
    }
    audit.cap_revokes += 1;
    audit.cap_revokes == 1
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_record_backend_cancel(identity: DriverIdentity) -> bool {
    let mut audit = C54_TARGET.lock();
    if !audit.is_primary(identity) || audit.scenario != C54Scenario::Healthy || audit.failed {
        return false;
    }
    audit.backend_cancels += 1;
    audit.backend_cancels == 1
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_record_runtime_cancel(identity: DriverIdentity) -> bool {
    let mut audit = C54_TARGET.lock();
    if !audit.is_primary(identity) || audit.scenario != C54Scenario::Healthy || audit.failed {
        return false;
    }
    audit.runtime_cancel_acks += 1;
    audit.runtime_cancel_acks == 1
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_record_cancel_idle(identity: DriverIdentity) -> bool {
    let mut audit = C54_TARGET.lock();
    if !audit.is_primary(identity) || audit.scenario != C54Scenario::Healthy || audit.failed {
        return false;
    }
    audit.cancel_idles += 1;
    audit.cancel_idles == 1
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) fn target_preserve_cancelled_after_stdout_revoke(
    key: ControlKey,
    instance: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance,
        task,
        domain,
        streams,
    };
    let Some(exact) = identity.exact() else {
        return false;
    };
    let resources = with_ledger(identity, |ledger| {
        Ok((
            ledger.resource_state(exact, ExactStreamResource::StdinReader)?,
            ledger.resource_state(exact, ExactStreamResource::StdoutWriter)?,
            ledger.input_spill_remaining(exact)?,
        ))
    });
    if resources
        != Ok((
            ExactResourceState::Live,
            ExactResourceState::Revoked,
            Some(C54_REVOKE_INPUT_SPILL_BYTES as u16),
        ))
    {
        return false;
    }
    let audit = C54_TARGET.lock();
    audit.is_primary(identity)
        && audit.scenario == C54Scenario::Healthy
        && audit.worker_complete
        && audit.worker_request.is_some_and(|request| {
            request.kind == C54WorkerKind::ConsumedPending && request.identity == identity
        })
        && audit.cancel_plan.is_none()
        && audit.claims == 1
        && audit.pending_claims == 1
        && audit.deferred_claims == 0
        && audit.cap_revokes == 1
        && audit.backend_cancels == 1
        && audit.core_already_consumed == 1
        && audit.consumed_deltas == 1
        && audit.runtime_cancel_acks == 1
        && audit.cancel_idles == 1
        && audit.canonical_total == C54_REVOKE_CANONICAL_TOTAL_BYTES as u64
        && audit.canonical_first == C54_CANONICAL_SLICE_BYTES as u64
        && audit.canonical_second == C54_CANONICAL_SLICE_BYTES as u64
        && audit.canonical_commits == C54_REVOKE_CANONICAL_COMMITS
        && audit.sent_output_total == C54_SENT_OUTPUT_TOTAL_BYTES as u64
        && audit.sent_output_prefixes == C54_SENT_OUTPUT_PREFIXES
        && audit.waiting_ops == 1
        && audit.cancelled_terminals == 0
        && audit.terminals == 0
        && !audit.failed
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_terminal_projection_exact(
    identity: DriverIdentity,
    terminal: ComponentTerminal,
    stdin: ExactResourceState,
    stdout: ExactResourceState,
) -> bool {
    let audit = C54_TARGET.lock();
    if audit.failed {
        return false;
    }
    if audit.is_primary(identity) {
        audit.scenario == C54Scenario::Healthy
            && terminal == ComponentTerminal::Cancelled
            && stdin == ExactResourceState::Live
            && stdout == ExactResourceState::Revoked
            && audit.cap_revokes == 1
            && audit.backend_cancels == 1
            && audit.runtime_cancel_acks == 1
            && audit.cancel_idles == 1
    } else if audit.is_replacement(identity) {
        terminal == ComponentTerminal::Success
            && stdin == ExactResourceState::Live
            && stdout == ExactResourceState::Live
    } else {
        false
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_record_shadow_retired(identity: DriverIdentity) -> bool {
    let continuation = {
        let audit = C54_TARGET.lock();
        if audit.failed {
            return false;
        }
        if audit.is_primary(identity) {
            if audit.shadow_retires != 0 {
                return false;
            }
            audit.stale_continuation
        } else if audit.is_replacement(identity) {
            if audit.shadow_retires != 1 {
                return false;
            }
            None
        } else {
            return false;
        }
    };
    if let Some(continuation) = continuation {
        if registry().signal_continuation(continuation)
            != crate::instance::InstanceContinuationSignal::Stale
        {
            return false;
        }
    }
    let mut audit = C54_TARGET.lock();
    if continuation.is_some() {
        audit.late_wake_stale += 1;
    }
    audit.shadow_retires += 1;
    audit.shadow_retires == audit.starts
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) fn target_record_revoke_terminal(
    key: ControlKey,
    instance: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    terminal: ComponentTerminal,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance,
        task,
        domain,
        streams,
    };
    let mut audit = C54_TARGET.lock();
    if audit.failed || audit.shadow_retires != audit.terminals.saturating_add(1) {
        return false;
    }
    if audit.is_primary(identity) {
        if audit.scenario != C54Scenario::Healthy
            || terminal != ComponentTerminal::Cancelled
            || audit.cancelled_terminals != 0
        {
            return false;
        }
        audit.cancelled_terminals = 1;
    } else if audit.is_replacement(identity) {
        if terminal != ComponentTerminal::Success || audit.replacement_success != 0 {
            return false;
        }
        audit.replacement_success = 1;
    } else {
        return false;
    }
    audit.terminals += 1;
    audit.cspace_resets += 1;
    audit.terminals == audit.starts && audit.cspace_resets == audit.starts
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) fn target_record_revoke_reaper(
    key: ControlKey,
    instance: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    managed: ManagedComponentToken,
    terminal: ComponentTerminal,
) -> bool {
    let expected = C54ManagedIdentity {
        driver: DriverIdentity {
            key,
            instance,
            task,
            domain,
            streams,
        },
        managed,
    };
    let mut audit = C54_TARGET.lock();
    if audit.failed || audit.terminals != audit.reaper_notifies.saturating_add(1) {
        return false;
    }
    let exact = if audit.primary == Some(expected) {
        terminal == ComponentTerminal::Cancelled
    } else if audit.replacement == Some(expected) {
        terminal == ComponentTerminal::Success
    } else {
        false
    };
    if !exact {
        return false;
    }
    audit.reaper_notifies += 1;
    audit.reaper_notifies == audit.terminals
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) fn target_record_revoke_ack(
    key: ControlKey,
    managed: ManagedComponentToken,
    terminal: ComponentTerminal,
) -> bool {
    let mut audit = C54_TARGET.lock();
    if audit.failed || audit.reaper_notifies != audit.acknowledgements.saturating_add(1) {
        return false;
    }
    let exact = audit
        .primary
        .is_some_and(|identity| identity.driver.key == key && identity.managed == managed)
        && terminal == ComponentTerminal::Cancelled
        || audit
            .replacement
            .is_some_and(|identity| identity.driver.key == key && identity.managed == managed)
            && terminal == ComponentTerminal::Success;
    if !exact {
        return false;
    }
    audit.acknowledgements += 1;
    audit.acknowledgements == audit.reaper_notifies
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) fn target_revoke_pending_shadow_residue() -> usize {
    PENDING_LEDGERS
        .iter()
        .enumerate()
        .filter(|(index, ledger)| {
            let operation_live = { ledger.lock().phase() != ExactLedgerPhase::Retired };
            let lease_live = { !LEASE_LEDGERS[*index].lock().is_retired() };
            operation_live || lease_live
        })
        .count()
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_record_raw_fault_seen(identity: DriverIdentity, phase: ExactLedgerPhase) -> bool {
    let mut audit = C54_TARGET.lock();
    let expected = match audit.scenario {
        C54Scenario::RawInvoking => ExactLedgerPhase::BackendInvoking,
        C54Scenario::RawLinearized => ExactLedgerPhase::BackendLinearized,
        _ => return false,
    };
    if !audit.is_primary(identity)
        || audit.failed
        || phase != expected
        || audit.raw_faults != 0
        || audit.raw_phase.is_some()
    {
        return false;
    }
    audit.raw_faults = 1;
    audit.raw_phase = Some(phase);
    true
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) fn target_record_raw_fault_outcome(
    key: ControlKey,
    instance: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    reclaimed: bool,
) {
    let identity = DriverIdentity {
        key,
        instance,
        task,
        domain,
        streams,
    };
    let (passed, phase) = {
        let mut audit = C54_TARGET.lock();
        if reclaimed {
            audit.raw_reclaims += 1;
        }
        let phase = match audit.raw_phase {
            Some(ExactLedgerPhase::BackendInvoking) => "backend-invoking",
            Some(ExactLedgerPhase::BackendLinearized) => "backend-linearized",
            _ => "invalid",
        };
        let passed = audit.is_primary(identity)
            && !reclaimed
            && !audit.failed
            && audit.starts == 1
            && audit.raw_faults == 1
            && audit.raw_reclaims == 0
            && audit.terminals == 0
            && audit.cspace_resets == 0
            && audit.reaper_notifies == 0
            && audit.acknowledgements == 0
            && ((audit.scenario == C54Scenario::RawInvoking
                && audit.raw_phase == Some(ExactLedgerPhase::BackendInvoking)
                && audit.backend_effects == 0)
                || (audit.scenario == C54Scenario::RawLinearized
                    && audit.raw_phase == Some(ExactLedgerPhase::BackendLinearized)
                    && audit.backend_effects == 1));
        (passed, phase)
    };
    if passed {
        crate::println!(
            "WASM_C54_NATIVE_RAW_FAULT_GUARD PASS phase={} starts=1 raw_faults=1 raw_reclaims=0 terminals=0 cspace_resets=0 reaper_notifies=0 acks=0",
            phase,
        );
    } else {
        c54_fail("raw-fault-guard-evidence");
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
#[allow(clippy::too_many_arguments)]
pub(super) fn target_revoke_ssh_completed(
    status: u32,
    route_exact: bool,
    gates_open: bool,
    pending_shadows: usize,
    registry_occupied: usize,
    registry_header_mismatches: usize,
    control_live: usize,
    stream_bindings: usize,
    cleanup_shadows: usize,
    reaper_slots: usize,
    reaper_waiters: usize,
) -> bool {
    let (lease_current, lease_peak, lease_limit, lease_exact) = target_lease_evidence();
    let residues_zero = pending_shadows == 0
        && registry_occupied == 0
        && registry_header_mismatches == 0
        && control_live == 0
        && stream_bindings == 0
        && cleanup_shadows == 0
        && reaper_slots == 0
        && reaper_waiters == 0;
    let mut audit = C54_TARGET.lock();
    let common = !audit.failed
        && audit.scenario == C54Scenario::Healthy
        && route_exact
        && gates_open
        && residues_zero
        && lease_exact
        && lease_current == 0
        && lease_peak <= lease_limit
        && audit.claims == 1
        && audit.pending_claims == 1
        && audit.deferred_claims == 0
        && audit.cap_revokes == 1
        && audit.backend_cancels == 1
        && audit.core_already_consumed == 1
        && audit.consumed_deltas == 1
        && audit.runtime_cancel_acks == 1
        && audit.cancel_idles == 1
        && audit.canonical_total == C54_REVOKE_CANONICAL_TOTAL_BYTES as u64
        && audit.canonical_first == C54_CANONICAL_SLICE_BYTES as u64
        && audit.canonical_second == C54_CANONICAL_SLICE_BYTES as u64
        && audit.canonical_commits == C54_REVOKE_CANONICAL_COMMITS
        && audit.sent_output_total == C54_SENT_OUTPUT_TOTAL_BYTES as u64
        && audit.sent_output_prefixes == C54_SENT_OUTPUT_PREFIXES
        && audit.waiting_ops == 1
        && audit.cancelled_terminals == 1
        && audit.late_wake_stale == 1
        && audit.raw_faults == 0
        && audit.raw_reclaims == 0;
    match audit.ssh_completions {
        0 => {
            let passed = common
                && status == 130
                && audit.starts == 1
                && audit.shadow_retires == 1
                && audit.terminals == 1
                && audit.cspace_resets == 1
                && audit.reaper_notifies == 1
                && audit.acknowledgements == 1
                && audit.replacement.is_none()
                && audit.replacement_success == 0
                && audit.restart_stale_claim == 0
                && audit.restart_stale_backend == 0;
            if passed {
                audit.ssh_completions = 1;
            }
            passed
        }
        1 => {
            let passed = common
                && status == 0
                && audit.starts == 2
                && audit.shadow_retires == 2
                && audit.terminals == 2
                && audit.cspace_resets == 2
                && audit.reaper_notifies == 2
                && audit.acknowledgements == 2
                && audit.replacement.is_some()
                && audit.replacement_success == 1
                && audit.restart_stale_claim == 1
                && audit.restart_stale_backend == 1;
            if passed {
                audit.ssh_completions = 2;
                crate::println!("WASM_C54_NATIVE_REVOKE PASS starts=2 claims=1 pending_claims=1 cap_revokes=1 backend_cancels=1 core_already_consumed=1 consumed_deltas=1 runtime_cancel_acks=1 cancel_idles=1 backend_first=257 backend_second=767 canonical_total=851 canonical_first=99 canonical_second=99 canonical_commits=9 sent_prefixes=8 sent_total=752 waiting_ops=1 cancelled_terminals=1 cspace_resets=2 reaper_notifies=2 acks=2 late_wake_stale=1 restart_stale_claim=1 restart_stale_backend=1 replacement_success=1 lease_current={} lease_peak={} lease_limit={}", lease_current, lease_peak, lease_limit);
            }
            passed
        }
        _ => false,
    }
}

fn ledger_error_terminal(identity: DriverIdentity, error: ExactLedgerError) -> ComponentTerminal {
    // A caller from an older CONTROL generation is inert. In particular it may
    // not quarantine a replacement which now owns the same fixed slot.
    if error != ExactLedgerError::StaleGeneration {
        quarantine_shadow(identity);
    }
    ComponentTerminal::RunnerFault
}

fn lease_error_terminal(
    identity: DriverIdentity,
    error: ExactNativeLeaseError,
) -> ComponentTerminal {
    // Like the operation shadow, an older generation is observationally inert
    // toward the replacement which now owns this fixed slot.
    if error != ExactNativeLeaseError::StaleGeneration {
        quarantine_shadow(identity);
    }
    ComponentTerminal::RunnerFault
}

pub(super) fn bind_pending_shadow(
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance: token,
        task,
        domain,
        streams,
    };
    let result = with_ledger(identity, |ledger| {
        let exact = identity.exact().ok_or(ExactLedgerError::IdentityMismatch)?;
        ledger.bind(exact)
    });
    match result {
        Ok(()) => {}
        Err(ExactLedgerError::StaleGeneration) => return false,
        Err(_) => {
            quarantine_shadow(identity);
            return false;
        }
    }
    let leases = with_leases(identity, |ledger| {
        let exact = identity
            .exact()
            .ok_or(ExactNativeLeaseError::IdentityMismatch)?;
        ledger.bind(exact)
    });
    match leases {
        Ok(()) => true,
        Err(ExactNativeLeaseError::StaleGeneration) => false,
        Err(_) => {
            quarantine_shadow(identity);
            false
        }
    }
}

fn ledger_begin_runtime(
    identity: DriverIdentity,
    runtime: NativeHostToken,
    resource: ExactStreamResource,
    function: ExactHostFunction,
    request_units: usize,
) -> Result<NativeLedgerSnapshot, ExactLedgerError> {
    with_ledger(identity, |ledger| {
        ledger.begin_runtime(
            identity.exact().ok_or(ExactLedgerError::IdentityMismatch)?,
            runtime,
            resource,
            function,
            request_units,
        )
    })
}

fn ledger_prepare_runtime(
    identity: DriverIdentity,
    previous: NativeLedgerSnapshot,
    runtime: NativeHostToken,
) -> Result<NativeLedgerSnapshot, ExactLedgerError> {
    with_ledger(identity, |ledger| ledger.prepare_runtime(previous, runtime))
}

fn ledger_begin_backend(
    identity: DriverIdentity,
    previous: NativeLedgerSnapshot,
    action: ExactBackendAction,
) -> Result<NativeLedgerSnapshot, ExactLedgerError> {
    let starts_backend = action == ExactBackendAction::Start;
    if starts_backend {
        with_leases(identity, |leases| {
            leases.begin_backend(
                identity
                    .exact()
                    .ok_or(ExactNativeLeaseError::IdentityMismatch)?,
            )
        })
        .map_err(|error| match error {
            ExactNativeLeaseError::StaleGeneration => ExactLedgerError::StaleGeneration,
            _ => {
                let _ = lease_error_terminal(identity, error);
                ExactLedgerError::Quarantined
            }
        })?;
    }
    let result = with_ledger(identity, |ledger| ledger.begin_backend(previous, action));
    if starts_backend && result.is_err() {
        let _ = with_leases(identity, |leases| {
            leases.finish_backend(
                identity
                    .exact()
                    .ok_or(ExactNativeLeaseError::IdentityMismatch)?,
            )
        });
    }
    result
}

fn finish_backend_lease(identity: DriverIdentity) -> Result<(), ComponentTerminal> {
    with_leases(identity, |leases| {
        leases.finish_backend(
            identity
                .exact()
                .ok_or(ExactNativeLeaseError::IdentityMismatch)?,
        )
    })
    .map_err(|error| lease_error_terminal(identity, error))
}

fn lease_result<T>(
    identity: DriverIdentity,
    result: Result<T, ExactNativeLeaseError>,
) -> Result<T, ComponentTerminal> {
    result.map_err(|error| lease_error_terminal(identity, error))
}

fn ledger_backend_pending(
    identity: DriverIdentity,
    invoking: NativeLedgerSnapshot,
    kind: PendingKind,
    backend: HostOperationToken,
) -> Result<NativeBackendReturn, ExactLedgerError> {
    let returned = with_ledger(identity, |ledger| {
        ledger.backend_pending(invoking, kind, backend)
    });
    if returned.is_ok() {
        record_shadow_kind_install(kind);
    }
    returned
}

fn ledger_snapshot(
    identity: DriverIdentity,
) -> Result<Option<NativeLedgerSnapshot>, ExactLedgerError> {
    with_ledger(identity, |ledger| {
        ledger.snapshot(identity.exact().ok_or(ExactLedgerError::IdentityMismatch)?)
    })
}

fn ledger_pending_kind(identity: DriverIdentity) -> Result<Option<PendingKind>, ExactLedgerError> {
    ledger_snapshot(identity).map(|snapshot| snapshot.and_then(NativeLedgerSnapshot::pending_kind))
}

fn quarantine_shadow(identity: DriverIdentity) {
    let Some(exact) = identity.exact() else {
        lifecycle_fail_stop();
        return;
    };
    let Some(slot) = ledger_slot(identity.key) else {
        lifecycle_fail_stop();
        return;
    };
    let stale = {
        let mut ledger = slot.lock();
        if ledger.snapshot(exact) == Err(ExactLedgerError::StaleGeneration) {
            true
        } else {
            ledger.quarantine();
            false
        }
    };
    if stale {
        return;
    }
    let Some(lease_slot) = lease_slot(identity.key) else {
        lifecycle_fail_stop();
        return;
    };
    let lease_stale = {
        let mut leases = lease_slot.lock();
        match leases.terminal_empty(exact) {
            Err(ExactNativeLeaseError::StaleGeneration) => true,
            Ok(_) | Err(_) => {
                leases.quarantine();
                false
            }
        }
    };
    if lease_stale {
        lifecycle_fail_stop();
        return;
    }
    if let Some(shadow) = CONTROL.child_shadow.get(identity.key.slot as usize) {
        shadow.quarantine(identity.key);
    }
    if let Some(shadow) = CONTROL.supervisor_shadow.get(identity.key.slot as usize) {
        shadow.quarantine(identity.key);
    }
    let _ = registry().quarantine(identity.instance);
    lifecycle_fail_stop();
}

fn exact_ledger_lease<T: Resource>(
    cspace: &CSpace,
    cap: Cap,
    rights: Rights,
) -> Option<InvocationLease<T>> {
    if cspace.rights_of(cap).ok()? != rights {
        return None;
    }
    cspace.lookup_lease::<T>(cap, rights).ok()
}

enum BackendCancelLease {
    Reader(InvocationLease<ByteStreamSupervisor>),
    Writer(InvocationLease<ByteStreamSupervisor>),
    Terminal(InvocationLease<ByteStreamSupervisor>),
}

fn backend_cancel_lease(
    space: &InstanceSpace,
    identity: DriverIdentity,
    kind: PendingKind,
) -> Option<BackendCancelLease> {
    let cspace = space.cspace().lock();
    backend_cancel_lease_from_cspace(&cspace, identity, kind)
}

fn backend_cancel_lease_from_cspace(
    cspace: &CSpace,
    identity: DriverIdentity,
    kind: PendingKind,
) -> Option<BackendCancelLease> {
    if validate_stream_space(cspace, identity.streams).is_err() {
        return None;
    }
    match kind {
        PendingKind::ReadWaiting | PendingKind::ReadPrepared => {
            exact_ledger_lease::<ByteStreamSupervisor>(
                cspace,
                identity.streams.stdin_supervisor,
                Rights::INVOKE,
            )
            .map(BackendCancelLease::Reader)
        }
        PendingKind::WriteWaiting => exact_ledger_lease::<ByteStreamSupervisor>(
            cspace,
            identity.streams.stdout_supervisor,
            Rights::INVOKE,
        )
        .map(BackendCancelLease::Writer),
        PendingKind::TerminalWaiting => exact_ledger_lease::<ByteStreamSupervisor>(
            cspace,
            identity.streams.stdin_supervisor,
            Rights::INVOKE,
        )
        .map(BackendCancelLease::Terminal),
    }
}

fn invoke_backend_cancel(
    lease: BackendCancelLease,
    backend: HostOperationToken,
) -> Result<(), StreamError> {
    match lease {
        BackendCancelLease::Reader(supervisor) => {
            supervisor.with(|supervisor| supervisor.cancel_reader_operation_exact(backend))
        }
        BackendCancelLease::Writer(supervisor) => {
            supervisor.with(|supervisor| supervisor.cancel_writer_operation_exact(backend))
        }
        BackendCancelLease::Terminal(supervisor) => {
            supervisor.with(|supervisor| supervisor.cancel_terminal(backend))
        }
    }
}

fn endpoint_cap(identity: DriverIdentity, resource: ExactStreamResource) -> Result<Cap, ()> {
    match resource {
        ExactStreamResource::StdinReader => Ok(identity.streams.stdin),
        ExactStreamResource::StdoutWriter => Ok(identity.streams.stdout),
        ExactStreamResource::StdinSupervisor | ExactStreamResource::StdoutSupervisor => Err(()),
    }
}

fn revoke_endpoint_cap_in_space(
    space: &InstanceSpace,
    identity: DriverIdentity,
    plan: NativeResourceRevokePlan,
) -> Result<(), ()> {
    if plan.identity() != identity.exact().ok_or(())? {
        return Err(());
    }
    let endpoint = endpoint_cap(identity, plan.resource())?;
    {
        let mut cspace = space.cspace().lock();
        if validate_stream_space(&cspace, identity.streams).is_err() {
            return Err(());
        }
        if cspace.revoke_exact_admin(endpoint).map_err(|_| ())? != 1 {
            return Err(());
        }
    }
    with_ledger(identity, |ledger| ledger.finish_cap_revoke(plan)).map_err(|_| ())?;
    with_leases(identity, |leases| {
        leases.release_stream_cap(
            identity
                .exact()
                .ok_or(ExactNativeLeaseError::IdentityMismatch)?,
            plan.resource(),
        )
    })
    .map_err(|_| ())?;
    Ok(())
}

fn revoke_endpoint_and_retain_cancel_lease(
    space: &InstanceSpace,
    identity: DriverIdentity,
    plan: NativeResourceRevokePlan,
    kind: PendingKind,
) -> Result<BackendCancelLease, ()> {
    if plan.identity() != identity.exact().ok_or(())? {
        return Err(());
    }
    let endpoint = endpoint_cap(identity, plan.resource())?;
    let lease = {
        let mut cspace = space.cspace().lock();
        let lease = backend_cancel_lease_from_cspace(&cspace, identity, kind).ok_or(())?;
        if cspace.revoke_exact_admin(endpoint).map_err(|_| ())? != 1 {
            return Err(());
        }
        lease
    };
    with_ledger(identity, |ledger| ledger.finish_cap_revoke(plan)).map_err(|_| ())?;
    with_leases(identity, |leases| {
        leases.release_stream_cap(
            identity
                .exact()
                .ok_or(ExactNativeLeaseError::IdentityMismatch)?,
            plan.resource(),
        )
    })
    .map_err(|_| ())?;
    Ok(lease)
}

/// Complete a SYSTEM cancellation without holding the ledger, CSpace, or
/// stream lock across another layer. The endpoint cap may already be revoked;
/// only the independently retained supervisor capability is used here.
#[derive(Clone, Copy)]
enum DeferredBackendContinuationRelease {
    Dropped {
        continuation: NativeLeaseContinuation,
        token: InstanceContinuationToken,
    },
    Abandoned {
        continuation: NativeLeaseContinuation,
    },
}

impl DeferredBackendContinuationRelease {
    const fn continuation(self) -> NativeLeaseContinuation {
        match self {
            Self::Dropped { continuation, .. } | Self::Abandoned { continuation } => continuation,
        }
    }

    fn validate(self, identity: DriverIdentity) -> Result<(), ()> {
        let continuation = self.continuation();
        if continuation.branch() != ExactNativeLeaseBranch::Backend
            || matches!(
                self,
                Self::Dropped { token, .. } if continuation.token() != Some(token)
            )
        {
            return Err(());
        }
        let exact = identity.exact().ok_or(())?;
        match with_leases(identity, |leases| leases.continuation(exact)) {
            Ok(Some(current)) if current == continuation => Ok(()),
            Ok(Some(_) | None) | Err(_) => Err(()),
        }
    }

    fn validate_for_plan(self, identity: DriverIdentity, plan: NativeCancelPlan) -> Result<(), ()> {
        if plan.claim().cause() == ExactCancelCause::Revoke
            || plan.continuation().token() != self.continuation().token()
        {
            return Err(());
        }
        self.validate(identity)
    }

    fn finish(self, identity: DriverIdentity) -> Result<(), ()> {
        self.validate(identity)?;
        with_leases(identity, |leases| match self {
            Self::Dropped {
                continuation,
                token,
            } => leases.drop_cancelled_continuation(continuation, token),
            Self::Abandoned { continuation } => leases.abandon_continuation_raw_fault(continuation),
        })
        .map_err(|_| ())
    }
}

fn cancel_plan_in_space(
    space: &InstanceSpace,
    identity: DriverIdentity,
    plan: NativeCancelPlan,
    deferred_continuation: Option<DeferredBackendContinuationRelease>,
) -> Result<NativeLedgerSnapshot, ()> {
    if plan.snapshot().identity() != identity.exact().ok_or(())? {
        return Err(());
    }
    if let Some(deferred) = deferred_continuation {
        // Validate before the external mutation. A bad aggregate receipt must
        // leave the still-live backend operation and its wake token untouched.
        deferred.validate_for_plan(identity, plan)?;
    }
    let lease = if plan.claim().cause() == ExactCancelCause::Revoke {
        let lease = revoke_endpoint_and_retain_cancel_lease(
            space,
            identity,
            plan.resource_revoke_plan(),
            plan.kind(),
        )?;
        #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
        if c54_is_healthy_primary(identity) && !c54_record_cap_revoke(identity) {
            return Err(());
        }
        lease
    } else {
        backend_cancel_lease(space, identity, plan.kind()).ok_or(())?
    };
    if let Some(deferred) = deferred_continuation {
        exact_backend_cancel_then_release(
            || invoke_backend_cancel(lease, plan.backend()).map_err(|_| ()),
            || {
                // The physical stream slot and its copied HostWakeToken are
                // gone. A second exact validation now guards the sole credit.
                deferred.finish(identity)
            },
        )?;
    } else {
        invoke_backend_cancel(lease, plan.backend()).map_err(|_| ())?;
        #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
        if plan.claim().cause() == ExactCancelCause::Revoke
            && c54_is_healthy_primary(identity)
            && !c54_record_backend_cancel(identity)
        {
            return Err(());
        }
    }
    let continuation = plan.continuation();
    let mut cancelled =
        with_ledger(identity, |ledger| ledger.finish_cancel(plan)).map_err(|_| ())?;
    if plan.claim().cause() == ExactCancelCause::Revoke {
        match continuation {
            ExactContinuation::Armed(token) | ExactContinuation::WakeRegistered(token) => {
                let cleanup = match registry().signal_continuation(token) {
                    crate::instance::InstanceContinuationSignal::Signalled => {
                        Some(ExactContinuationCleanup::Signalled)
                    }
                    crate::instance::InstanceContinuationSignal::AlreadySignalled => {
                        Some(ExactContinuationCleanup::AlreadySignalled)
                    }
                    crate::instance::InstanceContinuationSignal::AlreadyConsumed(receipt) => {
                        if !receipt.matches_token(token) {
                            return Err(());
                        }
                        if cancelled.continuation() != ExactContinuation::Consumed(token) {
                            cancelled = with_ledger(identity, |ledger| {
                                ledger.project_consumed_continuation(
                                    identity.exact().ok_or(ExactLedgerError::IdentityMismatch)?,
                                    token,
                                )
                            })
                            .map_err(|_| ())?;
                        }
                        None
                    }
                    crate::instance::InstanceContinuationSignal::Stale
                    | crate::instance::InstanceContinuationSignal::Quarantined => return Err(()),
                };
                if let Some(cleanup) = cleanup {
                    cancelled = with_ledger(identity, |ledger| {
                        ledger.finish_continuation_cleanup(cancelled, token, cleanup)
                    })
                    .map_err(|_| ())?;
                }
            }
            ExactContinuation::None | ExactContinuation::Consumed(_) => {}
            ExactContinuation::Signalled(_)
            | ExactContinuation::Cancelled(_)
            | ExactContinuation::Abandoned(_) => return Err(()),
        }
    }
    Ok(cancelled)
}

fn cancel_plan_in_current(
    identity: DriverIdentity,
    plan: NativeCancelPlan,
    deferred_continuation: Option<DeferredBackendContinuationRelease>,
) -> Result<NativeLedgerSnapshot, ()> {
    let witness = crate::exec::current_reclaimable_task_witness().ok_or(())?;
    if witness.instance_token() != Some(identity.instance)
        || witness.task_id() != identity.task
        || witness.allocation_domain() != identity.domain
    {
        return Err(());
    }
    unsafe {
        registry()
            .with_current_space_for_cleanup(witness, |space| {
                cancel_plan_in_space(space, identity, plan, deferred_continuation)
            })
            .map_err(|_| ())?
    }
}

#[derive(Clone, Copy)]
enum BackendPendingOutcome {
    Pending(NativeLedgerSnapshot),
    Revoked(NativeLedgerSnapshot),
}

fn backend_return_pending(
    identity: DriverIdentity,
    returned: NativeBackendReturn,
) -> Result<BackendPendingOutcome, ComponentTerminal> {
    match returned {
        ExactBackendReturn::Pending(snapshot) => Ok(BackendPendingOutcome::Pending(snapshot)),
        ExactBackendReturn::Cancel(plan) => {
            // The revoke claim won while the backend method was outside the
            // ledger. Revoke the exact endpoint cap and cancel only through its
            // supervisor. The driver still owns the runtime token and must
            // explicitly drop it before the cancellation can be consumed.
            cancel_plan_in_current(identity, plan, None)
                .map(BackendPendingOutcome::Revoked)
                .map_err(|()| unexpected_native_driver_error(identity, "deferred revoke cancel"))
        }
    }
}

fn finish_live_revoke(
    identity: DriverIdentity,
    cancelled: NativeLedgerSnapshot,
) -> Result<(), ComponentTerminal> {
    let acknowledged = model_result(
        identity,
        with_ledger(identity, |ledger| {
            ledger.acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Cancelled)
        }),
    )?;
    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    if c54_is_healthy_primary(identity) && !c54_record_runtime_cancel(identity) {
        return Err(unexpected_native_driver_error(
            identity,
            "C5.4 runtime cancel acknowledgement count",
        ));
    }
    model_result(
        identity,
        with_ledger(identity, |ledger| ledger.consume_cancelled(acknowledged)),
    )?;
    finish_backend_lease(identity)?;
    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    if c54_is_healthy_primary(identity) && !c54_record_cancel_idle(identity) {
        return Err(unexpected_native_driver_error(
            identity,
            "C5.4 cancel idle count",
        ));
    }
    Ok(())
}

fn cancel_residual_in_current(
    identity: DriverIdentity,
    plan: NativeResidualCancelPlan,
) -> Result<NativeLedgerSnapshot, ()> {
    let witness = crate::exec::current_reclaimable_task_witness().ok_or(())?;
    if witness.instance_token() != Some(identity.instance)
        || witness.task_id() != identity.task
        || witness.allocation_domain() != identity.domain
    {
        return Err(());
    }
    unsafe {
        registry()
            .with_current_space_for_cleanup(witness, |space| {
                let lease =
                    backend_cancel_lease(space, identity, PendingKind::ReadPrepared).ok_or(())?;
                invoke_backend_cancel(lease, plan.backend()).map_err(|_| ())?;
                with_ledger(identity, |ledger| {
                    ledger.finish_backend_residual_cancel(plan)
                })
                .map_err(|_| ())
            })
            .map_err(|_| ())?
    }
}

#[derive(Clone, Copy)]
struct NativeLeaseCleanupProjection {
    continuation: Option<NativeLeaseContinuation>,
    core_continuation: Option<InstanceContinuationToken>,
    core_continuation_branch: Option<ExactNativeLeaseBranch>,
    backend: bool,
    input_spill: bool,
    runtime_wait: Option<NativeWaitToken>,
}

fn lease_cleanup_projection(
    identity: DriverIdentity,
) -> Result<NativeLeaseCleanupProjection, ExactNativeLeaseError> {
    with_leases(identity, |leases| {
        let exact = identity
            .exact()
            .ok_or(ExactNativeLeaseError::IdentityMismatch)?;
        let continuation = leases.continuation(exact)?;
        let core_continuation = leases.core_continuation(exact)?;
        let core_continuation_branch = leases.core_continuation_branch(exact)?;
        Ok(NativeLeaseCleanupProjection {
            continuation,
            core_continuation,
            core_continuation_branch,
            backend: leases.has_backend(exact)?,
            input_spill: leases.has_input_spill(exact)?,
            runtime_wait: leases.runtime_wait(exact)?,
        })
    })
}

fn operation_holds_backend(snapshot: Option<NativeLedgerSnapshot>) -> bool {
    snapshot.is_some_and(|snapshot| {
        matches!(
            snapshot.phase(),
            ExactLedgerPhase::BackendInvoking
                | ExactLedgerPhase::BackendPending
                | ExactLedgerPhase::BackendLinearized
                | ExactLedgerPhase::CancelClaimed
                | ExactLedgerPhase::BackendCancelled
        )
    })
}

fn cleanup_projections_match(
    operation: Option<NativeLedgerSnapshot>,
    operation_input_spill: bool,
    leases: NativeLeaseCleanupProjection,
) -> bool {
    if operation_holds_backend(operation) != leases.backend
        || operation_input_spill != leases.input_spill
        || (leases.runtime_wait.is_some() && operation.is_some())
    {
        return false;
    }
    let operation_continuation = operation
        .map(NativeLedgerSnapshot::continuation)
        .unwrap_or(ExactContinuation::None);
    match leases.continuation {
        Some(continuation) => {
            let branch_exact = match continuation.branch() {
                ExactNativeLeaseBranch::Quantum => true,
                ExactNativeLeaseBranch::Backend => leases.backend && leases.runtime_wait.is_none(),
                ExactNativeLeaseBranch::RuntimeWait => {
                    !leases.backend && leases.runtime_wait.is_some()
                }
            };
            let live_token_exact = continuation.token().is_none_or(|token| {
                leases.core_continuation == Some(token)
                    && leases.core_continuation_branch == Some(continuation.branch())
            });
            let operation_exact = match operation_continuation {
                ExactContinuation::Armed(token)
                | ExactContinuation::WakeRegistered(token)
                | ExactContinuation::Signalled(token)
                | ExactContinuation::Cancelled(token)
                | ExactContinuation::Abandoned(token) => {
                    continuation.branch() == ExactNativeLeaseBranch::Backend
                        && continuation.token() == Some(token)
                }
                ExactContinuation::Consumed(token) => match continuation.branch() {
                    ExactNativeLeaseBranch::Backend => continuation.token() == Some(token),
                    ExactNativeLeaseBranch::Quantum => true,
                    ExactNativeLeaseBranch::RuntimeWait => false,
                },
                ExactContinuation::None => true,
            };
            branch_exact && live_token_exact && operation_exact
        }
        None => match leases.core_continuation_branch {
            Some(ExactNativeLeaseBranch::Backend) => operation_continuation
                .token()
                .is_none_or(|token| leases.core_continuation == Some(token)),
            Some(ExactNativeLeaseBranch::Quantum) => matches!(
                operation_continuation,
                ExactContinuation::None | ExactContinuation::Consumed(_)
            ),
            Some(ExactNativeLeaseBranch::RuntimeWait) | None => {
                operation_continuation == ExactContinuation::None
            }
        },
    }
}

fn reconcile_terminal_lease_residues(
    identity: DriverIdentity,
    projection: NativeLeaseCleanupProjection,
) -> Result<bool, ExactNativeLeaseError> {
    with_leases(identity, |leases| {
        let exact = identity
            .exact()
            .ok_or(ExactNativeLeaseError::IdentityMismatch)?;
        if leases.continuation(exact)?.is_some()
            || leases.core_continuation(exact)? != projection.core_continuation
            || leases.core_continuation_branch(exact)? != projection.core_continuation_branch
            || leases.has_backend(exact)? != projection.backend
            || leases.has_input_spill(exact)? != projection.input_spill
            || leases.runtime_wait(exact)? != projection.runtime_wait
        {
            return Ok(false);
        }
        if projection.backend {
            leases.finish_backend(exact)?;
        }
        if let Some(wait) = projection.runtime_wait {
            leases.finish_runtime_wait(exact, wait)?;
        }
        if projection.input_spill {
            leases.finish_input_spill(exact)?;
        }
        leases.terminal_empty(exact)
    })
}

pub(super) fn payload_drop(
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
) {
    let identity = DriverIdentity {
        key,
        instance: token,
        task,
        domain,
        streams,
    };
    let exact = match identity.exact() {
        Some(exact) => exact,
        None => {
            quarantine_shadow(identity);
            return;
        }
    };
    let before = match ledger_snapshot(identity) {
        Ok(snapshot) => snapshot,
        Err(ExactLedgerError::StaleGeneration) => return,
        Err(_) => {
            quarantine_shadow(identity);
            return;
        }
    };
    let operation_input_spill =
        match with_ledger(identity, |ledger| ledger.input_spill_remaining(exact)) {
            Ok(remaining) => remaining.is_some(),
            Err(ExactLedgerError::StaleGeneration) => return,
            Err(_) => {
                quarantine_shadow(identity);
                return;
            }
        };
    let lease_projection = match lease_cleanup_projection(identity) {
        Ok(projection) => projection,
        Err(ExactNativeLeaseError::StaleGeneration) => return,
        Err(_) => {
            quarantine_shadow(identity);
            return;
        }
    };
    if !cleanup_projections_match(before, operation_input_spill, lease_projection) {
        quarantine_shadow(identity);
        return;
    }
    let waiter = before.and_then(|snapshot| match snapshot.continuation() {
        ExactContinuation::Armed(token)
        | ExactContinuation::WakeRegistered(token)
        | ExactContinuation::Signalled(token) => Some(token),
        _ => None,
    });
    let mut deferred_backend_continuation = None;
    let cancelled_waiter = match lease_projection.continuation {
        Some(continuation) => match continuation.token() {
            Some(token) => {
                if (continuation.branch() == ExactNativeLeaseBranch::Backend
                    && waiter != Some(token))
                    || (continuation.branch() != ExactNativeLeaseBranch::Backend
                        && waiter.is_some())
                {
                    quarantine_shadow(identity);
                    return;
                }
                let cancelled = match registry().confirm_cancelled_continuation_current(token) {
                    Ok(receipt) if receipt.matches_token(token) => receipt,
                    _ => {
                        quarantine_shadow(identity);
                        return;
                    }
                };
                let backend_already_cancelled = before.is_some_and(|snapshot| {
                    snapshot.phase() == ExactLedgerPhase::BackendCancelled
                        && snapshot.continuation() == ExactContinuation::Signalled(token)
                });
                if continuation.branch() == ExactNativeLeaseBranch::Backend
                    && !backend_already_cancelled
                {
                    // Core's receipt retires only the scheduler continuation.
                    // The stream still owns its copied wake token until the
                    // exact backend cancellation below removes the operation.
                    deferred_backend_continuation =
                        Some(DeferredBackendContinuationRelease::Dropped {
                            continuation,
                            token,
                        });
                } else if with_leases(identity, |leases| {
                    leases.drop_cancelled_continuation(continuation, token)
                })
                .is_err()
                {
                    quarantine_shadow(identity);
                    return;
                }
                waiter.map(|_| cancelled)
            }
            None => {
                if waiter.is_some()
                    || with_leases(identity, |leases| {
                        leases.cancel_reserved_continuation(continuation)
                    })
                    .is_err()
                {
                    quarantine_shadow(identity);
                    return;
                }
                None
            }
        },
        None => {
            if waiter.is_some() {
                quarantine_shadow(identity);
                return;
            }
            None
        }
    };
    if let Err(error) = with_ledger(identity, |ledger| {
        ledger.acknowledge_runtime_owner_drop(exact)
    }) {
        if error != ExactLedgerError::StaleGeneration {
            quarantine_shadow(identity);
        }
        return;
    }
    if let (Some(snapshot), Some(waiter), Some(receipt)) = (before, waiter, cancelled_waiter) {
        if snapshot.phase() == ExactLedgerPhase::BackendCancelled
            && snapshot.continuation() == ExactContinuation::Signalled(waiter)
        {
            if !receipt.matches_token(waiter) {
                quarantine_shadow(identity);
                return;
            }
            let cancelled = match with_ledger(identity, |ledger| {
                ledger.finish_continuation_cleanup(
                    snapshot,
                    waiter,
                    ExactContinuationCleanup::Cancelled,
                )
            }) {
                Ok(cancelled) => cancelled,
                Err(_) => {
                    quarantine_shadow(identity);
                    return;
                }
            };
            let dropped = match with_ledger(identity, |ledger| {
                ledger.acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Dropped)
            }) {
                Ok(dropped) => dropped,
                Err(_) => {
                    quarantine_shadow(identity);
                    return;
                }
            };
            if with_ledger(identity, |ledger| ledger.consume_cancelled(dropped)).is_err() {
                quarantine_shadow(identity);
                return;
            }
            match reconcile_terminal_lease_residues(identity, lease_projection) {
                Ok(true) => {}
                Ok(false) | Err(_) => quarantine_shadow(identity),
            }
            return;
        }
    }
    let decision = match with_ledger(identity, |ledger| ledger.prepare_finalizer(exact, false)) {
        Ok(decision) => decision,
        Err(_) => {
            quarantine_shadow(identity);
            return;
        }
    };
    let plan = match decision {
        ExactCleanupDecision::ReclaimSafe => {
            match reconcile_terminal_lease_residues(identity, lease_projection) {
                Ok(true) => {}
                Ok(false) | Err(_) => quarantine_shadow(identity),
            }
            return;
        }
        ExactCleanupDecision::Quarantined => {
            quarantine_shadow(identity);
            return;
        }
        ExactCleanupDecision::Cancel(plan) => plan,
    };
    let continuation = plan.continuation();
    let mut cancelled = match cancel_plan_in_current(identity, plan, deferred_backend_continuation)
    {
        Ok(cancelled) => cancelled,
        Err(()) => {
            quarantine_shadow(identity);
            return;
        }
    };
    match (continuation, waiter, cancelled_waiter) {
        (
            ExactContinuation::Armed(current)
            | ExactContinuation::WakeRegistered(current)
            | ExactContinuation::Signalled(current),
            Some(waiter),
            Some(receipt),
        ) if current == waiter && receipt.matches_token(waiter) => {
            cancelled = match with_ledger(identity, |ledger| {
                ledger.finish_continuation_cleanup(
                    cancelled,
                    waiter,
                    ExactContinuationCleanup::Cancelled,
                )
            }) {
                Ok(cancelled) => cancelled,
                Err(_) => {
                    quarantine_shadow(identity);
                    return;
                }
            };
        }
        (ExactContinuation::None | ExactContinuation::Consumed(_), None, None) => {}
        _ => {
            quarantine_shadow(identity);
            return;
        }
    }
    cancelled = match with_ledger(identity, |ledger| {
        ledger.acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Dropped)
    }) {
        Ok(cancelled) => cancelled,
        Err(_) => {
            quarantine_shadow(identity);
            return;
        }
    };
    if with_ledger(identity, |ledger| ledger.consume_cancelled(cancelled)).is_err() {
        quarantine_shadow(identity);
        return;
    }
    match reconcile_terminal_lease_residues(identity, lease_projection) {
        Ok(true) => {}
        Ok(false) | Err(_) => quarantine_shadow(identity),
    }
}

fn terminal_shadow_empty(identity: DriverIdentity) -> bool {
    let Some(exact) = identity.exact() else {
        return false;
    };
    with_ledger(identity, |ledger| ledger.terminal_empty(exact)).is_ok_and(|empty| empty)
        && with_leases(identity, |leases| leases.terminal_empty(exact)).is_ok_and(|empty| empty)
}

pub(super) fn retire_terminal_shadow(
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance: token,
        task,
        domain,
        streams,
    };
    if !terminal_shadow_empty(identity) {
        quarantine_shadow(identity);
        return false;
    }
    let retired = with_ledger(identity, |ledger| {
        ledger.retire(identity.exact().ok_or(ExactLedgerError::IdentityMismatch)?)
    });
    if retired.is_err() {
        return false;
    }
    #[cfg(feature = "ssh-native-async-qemu-acceptance")]
    if !target_record_shadow_retired(identity) {
        quarantine_shadow(identity);
        return false;
    }
    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    if !c54_record_shadow_retired(identity) {
        quarantine_shadow(identity);
        return false;
    }
    true
}

pub(super) fn finish_terminal_lease_reset(
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    revoked_capabilities: usize,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance: token,
        task,
        domain,
        streams,
    };
    let Some(exact) = identity.exact() else {
        return false;
    };
    let Ok(revoked_capabilities) = u8::try_from(revoked_capabilities) else {
        return false;
    };
    with_leases(identity, |leases| {
        leases.reset_stream_caps(exact, revoked_capabilities)?;
        let metrics = leases.metrics();
        if metrics.current() != 0
            || metrics.peak() > metrics.limit()
            || metrics.limit() != EXACT_NATIVE_LEASE_LIMIT
        {
            leases.quarantine();
            return Ok(false);
        }
        leases.retire(exact)?;
        Ok(leases.is_retired())
    })
    .is_ok_and(|retired| retired)
}

fn validate_terminal_resource_projection(
    space: &InstanceSpace,
    identity: DriverIdentity,
    terminal: ComponentTerminal,
) -> bool {
    #[cfg(not(feature = "ssh-native-async-revoke-qemu-acceptance"))]
    let _ = terminal;
    let Some(exact) = identity.exact() else {
        return false;
    };
    let stdin = with_ledger(identity, |ledger| {
        ledger.resource_state(exact, ExactStreamResource::StdinReader)
    });
    let stdout = with_ledger(identity, |ledger| {
        ledger.resource_state(exact, ExactStreamResource::StdoutWriter)
    });
    let (Ok(stdin), Ok(stdout)) = (stdin, stdout) else {
        return false;
    };
    let cspace = space.cspace().lock();
    if validate_stream_space(&cspace, identity.streams).is_err()
        || exact_ledger_lease::<ByteStreamSupervisor>(
            &cspace,
            identity.streams.stdin_supervisor,
            Rights::INVOKE,
        )
        .is_none()
        || exact_ledger_lease::<ByteStreamSupervisor>(
            &cspace,
            identity.streams.stdout_supervisor,
            Rights::INVOKE,
        )
        .is_none()
    {
        return false;
    }
    let stdin_exact = match stdin {
        ExactResourceState::Live => {
            exact_ledger_lease::<ByteStreamReader>(&cspace, identity.streams.stdin, Rights::RECV)
                .is_some()
        }
        ExactResourceState::Revoked => matches!(
            cspace.rights_of(identity.streams.stdin),
            Err(CapError::Invalid)
        ),
        ExactResourceState::Revoking => false,
    };
    let stdout_exact = match stdout {
        ExactResourceState::Live => {
            exact_ledger_lease::<ByteStreamWriter>(&cspace, identity.streams.stdout, Rights::SEND)
                .is_some()
        }
        ExactResourceState::Revoked => matches!(
            cspace.rights_of(identity.streams.stdout),
            Err(CapError::Invalid)
        ),
        ExactResourceState::Revoking => false,
    };
    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    if !c54_terminal_projection_exact(identity, terminal, stdin, stdout) {
        return false;
    }
    stdin_exact && stdout_exact
}

/// Resolve the SYSTEM pending-operation projection while the registry has
/// restored and revalidated the exact Space, but before either raw arena
/// reclaim or the terminal CSpace reset is allowed to proceed. The registry,
/// CONTROL, shadow, and CSpace guards are all absent on entry.
pub(super) fn prepare_terminal_shadow(
    space: &InstanceSpace,
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    terminal: ComponentTerminal,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance: token,
        task,
        domain,
        streams,
    };
    let exact = match identity.exact() {
        Some(exact) => exact,
        None => {
            quarantine_shadow(identity);
            return false;
        }
    };
    if !validate_terminal_resource_projection(space, identity, terminal) {
        quarantine_shadow(identity);
        return false;
    }
    let decision = with_ledger(identity, |ledger| {
        ledger.prepare_finalizer(exact, terminal == ComponentTerminal::Success)
    });
    match decision {
        Ok(ExactCleanupDecision::ReclaimSafe) => {
            if terminal_shadow_empty(identity) {
                true
            } else {
                quarantine_shadow(identity);
                false
            }
        }
        Ok(ExactCleanupDecision::Quarantined) | Err(_) => {
            quarantine_shadow(identity);
            false
        }
        Ok(ExactCleanupDecision::Cancel(plan)) => {
            let continuation = plan.continuation();
            let mut cancelled = match cancel_plan_in_space(space, identity, plan, None) {
                Ok(cancelled) => cancelled,
                Err(()) => {
                    quarantine_shadow(identity);
                    return false;
                }
            };
            // The payload-drop gate must already have consumed Core's exact
            // Cancelled receipt. Only a waiter that was consumed normally can
            // therefore reach this supervisor-only finalizer.
            if !matches!(
                continuation,
                ExactContinuation::None | ExactContinuation::Consumed(_)
            ) {
                quarantine_shadow(identity);
                return false;
            }
            cancelled = match with_ledger(identity, |ledger| {
                ledger.acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Dropped)
            }) {
                Ok(cancelled) => cancelled,
                Err(_) => {
                    quarantine_shadow(identity);
                    return false;
                }
            };
            let _ = cancelled;
            match with_ledger(identity, |ledger| ledger.prepare_finalizer(exact, false)) {
                Ok(ExactCleanupDecision::ReclaimSafe) => {
                    if terminal_shadow_empty(identity) {
                        true
                    } else {
                        quarantine_shadow(identity);
                        false
                    }
                }
                Ok(ExactCleanupDecision::Cancel(_) | ExactCleanupDecision::Quarantined)
                | Err(_) => {
                    quarantine_shadow(identity);
                    false
                }
            }
        }
    }
}

pub(super) fn raw_fault_cleanup(
    space: &InstanceSpace,
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    receipt: FaultContinuationAbandonReceipt,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance: token,
        task,
        domain,
        streams,
    };
    let Some(exact) = identity.exact() else {
        quarantine_shadow(identity);
        return false;
    };
    let snapshot = match ledger_snapshot(identity) {
        Ok(snapshot) => snapshot,
        Err(ExactLedgerError::StaleGeneration) => return false,
        Err(_) => {
            quarantine_shadow(identity);
            return false;
        }
    };
    let operation_input_spill =
        match with_ledger(identity, |ledger| ledger.input_spill_remaining(exact)) {
            Ok(remaining) => remaining.is_some(),
            Err(ExactLedgerError::StaleGeneration) => return false,
            Err(_) => {
                quarantine_shadow(identity);
                return false;
            }
        };
    let lease_projection = match lease_cleanup_projection(identity) {
        Ok(projection) => projection,
        Err(ExactNativeLeaseError::StaleGeneration) => return false,
        Err(_) => {
            quarantine_shadow(identity);
            return false;
        }
    };
    if !cleanup_projections_match(snapshot, operation_input_spill, lease_projection) {
        quarantine_shadow(identity);
        return false;
    }
    if !receipt.matches_exact(token, lease_projection.core_continuation) {
        quarantine_shadow(identity);
        return false;
    }
    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    let raw_phase = snapshot.map(NativeLedgerSnapshot::phase);
    let mut deferred_backend_continuation = None;
    if let Some(continuation) = lease_projection.continuation {
        if continuation.branch() == ExactNativeLeaseBranch::Backend {
            // Core abandonment does not revoke the stream's copied wake
            // token. Keep both aggregate charges until exact backend cancel.
            deferred_backend_continuation =
                Some(DeferredBackendContinuationRelease::Abandoned { continuation });
        } else if with_leases(identity, |leases| {
            leases.abandon_continuation_raw_fault(continuation)
        })
        .is_err()
        {
            quarantine_shadow(identity);
            return false;
        }
    }
    let completed_revoke = snapshot.filter(|snapshot| {
        snapshot.phase() == ExactLedgerPhase::BackendCancelled
            && matches!(
                snapshot.continuation(),
                ExactContinuation::Signalled(_) | ExactContinuation::Consumed(_)
            )
    });
    if let Some(completed_revoke) = completed_revoke {
        // The exact revoked latch and BackendCancelled snapshot prove the
        // physical backend operation is already gone. Take over only after
        // Core's fault receipt matched the current continuation projection.
        if with_ledger(identity, |ledger| {
            ledger.abandon_completed_revoke_raw_fault(completed_revoke)
        })
        .is_err()
        {
            quarantine_shadow(identity);
            return false;
        }
        if let Some(deferred) = deferred_backend_continuation {
            if deferred.finish(identity).is_err() {
                quarantine_shadow(identity);
                return false;
            }
        }
        return match with_ledger(identity, |ledger| ledger.raw_fault(exact)) {
            Ok(ExactCleanupDecision::ReclaimSafe) => {
                match reconcile_terminal_lease_residues(identity, lease_projection) {
                    Ok(true) => true,
                    Ok(false) | Err(_) => {
                        quarantine_shadow(identity);
                        false
                    }
                }
            }
            Ok(ExactCleanupDecision::Cancel(_) | ExactCleanupDecision::Quarantined) | Err(_) => {
                quarantine_shadow(identity);
                false
            }
        };
    }
    let decision = with_ledger(identity, |ledger| ledger.raw_fault(exact));
    let plan = match decision {
        Ok(ExactCleanupDecision::ReclaimSafe) => {
            return match reconcile_terminal_lease_residues(identity, lease_projection) {
                Ok(true) => true,
                Ok(false) | Err(_) => {
                    quarantine_shadow(identity);
                    false
                }
            };
        }
        Ok(ExactCleanupDecision::Cancel(plan)) => plan,
        Ok(ExactCleanupDecision::Quarantined) | Err(_) => {
            #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
            {
                let expects_raw = {
                    let audit = C54_TARGET.lock();
                    audit.is_primary(identity)
                        && matches!(
                            audit.scenario,
                            C54Scenario::RawInvoking | C54Scenario::RawLinearized
                        )
                };
                if expects_raw
                    && raw_phase.is_none_or(|phase| !c54_record_raw_fault_seen(identity, phase))
                {
                    c54_fail("raw-fault-phase");
                }
            }
            quarantine_shadow(identity);
            return false;
        }
    };
    let continuation = plan.continuation();
    let mut cancelled =
        match cancel_plan_in_space(space, identity, plan, deferred_backend_continuation) {
            Ok(cancelled) => cancelled,
            Err(()) => {
                quarantine_shadow(identity);
                return false;
            }
        };
    match continuation {
        ExactContinuation::Armed(continuation)
        | ExactContinuation::WakeRegistered(continuation) => {
            if !receipt.matches_continuation(Some(continuation)) {
                quarantine_shadow(identity);
                return false;
            }
            cancelled = match with_ledger(identity, |ledger| {
                ledger.finish_continuation_cleanup(
                    cancelled,
                    continuation,
                    ExactContinuationCleanup::Abandoned,
                )
            }) {
                Ok(cancelled) => cancelled,
                Err(_) => {
                    quarantine_shadow(identity);
                    return false;
                }
            };
        }
        ExactContinuation::Consumed(continuation) => {
            if receipt.matches_continuation(Some(continuation)) {
                cancelled = match with_ledger(identity, |ledger| {
                    ledger.finish_continuation_cleanup(
                        cancelled,
                        continuation,
                        ExactContinuationCleanup::Abandoned,
                    )
                }) {
                    Ok(cancelled) => cancelled,
                    Err(_) => {
                        quarantine_shadow(identity);
                        return false;
                    }
                };
            } else if lease_projection.core_continuation_branch
                != Some(ExactNativeLeaseBranch::Quantum)
            {
                quarantine_shadow(identity);
                return false;
            }
        }
        ExactContinuation::None => {}
        ExactContinuation::Signalled(_)
        | ExactContinuation::Cancelled(_)
        | ExactContinuation::Abandoned(_) => {
            quarantine_shadow(identity);
            return false;
        }
    }
    cancelled = match with_ledger(identity, |ledger| {
        ledger.acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Abandoned)
    }) {
        Ok(cancelled) => cancelled,
        Err(_) => {
            quarantine_shadow(identity);
            return false;
        }
    };
    let _ = cancelled;
    match with_ledger(identity, |ledger| ledger.raw_fault(exact)) {
        Ok(ExactCleanupDecision::ReclaimSafe) => {
            match reconcile_terminal_lease_residues(identity, lease_projection) {
                Ok(true) => true,
                Ok(false) | Err(_) => {
                    quarantine_shadow(identity);
                    false
                }
            }
        }
        Ok(ExactCleanupDecision::Cancel(_) | ExactCleanupDecision::Quarantined) | Err(_) => {
            quarantine_shadow(identity);
            false
        }
    }
}

pub(super) fn quarantine_fault_shadow(
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
) {
    quarantine_shadow(DriverIdentity {
        key,
        instance: token,
        task,
        domain,
        streams,
    });
}

fn stream_reason(value: u8) -> Option<StreamCloseReason> {
    match value {
        0 => Some(StreamCloseReason::Normal),
        1 => Some(StreamCloseReason::Failure),
        2 => Some(StreamCloseReason::Cancelled),
        3 => Some(StreamCloseReason::Denied),
        4 => Some(StreamCloseReason::Unavailable),
        5 => Some(StreamCloseReason::Exhausted),
        6 => Some(StreamCloseReason::Invalid),
        7 => Some(StreamCloseReason::BackendFault),
        _ => None,
    }
}

fn stream_reason_value(reason: StreamCloseReason) -> u8 {
    reason as u8
}

fn promote_input_normal(identity: DriverIdentity) -> Result<(), ()> {
    let observed = with_active_reader(identity.instance, identity.streams, |_, supervisor| {
        supervisor.promote_normal_if_drained_observed()
    })
    .map_err(|_| ())?;
    match observed {
        None => Ok(()),
        Some(observation)
            if matches!(
                observation.outcome(),
                StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
            ) && observation.effective_reason().is_some() =>
        {
            Ok(())
        }
        Some(_) => Err(()),
    }
}

fn native_error_terminal(error: NativeError) -> ComponentTerminal {
    match error {
        NativeError::Allocation | NativeError::CoreAdmission | NativeError::InvalidBudget => {
            ComponentTerminal::BudgetExceeded
        }
        NativeError::AsyncUnavailable => ComponentTerminal::Unavailable,
        NativeError::CoreInstantiation
        | NativeError::MissingModule
        | NativeError::MissingExport
        | NativeError::InvalidWiring
        | NativeError::Busy
        | NativeError::Poisoned
        | NativeError::UnsupportedFeature
        | NativeError::NotValidationCandidate => ComponentTerminal::BackendFault,
    }
}

fn unexpected_native_driver_error(
    identity: DriverIdentity,
    _error: impl core::fmt::Debug,
) -> ComponentTerminal {
    quarantine_shadow(identity);
    ComponentTerminal::RunnerFault
}

fn poll_terminal(poll: NativePoll) -> Option<ComponentTerminal> {
    match poll {
        NativePoll::Trapped(trap) => Some(trap_terminal(trap)),
        _ => None,
    }
}

/// Normalizes the runtime's fail-stop handoff at one exact owner-visible
/// boundary. Authority is already fenced when `CleanupPending` is returned;
/// only the bounded reclamation charge may run after this quantum. No caller
/// may inspect or commit a runtime result until it has crossed this gate.
async fn drain_runtime_cleanup(
    invocation: &mut NativeInvocation<'_>,
    identity: DriverIdentity,
    poll: NativePoll,
) -> Result<NativePoll, ComponentTerminal> {
    let NativePoll::CleanupPending { trap, .. } = poll else {
        return Ok(poll);
    };
    quantum(identity).await?;
    match invocation.poll() {
        NativePoll::Trapped(observed) if observed == trap => Ok(NativePoll::Trapped(observed)),
        other => Err(unexpected_native_driver_error(
            identity,
            ("invalid cleanup terminal", trap, other),
        )),
    }
}

/// Finalization is itself one charged runtime turn. If that turn detects a
/// sealed invariant, normalize its distinct handoff through the same exact
/// quantum-delayed cleanup gate before reporting the runner fault.
async fn finalize_runtime_transport(
    invocation: &mut NativeInvocation<'_>,
    identity: DriverIdentity,
) -> Result<(), ComponentTerminal> {
    match invocation.finalize_transport() {
        Ok(()) => Ok(()),
        Err(NativeFinalizeError::CleanupPending { trap, metrics }) => {
            match drain_runtime_cleanup(
                invocation,
                identity,
                NativePoll::CleanupPending { trap, metrics },
            )
            .await?
            {
                NativePoll::Trapped(observed) if observed == trap => Err(
                    unexpected_native_driver_error(identity, "transport finalization invariant"),
                ),
                other => Err(unexpected_native_driver_error(
                    identity,
                    ("invalid finalized cleanup terminal", trap, other),
                )),
            }
        }
        Err(error) => Err(unexpected_native_driver_error(
            identity,
            ("transport finalization rejected", error),
        )),
    }
}

async fn quantum(identity: DriverIdentity) -> Result<(), ComponentTerminal> {
    let exact = identity
        .exact()
        .ok_or_else(|| unexpected_native_driver_error(identity, "quantum identity"))?;
    let reserved = lease_result(
        identity,
        with_leases(identity, |leases| {
            leases.reserve_quantum_continuation(exact)
        }),
    )?;
    let operation = match registry()
        .arm_continuation_current(identity.instance, InstanceContinuationKind::Quantum)
    {
        Ok(operation) => operation,
        Err(error) => {
            lease_result(
                identity,
                with_leases(identity, |leases| {
                    leases.cancel_reserved_continuation(reserved)
                }),
            )?;
            return Err(unexpected_native_driver_error(identity, error));
        }
    };
    let bound = lease_result(
        identity,
        with_leases(identity, |leases| {
            leases.bind_continuation(reserved, operation)
        }),
    )?;
    let continuation = registry()
        .wait_continuation(operation)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    let consumed = continuation
        .await
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    if !consumed.matches_token(operation) {
        return Err(unexpected_native_driver_error(
            identity,
            "quantum continuation receipt mismatch",
        ));
    }
    lease_result(
        identity,
        with_leases(identity, |leases| {
            leases.consume_quantum_continuation(bound, operation)
        }),
    )
}

async fn await_runtime_wait(
    invocation: &mut NativeInvocation<'_>,
    identity: DriverIdentity,
    wait: NativeWaitToken,
) -> Result<NativePoll, ComponentTerminal> {
    let exact = identity
        .exact()
        .ok_or_else(|| unexpected_native_driver_error(identity, "runtime wait identity"))?;
    lease_result(
        identity,
        with_leases(identity, |leases| leases.begin_runtime_wait(exact, wait)),
    )?;
    let (continuation_token, bound_lease, continuation) =
        arm_external_lease_continuation(identity)?;
    let registered_lease = lease_result(
        identity,
        with_leases(identity, |leases| {
            leases.register_runtime_wake(bound_lease, wait)
        }),
    )?;
    let wake = HostWakeToken::new(continuation_token.signal_words(), stream_wake);
    let registration: NativeWaitRegistration = match invocation.register_wait_wake(wait, wake) {
        Ok(registration) => registration,
        Err(error) => {
            drop(continuation);
            confirm_dropped_lease_continuation(identity, registered_lease, continuation_token)?;
            lease_result(
                identity,
                with_leases(identity, |leases| leases.finish_runtime_wait(exact, wait)),
            )?;
            return Err(unexpected_native_driver_error(identity, error));
        }
    };
    let consumed = continuation
        .await
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    if !consumed.matches_token(continuation_token) {
        return Err(unexpected_native_driver_error(
            identity,
            "runtime wait continuation receipt mismatch",
        ));
    }
    lease_result(
        identity,
        with_leases(identity, |leases| {
            leases.consume_continuation(registered_lease, continuation_token)
        }),
    )?;
    let resumed = invocation
        .resume_wait(registration)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    lease_result(
        identity,
        with_leases(identity, |leases| leases.finish_runtime_wait(exact, wait)),
    )?;
    drain_runtime_cleanup(invocation, identity, resumed).await
}

fn stream_wake(words: [usize; 4]) {
    match registry().signal_continuation_words(words) {
        crate::instance::InstanceContinuationSignal::Signalled
        | crate::instance::InstanceContinuationSignal::AlreadySignalled
        | crate::instance::InstanceContinuationSignal::AlreadyConsumed(_)
        | crate::instance::InstanceContinuationSignal::Stale => {}
        crate::instance::InstanceContinuationSignal::Quarantined => lifecycle_fail_stop(),
    }
}

fn arm_external_lease_continuation(
    identity: DriverIdentity,
) -> Result<
    (
        InstanceContinuationToken,
        NativeLeaseContinuation,
        crate::instance::InstanceContinuation<'static>,
    ),
    ComponentTerminal,
> {
    let exact = identity.exact().ok_or_else(|| {
        unexpected_native_driver_error(identity, "external continuation identity")
    })?;
    let reserved = lease_result(
        identity,
        with_leases(identity, |leases| leases.reserve_continuation(exact)),
    )?;
    let token = match registry()
        .arm_continuation_current(identity.instance, InstanceContinuationKind::External)
    {
        Ok(token) => token,
        Err(error) => {
            lease_result(
                identity,
                with_leases(identity, |leases| {
                    leases.cancel_reserved_continuation(reserved)
                }),
            )?;
            return Err(unexpected_native_driver_error(identity, error));
        }
    };
    let bound = lease_result(
        identity,
        with_leases(identity, |leases| leases.bind_continuation(reserved, token)),
    )?;
    let continuation = registry()
        .wait_continuation(token)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    Ok((token, bound, continuation))
}

fn confirm_dropped_lease_continuation(
    identity: DriverIdentity,
    receipt: NativeLeaseContinuation,
    token: InstanceContinuationToken,
) -> Result<(), ComponentTerminal> {
    let cancelled = registry()
        .confirm_cancelled_continuation_current(token)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    if !cancelled.matches_token(token) {
        return Err(unexpected_native_driver_error(
            identity,
            "cancelled continuation receipt mismatch",
        ));
    }
    lease_result(
        identity,
        with_leases(identity, |leases| {
            leases.drop_cancelled_continuation(receipt, token)
        }),
    )
}

fn model_result<T>(
    identity: DriverIdentity,
    result: Result<T, ExactLedgerError>,
) -> Result<T, ComponentTerminal> {
    result.map_err(|error| ledger_error_terminal(identity, error))
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
async fn c54_request_worker(
    identity: DriverIdentity,
    kind: C54WorkerKind,
    continuation: Option<InstanceContinuationToken>,
) -> Result<Option<NativeCancelPlan>, ComponentTerminal> {
    let listener = C54_WORK_COMPLETE.wait(C54_TARGET_EVENT);
    {
        let mut audit = C54_TARGET.lock();
        let scenario_exact = matches!(
            (kind, audit.scenario),
            (C54WorkerKind::ConsumedPending, C54Scenario::Healthy)
                | (
                    C54WorkerKind::InvokingDeferred,
                    C54Scenario::LinearizedGuard
                )
        );
        if !audit.is_primary(identity)
            || !scenario_exact
            || audit.worker_request.is_some()
            || audit.worker_complete
            || audit.cancel_plan.is_some()
            || audit.failed
            || (kind == C54WorkerKind::ConsumedPending) != continuation.is_some()
        {
            return Err(unexpected_native_driver_error(
                identity,
                "C5.4 worker request mismatch",
            ));
        }
        audit.worker_request = Some(C54WorkerRequest {
            kind,
            identity,
            continuation,
        });
    }
    let wake = C54_WORK_READY.publish(C54_TARGET_EVENT).map_err(|error| {
        unexpected_native_driver_error(identity, ("C5.4 worker publish", error))
    })?;
    wake.dispatch();
    listener.await.map_err(|error| {
        unexpected_native_driver_error(identity, ("C5.4 worker completion", error))
    })?;
    let mut audit = C54_TARGET.lock();
    if !audit.worker_complete || audit.failed {
        return Err(unexpected_native_driver_error(
            identity,
            "C5.4 worker did not complete exactly",
        ));
    }
    match kind {
        C54WorkerKind::ConsumedPending => audit.cancel_plan.take().map(Some).ok_or_else(|| {
            unexpected_native_driver_error(identity, "C5.4 worker lost cancel plan")
        }),
        C54WorkerKind::InvokingDeferred if audit.cancel_plan.is_none() => Ok(None),
        C54WorkerKind::InvokingDeferred => Err(unexpected_native_driver_error(
            identity,
            "C5.4 deferred claim manufactured a cancel plan",
        )),
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_finish_worker(request: C54WorkerRequest, plan: Option<NativeCancelPlan>) -> bool {
    {
        let mut audit = C54_TARGET.lock();
        if audit.worker_request.is_none_or(|current| {
            current.kind != request.kind
                || current.identity != request.identity
                || current.continuation != request.continuation
        }) || audit.worker_complete
            || audit.failed
        {
            return false;
        }
        audit.cancel_plan = plan;
        audit.worker_complete = true;
    }
    match C54_WORK_COMPLETE.publish(C54_TARGET_EVENT) {
        Ok(wake) => {
            wake.dispatch();
            true
        }
        Err(_) => false,
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_abort_worker(reason: &'static str) {
    c54_fail(reason);
    if let Ok(wake) = C54_WORK_COMPLETE.publish(C54_TARGET_EVENT) {
        wake.dispatch();
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
pub(super) async fn run_revoke_worker() {
    let listener = C54_WORK_READY.wait(C54_TARGET_EVENT);
    let ready = C54_TARGET.lock().worker_request.is_some();
    if !ready && listener.await.is_err() {
        c54_abort_worker("worker-registration");
        return;
    }
    let Some(request) = C54_TARGET.lock().worker_request else {
        c54_abort_worker("worker-request-missing");
        return;
    };
    let exact = match request.identity.exact() {
        Some(exact) => exact,
        None => {
            c54_abort_worker("worker-identity");
            return;
        }
    };
    let decision = with_ledger(request.identity, |ledger| {
        ledger.claim_revoke(exact, ExactStreamResource::StdoutWriter)
    });
    match (request.kind, decision) {
        (C54WorkerKind::ConsumedPending, Ok(ExactRevokeDecision::Cancel(plan))) => {
            let Some(continuation) = request.continuation else {
                c54_abort_worker("pending-continuation-missing");
                return;
            };
            if !matches!(
                plan.continuation(),
                ExactContinuation::WakeRegistered(current) if current == continuation
            ) {
                c54_abort_worker("pending-plan-continuation");
                return;
            }
            let receipt = match registry().signal_continuation(continuation) {
                crate::instance::InstanceContinuationSignal::AlreadyConsumed(receipt)
                    if receipt.matches_token(continuation) =>
                {
                    receipt
                }
                _ => {
                    c54_abort_worker("pending-core-not-consumed");
                    return;
                }
            };
            let projected = with_ledger(request.identity, |ledger| {
                ledger.project_consumed_continuation(exact, receipt.token())
            });
            if !matches!(
                projected,
                Ok(snapshot)
                    if snapshot.phase() == ExactLedgerPhase::CancelClaimed
                        && snapshot.continuation()
                            == ExactContinuation::Consumed(continuation)
            ) {
                c54_abort_worker("pending-consumed-projection");
                return;
            }
            {
                let mut audit = C54_TARGET.lock();
                audit.claims += 1;
                audit.pending_claims += 1;
                audit.core_already_consumed += 1;
                audit.consumed_deltas += 1;
            }
            if !c54_finish_worker(request, Some(plan)) {
                c54_abort_worker("pending-worker-completion");
            }
        }
        (C54WorkerKind::InvokingDeferred, Ok(ExactRevokeDecision::Deferred(_))) => {
            {
                let mut audit = C54_TARGET.lock();
                audit.claims += 1;
                audit.deferred_claims += 1;
            }
            if !c54_finish_worker(request, None) {
                c54_abort_worker("deferred-worker-completion");
            }
        }
        _ => c54_abort_worker("worker-revoke-decision"),
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
async fn c54_before_output_backend(
    identity: DriverIdentity,
    invoking: NativeLedgerSnapshot,
) -> Result<(), ComponentTerminal> {
    let scenario = {
        let audit = C54_TARGET.lock();
        if !audit.is_primary(identity) || audit.failed {
            return Ok(());
        }
        audit.scenario
    };
    if invoking.phase() != ExactLedgerPhase::BackendInvoking {
        return Err(unexpected_native_driver_error(
            identity,
            "C5.4 output did not enter BackendInvoking",
        ));
    }
    match scenario {
        C54Scenario::LinearizedGuard => {
            c54_request_worker(identity, C54WorkerKind::InvokingDeferred, None)
                .await
                .map(|_| ())
        }
        C54Scenario::RawInvoking => {
            panic!("deliberate C5.4 raw fault at BackendInvoking");
        }
        C54Scenario::Undecided => Err(unexpected_native_driver_error(
            identity,
            "C5.4 output preceded scenario selection",
        )),
        C54Scenario::Healthy | C54Scenario::RawLinearized => Ok(()),
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_after_output_linearized(identity: DriverIdentity, linearized: NativeLedgerSnapshot) {
    let raw = {
        let mut audit = C54_TARGET.lock();
        if !audit.is_primary(identity) || audit.failed {
            return;
        }
        if audit.scenario == C54Scenario::RawLinearized {
            audit.backend_effects += 1;
            true
        } else {
            false
        }
    };
    if raw {
        assert_eq!(linearized.phase(), ExactLedgerPhase::BackendLinearized);
        panic!("deliberate C5.4 raw fault at BackendLinearized");
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_record_linearized_guard(identity: DriverIdentity) {
    let exact_ledger = ledger_slot(identity.key).is_some_and(|slot| {
        let ledger = slot.lock();
        ledger.phase() == ExactLedgerPhase::Quarantined
            && ledger.is_quarantined()
            && ledger.quarantined_effect()
                == Some(BackendEffect::OutputSent {
                    length: C54_LINEARIZED_OUTPUT_BYTES as u16,
                })
            && identity.exact().is_some_and(|exact| {
                ledger.quarantined_resource_state(exact, ExactStreamResource::StdoutWriter)
                    == Some(ExactResourceState::Revoking)
            })
    });
    let passed = {
        let mut audit = C54_TARGET.lock();
        if !audit.is_primary(identity)
            || audit.scenario != C54Scenario::LinearizedGuard
            || audit.failed
        {
            return;
        }
        audit.backend_effects += 1;
        exact_ledger
            && audit.starts == 1
            && audit.claims == 1
            && audit.deferred_claims == 1
            && audit.backend_effects == 1
            && audit.cap_revokes == 0
            && audit.backend_cancels == 0
            && audit.runtime_cancel_acks == 0
            && audit.terminals == 0
            && audit.cspace_resets == 0
            && audit.reaper_notifies == 0
            && audit.acknowledgements == 0
            && audit.raw_reclaims == 0
    };
    if passed {
        crate::println!("WASM_C54_NATIVE_LINEARIZED_GUARD PASS starts=1 claims=1 deferred_claims=1 backend_effects=1 output_sent=99 cap_revokes=0 backend_cancels=0 runtime_cancel_acks=0 terminals=0 cspace_resets=0 reaper_notifies=0 acks=0 raw_reclaims=0");
    } else {
        c54_fail("linearized-guard-evidence");
    }
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
fn c54_open_stdout_drain(
    identity: DriverIdentity,
    registered: NativeLedgerSnapshot,
) -> Result<(), ComponentTerminal> {
    let continuation = match registered.continuation() {
        ExactContinuation::WakeRegistered(continuation) => continuation,
        _ => {
            return Err(unexpected_native_driver_error(
                identity,
                "C5.4 waiting output lacked registered continuation",
            ));
        }
    };
    {
        let mut audit = C54_TARGET.lock();
        if !audit.is_primary(identity) || audit.scenario != C54Scenario::Healthy {
            return Ok(());
        }
        if audit.waiting_ops != 0
            || audit.drain_open
            || registered.pending_kind() != Some(PendingKind::WriteWaiting)
            || audit.canonical_total != C54_REVOKE_CANONICAL_TOTAL_BYTES as u64
            || audit.canonical_first != C54_CANONICAL_SLICE_BYTES as u64
            || audit.canonical_second != C54_CANONICAL_SLICE_BYTES as u64
            || audit.canonical_commits != C54_REVOKE_CANONICAL_COMMITS
            || audit.sent_output_total != C54_SENT_OUTPUT_TOTAL_BYTES as u64
            || audit.sent_output_prefixes != C54_SENT_OUTPUT_PREFIXES
            || audit.failed
        {
            return Err(unexpected_native_driver_error(
                identity,
                "C5.4 waiting output evidence mismatch",
            ));
        }
        audit.waiting_ops = 1;
        audit.stale_snapshot = Some(registered);
        audit.stale_continuation = Some(continuation);
        audit.drain_open = true;
    }
    Ok(())
}

#[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
async fn c54_claim_after_consumed(
    identity: DriverIdentity,
    receipt: InstanceContinuationConsumed,
) -> Result<Option<NativeCancelPlan>, ComponentTerminal> {
    let target = {
        let audit = C54_TARGET.lock();
        audit.is_primary(identity)
            && audit.scenario == C54Scenario::Healthy
            && audit.waiting_ops == 1
            && audit.stale_continuation == Some(receipt.token())
            && !audit.failed
    };
    if !target {
        return Ok(None);
    }
    c54_request_worker(
        identity,
        C54WorkerKind::ConsumedPending,
        Some(receipt.token()),
    )
    .await
}

fn abort_backend_call(
    identity: DriverIdentity,
    invoking: NativeLedgerSnapshot,
) -> ComponentTerminal {
    let _ = with_ledger(identity, |ledger| ledger.abort_backend_invoke(invoking));
    quarantine_shadow(identity);
    ComponentTerminal::RunnerFault
}

fn backend_effect(
    identity: DriverIdentity,
    invoking: NativeLedgerSnapshot,
    effect: BackendEffect,
) -> Result<NativeLedgerSnapshot, ComponentTerminal> {
    model_result(
        identity,
        with_ledger(identity, |ledger| {
            ledger.backend_linearized(invoking, effect)
        }),
    )
}

fn commit_backend_runtime(
    identity: DriverIdentity,
    linearized: NativeLedgerSnapshot,
) -> Result<(), ComponentTerminal> {
    model_result(
        identity,
        with_ledger(identity, |ledger| ledger.commit_runtime(linearized)),
    )?;
    finish_backend_lease(identity)
}

fn drop_backend_runtime_peer(
    identity: DriverIdentity,
    linearized: NativeLedgerSnapshot,
) -> Result<(), ComponentTerminal> {
    model_result(
        identity,
        with_ledger(identity, |ledger| ledger.drop_runtime_peer(linearized)),
    )?;
    finish_backend_lease(identity)
}

enum WakeOutcome {
    Resume(NativeLedgerSnapshot),
    Revoked(NativeLedgerSnapshot),
}

fn begin_register_wake(
    identity: DriverIdentity,
    pending: NativeLedgerSnapshot,
    continuation: InstanceContinuationToken,
) -> Result<WakeOutcome, ExactLedgerError> {
    with_ledger(identity, |ledger| {
        let current = ledger
            .snapshot(identity.exact().ok_or(ExactLedgerError::IdentityMismatch)?)?
            .ok_or(ExactLedgerError::Vacant)?;
        if current == pending {
            let armed = ledger.arm_continuation(current, continuation)?;
            return ledger
                .begin_backend(armed, ExactBackendAction::RegisterWake)
                .map(WakeOutcome::Resume);
        }
        if current.phase() == ExactLedgerPhase::BackendCancelled
            && current.resource() == pending.resource()
            && current.function() == pending.function()
            && current.continuation() == ExactContinuation::None
        {
            return Ok(WakeOutcome::Revoked(current));
        }
        Err(ExactLedgerError::SnapshotMismatch)
    })
}

fn finish_wake_receipt(
    identity: DriverIdentity,
    returned: BackendPendingOutcome,
    receipt: InstanceContinuationConsumed,
) -> Result<WakeOutcome, ComponentTerminal> {
    let continuation = receipt.token();
    model_result(
        identity,
        with_ledger(identity, |ledger| {
            let current = ledger
                .snapshot(identity.exact().ok_or(ExactLedgerError::IdentityMismatch)?)?
                .ok_or(ExactLedgerError::Vacant)?;
            if matches!(returned, BackendPendingOutcome::Pending(expected) if current == expected) {
                let consumed = ledger.consume_continuation(current, continuation)?;
                return ledger
                    .begin_backend(consumed, ExactBackendAction::Resume)
                    .map(WakeOutcome::Resume);
            }
            if current.phase() == ExactLedgerPhase::BackendCancelled
                && current.continuation() == ExactContinuation::Signalled(continuation)
            {
                return ledger
                    .acknowledge_cancelled_continuation(current, continuation)
                    .map(WakeOutcome::Revoked);
            }
            if current.phase() == ExactLedgerPhase::BackendCancelled
                && current.continuation() == ExactContinuation::Consumed(continuation)
            {
                return Ok(WakeOutcome::Revoked(current));
            }
            Err(ExactLedgerError::SnapshotMismatch)
        }),
    )
}

async fn await_reader_wake(
    identity: DriverIdentity,
    pending: NativeLedgerSnapshot,
) -> Result<WakeOutcome, ComponentTerminal> {
    let operation = pending.backend().ok_or_else(|| {
        unexpected_native_driver_error(identity, "reader waiter without backend token")
    })?;
    let (continuation_token, bound_lease, continuation) =
        arm_external_lease_continuation(identity)?;
    let invoking = match begin_register_wake(identity, pending, continuation_token) {
        Ok(WakeOutcome::Resume(invoking)) => invoking,
        Ok(WakeOutcome::Revoked(cancelled)) => {
            drop(continuation);
            confirm_dropped_lease_continuation(identity, bound_lease, continuation_token)?;
            return Ok(WakeOutcome::Revoked(cancelled));
        }
        Err(error) => {
            drop(continuation);
            confirm_dropped_lease_continuation(identity, bound_lease, continuation_token)?;
            return Err(ledger_error_terminal(identity, error));
        }
    };
    let registered_lease = lease_result(
        identity,
        with_leases(identity, |leases| leases.register_stream_wake(bound_lease)),
    )?;
    let wake = HostWakeToken::new(continuation_token.signal_words(), stream_wake);
    if !matches!(
        with_active_reader(identity.instance, identity.streams, |reader, _| {
            reader.register_wake(operation, wake)
        }),
        Ok(Ok(()))
    ) {
        drop(continuation);
        confirm_dropped_lease_continuation(identity, registered_lease, continuation_token)?;
        return Err(abort_backend_call(identity, invoking));
    }
    let registered = match with_ledger(identity, |ledger| {
        ledger.finish_register_wake(invoking, continuation_token)
    }) {
        Ok(registered) => registered,
        Err(error) => {
            // The backend already retained its copied wake token. Unwinding
            // drops Core's listener, but the aggregate wake/continuation lease
            // must remain charged on this fail-stop path rather than inventing
            // a cancellation receipt for the external registration.
            return Err(ledger_error_terminal(identity, error));
        }
    };
    let returned = backend_return_pending(identity, registered)?;
    let consumed = continuation
        .await
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    if !consumed.matches_token(continuation_token) {
        return Err(unexpected_native_driver_error(
            identity,
            "reader continuation receipt mismatch",
        ));
    }
    lease_result(
        identity,
        with_leases(identity, |leases| {
            leases.consume_continuation(registered_lease, continuation_token)
        }),
    )?;
    finish_wake_receipt(identity, returned, consumed)
}

async fn await_writer_wake(
    identity: DriverIdentity,
    pending: NativeLedgerSnapshot,
) -> Result<WakeOutcome, ComponentTerminal> {
    let operation = pending.backend().ok_or_else(|| {
        unexpected_native_driver_error(identity, "writer waiter without backend token")
    })?;
    let (continuation_token, bound_lease, continuation) =
        arm_external_lease_continuation(identity)?;
    let invoking = match begin_register_wake(identity, pending, continuation_token) {
        Ok(WakeOutcome::Resume(invoking)) => invoking,
        Ok(WakeOutcome::Revoked(cancelled)) => {
            drop(continuation);
            confirm_dropped_lease_continuation(identity, bound_lease, continuation_token)?;
            return Ok(WakeOutcome::Revoked(cancelled));
        }
        Err(error) => {
            drop(continuation);
            confirm_dropped_lease_continuation(identity, bound_lease, continuation_token)?;
            return Err(ledger_error_terminal(identity, error));
        }
    };
    let registered_lease = lease_result(
        identity,
        with_leases(identity, |leases| leases.register_stream_wake(bound_lease)),
    )?;
    let wake = HostWakeToken::new(continuation_token.signal_words(), stream_wake);
    if !matches!(
        with_active_writer(identity.instance, identity.streams, |writer| {
            writer.register_wake(operation, wake)
        }),
        Ok(Ok(()))
    ) {
        drop(continuation);
        confirm_dropped_lease_continuation(identity, registered_lease, continuation_token)?;
        return Err(abort_backend_call(identity, invoking));
    }
    let registered = match with_ledger(identity, |ledger| {
        ledger.finish_register_wake(invoking, continuation_token)
    }) {
        Ok(registered) => registered,
        Err(error) => {
            // Physical registration is irreversible here; retain both charged
            // aggregate authorities while the generation is fail-stopped.
            return Err(ledger_error_terminal(identity, error));
        }
    };
    let returned = backend_return_pending(identity, registered)?;
    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    if let BackendPendingOutcome::Pending(registered) = returned {
        c54_open_stdout_drain(identity, registered)?;
    }
    let consumed = continuation
        .await
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    if !consumed.matches_token(continuation_token) {
        return Err(unexpected_native_driver_error(
            identity,
            "writer continuation receipt mismatch",
        ));
    }
    lease_result(
        identity,
        with_leases(identity, |leases| {
            leases.consume_continuation(registered_lease, continuation_token)
        }),
    )?;
    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    if let Some(plan) = c54_claim_after_consumed(identity, consumed).await? {
        let cancelled = cancel_plan_in_current(identity, plan, None).map_err(|()| {
            unexpected_native_driver_error(identity, "C5.4 exact pending cancellation")
        })?;
        return Ok(WakeOutcome::Revoked(cancelled));
    }
    finish_wake_receipt(identity, returned, consumed)
}

async fn await_terminal_wake(
    identity: DriverIdentity,
    pending: NativeLedgerSnapshot,
) -> Result<WakeOutcome, ComponentTerminal> {
    let operation = pending.backend().ok_or_else(|| {
        unexpected_native_driver_error(identity, "terminal waiter without backend token")
    })?;
    let (continuation_token, bound_lease, continuation) =
        arm_external_lease_continuation(identity)?;
    let invoking = match begin_register_wake(identity, pending, continuation_token) {
        Ok(WakeOutcome::Resume(invoking)) => invoking,
        Ok(WakeOutcome::Revoked(cancelled)) => {
            drop(continuation);
            confirm_dropped_lease_continuation(identity, bound_lease, continuation_token)?;
            return Ok(WakeOutcome::Revoked(cancelled));
        }
        Err(error) => {
            drop(continuation);
            confirm_dropped_lease_continuation(identity, bound_lease, continuation_token)?;
            return Err(ledger_error_terminal(identity, error));
        }
    };
    let registered_lease = lease_result(
        identity,
        with_leases(identity, |leases| leases.register_stream_wake(bound_lease)),
    )?;
    let wake = HostWakeToken::new(continuation_token.signal_words(), stream_wake);
    if !matches!(
        with_active_reader(identity.instance, identity.streams, |_, supervisor| {
            supervisor.register_terminal_wake(operation, wake)
        }),
        Ok(Ok(()))
    ) {
        drop(continuation);
        confirm_dropped_lease_continuation(identity, registered_lease, continuation_token)?;
        return Err(abort_backend_call(identity, invoking));
    }
    let registered = match with_ledger(identity, |ledger| {
        ledger.finish_register_wake(invoking, continuation_token)
    }) {
        Ok(registered) => registered,
        Err(error) => {
            // Physical registration is irreversible here; retain both charged
            // aggregate authorities while the generation is fail-stopped.
            return Err(ledger_error_terminal(identity, error));
        }
    };
    let returned = backend_return_pending(identity, registered)?;
    let consumed = continuation
        .await
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    if !consumed.matches_token(continuation_token) {
        return Err(unexpected_native_driver_error(
            identity,
            "terminal continuation receipt mismatch",
        ));
    }
    lease_result(
        identity,
        with_leases(identity, |leases| {
            leases.consume_continuation(registered_lease, continuation_token)
        }),
    )?;
    finish_wake_receipt(identity, returned, consumed)
}

enum PreparedReader {
    Prepared(StreamPreparedReceive, NativeLedgerSnapshot),
    Closed(StreamCloseReason, NativeLedgerSnapshot),
    Revoked(NativeLedgerSnapshot),
}

async fn prepared_reader(
    identity: DriverIdentity,
    runtime: NativeLedgerSnapshot,
) -> Result<PreparedReader, ComponentTerminal> {
    let mut invoking = model_result(
        identity,
        ledger_begin_backend(identity, runtime, ExactBackendAction::Start),
    )?;
    let mut dispatch = match with_active_reader(identity.instance, identity.streams, |reader, _| {
        reader.start()
    }) {
        Ok(Ok(dispatch)) => dispatch,
        Ok(Err(_)) | Err(_) => return Err(abort_backend_call(identity, invoking)),
    };
    loop {
        match dispatch {
            StreamReceiveDispatch::Prepared(prepared) => {
                let returned = model_result(
                    identity,
                    ledger_backend_pending(
                        identity,
                        invoking,
                        PendingKind::ReadPrepared,
                        prepared.operation(),
                    ),
                )?;
                return match backend_return_pending(identity, returned)? {
                    BackendPendingOutcome::Pending(snapshot) => {
                        Ok(PreparedReader::Prepared(prepared, snapshot))
                    }
                    BackendPendingOutcome::Revoked(cancelled) => {
                        Ok(PreparedReader::Revoked(cancelled))
                    }
                };
            }
            StreamReceiveDispatch::Closed(reason) => {
                let linearized = backend_effect(
                    identity,
                    invoking,
                    BackendEffect::InputPeerClosed {
                        reason: stream_reason_value(reason),
                    },
                )?;
                return Ok(PreparedReader::Closed(reason, linearized));
            }
            StreamReceiveDispatch::Waiting(operation) => {
                let returned = model_result(
                    identity,
                    ledger_backend_pending(identity, invoking, PendingKind::ReadWaiting, operation),
                )?;
                let pending = match backend_return_pending(identity, returned)? {
                    BackendPendingOutcome::Pending(pending) => pending,
                    BackendPendingOutcome::Revoked(cancelled) => {
                        return Ok(PreparedReader::Revoked(cancelled));
                    }
                };
                invoking = match await_reader_wake(identity, pending).await? {
                    WakeOutcome::Resume(invoking) => invoking,
                    WakeOutcome::Revoked(cancelled) => {
                        return Ok(PreparedReader::Revoked(cancelled));
                    }
                };
                dispatch = match with_active_reader(
                    identity.instance,
                    identity.streams,
                    |reader, supervisor| {
                        let promoted = supervisor.promote_normal_if_drained_observed();
                        if promoted.is_some_and(|observation| {
                            observation.effective_reason().is_none()
                                || observation.outcome() == StreamCloseOutcome::Conflict
                        }) {
                            return Err(StreamError::FailStopped);
                        }
                        reader.resume(operation)
                    },
                ) {
                    Ok(Ok(dispatch)) => dispatch,
                    Ok(Err(_)) | Err(_) => return Err(abort_backend_call(identity, invoking)),
                };
            }
        }
    }
}

enum OutputDispatch {
    Sent(NativeLedgerSnapshot),
    Closed(StreamCloseReason, NativeLedgerSnapshot),
    Revoked(NativeLedgerSnapshot),
}

async fn send_output(
    identity: DriverIdentity,
    runtime: NativeLedgerSnapshot,
    bytes: &[u8],
) -> Result<OutputDispatch, ComponentTerminal> {
    let mut invoking = model_result(
        identity,
        ledger_begin_backend(identity, runtime, ExactBackendAction::Start),
    )?;
    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    c54_before_output_backend(identity, invoking).await?;
    let mut dispatch = match with_active_writer(identity.instance, identity.streams, |writer| {
        writer.start(bytes)
    }) {
        Ok(Ok(dispatch)) => dispatch,
        Ok(Err(_)) | Err(_) => return Err(abort_backend_call(identity, invoking)),
    };
    loop {
        match dispatch {
            StreamSendDispatch::Sent => {
                let effect = BackendEffect::OutputSent {
                    length: u16::try_from(bytes.len()).map_err(|_| {
                        unexpected_native_driver_error(identity, "output length overflow")
                    })?,
                };
                #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
                match with_ledger(identity, |ledger| {
                    ledger.backend_linearized(invoking, effect)
                }) {
                    Ok(linearized) => {
                        c54_after_output_linearized(identity, linearized);
                        return Ok(OutputDispatch::Sent(linearized));
                    }
                    Err(ExactLedgerError::Quarantined) => {
                        c54_record_linearized_guard(identity);
                        return Err(ComponentTerminal::RunnerFault);
                    }
                    Err(error) => return Err(ledger_error_terminal(identity, error)),
                }
                #[cfg(not(feature = "ssh-native-async-revoke-qemu-acceptance"))]
                return backend_effect(identity, invoking, effect).map(OutputDispatch::Sent);
            }
            StreamSendDispatch::Closed(reason) => {
                return backend_effect(
                    identity,
                    invoking,
                    BackendEffect::OutputPeerClosed {
                        reason: stream_reason_value(reason),
                    },
                )
                .map(|snapshot| OutputDispatch::Closed(reason, snapshot));
            }
            StreamSendDispatch::Waiting(operation) => {
                let returned = model_result(
                    identity,
                    ledger_backend_pending(
                        identity,
                        invoking,
                        PendingKind::WriteWaiting,
                        operation,
                    ),
                )?;
                let pending = match backend_return_pending(identity, returned)? {
                    BackendPendingOutcome::Pending(pending) => pending,
                    BackendPendingOutcome::Revoked(cancelled) => {
                        return Ok(OutputDispatch::Revoked(cancelled));
                    }
                };
                invoking = match await_writer_wake(identity, pending).await? {
                    WakeOutcome::Resume(invoking) => invoking,
                    WakeOutcome::Revoked(cancelled) => {
                        return Ok(OutputDispatch::Revoked(cancelled));
                    }
                };
                dispatch = match with_active_writer(identity.instance, identity.streams, |writer| {
                    writer.resume(operation, bytes)
                }) {
                    Ok(Ok(dispatch)) => dispatch,
                    Ok(Err(_)) | Err(_) => return Err(abort_backend_call(identity, invoking)),
                };
            }
        }
    }
}

fn prepared_host_token(
    identity: DriverIdentity,
    poll: NativePoll,
    expected: fn(NativeHostRequest) -> bool,
) -> Result<NativeHostToken, ComponentTerminal> {
    match poll {
        NativePoll::HostPending { token, request, .. } if expected(request) => Ok(token),
        NativePoll::Trapped(trap) => Err(trap_terminal(trap)),
        _ => Err(unexpected_native_driver_error(
            identity,
            "invalid prepared host poll",
        )),
    }
}

fn is_input_stream(request: NativeHostRequest) -> bool {
    matches!(request, NativeHostRequest::InputStream { .. })
}

fn is_input_closed(request: NativeHostRequest) -> bool {
    matches!(request, NativeHostRequest::InputClosed)
}

fn is_output_stream(request: NativeHostRequest) -> bool {
    matches!(request, NativeHostRequest::OutputStream { .. })
}

fn is_output_closed(request: NativeHostRequest) -> bool {
    matches!(request, NativeHostRequest::OutputClosed { value: Some(_) })
}

async fn drive_input_stream(
    invocation: &mut NativeInvocation<'_>,
    identity: DriverIdentity,
    offered: NativeHostToken,
    maximum: u32,
    spill: &mut InputSpill,
    spill_receipt: &mut Option<NativeInputSpillReceipt>,
) -> Result<NativePoll, ComponentTerminal> {
    let maximum = usize::try_from(maximum)
        .unwrap_or(usize::MAX)
        .min(DRIVER_CHUNK_BYTES);
    if spill.is_empty() != spill_receipt.is_none() {
        return Err(unexpected_native_driver_error(
            identity,
            "input spill receipt divergence",
        ));
    }
    if !spill.is_empty() {
        let progress = spill.remaining_prefix(maximum).len();
        let receipt = spill_receipt.take().ok_or_else(|| {
            unexpected_native_driver_error(identity, "spill missing linear receipt")
        })?;
        if usize::from(receipt.remaining()) != spill.remaining_prefix(DRIVER_CHUNK_BYTES).len() {
            return Err(unexpected_native_driver_error(
                identity,
                "spill receipt extent mismatch",
            ));
        }
        let offered_snapshot = model_result(
            identity,
            with_ledger(identity, |ledger| {
                ledger.attach_input_runtime(receipt, offered, maximum)
            }),
        )?;
        let prepared = invocation
            .prepare_host_input_stream(offered, progress as u32)
            .map_err(|error| unexpected_native_driver_error(identity, error))?;
        let prepared = drain_runtime_cleanup(invocation, identity, prepared).await?;
        let prepared = prepared_host_token(identity, prepared, is_input_stream)?;
        let prepared_snapshot = model_result(
            identity,
            with_ledger(identity, |ledger| {
                ledger.prepare_input_runtime(offered_snapshot, prepared)
            }),
        )?;
        let committed = invocation
            .commit_host_input_stream(prepared, spill.remaining_prefix(progress))
            .map_err(|error| unexpected_native_driver_error(identity, error))?;
        let committed = drain_runtime_cleanup(invocation, identity, committed).await?;
        if let Some(terminal) = poll_terminal(committed) {
            quarantine_shadow(identity);
            return Err(terminal);
        }
        let next_receipt = model_result(
            identity,
            with_ledger(identity, |ledger| {
                ledger.commit_input_prefix(
                    prepared_snapshot,
                    u16::try_from(progress).map_err(|_| ExactLedgerError::InvalidEffect)?,
                )
            }),
        )?;
        #[cfg(feature = "ssh-native-async-qemu-acceptance")]
        if !target_record_input_bytes(identity, progress) {
            return Err(unexpected_native_driver_error(
                identity,
                "target input byte ledger mismatch",
            ));
        }
        #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
        if !c54_record_input_progress(identity, progress) {
            return Err(unexpected_native_driver_error(
                identity,
                "C5.4 canonical spill ledger mismatch",
            ));
        }
        if !spill.consume(progress) {
            return Err(unexpected_native_driver_error(
                identity,
                "spill cursor mismatch",
            ));
        }
        if spill.is_empty() != next_receipt.is_none() {
            return Err(unexpected_native_driver_error(
                identity,
                "input spill successor divergence",
            ));
        }
        match next_receipt.as_ref() {
            Some(receipt) => lease_result(
                identity,
                with_leases(identity, |leases| leases.update_input_spill(receipt)),
            )?,
            None => lease_result(
                identity,
                with_leases(identity, |leases| {
                    leases.finish_input_spill(
                        identity
                            .exact()
                            .ok_or(ExactNativeLeaseError::IdentityMismatch)?,
                    )
                }),
            )?,
        }
        *spill_receipt = next_receipt;
        return Ok(committed);
    }

    let runtime = model_result(
        identity,
        ledger_begin_runtime(
            identity,
            offered,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            maximum,
        ),
    )?;
    if maximum == 0 {
        let prepared = invocation
            .prepare_host_input_stream(offered, 0)
            .map_err(|error| unexpected_native_driver_error(identity, error))?;
        let prepared = drain_runtime_cleanup(invocation, identity, prepared).await?;
        let prepared = prepared_host_token(identity, prepared, is_input_stream)?;
        let prepared_snapshot = model_result(
            identity,
            ledger_prepare_runtime(identity, runtime, prepared),
        )?;
        let committed = invocation
            .commit_host_input_stream(prepared, &[])
            .map_err(|error| unexpected_native_driver_error(identity, error))?;
        let committed = drain_runtime_cleanup(invocation, identity, committed).await?;
        if let Some(terminal) = poll_terminal(committed) {
            quarantine_shadow(identity);
            return Err(terminal);
        }
        model_result(
            identity,
            with_ledger(identity, |ledger| {
                ledger.commit_runtime_only(prepared_snapshot)
            }),
        )?;
        return Ok(committed);
    }

    if promote_input_normal(identity).is_err() {
        return Err(unexpected_native_driver_error(
            identity,
            "input normal promotion conflict",
        ));
    }
    let prepared = match prepared_reader(identity, runtime).await? {
        PreparedReader::Prepared(prepared, snapshot) => (prepared, snapshot),
        PreparedReader::Closed(_reason, linearized) => {
            let dropped = invocation
                .drop_host_copy_peer(offered)
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            let dropped = drain_runtime_cleanup(invocation, identity, dropped).await?;
            if let Some(terminal) = poll_terminal(dropped) {
                quarantine_shadow(identity);
                return Err(terminal);
            }
            drop_backend_runtime_peer(identity, linearized)?;
            return Ok(dropped);
        }
        PreparedReader::Revoked(cancelled) => {
            let dropped = invocation
                .drop_host_copy_peer(offered)
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            let dropped = drain_runtime_cleanup(invocation, identity, dropped).await?;
            if let Some(terminal) = poll_terminal(dropped) {
                quarantine_shadow(identity);
                return Err(terminal);
            }
            finish_live_revoke(identity, cancelled)?;
            return Ok(dropped);
        }
    };
    let (backend, backend_pending) = prepared;
    let length = backend.length();
    if length == 0 || length > DRIVER_CHUNK_BYTES {
        quarantine_shadow(identity);
        return Err(ComponentTerminal::RunnerFault);
    }
    let progress = length.min(maximum);
    let runtime_prepared = invocation
        .prepare_host_input_stream(offered, progress as u32)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    let runtime_prepared = drain_runtime_cleanup(invocation, identity, runtime_prepared).await?;
    let runtime_prepared = prepared_host_token(identity, runtime_prepared, is_input_stream)?;
    let backend_pending = model_result(
        identity,
        ledger_prepare_runtime(identity, backend_pending, runtime_prepared),
    )?;
    let target = spill
        .receive_target(length)
        .ok_or_else(|| unexpected_native_driver_error(identity, "invalid spill target"))?;
    let invoking = model_result(
        identity,
        ledger_begin_backend(
            identity,
            backend_pending,
            ExactBackendAction::CommitPrepared,
        ),
    )?;
    let committed = with_active_reader(identity.instance, identity.streams, |reader, _| {
        reader.commit(backend.operation(), target)
    });
    let committed = match committed {
        Ok(Ok(committed)) => committed,
        Ok(Err(_)) | Err(_) => {
            spill.abort_receive();
            return Err(abort_backend_call(identity, invoking));
        }
    };
    match committed {
        StreamReceiveCommit::Received(received) if received == length => {
            #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
            if !c54_select_scenario(identity, spill.remaining_prefix(length)) {
                return Err(unexpected_native_driver_error(
                    identity,
                    "C5.4 scenario fixture mismatch",
                ));
            }
            let linearized = backend_effect(
                identity,
                invoking,
                BackendEffect::InputReceived {
                    total: u16::try_from(length).map_err(|_| {
                        unexpected_native_driver_error(identity, "input length overflow")
                    })?,
                    cursor: 0,
                },
            )?;
            let runtime_committed = invocation
                .commit_host_input_stream(runtime_prepared, spill.remaining_prefix(progress))
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            let runtime_committed =
                drain_runtime_cleanup(invocation, identity, runtime_committed).await?;
            if let Some(terminal) = poll_terminal(runtime_committed) {
                quarantine_shadow(identity);
                return Err(terminal);
            }
            let next_receipt = model_result(
                identity,
                with_ledger(identity, |ledger| {
                    ledger.commit_input_prefix(
                        linearized,
                        u16::try_from(progress).map_err(|_| ExactLedgerError::InvalidEffect)?,
                    )
                }),
            )?;
            #[cfg(feature = "ssh-native-async-qemu-acceptance")]
            if !target_record_input_bytes(identity, progress) {
                return Err(unexpected_native_driver_error(
                    identity,
                    "target input byte ledger mismatch",
                ));
            }
            #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
            if !c54_record_input_progress(identity, progress) {
                return Err(unexpected_native_driver_error(
                    identity,
                    "C5.4 initial partial input ledger mismatch",
                ));
            }
            if !spill.consume(progress) {
                return Err(unexpected_native_driver_error(
                    identity,
                    "spill commit mismatch",
                ));
            }
            if spill.is_empty() != next_receipt.is_none() {
                return Err(unexpected_native_driver_error(
                    identity,
                    "initial input spill receipt divergence",
                ));
            }
            if let Some(receipt) = next_receipt.as_ref() {
                lease_result(
                    identity,
                    with_leases(identity, |leases| leases.begin_input_spill(receipt)),
                )?;
            }
            finish_backend_lease(identity)?;
            *spill_receipt = next_receipt;
            return Ok(runtime_committed);
        }
        StreamReceiveCommit::Received(_) => {
            spill.abort_receive();
            let _ = with_ledger(identity, |ledger| ledger.abort_backend_invoke(invoking));
            quarantine_shadow(identity);
            return Err(ComponentTerminal::RunnerFault);
        }
        StreamReceiveCommit::Closed(reason) => {
            spill.abort_receive();
            let linearized = backend_effect(
                identity,
                invoking,
                BackendEffect::InputPreparedClosed {
                    reason: stream_reason_value(reason),
                },
            )?;
            let residual = model_result(
                identity,
                with_ledger(identity, |ledger| ledger.claim_backend_residual(linearized)),
            )?;
            let linearized = match cancel_residual_in_current(identity, residual) {
                Ok(linearized) => linearized,
                Err(()) => {
                    quarantine_shadow(identity);
                    return Err(ComponentTerminal::RunnerFault);
                }
            };
            let dropped = invocation
                .drop_host_copy_peer(runtime_prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            let dropped = drain_runtime_cleanup(invocation, identity, dropped).await?;
            if let Some(terminal) = poll_terminal(dropped) {
                quarantine_shadow(identity);
                return Err(terminal);
            }
            drop_backend_runtime_peer(identity, linearized)?;
            return Ok(dropped);
        }
    }
}

async fn drive_input_closed(
    invocation: &mut NativeInvocation<'_>,
    identity: DriverIdentity,
    offered: NativeHostToken,
    spill: &InputSpill,
    spill_receipt: &Option<NativeInputSpillReceipt>,
) -> Result<NativePoll, ComponentTerminal> {
    if !spill.is_empty() || spill_receipt.is_some() || promote_input_normal(identity).is_err() {
        return Err(unexpected_native_driver_error(
            identity,
            "input close before drain",
        ));
    }
    let runtime = model_result(
        identity,
        ledger_begin_runtime(
            identity,
            offered,
            ExactStreamResource::StdinSupervisor,
            ExactHostFunction::InputClosed,
            0,
        ),
    )?;
    let mut invoking = model_result(
        identity,
        ledger_begin_backend(identity, runtime, ExactBackendAction::Start),
    )?;
    let mut dispatch =
        match with_active_reader(identity.instance, identity.streams, |_, supervisor| {
            supervisor.start_terminal()
        }) {
            Ok(Ok(dispatch)) => dispatch,
            Ok(Err(_)) | Err(_) => return Err(abort_backend_call(identity, invoking)),
        };
    let mut ledger_state = match dispatch {
        StreamTerminalDispatch::Waiting(operation) => {
            let returned = model_result(
                identity,
                ledger_backend_pending(identity, invoking, PendingKind::TerminalWaiting, operation),
            )?;
            match backend_return_pending(identity, returned)? {
                BackendPendingOutcome::Pending(pending) => pending,
                BackendPendingOutcome::Revoked(_) => {
                    return Err(unexpected_native_driver_error(
                        identity,
                        "terminal supervisor cannot be revoked",
                    ));
                }
            }
        }
        StreamTerminalDispatch::Ready(reason) => backend_effect(
            identity,
            invoking,
            BackendEffect::InputTerminalObserved {
                reason: stream_reason_value(reason),
            },
        )?,
    };
    let runtime_prepared = invocation
        .prepare_host_input_closed(offered)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    let runtime_prepared = drain_runtime_cleanup(invocation, identity, runtime_prepared).await?;
    let runtime_prepared = prepared_host_token(identity, runtime_prepared, is_input_closed)?;
    ledger_state = model_result(
        identity,
        ledger_prepare_runtime(identity, ledger_state, runtime_prepared),
    )?;
    loop {
        match dispatch {
            StreamTerminalDispatch::Ready(reason) => {
                let committed = invocation
                    .commit_host_input_closed(runtime_prepared, stream_reason_value(reason))
                    .map_err(|error| unexpected_native_driver_error(identity, error))?;
                let committed = drain_runtime_cleanup(invocation, identity, committed).await?;
                if let Some(terminal) = poll_terminal(committed) {
                    quarantine_shadow(identity);
                    return Err(terminal);
                }
                commit_backend_runtime(identity, ledger_state)?;
                #[cfg(feature = "ssh-native-async-qemu-acceptance")]
                if reason == StreamCloseReason::Normal
                    && poll_terminal(committed).is_none()
                    && !target_record_normal_eof(identity)
                {
                    return Err(unexpected_native_driver_error(
                        identity,
                        "target normal EOF ledger mismatch",
                    ));
                }
                return Ok(committed);
            }
            StreamTerminalDispatch::Waiting(operation) => {
                invoking = match await_terminal_wake(identity, ledger_state).await? {
                    WakeOutcome::Resume(invoking) => invoking,
                    WakeOutcome::Revoked(_) => {
                        return Err(unexpected_native_driver_error(
                            identity,
                            "terminal supervisor cannot be revoked",
                        ));
                    }
                };
                dispatch = match with_active_reader(
                    identity.instance,
                    identity.streams,
                    |_, supervisor| supervisor.resume_terminal(operation),
                ) {
                    Ok(Ok(dispatch)) => dispatch,
                    Ok(Err(_)) | Err(_) => return Err(abort_backend_call(identity, invoking)),
                };
                ledger_state = match dispatch {
                    StreamTerminalDispatch::Waiting(fresh) => {
                        let returned = model_result(
                            identity,
                            ledger_backend_pending(
                                identity,
                                invoking,
                                PendingKind::TerminalWaiting,
                                fresh,
                            ),
                        )?;
                        match backend_return_pending(identity, returned)? {
                            BackendPendingOutcome::Pending(pending) => pending,
                            BackendPendingOutcome::Revoked(_) => {
                                return Err(unexpected_native_driver_error(
                                    identity,
                                    "terminal supervisor cannot be revoked",
                                ));
                            }
                        }
                    }
                    StreamTerminalDispatch::Ready(reason) => backend_effect(
                        identity,
                        invoking,
                        BackendEffect::InputTerminalObserved {
                            reason: stream_reason_value(reason),
                        },
                    )?,
                };
            }
        }
    }
}

async fn drive_output_stream(
    invocation: &mut NativeInvocation<'_>,
    identity: DriverIdentity,
    offered: NativeHostToken,
    maximum: u32,
    staging: &mut OutputStaging,
) -> Result<NativePoll, ComponentTerminal> {
    let maximum = usize::try_from(maximum)
        .unwrap_or(usize::MAX)
        .min(DRIVER_CHUNK_BYTES);
    let runtime = model_result(
        identity,
        ledger_begin_runtime(
            identity,
            offered,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            maximum,
        ),
    )?;
    let output = staging.prepare(maximum);
    let prepared = invocation
        .prepare_host_output_stream(offered, output)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    let prepared = drain_runtime_cleanup(invocation, identity, prepared).await?;
    let prepared = prepared_host_token(identity, prepared, is_output_stream)?;
    let prepared_snapshot = model_result(
        identity,
        ledger_prepare_runtime(identity, runtime, prepared),
    )?;
    if staging.prepared().is_empty() {
        let committed = invocation
            .commit_host_output(prepared)
            .map_err(|error| unexpected_native_driver_error(identity, error))?;
        let committed = drain_runtime_cleanup(invocation, identity, committed).await?;
        if let Some(terminal) = poll_terminal(committed) {
            quarantine_shadow(identity);
            return Err(terminal);
        }
        model_result(
            identity,
            with_ledger(identity, |ledger| {
                ledger.commit_runtime_only(prepared_snapshot)
            }),
        )?;
        staging.clear();
        return Ok(committed);
    }
    match send_output(identity, prepared_snapshot, staging.prepared()).await? {
        OutputDispatch::Sent(linearized) => {
            #[cfg(any(
                feature = "ssh-native-async-qemu-acceptance",
                feature = "ssh-native-async-revoke-qemu-acceptance"
            ))]
            let output_bytes = staging.prepared().len();
            let committed = invocation
                .commit_host_output(prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            let committed = drain_runtime_cleanup(invocation, identity, committed).await?;
            if let Some(terminal) = poll_terminal(committed) {
                // Sent is the transport linearization point. A rejected
                // runtime commit after it is a global lifecycle divergence.
                quarantine_shadow(identity);
                return Err(terminal);
            }
            staging.clear();
            commit_backend_runtime(identity, linearized)?;
            #[cfg(feature = "ssh-native-async-qemu-acceptance")]
            if !target_record_output_bytes(identity, output_bytes) {
                return Err(unexpected_native_driver_error(
                    identity,
                    "target output byte ledger mismatch",
                ));
            }
            #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
            if !c54_record_sent_output_prefix(identity, output_bytes) {
                return Err(unexpected_native_driver_error(
                    identity,
                    "C5.4 sent output prefix mismatch",
                ));
            }
            Ok(committed)
        }
        OutputDispatch::Closed(_reason, linearized) => {
            let dropped = invocation
                .drop_host_copy_peer(prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            let dropped = drain_runtime_cleanup(invocation, identity, dropped).await?;
            if let Some(terminal) = poll_terminal(dropped) {
                quarantine_shadow(identity);
                return Err(terminal);
            }
            staging.clear();
            drop_backend_runtime_peer(identity, linearized)?;
            Ok(dropped)
        }
        OutputDispatch::Revoked(cancelled) => {
            #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
            let target_cancelled = c54_is_healthy_primary(identity);
            let dropped = invocation
                .drop_host_copy_peer(prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            let dropped = drain_runtime_cleanup(invocation, identity, dropped).await?;
            if let Some(terminal) = poll_terminal(dropped) {
                quarantine_shadow(identity);
                return Err(terminal);
            }
            staging.clear();
            finish_live_revoke(identity, cancelled)?;
            #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
            if target_cancelled {
                let _ = dropped;
                return Err(ComponentTerminal::Cancelled);
            }
            Ok(dropped)
        }
    }
}

fn output_close_observation(
    identity: DriverIdentity,
    reason: StreamCloseReason,
) -> Result<StreamCloseObservation, ComponentTerminal> {
    with_active_writer(identity.instance, identity.streams, |writer| {
        writer.close_observed(reason)
    })
    .map_err(|_| unexpected_native_driver_error(identity, "writer close CSpace mismatch"))
}

async fn drive_output_closed(
    invocation: &mut NativeInvocation<'_>,
    identity: DriverIdentity,
    offered: NativeHostToken,
) -> Result<NativePoll, ComponentTerminal> {
    let runtime = model_result(
        identity,
        ledger_begin_runtime(
            identity,
            offered,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputClosed,
            0,
        ),
    )?;
    let prepared_poll = invocation
        .prepare_host_output_closed(offered)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    let prepared_poll = drain_runtime_cleanup(invocation, identity, prepared_poll).await?;
    let (prepared, value) = match prepared_poll {
        NativePoll::HostPending {
            token,
            request: NativeHostRequest::OutputClosed { value: Some(value) },
            ..
        } => (token, value),
        NativePoll::Trapped(trap) => return Err(trap_terminal(trap)),
        _ => {
            return Err(unexpected_native_driver_error(
                identity,
                "invalid output-close prepare",
            ))
        }
    };
    let Some(reason) = stream_reason(value) else {
        return Err(unexpected_native_driver_error(
            identity,
            "invalid output-close discriminant",
        ));
    };
    let prepared_snapshot = model_result(
        identity,
        ledger_prepare_runtime(identity, runtime, prepared),
    )?;
    let invoking = model_result(
        identity,
        ledger_begin_backend(identity, prepared_snapshot, ExactBackendAction::Start),
    )?;
    let observation = match output_close_observation(identity, reason) {
        Ok(observation) => observation,
        Err(_) => return Err(abort_backend_call(identity, invoking)),
    };
    let outcome = match observation.outcome() {
        StreamCloseOutcome::Published => 0,
        StreamCloseOutcome::AlreadyPublished => 1,
        StreamCloseOutcome::Conflict => 2,
    };
    let linearized = backend_effect(
        identity,
        invoking,
        BackendEffect::OutputCloseObserved {
            requested: stream_reason_value(reason),
            outcome,
            effective: observation.effective_reason().map(stream_reason_value),
        },
    )?;
    match (observation.outcome(), observation.effective_reason()) {
        (StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished, Some(effective))
            if effective == reason =>
        {
            let committed = invocation
                .commit_host_output(prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            let committed = drain_runtime_cleanup(invocation, identity, committed).await?;
            if let Some(terminal) = poll_terminal(committed) {
                quarantine_shadow(identity);
                Err(terminal)
            } else {
                commit_backend_runtime(identity, linearized)?;
                #[cfg(feature = "ssh-native-async-qemu-acceptance")]
                if reason == StreamCloseReason::Normal && !target_record_normal_close(identity) {
                    return Err(unexpected_native_driver_error(
                        identity,
                        "target normal close ledger mismatch",
                    ));
                }
                Ok(committed)
            }
        }
        (StreamCloseOutcome::AlreadyPublished, Some(effective))
            if reason == StreamCloseReason::Normal && effective != StreamCloseReason::Normal =>
        {
            // An established failure owns the terminal. A late guest Normal is
            // not committed and does not publish a conflicting close.
            let dropped = invocation
                .drop_host_copy_peer(prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            let dropped = drain_runtime_cleanup(invocation, identity, dropped).await?;
            if let Some(terminal) = poll_terminal(dropped) {
                quarantine_shadow(identity);
                return Err(terminal);
            }
            drop_backend_runtime_peer(identity, linearized)?;
            Ok(dropped)
        }
        _ => Err(unexpected_native_driver_error(
            identity,
            "conflicting output close",
        )),
    }
}

async fn run_driver(
    root: &'static NativeImageRoot,
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
) -> u64 {
    let identity = DriverIdentity {
        key,
        instance: token,
        task,
        domain,
        streams,
    };
    if !revalidate_image_root(root) {
        quarantine_shadow(identity);
        return terminal_word(ComponentTerminal::BackendFault);
    }
    let plan = match root.validated_plan() {
        Ok(plan) => plan,
        Err(_) => {
            quarantine_shadow(identity);
            return terminal_word(ComponentTerminal::BackendFault);
        }
    };
    let engine = ProfileEngine::new();
    let mut component = match NativeComponent::instantiate_validation_candidate_with_memory_limit(
        &plan,
        &engine,
        OwnerAllocationReservation::new(root.memory_bytes()),
        root.memory_bytes(),
        u32::from(root.resource_limit()),
    ) {
        Ok(component) => component,
        Err(error) => return terminal_word(native_error_terminal(error)),
    };
    let mut invocation =
        match component.start_filter(root.entrypoint(), root.total_fuel(), root.poll_quantum()) {
            Ok(invocation) => invocation,
            Err(error) => return terminal_word(native_error_terminal(error)),
        };
    let mut spill = InputSpill::new();
    let mut spill_receipt = None;
    let mut staging = OutputStaging::new();
    let mut next = None;
    loop {
        let poll = next.take().unwrap_or_else(|| invocation.poll());
        let poll = match drain_runtime_cleanup(&mut invocation, identity, poll).await {
            Ok(poll) => poll,
            Err(terminal) => return terminal_word(terminal),
        };
        let result = match poll {
            NativePoll::Pending(_) | NativePoll::Resolved(_) | NativePoll::Yielded(_) => {
                match quantum(identity).await {
                    Ok(()) => {
                        next = None;
                        continue;
                    }
                    Err(terminal) => Err(terminal),
                }
            }
            NativePoll::WaitPending { token: wait, .. } => {
                await_runtime_wait(&mut invocation, identity, wait).await
            }
            NativePoll::HostPending {
                token: host,
                request: NativeHostRequest::InputStream { maximum },
                ..
            } => {
                drive_input_stream(
                    &mut invocation,
                    identity,
                    host,
                    maximum,
                    &mut spill,
                    &mut spill_receipt,
                )
                .await
            }
            NativePoll::HostPending {
                token: host,
                request: NativeHostRequest::InputClosed,
                ..
            } => drive_input_closed(&mut invocation, identity, host, &spill, &spill_receipt).await,
            NativePoll::HostPending {
                token: host,
                request: NativeHostRequest::OutputStream { maximum },
                ..
            } => drive_output_stream(&mut invocation, identity, host, maximum, &mut staging).await,
            NativePoll::HostPending {
                token: host,
                request: NativeHostRequest::OutputClosed { .. },
                ..
            } => drive_output_closed(&mut invocation, identity, host).await,
            NativePoll::Complete(_) => {
                // Runtime completion cannot discard bytes which the backend
                // has already popped but the guest has not consumed, nor can
                // it cross an in-flight frozen output buffer. Either state is
                // a transport/runtime lifecycle divergence, not Success.
                if !spill.is_empty()
                    || spill_receipt.is_some()
                    || !staging.is_empty()
                    || !terminal_shadow_empty(identity)
                {
                    quarantine_shadow(identity);
                    return terminal_word(ComponentTerminal::RunnerFault);
                }
                match finalize_runtime_transport(&mut invocation, identity).await {
                    Ok(()) => return terminal_word(ComponentTerminal::Success),
                    Err(terminal) => return terminal_word(terminal),
                }
            }
            NativePoll::CleanupPending { .. } => Err(unexpected_native_driver_error(
                identity,
                "undrained runtime cleanup",
            )),
            NativePoll::Trapped(trap) => Err(trap_terminal(trap)),
        };
        match result {
            Ok(poll) => next = Some(poll),
            Err(terminal) => return terminal_word(terminal),
        }
    }
}

pub(super) async fn run(
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
) -> u64 {
    let Some(root) = image_root() else {
        lifecycle_fail_stop();
        return terminal_word(ComponentTerminal::Unavailable);
    };
    run_driver(root, key, token, task, domain, streams).await
}

#[cfg(feature = "ssh-native-async-command")]
struct NativeImageComponentLifecycle;

// SAFETY: the boot-static projection is immutable and every invocation enters
// the same exact registry/control transaction as the synchronous lifecycle.
// The distinct start input forces a managed cleanup lease and the native
// pending shadow before child publication.
#[cfg(feature = "ssh-native-async-command")]
unsafe impl ManagedComponentLifecycle for NativeImageComponentLifecycle {
    fn manifest(&self) -> &ComponentCommandManifest {
        image_root()
            .expect("native managed lifecycle used before boot projection")
            .projection
            .manifest()
    }

    fn start(
        &self,
        cleanup: ManagedComponentStartLease,
    ) -> Result<ManagedComponentToken, ComponentTerminal> {
        start_native_async_instance(cleanup)
    }

    fn state(&self, token: ManagedComponentToken) -> ManagedComponentState {
        observe_instance(token)
    }

    fn wait_state<'a>(&'a self, token: ManagedComponentToken) -> ManagedComponentStateFuture<'a> {
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let future = Box::pin(wait_instance(token));
        system.restore();
        future
    }

    fn request_cancel(
        &self,
        token: ManagedComponentToken,
        terminal: ComponentTerminal,
    ) -> ManagedComponentCancel {
        cancel_instance_with_terminal(token, terminal)
    }

    fn acknowledge_complete(&self, token: ManagedComponentToken) -> ManagedComponentAcknowledge {
        acknowledge_instance(token)
    }
}

#[cfg(feature = "ssh-native-async-command")]
pub(super) fn ssh_exec_policy(profile: AuthorizedProfile) -> Option<SshExecComponentSessionPolicy> {
    if !policy_gate_passed() {
        return None;
    }
    let root = image_root()?;
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let matches = revalidate_image_root(root);
    system.restore();
    if !matches || !policy_gate_passed() {
        lifecycle_fail_stop();
        return None;
    }
    Some(SshExecComponentSessionPolicy::new(
        profile,
        root.incarnation,
        C53_NATIVE_ASYNC_COMMAND.command_name(),
        C53_NATIVE_ASYNC_COMMAND.expected_sha256(),
    ))
}

#[cfg(feature = "ssh-native-async-command")]
pub(super) fn install_ssh_exec_component(
    session: &mut Session,
    accepted: SshExecComponentSessionPolicy,
    io: SshExecComponentIoInstall,
) -> Result<(), vibeos_vsh::Diagnostic> {
    if ssh_exec_policy(accepted.profile()) != Some(accepted) {
        return Err(vibeos_vsh::ssh_exec_component_policy_rejected(
            accepted.command_name(),
        ));
    }
    let Some(root) = image_root() else {
        return Err(vibeos_vsh::ssh_exec_component_policy_rejected(
            accepted.command_name(),
        ));
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let matches = revalidate_image_root(root)
        && accepted.command_name() == C53_NATIVE_ASYNC_COMMAND.command_name()
        && accepted.artifact_sha256() == C53_NATIVE_ASYNC_COMMAND.expected_sha256()
        && accepted.incarnation() == root.incarnation;
    system.restore();
    if !matches || !policy_gate_passed() {
        lifecycle_fail_stop();
        return Err(vibeos_vsh::ssh_exec_component_policy_rejected(
            accepted.command_name(),
        ));
    }
    unsafe {
        session.install_ssh_exec_managed_native_async_component_io(&root.ssh_policy, &LIFECYCLE, io)
    }
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
const ACCEPTANCE_WAIT_SECONDS: u64 = 10;

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
fn acceptance_deadline_expired(started: u64) -> bool {
    crate::sbi::time().wrapping_sub(started)
        >= crate::exec::timebase_hz().saturating_mul(ACCEPTANCE_WAIT_SECONDS)
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
fn acceptance_driver_identity(token: ManagedComponentToken) -> Result<Option<DriverIdentity>, ()> {
    let Some(key) = managed_token_key(token) else {
        return Err(());
    };
    let mut control = match CONTROL.try_lock() {
        Ok(control) => control,
        Err(ControlGateError::Busy) => return Ok(None),
        Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => return Err(()),
    };
    match control.running_tuple_structural(key) {
        Ok(Some(tuple))
            if tuple.start_kind == ControlStartKind::NativeAsyncAcceptance
                && tuple.cleanup.is_none() =>
        {
            Ok(Some(DriverIdentity {
                key,
                instance: tuple.core_token,
                task: tuple.handle.id(),
                domain: tuple.domain,
                streams: tuple.streams,
            }))
        }
        Ok(None) => Ok(None),
        Ok(Some(_)) | Err(()) => Err(()),
    }
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
async fn acceptance_wait_for_shadow(token: ManagedComponentToken, expected: PendingKind) -> bool {
    let started = crate::sbi::time();
    loop {
        if let Ok(Some(identity)) = acceptance_driver_identity(token) {
            match ledger_pending_kind(identity) {
                Ok(Some(kind)) if kind == expected => return true,
                Ok(None | Some(_)) => {}
                Err(_) => {
                    quarantine_shadow(identity);
                    return false;
                }
            }
        } else if matches!(
            observe_instance(token),
            ManagedComponentState::Complete(_) | ManagedComponentState::Lost
        ) {
            return false;
        }
        if acceptance_deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
async fn acceptance_receive_exact(reader: &ByteStreamReader, output: &mut [u8]) -> bool {
    let started = crate::sbi::time();
    let mut dispatch = match reader.start() {
        Ok(dispatch) => dispatch,
        Err(_) => return false,
    };
    loop {
        match dispatch {
            StreamReceiveDispatch::Prepared(prepared) if prepared.length() == output.len() => {
                return reader.commit(prepared.operation(), output)
                    == Ok(StreamReceiveCommit::Received(output.len()));
            }
            StreamReceiveDispatch::Prepared(prepared) => {
                let _ = reader.cancel(prepared.operation());
                return false;
            }
            StreamReceiveDispatch::Closed(_) => return false,
            StreamReceiveDispatch::Waiting(operation) => {
                if acceptance_deadline_expired(started) {
                    let _ = reader.cancel(operation);
                    return false;
                }
                crate::exec::yield_now().await;
                dispatch = match reader.resume(operation) {
                    Ok(dispatch) => dispatch,
                    Err(_) => return false,
                };
            }
        }
    }
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
async fn acceptance_wait_for_success(token: ManagedComponentToken) -> bool {
    let started = crate::sbi::time();
    loop {
        match observe_instance(token) {
            ManagedComponentState::Complete(ComponentTerminal::Success) => return true,
            ManagedComponentState::Complete(_) | ManagedComponentState::Lost => return false,
            ManagedComponentState::Busy | ManagedComponentState::Running => {}
        }
        if acceptance_deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
async fn acceptance_acknowledge(token: ManagedComponentToken) -> bool {
    let started = crate::sbi::time();
    loop {
        match acknowledge_instance(token) {
            ManagedComponentAcknowledge::Acknowledged => return true,
            ManagedComponentAcknowledge::Lost => return false,
            ManagedComponentAcknowledge::Busy => {}
        }
        if acceptance_deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
}

/// Dedicated feature-gated target fixture. It deliberately begins with an
/// empty input and a full output backend, forcing the real driver through
/// ReadWaiting -> ReadPrepared and WriteWaiting SYSTEM shadows. The sealed
/// two-module/two-instance candidate then transforms one exact 1024-byte chunk
/// before the fixture verifies Normal EOF/close and terminal retirement.
#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
pub(super) async fn run_acceptance() -> bool {
    let Some((module_count, instance_count)) = image_root().and_then(|root| {
        root.admitted
            .validated_plan()
            .ok()
            .map(|plan| (plan.embedded_modules().len(), plan.runtime_instance_count()))
    }) else {
        return false;
    };
    if module_count != 2 || instance_count != 2 {
        return false;
    }
    let shadow_counts_before = shadow_kind_install_counts();
    let (stdin, stdout, input, output, prefill, io) = {
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let stdin = ByteStream::new();
        let stdout = ByteStream::new();
        let input = stdin.writer();
        let output = stdout.reader();
        let prefill = stdout.writer();
        let io = InstalledComponentIo {
            stdin: stdin.reader(),
            stdout: stdout.writer(),
            stdin_supervisor: stdin.supervisor(),
            stdout_supervisor: stdout.supervisor(),
        };
        system.restore();
        (stdin, stdout, input, output, prefill, io)
    };

    for index in 0..STREAM_BUFFER_CHUNKS {
        if prefill.start(&[0xa0 | index as u8]) != Ok(StreamSendDispatch::Sent) {
            return false;
        }
    }
    let token = match start_with_io(io) {
        Ok(token) => token,
        Err(_) => return false,
    };
    if !acceptance_wait_for_shadow(token, PendingKind::ReadWaiting).await {
        return false;
    }

    let mut input_bytes = [0_u8; DRIVER_CHUNK_BYTES];
    for (index, byte) in input_bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
    }
    if input.start(&input_bytes) != Ok(StreamSendDispatch::Sent)
        || input.close(StreamCloseReason::Normal) != StreamCloseOutcome::Published
        || !acceptance_wait_for_shadow(token, PendingKind::WriteWaiting).await
    {
        return false;
    }

    for index in 0..STREAM_BUFFER_CHUNKS {
        let mut sentinel = [0_u8; 1];
        if !acceptance_receive_exact(&output, &mut sentinel).await
            || sentinel[0] != 0xa0 | index as u8
        {
            return false;
        }
    }
    let mut transformed = [0_u8; DRIVER_CHUNK_BYTES];
    if !acceptance_receive_exact(&output, &mut transformed).await
        || !transformed
            .iter()
            .zip(input_bytes.iter())
            .all(|(actual, input)| *actual == *input ^ 0x20)
        || !acceptance_wait_for_success(token).await
        || stdin.final_reason() != Some(StreamCloseReason::Normal)
        || stdout.final_reason() != Some(StreamCloseReason::Normal)
        || stdin.is_fail_stopped()
        || stdout.is_fail_stopped()
        || stdout.depth() != 0
        || !acceptance_acknowledge(token).await
        || SSH_POLICY_GATE.load(Ordering::Acquire) != POLICY_CLOSED
        || NATIVE_POLICY_GATE.load(Ordering::Acquire) != POLICY_CLOSED
        || !lifecycle_is_healthy()
    {
        return false;
    }
    let shadow_counts_after = shadow_kind_install_counts();
    let read_waiting = shadow_counts_after[0].saturating_sub(shadow_counts_before[0]);
    let read_prepared = shadow_counts_after[1].saturating_sub(shadow_counts_before[1]);
    let write_waiting = shadow_counts_after[2].saturating_sub(shadow_counts_before[2]);
    if read_waiting == 0 || read_prepared == 0 || write_waiting == 0 {
        return false;
    }
    crate::println!(
        "WASM_C53_NATIVE_ASYNC_PASS bytes={} modules={} instances={} shadow_installs=read-wait:{},read-prepared:{},write-wait:{}",
        DRIVER_CHUNK_BYTES,
        module_count,
        instance_count,
        read_waiting,
        read_prepared,
        write_waiting,
    );
    true
}
