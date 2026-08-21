//! C5.3 native-async driver shared by two sealed image roots.
//!
//! The direct QEMU fixture retains its acceptance-only pin and cleanup-free
//! start envelope. The formal command feature instead retains the opaque
//! projection produced by `component-image-adapter` and can start only through
//! a VSH-managed cleanup lease. Both use the same exact driver and SYSTEM
//! pending-operation shadow while the validation-only profile and runtime
//! readiness bits remain inert.

use super::native_pending_shadow_model::{
    InputSpill, OutputStaging, PendingIdentity, PendingKind, PendingShadow, PendingShadowError,
    PendingSnapshot, DRIVER_CHUNK_BYTES,
};
use super::*;

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
    Component as NativeComponent, Error as NativeError, HostRequest as NativeHostRequest,
    HostToken as NativeHostToken, Invocation as NativeInvocation, Poll as NativePoll,
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
    streams: RegistryStreamBindings,
}

impl DriverIdentity {
    const fn shadow(self) -> PendingIdentity<InstanceToken, RegistryStreamBindings> {
        PendingIdentity {
            control_generation: self.key.generation,
            instance: self.instance,
            bindings: self.streams,
        }
    }
}

type NativePendingShadow = PendingShadow<InstanceToken, RegistryStreamBindings, HostOperationToken>;
type NativePendingSnapshot =
    PendingSnapshot<InstanceToken, RegistryStreamBindings, HostOperationToken>;

static PENDING_SHADOWS: [SpinLock<NativePendingShadow>; CONTROL_SLOTS] =
    [const { SpinLock::new(NativePendingShadow::new()) }; CONTROL_SLOTS];
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

fn shadow_slot(key: ControlKey) -> Option<&'static SpinLock<NativePendingShadow>> {
    PENDING_SHADOWS.get(key.slot as usize)
}

fn shadow_bind(identity: DriverIdentity) -> Result<(), PendingShadowError> {
    let Some(slot) = shadow_slot(identity.key) else {
        return Err(PendingShadowError::IdentityMismatch);
    };
    slot.lock().bind(identity.shadow())
}

pub(super) fn bind_pending_shadow(
    key: ControlKey,
    token: InstanceToken,
    streams: RegistryStreamBindings,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance: token,
        streams,
    };
    if shadow_bind(identity).is_ok() {
        true
    } else {
        quarantine_shadow(identity);
        false
    }
}

fn shadow_install(
    identity: DriverIdentity,
    kind: PendingKind,
    operation: HostOperationToken,
) -> Result<NativePendingSnapshot, PendingShadowError> {
    let Some(slot) = shadow_slot(identity.key) else {
        return Err(PendingShadowError::IdentityMismatch);
    };
    let installed = slot.lock().install(identity.shadow(), kind, operation);
    if installed.is_ok() {
        record_shadow_kind_install(kind);
    }
    installed
}

fn shadow_replace_for(
    identity: DriverIdentity,
    previous: NativePendingSnapshot,
    kind: PendingKind,
    operation: HostOperationToken,
) -> Result<NativePendingSnapshot, PendingShadowError> {
    let Some(slot) = shadow_slot(identity.key) else {
        return Err(PendingShadowError::IdentityMismatch);
    };
    if previous.identity != identity.shadow() {
        slot.lock().quarantine();
        return Err(PendingShadowError::IdentityMismatch);
    }
    let replaced = slot.lock().replace(previous, kind, operation);
    if replaced.is_ok() {
        record_shadow_kind_install(kind);
    }
    replaced
}

fn shadow_snapshot(
    identity: DriverIdentity,
) -> Result<Option<NativePendingSnapshot>, PendingShadowError> {
    let Some(slot) = shadow_slot(identity.key) else {
        return Err(PendingShadowError::IdentityMismatch);
    };
    slot.lock().snapshot(identity.shadow())
}

fn shadow_observe_kind_if_installed(
    identity: DriverIdentity,
) -> Result<Option<PendingKind>, PendingShadowError> {
    let Some(slot) = shadow_slot(identity.key) else {
        return Err(PendingShadowError::IdentityMismatch);
    };
    slot.lock().observe_kind_if_installed(identity.shadow())
}

fn shadow_clear(
    identity: DriverIdentity,
    expected: NativePendingSnapshot,
) -> Result<(), PendingShadowError> {
    let Some(slot) = shadow_slot(identity.key) else {
        return Err(PendingShadowError::IdentityMismatch);
    };
    if expected.identity != identity.shadow() {
        slot.lock().quarantine();
        return Err(PendingShadowError::IdentityMismatch);
    }
    slot.lock().clear(expected)
}

fn shadow_retire(identity: DriverIdentity) -> Result<(), PendingShadowError> {
    let Some(slot) = shadow_slot(identity.key) else {
        return Err(PendingShadowError::IdentityMismatch);
    };
    slot.lock().retire(identity.shadow())
}

fn quarantine_shadow(identity: DriverIdentity) {
    if let Some(slot) = shadow_slot(identity.key) {
        slot.lock().quarantine();
    }
    CONTROL.child_shadow[identity.key.slot as usize].quarantine(identity.key);
    CONTROL.supervisor_shadow[identity.key.slot as usize].quarantine(identity.key);
    let _ = registry().quarantine(identity.instance);
    lifecycle_fail_stop();
}

fn exact_shadow_lease<T: Resource>(
    cspace: &CSpace,
    cap: Cap,
    rights: Rights,
) -> Option<InvocationLease<T>> {
    if cspace.rights_of(cap).ok()? != rights {
        return None;
    }
    cspace.lookup_lease::<T>(cap, rights).ok()
}

/// Cancel one snapshotted backend operation without retaining any lock across
/// layers. The caller takes/releases the shadow lock before this function;
/// this function takes/releases the CSpace lock before invoking the stream;
/// only after the stream returns does it reacquire the shadow lock to clear.
fn cancel_snapshot_in_space(
    space: &InstanceSpace,
    identity: DriverIdentity,
    snapshot: NativePendingSnapshot,
) -> bool {
    if snapshot.identity != identity.shadow() {
        return false;
    }
    enum Lease {
        Reader(InvocationLease<ByteStreamReader>),
        Writer(InvocationLease<ByteStreamWriter>),
        Supervisor(InvocationLease<ByteStreamSupervisor>),
    }
    let lease = {
        let cspace = space.cspace().lock();
        if validate_stream_space(&cspace, identity.streams).is_err() {
            return false;
        }
        match snapshot.kind {
            PendingKind::ReadWaiting | PendingKind::ReadPrepared => {
                exact_shadow_lease::<ByteStreamReader>(
                    &cspace,
                    identity.streams.stdin,
                    Rights::RECV,
                )
                .map(Lease::Reader)
            }
            PendingKind::WriteWaiting => exact_shadow_lease::<ByteStreamWriter>(
                &cspace,
                identity.streams.stdout,
                Rights::SEND,
            )
            .map(Lease::Writer),
            PendingKind::TerminalWaiting => exact_shadow_lease::<ByteStreamSupervisor>(
                &cspace,
                identity.streams.stdin_supervisor,
                Rights::INVOKE,
            )
            .map(Lease::Supervisor),
        }
    };
    let Some(lease) = lease else {
        return false;
    };
    let cancelled = match lease {
        Lease::Reader(reader) => reader.with(|reader| reader.cancel(snapshot.operation)),
        Lease::Writer(writer) => writer.with(|writer| writer.cancel(snapshot.operation)),
        Lease::Supervisor(supervisor) => {
            supervisor.with(|supervisor| supervisor.cancel_terminal(snapshot.operation))
        }
    };
    if cancelled.is_err() {
        return false;
    }
    shadow_clear(identity, snapshot).is_ok()
}

fn cancel_current_shadow(identity: DriverIdentity) -> bool {
    let snapshot = match shadow_snapshot(identity) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return true,
        Err(_) => return false,
    };
    let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
        return false;
    };
    if witness.instance_token() != Some(identity.instance) {
        return false;
    }
    unsafe {
        registry()
            .with_current_space_for_cleanup(witness, |space| {
                cancel_snapshot_in_space(space, identity, snapshot)
            })
            .is_ok_and(|cancelled| cancelled)
    }
}

pub(super) fn payload_drop(key: ControlKey, token: InstanceToken, streams: RegistryStreamBindings) {
    let identity = DriverIdentity {
        key,
        instance: token,
        streams,
    };
    if !cancel_current_shadow(identity) {
        quarantine_shadow(identity);
    }
}

pub(super) fn terminal_shadow_empty(
    key: ControlKey,
    token: InstanceToken,
    streams: RegistryStreamBindings,
) -> bool {
    shadow_snapshot(DriverIdentity {
        key,
        instance: token,
        streams,
    })
    .is_ok_and(|snapshot| snapshot.is_none())
}

pub(super) fn retire_terminal_shadow(
    key: ControlKey,
    token: InstanceToken,
    streams: RegistryStreamBindings,
) -> bool {
    shadow_retire(DriverIdentity {
        key,
        instance: token,
        streams,
    })
    .is_ok()
}

/// Resolve the SYSTEM pending-operation projection while the registry has
/// restored and revalidated the exact Space, but before either raw arena
/// reclaim or the terminal CSpace reset is allowed to proceed. The registry,
/// CONTROL, shadow, and CSpace guards are all absent on entry.
pub(super) fn prepare_terminal_shadow(
    space: &InstanceSpace,
    key: ControlKey,
    token: InstanceToken,
    streams: RegistryStreamBindings,
    terminal: ComponentTerminal,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance: token,
        streams,
    };
    let snapshot = match shadow_snapshot(identity) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            quarantine_shadow(identity);
            return false;
        }
    };
    match snapshot {
        // Success must have crossed every backend/runtime linearization point
        // and therefore cannot retain a backend pending operation.
        Some(_) if terminal == ComponentTerminal::Success => {
            quarantine_shadow(identity);
            false
        }
        // Fault/cancel terminals may finally cancel the exact backend token.
        Some(snapshot) => {
            if cancel_snapshot_in_space(space, identity, snapshot) {
                true
            } else {
                quarantine_shadow(identity);
                false
            }
        }
        None => true,
    }
}

pub(super) fn fault_snapshot(
    key: ControlKey,
    token: InstanceToken,
    streams: RegistryStreamBindings,
) -> Result<Option<NativePendingSnapshot>, PendingShadowError> {
    shadow_snapshot(DriverIdentity {
        key,
        instance: token,
        streams,
    })
}

pub(super) fn cancel_fault_snapshot(
    space: &InstanceSpace,
    key: ControlKey,
    token: InstanceToken,
    streams: RegistryStreamBindings,
    snapshot: Option<NativePendingSnapshot>,
) -> bool {
    let identity = DriverIdentity {
        key,
        instance: token,
        streams,
    };
    match snapshot {
        Some(snapshot) => cancel_snapshot_in_space(space, identity, snapshot),
        None => true,
    }
}

pub(super) fn quarantine_fault_shadow(
    key: ControlKey,
    token: InstanceToken,
    streams: RegistryStreamBindings,
) {
    quarantine_shadow(DriverIdentity {
        key,
        instance: token,
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

async fn quantum(instance: InstanceToken) -> Result<(), ()> {
    let continuation = registry()
        .yield_continuation_current(instance)
        .map_err(|_| ())?;
    continuation.await.map_err(|_| ())
}

fn stream_wake(words: [usize; 4]) {
    match registry().signal_continuation_words(words) {
        crate::instance::InstanceContinuationSignal::Signalled
        | crate::instance::InstanceContinuationSignal::AlreadySignalled
        | crate::instance::InstanceContinuationSignal::Stale => {}
        crate::instance::InstanceContinuationSignal::Quarantined => lifecycle_fail_stop(),
    }
}

async fn await_reader_wake(
    identity: DriverIdentity,
    snapshot: NativePendingSnapshot,
) -> Result<(), ()> {
    let continuation_token = registry()
        .arm_continuation_current(identity.instance, InstanceContinuationKind::External)
        .map_err(|_| ())?;
    let continuation = registry()
        .wait_continuation(continuation_token)
        .map_err(|_| ())?;
    let wake = HostWakeToken::new(continuation_token.signal_words(), stream_wake);
    let registered = with_active_reader(identity.instance, identity.streams, |reader, _| {
        reader.register_wake(snapshot.operation, wake)
    });
    if !matches!(registered, Ok(Ok(()))) {
        let cancelled = cancel_current_shadow(identity);
        drop(continuation);
        if !cancelled {
            quarantine_shadow(identity);
        }
        return Err(());
    }
    if continuation.await.is_err() {
        if !cancel_current_shadow(identity) {
            quarantine_shadow(identity);
        }
        return Err(());
    }
    Ok(())
}

async fn await_writer_wake(
    identity: DriverIdentity,
    snapshot: NativePendingSnapshot,
) -> Result<(), ()> {
    let continuation_token = registry()
        .arm_continuation_current(identity.instance, InstanceContinuationKind::External)
        .map_err(|_| ())?;
    let continuation = registry()
        .wait_continuation(continuation_token)
        .map_err(|_| ())?;
    let wake = HostWakeToken::new(continuation_token.signal_words(), stream_wake);
    let registered = with_active_writer(identity.instance, identity.streams, |writer| {
        writer.register_wake(snapshot.operation, wake)
    });
    if !matches!(registered, Ok(Ok(()))) {
        let cancelled = cancel_current_shadow(identity);
        drop(continuation);
        if !cancelled {
            quarantine_shadow(identity);
        }
        return Err(());
    }
    if continuation.await.is_err() {
        if !cancel_current_shadow(identity) {
            quarantine_shadow(identity);
        }
        return Err(());
    }
    Ok(())
}

async fn await_terminal_wake(
    identity: DriverIdentity,
    snapshot: NativePendingSnapshot,
) -> Result<(), ()> {
    let continuation_token = registry()
        .arm_continuation_current(identity.instance, InstanceContinuationKind::External)
        .map_err(|_| ())?;
    let continuation = registry()
        .wait_continuation(continuation_token)
        .map_err(|_| ())?;
    let wake = HostWakeToken::new(continuation_token.signal_words(), stream_wake);
    let registered = with_active_reader(identity.instance, identity.streams, |_, supervisor| {
        supervisor.register_terminal_wake(snapshot.operation, wake)
    });
    if !matches!(registered, Ok(Ok(()))) {
        let cancelled = cancel_current_shadow(identity);
        drop(continuation);
        if !cancelled {
            quarantine_shadow(identity);
        }
        return Err(());
    }
    if continuation.await.is_err() {
        if !cancel_current_shadow(identity) {
            quarantine_shadow(identity);
        }
        return Err(());
    }
    Ok(())
}

fn install_or_replace(
    identity: DriverIdentity,
    previous: Option<NativePendingSnapshot>,
    kind: PendingKind,
    operation: HostOperationToken,
) -> Result<NativePendingSnapshot, PendingShadowError> {
    match previous {
        Some(previous) => shadow_replace_for(identity, previous, kind, operation),
        None => shadow_install(identity, kind, operation),
    }
}

async fn prepared_reader(
    identity: DriverIdentity,
    initial: StreamReceiveDispatch,
) -> Result<Result<(StreamPreparedReceive, NativePendingSnapshot), StreamCloseReason>, ()> {
    let mut dispatch = initial;
    let mut previous = None;
    loop {
        match dispatch {
            StreamReceiveDispatch::Prepared(prepared) => {
                let installed = install_or_replace(
                    identity,
                    previous,
                    PendingKind::ReadPrepared,
                    prepared.operation(),
                );
                return match installed {
                    Ok(snapshot) => Ok(Ok((prepared, snapshot))),
                    Err(_) => {
                        let _ =
                            with_active_reader(identity.instance, identity.streams, |reader, _| {
                                reader.cancel(prepared.operation())
                            });
                        quarantine_shadow(identity);
                        Err(())
                    }
                };
            }
            StreamReceiveDispatch::Closed(reason) => {
                if let Some(previous) = previous {
                    if shadow_clear(identity, previous).is_err() {
                        quarantine_shadow(identity);
                        return Err(());
                    }
                }
                return Ok(Err(reason));
            }
            StreamReceiveDispatch::Waiting(operation) => {
                let snapshot = match install_or_replace(
                    identity,
                    previous,
                    PendingKind::ReadWaiting,
                    operation,
                ) {
                    Ok(snapshot) => snapshot,
                    Err(_) => {
                        let _ =
                            with_active_reader(identity.instance, identity.streams, |reader, _| {
                                reader.cancel(operation)
                            });
                        quarantine_shadow(identity);
                        return Err(());
                    }
                };
                if await_reader_wake(identity, snapshot).await.is_err() {
                    quarantine_shadow(identity);
                    return Err(());
                }
                dispatch = with_active_reader(
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
                )
                .map_err(|_| ())?
                .map_err(|_| ())?;
                previous = Some(snapshot);
            }
        }
    }
}

async fn send_output(
    identity: DriverIdentity,
    bytes: &[u8],
) -> Result<Result<(), StreamCloseReason>, ()> {
    if bytes.is_empty() {
        return Ok(Ok(()));
    }
    let mut dispatch = with_active_writer(identity.instance, identity.streams, |writer| {
        writer.start(bytes)
    })
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let mut previous = None;
    loop {
        match dispatch {
            StreamSendDispatch::Sent => {
                if let Some(previous) = previous {
                    if shadow_clear(identity, previous).is_err() {
                        quarantine_shadow(identity);
                        return Err(());
                    }
                }
                return Ok(Ok(()));
            }
            StreamSendDispatch::Closed(reason) => {
                if let Some(previous) = previous {
                    if shadow_clear(identity, previous).is_err() {
                        quarantine_shadow(identity);
                        return Err(());
                    }
                }
                return Ok(Err(reason));
            }
            StreamSendDispatch::Waiting(operation) => {
                let snapshot = match install_or_replace(
                    identity,
                    previous,
                    PendingKind::WriteWaiting,
                    operation,
                ) {
                    Ok(snapshot) => snapshot,
                    Err(_) => {
                        let _ = with_active_writer(identity.instance, identity.streams, |writer| {
                            writer.cancel(operation)
                        });
                        quarantine_shadow(identity);
                        return Err(());
                    }
                };
                if await_writer_wake(identity, snapshot).await.is_err() {
                    quarantine_shadow(identity);
                    return Err(());
                }
                dispatch = with_active_writer(identity.instance, identity.streams, |writer| {
                    writer.resume(operation, bytes)
                })
                .map_err(|_| ())?
                .map_err(|_| ())?;
                previous = Some(snapshot);
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
) -> Result<NativePoll, ComponentTerminal> {
    let maximum = usize::try_from(maximum)
        .unwrap_or(usize::MAX)
        .min(DRIVER_CHUNK_BYTES);
    if !spill.is_empty() {
        let progress = spill.remaining_prefix(maximum).len();
        let prepared = invocation
            .prepare_host_input_stream(offered, progress as u32)
            .map_err(|error| unexpected_native_driver_error(identity, error))?;
        let prepared = prepared_host_token(identity, prepared, is_input_stream)?;
        let committed = invocation
            .commit_host_input_stream(prepared, spill.remaining_prefix(progress))
            .map_err(|error| unexpected_native_driver_error(identity, error))?;
        if let Some(terminal) = poll_terminal(committed) {
            quarantine_shadow(identity);
            return Err(terminal);
        }
        if !spill.consume(progress) {
            return Err(unexpected_native_driver_error(
                identity,
                "spill cursor mismatch",
            ));
        }
        return Ok(committed);
    }

    if promote_input_normal(identity).is_err() {
        return Err(unexpected_native_driver_error(
            identity,
            "input normal promotion conflict",
        ));
    }
    let initial = with_active_reader(identity.instance, identity.streams, |reader, _| {
        reader.start()
    })
    .map_err(|_| unexpected_native_driver_error(identity, "reader CSpace mismatch"))?
    .map_err(|error| unexpected_native_driver_error(identity, error))?;
    let prepared = match prepared_reader(identity, initial).await {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(_reason)) => {
            return invocation
                .drop_host_copy_peer(offered)
                .map_err(|error| unexpected_native_driver_error(identity, error));
        }
        Err(()) => return Err(ComponentTerminal::RunnerFault),
    };
    let (backend, backend_shadow) = prepared;
    let length = backend.length();
    if length == 0 || length > DRIVER_CHUNK_BYTES {
        quarantine_shadow(identity);
        return Err(ComponentTerminal::RunnerFault);
    }
    let progress = length.min(maximum);
    let runtime_prepared = invocation
        .prepare_host_input_stream(offered, progress as u32)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    let runtime_prepared = match prepared_host_token(identity, runtime_prepared, is_input_stream) {
        Ok(token) => token,
        Err(terminal) => {
            if !cancel_current_shadow(identity) {
                quarantine_shadow(identity);
            }
            return Err(terminal);
        }
    };
    let target = spill
        .receive_target(length)
        .ok_or_else(|| unexpected_native_driver_error(identity, "invalid spill target"))?;
    let committed = with_active_reader(identity.instance, identity.streams, |reader, _| {
        reader.commit(backend.operation(), target)
    })
    .map_err(|_| unexpected_native_driver_error(identity, "reader commit CSpace mismatch"))?
    .map_err(|error| unexpected_native_driver_error(identity, error))?;
    match committed {
        StreamReceiveCommit::Received(received) if received == length => {
            if shadow_clear(identity, backend_shadow).is_err() {
                quarantine_shadow(identity);
                return Err(ComponentTerminal::RunnerFault);
            }
        }
        StreamReceiveCommit::Received(_) => {
            quarantine_shadow(identity);
            return Err(ComponentTerminal::RunnerFault);
        }
        StreamReceiveCommit::Closed(_) => {
            spill.abort_receive();
            let cancelled = with_active_reader(identity.instance, identity.streams, |reader, _| {
                reader.cancel(backend.operation())
            });
            if !matches!(cancelled, Ok(Ok(()))) || shadow_clear(identity, backend_shadow).is_err() {
                quarantine_shadow(identity);
                return Err(ComponentTerminal::RunnerFault);
            }
            return invocation
                .drop_host_copy_peer(runtime_prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error));
        }
    }
    let runtime_committed = invocation
        .commit_host_input_stream(runtime_prepared, spill.remaining_prefix(progress))
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    if let Some(terminal) = poll_terminal(runtime_committed) {
        // The backend chunk has already been popped. Any rejected runtime
        // commit loses synchronization with transport and is globally fatal.
        quarantine_shadow(identity);
        return Err(terminal);
    }
    if !spill.consume(progress) {
        return Err(unexpected_native_driver_error(
            identity,
            "spill commit mismatch",
        ));
    }
    Ok(runtime_committed)
}

async fn drive_input_closed(
    invocation: &mut NativeInvocation<'_>,
    identity: DriverIdentity,
    offered: NativeHostToken,
    spill: &InputSpill,
) -> Result<NativePoll, ComponentTerminal> {
    if !spill.is_empty() || promote_input_normal(identity).is_err() {
        return Err(unexpected_native_driver_error(
            identity,
            "input close before drain",
        ));
    }
    let mut dispatch = with_active_reader(identity.instance, identity.streams, |_, supervisor| {
        supervisor.start_terminal()
    })
    .map_err(|_| unexpected_native_driver_error(identity, "terminal CSpace mismatch"))?
    .map_err(|error| unexpected_native_driver_error(identity, error))?;
    let mut shadow = match dispatch {
        StreamTerminalDispatch::Waiting(operation) => Some(
            shadow_install(identity, PendingKind::TerminalWaiting, operation)
                .map_err(|error| unexpected_native_driver_error(identity, error))?,
        ),
        StreamTerminalDispatch::Ready(_) => None,
    };
    let runtime_prepared = invocation
        .prepare_host_input_closed(offered)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    let runtime_prepared = match prepared_host_token(identity, runtime_prepared, is_input_closed) {
        Ok(token) => token,
        Err(terminal) => {
            if shadow.is_some() && !cancel_current_shadow(identity) {
                quarantine_shadow(identity);
            }
            return Err(terminal);
        }
    };
    loop {
        match dispatch {
            StreamTerminalDispatch::Ready(reason) => {
                return invocation
                    .commit_host_input_closed(runtime_prepared, stream_reason_value(reason))
                    .map_err(|error| unexpected_native_driver_error(identity, error));
            }
            StreamTerminalDispatch::Waiting(operation) => {
                let current = shadow.expect("terminal waiting has a SYSTEM shadow");
                if await_terminal_wake(identity, current).await.is_err() {
                    quarantine_shadow(identity);
                    return Err(ComponentTerminal::RunnerFault);
                }
                dispatch =
                    with_active_reader(identity.instance, identity.streams, |_, supervisor| {
                        supervisor.resume_terminal(operation)
                    })
                    .map_err(|_| {
                        unexpected_native_driver_error(identity, "terminal resume CSpace mismatch")
                    })?
                    .map_err(|error| unexpected_native_driver_error(identity, error))?;
                match dispatch {
                    StreamTerminalDispatch::Waiting(fresh) => {
                        shadow = Some(
                            shadow_replace_for(
                                identity,
                                current,
                                PendingKind::TerminalWaiting,
                                fresh,
                            )
                            .map_err(|_| {
                                let _ = with_active_reader(
                                    identity.instance,
                                    identity.streams,
                                    |_, supervisor| supervisor.cancel_terminal(fresh),
                                );
                                unexpected_native_driver_error(
                                    identity,
                                    "terminal token replacement",
                                )
                            })?,
                        );
                    }
                    StreamTerminalDispatch::Ready(_) => {
                        if shadow_clear(identity, current).is_err() {
                            quarantine_shadow(identity);
                            return Err(ComponentTerminal::RunnerFault);
                        }
                        shadow = None;
                    }
                }
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
    let output = staging.prepare(maximum);
    let prepared = invocation
        .prepare_host_output_stream(offered, output)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
    let prepared = prepared_host_token(identity, prepared, is_output_stream)?;
    let send = send_output(identity, staging.prepared()).await;
    match send {
        Ok(Ok(())) => {
            let committed = invocation
                .commit_host_output(prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            staging.clear();
            if let Some(terminal) = poll_terminal(committed) {
                // Sent is the transport linearization point. A rejected
                // runtime commit after it is a global lifecycle divergence.
                quarantine_shadow(identity);
                return Err(terminal);
            }
            Ok(committed)
        }
        Ok(Err(_reason)) => {
            staging.clear();
            invocation
                .drop_host_copy_peer(prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error))
        }
        Err(()) => {
            staging.clear();
            Err(ComponentTerminal::RunnerFault)
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
    let prepared_poll = invocation
        .prepare_host_output_closed(offered)
        .map_err(|error| unexpected_native_driver_error(identity, error))?;
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
    let observation = output_close_observation(identity, reason)?;
    match (observation.outcome(), observation.effective_reason()) {
        (StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished, Some(effective))
            if effective == reason =>
        {
            let committed = invocation
                .commit_host_output(prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error))?;
            if let Some(terminal) = poll_terminal(committed) {
                quarantine_shadow(identity);
                Err(terminal)
            } else {
                Ok(committed)
            }
        }
        (StreamCloseOutcome::AlreadyPublished, Some(effective))
            if reason == StreamCloseReason::Normal && effective != StreamCloseReason::Normal =>
        {
            // An established failure owns the terminal. A late guest Normal is
            // not committed and does not publish a conflicting close.
            invocation
                .drop_host_copy_peer(prepared)
                .map_err(|error| unexpected_native_driver_error(identity, error))
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
    streams: RegistryStreamBindings,
) -> u64 {
    let identity = DriverIdentity {
        key,
        instance: token,
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
    let mut staging = OutputStaging::new();
    let mut next = None;
    loop {
        let poll = next.take().unwrap_or_else(|| invocation.poll());
        let result = match poll {
            NativePoll::Pending(_) | NativePoll::Resolved(_) | NativePoll::Yielded(_) => {
                if quantum(token).await.is_err() {
                    Err(unexpected_native_driver_error(
                        identity,
                        "quantum continuation",
                    ))
                } else {
                    next = None;
                    continue;
                }
            }
            NativePoll::WaitPending { token: wait, .. } => {
                if quantum(token).await.is_err() {
                    Err(unexpected_native_driver_error(identity, "wait quantum"))
                } else {
                    invocation
                        .resume_wait(wait)
                        .map_err(|error| unexpected_native_driver_error(identity, error))
                }
            }
            NativePoll::HostPending {
                token: host,
                request: NativeHostRequest::InputStream { maximum },
                ..
            } => drive_input_stream(&mut invocation, identity, host, maximum, &mut spill).await,
            NativePoll::HostPending {
                token: host,
                request: NativeHostRequest::InputClosed,
                ..
            } => drive_input_closed(&mut invocation, identity, host, &spill).await,
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
                    || !staging.is_empty()
                    || !terminal_shadow_empty(key, token, streams)
                    || invocation.finalize_transport().is_err()
                {
                    quarantine_shadow(identity);
                    return terminal_word(ComponentTerminal::RunnerFault);
                }
                return terminal_word(ComponentTerminal::Success);
            }
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
    streams: RegistryStreamBindings,
) -> u64 {
    let Some(root) = image_root() else {
        lifecycle_fail_stop();
        return terminal_word(ComponentTerminal::Unavailable);
    };
    run_driver(root, key, token, streams).await
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
            match shadow_observe_kind_if_installed(identity) {
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
