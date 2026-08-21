use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vibeos_component_format::TrapCode;
use vibeos_component_host::{
    BlobBackend, BlobBackendFault, BlobResource, ClockBackend, ClockBackendFault, ClockResource,
    ComponentAuthority, ComponentAuthoritySpace, ComponentHostDispatcher, LogLevel, RandomBackend,
    RandomBackendFault, RandomResource, SharedCSpace, StructuredLogResource, StructuredLogSink,
    StructuredLogSinkFault, ValidatedLogEvent, VibeHostManifest, RANDOM_INTERFACE,
};
use vibeos_component_runtime::decode::inspect_component;
use vibeos_component_runtime::host::HostError;
use vibeos_component_runtime::resource::{ResourceTable, ResourceToken, ResourceTypeId};
use vibeos_component_runtime::sync::{
    SyncError, SynchronousComponent, TypedCallMetrics, TypedPoll,
};
use vibeos_component_runtime::value::CanonicalValue;
use vibeos_core::cap::{CSpace, Cap, Rights};
use vibeos_core::sync::SpinLock;
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

const CLOCK_COMPONENT: &str =
    include_str!("../../../component-runtime/tests/fixtures/host-clock.component.wat");
const RANDOM_COMPONENT: &str = include_str!("fixtures/host-random.component.wat");
const BLOB_COMPONENT: &str = include_str!("fixtures/host-blob.component.wat");
const LOG_COMPONENT: &str = include_str!("fixtures/host-log.component.wat");
const RESOURCE_TYPE: ResourceTypeId = ResourceTypeId(1);

fn new_dispatcher(cspace: SharedCSpace, source: &str) -> ComponentHostDispatcher {
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let manifest = VibeHostManifest::from_plan(&plan).unwrap();
    ComponentHostDispatcher::new(cspace, manifest)
}

fn instantiate(source: &str) -> SynchronousComponent {
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    SynchronousComponent::instantiate(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap()
}

fn space(name: &str) -> (SharedCSpace, ComponentAuthoritySpace) {
    let cspace = Arc::new(SpinLock::new(CSpace::new(name)));
    let binding = ComponentAuthoritySpace::new(cspace.clone(), 1).unwrap();
    (cspace, binding)
}

fn insert(
    table: &mut ResourceTable<ComponentAuthority>,
    authority: ComponentAuthority,
) -> ResourceToken {
    table.insert_owned(RESOURCE_TYPE, authority).unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InvokeFailure {
    Host(HostError),
    Trap(TrapCode),
}

fn invoke(
    component: &mut SynchronousComponent,
    table: &mut ResourceTable<ComponentAuthority>,
    dispatcher: &mut ComponentHostDispatcher,
    export: &str,
    arguments: Vec<CanonicalValue>,
) -> Result<CanonicalValue, InvokeFailure> {
    let mut call = component
        .start_typed_call_with_host(table, dispatcher, export, arguments, 100_000, 100)
        .unwrap();
    for _ in 0..100_000 {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(_) => panic!("synchronous dispatcher unexpectedly suspended"),
            TypedPoll::Ready(value) => return Ok(value),
            TypedPoll::HostFailed(error) => return Err(InvokeFailure::Host(error)),
            TypedPoll::Trapped(trap) => return Err(InvokeFailure::Trap(trap)),
        }
    }
    panic!("bounded component host call did not terminate")
}

fn invoke_with_monotonic_metrics(
    component: &mut SynchronousComponent,
    table: &mut ResourceTable<ComponentAuthority>,
    dispatcher: &mut ComponentHostDispatcher,
    export: &str,
    arguments: Vec<CanonicalValue>,
) -> (Result<CanonicalValue, InvokeFailure>, TypedCallMetrics) {
    let mut call = component
        .start_typed_call_with_host(table, dispatcher, export, arguments, 100_000, 100)
        .unwrap();
    let mut previous = call.metrics();
    for _ in 0..100_000 {
        let terminal = match call.poll() {
            TypedPoll::Pending(metrics) => {
                assert!(metrics.consumed_work >= previous.consumed_work);
                assert!(metrics.remaining_work <= previous.remaining_work);
                assert_eq!(metrics.consumed_work + metrics.remaining_work, 100_000);
                previous = metrics;
                None
            }
            TypedPoll::HostPending(_) => panic!("synchronous dispatcher unexpectedly suspended"),
            TypedPoll::Ready(value) => Some(Ok(value)),
            TypedPoll::HostFailed(error) => Some(Err(InvokeFailure::Host(error))),
            TypedPoll::Trapped(trap) => Some(Err(InvokeFailure::Trap(trap))),
        };
        if let Some(terminal) = terminal {
            let metrics = call.metrics();
            assert!(metrics.consumed_work >= previous.consumed_work);
            assert_eq!(metrics.consumed_work + metrics.remaining_work, 100_000);
            return (terminal, metrics);
        }
    }
    panic!("bounded component host call did not terminate")
}

fn ok_bytes(bytes: &[u8]) -> CanonicalValue {
    CanonicalValue::Result(Ok(Some(Box::new(CanonicalValue::List(
        bytes.iter().copied().map(CanonicalValue::U8).collect(),
    )))))
}

fn error_case(case: u32) -> CanonicalValue {
    CanonicalValue::Result(Err(Some(Box::new(CanonicalValue::Enum(case)))))
}

fn assert_manifest_rejects(source: &str) {
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    assert!(VibeHostManifest::from_plan(&plan).is_err());
}

#[test]
fn manifest_rejects_resource_enum_record_and_member_order_spoofs() {
    assert_manifest_rejects(&CLOCK_COMPONENT.replace("\"clock\"", "\"monotonic-clock\""));
    assert_manifest_rejects(&RANDOM_COMPONENT.replace("\"exhausted\"", "\"retry\""));
    assert_manifest_rejects(&LOG_COMPONENT.replace(
        "(type $field-private (record (field \"key\" string) (field \"value\" string)))",
        "(type $field-private (record (field \"value\" string) (field \"key\" string)))",
    ));
    assert_manifest_rejects(&BLOB_COMPONENT.replace(
        "      (export \"len\" (func (type $len-type)))\n      (export \"read\" (func (type $read-type)))",
        "      (export \"read\" (func (type $read-type)))\n      (export \"len\" (func (type $len-type)))",
    ));
}

struct FixedClock(u64);

impl ClockBackend for FixedClock {
    fn now_ns(&self) -> Result<u64, ClockBackendFault> {
        Ok(self.0)
    }
}

#[test]
fn empty_and_cross_table_handles_fail_before_observing_clock_authority() {
    let mut component = instantiate(CLOCK_COMPONENT);
    let (cspace, _) = space("empty-table");
    let mut dispatcher = new_dispatcher(cspace, CLOCK_COMPONENT);
    let mut empty = ResourceTable::new(1, 2).unwrap();
    let guessed = empty.token_from_guest_index(1);
    assert!(matches!(
        component.start_typed_call_with_host(
            &mut empty,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(guessed)],
            100_000,
            100,
        ),
        Err(SyncError::Resource),
    ));

    let (first_space, first_binding) = space("first-table");
    let cap = first_space.lock().mint(
        Arc::new(ClockResource::new(Arc::new(FixedClock(1)))),
        Rights::READ,
    );
    let authority = first_binding
        .bind_ephemeral::<ClockResource>(cap, Rights::READ)
        .unwrap();
    let mut first = ResourceTable::new(2, 2).unwrap();
    let first_token = insert(&mut first, authority);

    let (second_space, second_binding) = space("second-table");
    let cap = second_space.lock().mint(
        Arc::new(ClockResource::new(Arc::new(FixedClock(2)))),
        Rights::READ,
    );
    let authority = second_binding
        .bind_ephemeral::<ClockResource>(cap, Rights::READ)
        .unwrap();
    let mut second = ResourceTable::new(2, 2).unwrap();
    let second_token = insert(&mut second, authority);
    assert_ne!(
        first_token, second_token,
        "table identity must dominate any coincidental guest integer",
    );
    let mut component = instantiate(CLOCK_COMPONENT);
    let mut dispatcher = new_dispatcher(second_space, CLOCK_COMPONENT);
    assert!(matches!(
        component.start_typed_call_with_host(
            &mut second,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(first_token)],
            100_000,
            100,
        ),
        Err(SyncError::Resource),
    ));
}

#[test]
fn clock_dispatch_is_exact_and_wrong_kind_rights_or_revocation_are_denied() {
    let (cspace, binding) = space("clock-dispatch");
    let cap = cspace.lock().mint(
        Arc::new(ClockResource::new(Arc::new(FixedClock(55)))),
        Rights::READ,
    );
    let authority = binding
        .bind_ephemeral::<ClockResource>(cap, Rights::READ)
        .unwrap();
    let mut table = ResourceTable::new(3, 2).unwrap();
    let token = insert(&mut table, authority);
    let mut component = instantiate(CLOCK_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace.clone(), CLOCK_COMPONENT);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(token)],
        ),
        Ok(CanonicalValue::U64(55)),
    );
    assert_eq!(cspace.lock().revoke_slot(cap.slot()), 1);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(token)],
        ),
        Err(InvokeFailure::Host(HostError::Denied)),
    );

    let (wrong_space, wrong_binding) = space("clock-wrong-rights");
    let cap = wrong_space.lock().mint(
        Arc::new(ClockResource::new(Arc::new(FixedClock(77)))),
        Rights::WRITE,
    );
    assert_eq!(
        wrong_binding
            .bind_ephemeral::<ClockResource>(cap, Rights::WRITE)
            .unwrap_err(),
        vibeos_component_host::AuthorityError::RightsExceedCeiling,
    );
}

struct Fill {
    byte: u8,
    calls: AtomicUsize,
    fail: bool,
}

impl RandomBackend for Fill {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomBackendFault> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(RandomBackendFault);
        }
        destination.fill(self.byte);
        Ok(())
    }
}

fn random_table(
    name: &str,
    rights: Rights,
    backend: Arc<Fill>,
) -> (
    SharedCSpace,
    Cap,
    ResourceTable<ComponentAuthority>,
    ResourceToken,
) {
    let (cspace, binding) = space(name);
    let cap = cspace
        .lock()
        .mint(Arc::new(RandomResource::new(backend)), rights);
    let authority = binding
        .bind_ephemeral::<RandomResource>(cap, rights)
        .unwrap();
    let mut table = ResourceTable::new(5, 2).unwrap();
    let token = insert(&mut table, authority);
    (cspace, cap, table, token)
}

#[test]
fn only_exact_random_grant_succeeds_and_revocation_denies_the_next_call() {
    let backend = Arc::new(Fill {
        byte: 0xa5,
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let (cspace, cap, mut table, token) = random_table("random-dispatch", Rights::READ, backend);
    let mut component = instantiate(RANDOM_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace.clone(), RANDOM_COMPONENT);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(token), CanonicalValue::U32(3)],
        ),
        Ok(ok_bytes(&[0xa5; 3])),
    );
    assert_eq!(cspace.lock().revoke_slot(cap.slot()), 1);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(token), CanonicalValue::U32(1)],
        ),
        Ok(error_case(0)),
    );
}

#[test]
fn dynamic_host_reservations_release_to_exact_monotonic_work() {
    let success_backend = Arc::new(Fill {
        byte: 0x5a,
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let (cspace, _, mut table, token) = random_table(
        "random-exact-success",
        Rights::READ,
        success_backend.clone(),
    );
    let mut component = instantiate(RANDOM_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace, RANDOM_COMPONENT);
    let (success, success_metrics) = invoke_with_monotonic_metrics(
        &mut component,
        &mut table,
        &mut dispatcher,
        "run",
        vec![CanonicalValue::Resource(token), CanonicalValue::U32(1)],
    );
    assert_eq!(success, Ok(ok_bytes(&[0x5a])));
    assert_eq!(success_backend.calls.load(Ordering::SeqCst), 1);

    let error_backend = Arc::new(Fill {
        byte: 0,
        calls: AtomicUsize::new(0),
        fail: true,
    });
    let (cspace, _, mut table, token) =
        random_table("random-exact-error", Rights::READ, error_backend.clone());
    let mut component = instantiate(RANDOM_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace, RANDOM_COMPONENT);
    let (error, error_metrics) = invoke_with_monotonic_metrics(
        &mut component,
        &mut table,
        &mut dispatcher,
        "run",
        vec![CanonicalValue::Resource(token), CanonicalValue::U32(1)],
    );
    assert_eq!(error, Ok(error_case(1)));
    assert_eq!(error_backend.calls.load(Ordering::SeqCst), 1);

    // The result schema reserves the Profile-wide dynamic lower bound and two
    // whole provider quanta, but neither appears as consumed work. The error
    // branch retains only the additional realloc(..., 0) instructions it ran.
    assert!(success_metrics.consumed_work < 10_000);
    assert!(error_metrics.consumed_work < 10_000);
    assert!(error_metrics.consumed_work > success_metrics.consumed_work);
}

#[test]
fn random_provider_span_overlapping_the_host_retptr_traps_before_dispatch() {
    let hostile = RANDOM_COMPONENT.replace(
        r#"(data (i32.const 0) "\00\40\00\00")"#,
        r#"(data (i32.const 0) "\00\02\00\00")"#,
    );
    assert_ne!(hostile, RANDOM_COMPONENT);
    let backend = Arc::new(Fill {
        byte: 0xaa,
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let (cspace, _, mut table, token) =
        random_table("random-overlap", Rights::READ, backend.clone());
    let mut component = instantiate(&hostile);
    let mut dispatcher = new_dispatcher(cspace, &hostile);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(token), CanonicalValue::U32(3)],
        ),
        Err(InvokeFailure::Trap(TrapCode::CanonicalAbi)),
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn random_dispatch_maps_rights_bounds_fault_and_exact_allowlist() {
    let denied_backend = Arc::new(Fill {
        byte: 1,
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let (denied_space, denied_binding) = space("random-denied");
    let denied_cap = denied_space.lock().mint(
        Arc::new(RandomResource::new(denied_backend.clone())),
        Rights::WRITE,
    );
    assert_eq!(
        denied_binding
            .bind_ephemeral::<RandomResource>(denied_cap, Rights::WRITE)
            .unwrap_err(),
        vibeos_component_host::AuthorityError::RightsExceedCeiling,
    );
    assert_eq!(denied_backend.calls.load(Ordering::SeqCst), 0);

    let fault = Arc::new(Fill {
        byte: 2,
        calls: AtomicUsize::new(0),
        fail: true,
    });
    let (cspace, _, mut table, token) = random_table("random-fault", Rights::READ, fault);
    let mut component = instantiate(RANDOM_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace, RANDOM_COMPONENT);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(token), CanonicalValue::U32(1)],
        ),
        Ok(error_case(1)),
    );

    let okay = Arc::new(Fill {
        byte: 3,
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let (cspace, _, mut table, token) = random_table("random-bounds", Rights::READ, okay.clone());
    let mut component = instantiate(RANDOM_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace, RANDOM_COMPONENT);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(token), CanonicalValue::U32(4097)],
        ),
        Ok(error_case(1)),
    );
    assert_eq!(okay.calls.load(Ordering::SeqCst), 0);

    for hostile in [
        RANDOM_COMPONENT.replace(RANDOM_INTERFACE, "vibe:random/other@1.0.0"),
        RANDOM_COMPONENT.replace("\"fill\"", "\"other\""),
        RANDOM_COMPONENT.replace("(param \"len\" u32)", "(param \"length\" u32)"),
    ] {
        let bytes = wat::parse_str(&hostile).unwrap();
        let plan = inspect_component(&bytes).unwrap();
        assert!(VibeHostManifest::from_plan(&plan).is_err());
    }
}

struct BytesBlob {
    bytes: &'static [u8],
    fail: bool,
}

impl BlobBackend for BytesBlob {
    fn len(&self) -> Result<u64, BlobBackendFault> {
        if self.fail {
            Err(BlobBackendFault)
        } else {
            Ok(self.bytes.len() as u64)
        }
    }

    fn read_exact(&self, offset: u64, output: &mut [u8]) -> Result<(), BlobBackendFault> {
        if self.fail {
            return Err(BlobBackendFault);
        }
        let start = usize::try_from(offset).map_err(|_| BlobBackendFault)?;
        let end = start.checked_add(output.len()).ok_or(BlobBackendFault)?;
        output.copy_from_slice(self.bytes.get(start..end).ok_or(BlobBackendFault)?);
        Ok(())
    }
}

fn blob_table(
    name: &str,
    rights: Rights,
    backend: Arc<BytesBlob>,
) -> (
    SharedCSpace,
    ResourceTable<ComponentAuthority>,
    ResourceToken,
) {
    let (cspace, binding) = space(name);
    let cap = cspace
        .lock()
        .mint(Arc::new(BlobResource::new(backend)), rights);
    let authority = binding.bind_ephemeral::<BlobResource>(cap, rights).unwrap();
    let mut table = ResourceTable::new(6, 2).unwrap();
    let token = insert(&mut table, authority);
    (cspace, table, token)
}

#[test]
fn blob_dispatch_has_exact_len_read_and_stable_error_variants() {
    let (cspace, mut table, token) = blob_table(
        "blob-dispatch",
        Rights::READ,
        Arc::new(BytesBlob {
            bytes: b"abcdef",
            fail: false,
        }),
    );
    let mut component = instantiate(BLOB_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace, BLOB_COMPONENT);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run-len",
            vec![CanonicalValue::Resource(token)],
        ),
        Ok(CanonicalValue::U64(6)),
    );
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run-read",
            vec![
                CanonicalValue::Resource(token),
                CanonicalValue::U64(2),
                CanonicalValue::U32(3),
            ],
        ),
        Ok(ok_bytes(b"cde")),
    );
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run-read",
            vec![
                CanonicalValue::Resource(token),
                CanonicalValue::U64(6),
                CanonicalValue::U32(1),
            ],
        ),
        Ok(error_case(1)),
    );

    let (cspace, mut table, token) = blob_table(
        "blob-fault",
        Rights::READ,
        Arc::new(BytesBlob {
            bytes: b"x",
            fail: true,
        }),
    );
    let mut component = instantiate(BLOB_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace, BLOB_COMPONENT);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run-read",
            vec![
                CanonicalValue::Resource(token),
                CanonicalValue::U64(0),
                CanonicalValue::U32(1),
            ],
        ),
        Ok(error_case(2)),
    );
}

struct RecordingLog {
    calls: AtomicUsize,
    fail: bool,
    last: Mutex<Option<(LogLevel, String)>>,
}

impl StructuredLogSink for RecordingLog {
    fn write(&self, event: &ValidatedLogEvent<'_>) -> Result<(), StructuredLogSinkFault> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(StructuredLogSinkFault);
        }
        *self.last.lock().unwrap() = Some((event.level, event.message.to_owned()));
        Ok(())
    }
}

fn log_table(
    name: &str,
    rights: Rights,
    sink: Arc<RecordingLog>,
) -> (
    SharedCSpace,
    ResourceTable<ComponentAuthority>,
    ResourceToken,
) {
    let (cspace, binding) = space(name);
    let cap = cspace
        .lock()
        .mint(Arc::new(StructuredLogResource::new(sink)), rights);
    let authority = binding
        .bind_ephemeral::<StructuredLogResource>(cap, rights)
        .unwrap();
    let mut table = ResourceTable::new(7, 2).unwrap();
    let token = insert(&mut table, authority);
    (cspace, table, token)
}

fn log_event(target: &str, message: &str) -> CanonicalValue {
    CanonicalValue::Record(vec![
        CanonicalValue::Enum(2),
        CanonicalValue::String(target.to_owned()),
        CanonicalValue::String(message.to_owned()),
        CanonicalValue::List(vec![CanonicalValue::Record(vec![
            CanonicalValue::String("request_id".to_owned()),
            CanonicalValue::String("42".to_owned()),
        ])]),
    ])
}

#[test]
fn structured_log_dispatch_validates_and_maps_denied_invalid_failed() {
    let sink = Arc::new(RecordingLog {
        calls: AtomicUsize::new(0),
        fail: false,
        last: Mutex::new(None),
    });
    let (cspace, mut table, token) = log_table("log-dispatch", Rights::WRITE, sink.clone());
    let mut component = instantiate(LOG_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace, LOG_COMPONENT);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![
                CanonicalValue::Resource(token),
                log_event("component", "hello")
            ],
        ),
        Ok(CanonicalValue::Result(Ok(None))),
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        sink.last.lock().unwrap().as_ref(),
        Some(&(LogLevel::Info, "hello".to_owned())),
    );
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(token), log_event("", "invalid")],
        ),
        Ok(error_case(1)),
    );

    let denied = Arc::new(RecordingLog {
        calls: AtomicUsize::new(0),
        fail: false,
        last: Mutex::new(None),
    });
    let (cspace, mut table, token) = log_table("log-denied", Rights::WRITE, denied.clone());
    cspace.lock().revoke_all();
    let mut component = instantiate(LOG_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace, LOG_COMPONENT);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![
                CanonicalValue::Resource(token),
                log_event("component", "denied")
            ],
        ),
        Ok(error_case(0)),
    );
    assert_eq!(denied.calls.load(Ordering::SeqCst), 0);

    let failed = Arc::new(RecordingLog {
        calls: AtomicUsize::new(0),
        fail: true,
        last: Mutex::new(None),
    });
    let (cspace, mut table, token) = log_table("log-failed", Rights::WRITE, failed);
    let mut component = instantiate(LOG_COMPONENT);
    let mut dispatcher = new_dispatcher(cspace, LOG_COMPONENT);
    assert_eq!(
        invoke(
            &mut component,
            &mut table,
            &mut dispatcher,
            "run",
            vec![
                CanonicalValue::Resource(token),
                log_event("component", "failed")
            ],
        ),
        Ok(error_case(2)),
    );
}
