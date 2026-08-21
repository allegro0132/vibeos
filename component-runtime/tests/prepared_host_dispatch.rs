use core::sync::atomic::{AtomicUsize, Ordering};

use vibeos_component_format::TrapCode;
use vibeos_component_runtime::{
    decode::inspect_component,
    host::{
        HostDispatch, HostDispatcher, HostError, HostOperationToken, HostPayloadAllocation,
        HostPrepared, HostRequest, HostResponse, HostWakeToken,
    },
    resource::{ResourceTable, ResourceTypeId},
    sync::{SynchronousComponent, TypedCall, TypedPoll},
    value::{CanonicalValue, ResourceOwnership, ValueType},
    HostImportInfo,
};
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

const HOST_STREAM_COMPONENT: &str = include_str!("fixtures/host-stream.component.wat");
const RUN: &str = "run";
const MAX_CHUNK: u32 = 1024;
fn record_wake(words: [usize; 4]) {
    assert_eq!(&words[1..], &[22, 33, 44]);
    // The test leaks this one AtomicUsize so the copy-only callback envelope
    // remains valid independently of call/drop timing.
    let counter = unsafe { &*(words[0] as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::SeqCst);
}

fn ignore_wake(_words: [usize; 4]) {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endpoint {
    Reader(u32),
    Writer(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadBehavior {
    PendingPrepared,
    FreshPendingThenPrepared,
    ImmediatePrepared,
    RegressedPrepared,
    RegressedPending,
    OversizedPlan,
    WrongAlignment,
    MismatchedResponse,
    CommitUnavailable,
}

struct StreamDispatcher {
    behavior: ReadBehavior,
    payload: Vec<u8>,
    response: Option<HostResponse>,
    active: Option<HostOperationToken>,
    starts: u32,
    registrations: u32,
    resumes: u32,
    commits: u32,
    cancels: u32,
    writes: u32,
    closes: u32,
}

impl StreamDispatcher {
    fn new(behavior: ReadBehavior, payload: &[u8]) -> Self {
        let published = if behavior == ReadBehavior::MismatchedResponse {
            &payload[..payload.len() - 1]
        } else {
            payload
        };
        let values = vec![CanonicalValue::List(
            published.iter().copied().map(CanonicalValue::U8).collect(),
        )];
        Self {
            behavior,
            payload: payload.to_vec(),
            response: Some(HostResponse::new(values, 7).unwrap()),
            active: None,
            starts: 0,
            registrations: 0,
            resumes: 0,
            commits: 0,
            cancels: 0,
            writes: 0,
            closes: 0,
        }
    }

    fn pending_token() -> HostOperationToken {
        HostOperationToken::from_generation(10).unwrap()
    }

    fn prepared_token(&self) -> HostOperationToken {
        HostOperationToken::from_generation(match self.behavior {
            ReadBehavior::RegressedPrepared => 9,
            ReadBehavior::FreshPendingThenPrepared => 12,
            _ => 11,
        })
        .unwrap()
    }

    fn plan(&self, operation: HostOperationToken) -> HostPrepared {
        let (size, alignment) = match self.behavior {
            ReadBehavior::OversizedPlan => (MAX_CHUNK + 1, 1),
            ReadBehavior::WrongAlignment => (self.payload.len() as u32, 2),
            _ => (self.payload.len() as u32, 1),
        };
        HostPrepared::new(operation, vec![HostPayloadAllocation { size, alignment }]).unwrap()
    }

    fn check_endpoint(
        request: &HostRequest<'_, Endpoint>,
        expected: Endpoint,
    ) -> Result<(), HostError> {
        let endpoint = request.with_borrow_argument(0, |endpoint| *endpoint)?;
        (endpoint == expected)
            .then_some(())
            .ok_or(HostError::Denied)
    }
}

impl HostDispatcher<Endpoint> for StreamDispatcher {
    fn required_work(
        &self,
        import: &HostImportInfo,
        _arguments: &[CanonicalValue],
    ) -> Result<u64, HostError> {
        Ok(match import.function.as_str() {
            "read" => 7,
            "write" => 5,
            "close-reader" | "close-writer" => 3,
            _ => return Err(HostError::Denied),
        })
    }

    fn result_allocations(
        &self,
        import: &HostImportInfo,
        _arguments: &[CanonicalValue],
    ) -> Result<Vec<HostPayloadAllocation>, HostError> {
        Ok(if import.function == "read" {
            vec![HostPayloadAllocation {
                size: MAX_CHUNK,
                alignment: 1,
            }]
        } else {
            Vec::new()
        })
    }

    fn start(&mut self, request: HostRequest<'_, Endpoint>) -> Result<HostDispatch, HostError> {
        assert_eq!(request.import().interface, "vibe:stream/streams@1.0.0");
        self.starts += 1;
        match request.import().function.as_str() {
            "read" => {
                Self::check_endpoint(&request, Endpoint::Reader(41))?;
                let operation = if self.behavior == ReadBehavior::ImmediatePrepared {
                    self.prepared_token()
                } else {
                    Self::pending_token()
                };
                self.active = Some(operation);
                if self.behavior == ReadBehavior::ImmediatePrepared {
                    Ok(HostDispatch::Prepared(self.plan(operation)))
                } else {
                    Ok(HostDispatch::Pending(operation))
                }
            }
            "write" => {
                Self::check_endpoint(&request, Endpoint::Writer(42))?;
                let Some(CanonicalValue::List(bytes)) = request.arguments().get(1) else {
                    return Err(HostError::InvalidArgument);
                };
                let bytes: Vec<u8> = bytes
                    .iter()
                    .map(|byte| match byte {
                        CanonicalValue::U8(byte) => Ok(*byte),
                        _ => Err(HostError::InvalidArgument),
                    })
                    .collect::<Result<_, _>>()?;
                assert_eq!(bytes, self.payload);
                self.writes += 1;
                Ok(HostDispatch::Ready(HostResponse::unit(5)?))
            }
            "close-reader" => {
                Self::check_endpoint(&request, Endpoint::Reader(41))?;
                assert_eq!(request.arguments().get(1), Some(&CanonicalValue::Enum(0)));
                self.closes += 1;
                Ok(HostDispatch::Ready(HostResponse::unit(3)?))
            }
            "close-writer" => {
                Self::check_endpoint(&request, Endpoint::Writer(42))?;
                assert_eq!(request.arguments().get(1), Some(&CanonicalValue::Enum(0)));
                self.closes += 1;
                Ok(HostDispatch::Ready(HostResponse::unit(3)?))
            }
            _ => Err(HostError::Denied),
        }
    }

    fn register_wake(
        &mut self,
        operation: HostOperationToken,
        wake: HostWakeToken,
    ) -> Result<(), HostError> {
        if self.active != Some(operation) {
            return Err(HostError::InvalidArgument);
        }
        self.registrations += 1;
        wake.wake();
        Ok(())
    }

    fn resume(
        &mut self,
        operation: HostOperationToken,
        request: HostRequest<'_, Endpoint>,
    ) -> Result<HostDispatch, HostError> {
        let exact_first = self.active == Some(operation) && operation == Self::pending_token();
        let exact_second = self.behavior == ReadBehavior::FreshPendingThenPrepared
            && self.active == Some(operation)
            && operation == HostOperationToken::from_generation(11).unwrap();
        if !exact_first && !exact_second {
            return Err(HostError::InvalidArgument);
        }
        Self::check_endpoint(&request, Endpoint::Reader(41))?;
        self.resumes += 1;
        if self.behavior == ReadBehavior::FreshPendingThenPrepared && self.resumes == 1 {
            let pending = HostOperationToken::from_generation(11).unwrap();
            self.active = Some(pending);
            return Ok(HostDispatch::Pending(pending));
        }
        if self.behavior == ReadBehavior::RegressedPending {
            let pending = HostOperationToken::from_generation(9).unwrap();
            self.active = Some(pending);
            return Ok(HostDispatch::Pending(pending));
        }
        let prepared = self.prepared_token();
        self.active = Some(prepared);
        Ok(HostDispatch::Prepared(self.plan(prepared)))
    }

    fn commit_prepared(
        &mut self,
        operation: HostOperationToken,
        request: HostRequest<'_, Endpoint>,
    ) -> Result<HostResponse, HostError> {
        if self.active != Some(operation) {
            return Err(HostError::InvalidArgument);
        }
        Self::check_endpoint(&request, Endpoint::Reader(41))?;
        self.commits += 1;
        if self.behavior == ReadBehavior::CommitUnavailable {
            // A pre-publication failure preserves the SYSTEM reservation so
            // the runtime can cancel this exact token before rolling back the
            // now-known guest allocation.
            return Err(HostError::Unavailable);
        }
        self.active = None;
        self.response.take().ok_or(HostError::BackendFault)
    }

    fn cancel(&mut self, operation: HostOperationToken) -> Result<(), HostError> {
        if self.active != Some(operation) {
            return Err(HostError::InvalidArgument);
        }
        self.active = None;
        self.cancels += 1;
        Ok(())
    }
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

fn allocator_variant(replacement: &str) -> String {
    const IN_PLACE: &str = r#"        i32.const 24
        local.get $new-size
        i32.store
        local.get $old-pointer
        return"#;
    let source = HOST_STREAM_COMPONENT.replace(IN_PLACE, replacement);
    assert_ne!(source, HOST_STREAM_COMPONENT, "allocator marker changed");
    source
}

fn resource_types(component: &SynchronousComponent) -> (ResourceTypeId, ResourceTypeId) {
    let function = component.function_type(RUN).unwrap();
    let resource = |index: usize| match function.parameters[index].value {
        ValueType::Resource {
            resource_type,
            ownership: ResourceOwnership::Borrow,
        } => resource_type,
        ref other => panic!("unexpected stream endpoint type: {other:?}"),
    };
    (resource(0), resource(1))
}

fn start<'a>(
    component: &'a mut SynchronousComponent,
    resources: &'a mut ResourceTable<Endpoint>,
    dispatcher: &'a mut StreamDispatcher,
) -> TypedCall<'a, Endpoint> {
    let (reader_type, writer_type) = resource_types(component);
    let reader = resources
        .insert_owned(reader_type, Endpoint::Reader(41))
        .unwrap();
    let writer = resources
        .insert_owned(writer_type, Endpoint::Writer(42))
        .unwrap();
    component
        .start_typed_call_with_host(
            resources,
            dispatcher,
            RUN,
            vec![
                CanonicalValue::Resource(reader),
                CanonicalValue::Resource(writer),
            ],
            1_000_000,
            1_000,
        )
        .unwrap()
}

fn read_u32(component: &SynchronousComponent, offset: u32) -> u32 {
    let mut bytes = [0; 4];
    component
        .read_export_memory(RUN, offset, &mut bytes)
        .unwrap();
    u32::from_le_bytes(bytes)
}

fn poll_to_host_pending(call: &mut TypedCall<'_, Endpoint>) -> HostOperationToken {
    for _ in 0..100 {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(operation) => return operation,
            other => panic!("expected host suspension, observed {other:?}"),
        }
    }
    panic!("host call did not suspend")
}

fn drive_ready(call: &mut TypedCall<'_, Endpoint>) -> CanonicalValue {
    for _ in 0..500 {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::Ready(value) => return value,
            TypedPoll::HostPending(operation) => {
                panic!("unexpected second host suspension at {operation:?}")
            }
            TypedPoll::HostFailed(error) => panic!("host failed: {error:?}"),
            TypedPoll::Trapped(trap) => panic!("component trapped: {trap:?}"),
        }
    }
    panic!("component did not terminate")
}

fn drive_trap(call: &mut TypedCall<'_, Endpoint>) -> TrapCode {
    for _ in 0..500 {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::Trapped(trap) => return trap,
            TypedPoll::HostPending(operation) => {
                panic!("unexpected host suspension at {operation:?}")
            }
            TypedPoll::HostFailed(error) => panic!("host failed: {error:?}"),
            TypedPoll::Ready(value) => panic!("component returned {value:?}"),
        }
    }
    panic!("component did not trap")
}

fn drive_host_failure(call: &mut TypedCall<'_, Endpoint>) -> HostError {
    for _ in 0..500 {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostFailed(error) => return error,
            TypedPoll::HostPending(operation) => {
                panic!("unexpected host suspension at {operation:?}")
            }
            TypedPoll::Trapped(trap) => panic!("component trapped: {trap:?}"),
            TypedPoll::Ready(value) => panic!("component returned {value:?}"),
        }
    }
    panic!("component did not publish its host failure")
}

#[test]
fn pending_prepared_exact_shrink_commits_once_and_frees_exact_size() {
    let wake_count = Box::leak(Box::new(AtomicUsize::new(0)));
    let wake_words = [wake_count as *const AtomicUsize as usize, 22, 33, 44];
    let mut component = instantiate(HOST_STREAM_COMPONENT);
    let mut resources = ResourceTable::new(900, 8).unwrap();
    let mut dispatcher = StreamDispatcher::new(ReadBehavior::PendingPrepared, b"hello");
    let mut call = start(&mut component, &mut resources, &mut dispatcher);
    let operation = poll_to_host_pending(&mut call);

    for _ in 0..3 {
        assert_eq!(call.poll(), TypedPoll::HostPending(operation));
    }
    assert_eq!(
        call.register_host_wake(operation, HostWakeToken::new(wake_words, record_wake),),
        Ok(())
    );
    assert_eq!(wake_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        call.register_host_wake(operation, HostWakeToken::new(wake_words, record_wake),),
        Err(HostError::InvalidArgument)
    );
    call.resume_host(operation).unwrap();
    assert_eq!(drive_ready(&mut call), CanonicalValue::Tuple(Vec::new()));
    drop(call);

    assert_eq!((dispatcher.resumes, dispatcher.commits), (1, 1));
    assert_eq!((dispatcher.writes, dispatcher.closes), (1, 2));
    assert_eq!(dispatcher.cancels, 0);
    assert_eq!(read_u32(&component, 4), 1, "one max allocation");
    assert_eq!(read_u32(&component, 8), 1, "one exact shrink");
    assert_eq!(read_u32(&component, 12), 1, "guest freed the exact list");
    assert_eq!(read_u32(&component, 16), 0, "allocator saw no size lie");
    assert_eq!(read_u32(&component, 28), 5);
    assert_eq!(read_u32(&component, 32), 0);
    assert!(!component.is_poisoned());
}

#[test]
fn wrong_token_plan_shape_and_regression_cancel_before_commit() {
    for behavior in [
        ReadBehavior::RegressedPrepared,
        ReadBehavior::RegressedPending,
        ReadBehavior::OversizedPlan,
        ReadBehavior::WrongAlignment,
    ] {
        let mut component = instantiate(HOST_STREAM_COMPONENT);
        let mut resources = ResourceTable::new(901 + behavior as u64, 8).unwrap();
        let mut dispatcher = StreamDispatcher::new(behavior, b"shape");
        let mut call = start(&mut component, &mut resources, &mut dispatcher);
        let operation = poll_to_host_pending(&mut call);
        let wrong = HostOperationToken::from_generation(999).unwrap();
        assert_eq!(
            call.register_host_wake(wrong, HostWakeToken::new([0; 4], ignore_wake),),
            Err(HostError::InvalidArgument)
        );
        call.register_host_wake(operation, HostWakeToken::new([0; 4], ignore_wake))
            .unwrap();
        assert_eq!(call.resume_host(wrong), Err(HostError::InvalidArgument));
        call.resume_host(operation).unwrap();
        assert_eq!(drive_trap(&mut call), TrapCode::Validation);
        drop(call);
        assert_eq!(dispatcher.commits, 0);
        assert_eq!(dispatcher.cancels, 1);
        assert!(component.is_poisoned());
    }
}

#[test]
fn response_length_mismatch_hits_strict_replay_after_exact_shrink() {
    let mut component = instantiate(HOST_STREAM_COMPONENT);
    let mut resources = ResourceTable::new(910, 8).unwrap();
    let mut dispatcher = StreamDispatcher::new(ReadBehavior::MismatchedResponse, b"length");
    let mut call = start(&mut component, &mut resources, &mut dispatcher);
    let operation = poll_to_host_pending(&mut call);
    call.register_host_wake(operation, HostWakeToken::new([0; 4], ignore_wake))
        .unwrap();
    call.resume_host(operation).unwrap();
    assert_eq!(drive_trap(&mut call), TrapCode::CanonicalAbi);
    drop(call);
    assert_eq!(dispatcher.commits, 1, "commit is the sole backend effect");
    assert_eq!(dispatcher.cancels, 0, "committed token cannot be cancelled");
    assert_eq!(read_u32(&component, 8), 1);
    assert_eq!(read_u32(&component, 12), 1, "known exact span rolled back");
    assert!(component.is_poisoned());
}

#[test]
fn prepublication_commit_error_cancels_exact_token_before_known_span_rollback() {
    let mut component = instantiate(HOST_STREAM_COMPONENT);
    let mut resources = ResourceTable::new(911, 8).unwrap();
    let mut dispatcher = StreamDispatcher::new(ReadBehavior::CommitUnavailable, b"retry");
    let mut call = start(&mut component, &mut resources, &mut dispatcher);
    let operation = poll_to_host_pending(&mut call);
    call.register_host_wake(operation, HostWakeToken::new([0; 4], ignore_wake))
        .unwrap();
    call.resume_host(operation).unwrap();
    assert_eq!(drive_host_failure(&mut call), HostError::Unavailable);
    drop(call);

    assert_eq!(dispatcher.commits, 1, "one commit attempt");
    assert_eq!(dispatcher.cancels, 1, "prepared reservation detached once");
    assert_eq!(read_u32(&component, 8), 1, "exact shrink completed");
    assert_eq!(
        read_u32(&component, 12),
        1,
        "known exact guest span rolled back"
    );
    assert_eq!(read_u32(&component, 20), 0, "allocator has no live span");
    assert_eq!(read_u32(&component, 24), 0, "allocator size ledger cleared");
    assert!(component.is_poisoned());
}

#[test]
fn cancellation_and_drop_detach_the_exact_wait_once_without_retry() {
    for drop_only in [false, true] {
        let mut component = instantiate(HOST_STREAM_COMPONENT);
        let mut resources = ResourceTable::new(920 + u64::from(drop_only), 8).unwrap();
        let mut dispatcher = StreamDispatcher::new(ReadBehavior::PendingPrepared, b"cancel");
        let mut call = start(&mut component, &mut resources, &mut dispatcher);
        let _operation = poll_to_host_pending(&mut call);
        if drop_only {
            drop(call);
        } else {
            call.cancel();
            assert_eq!(call.poll(), TypedPoll::Trapped(TrapCode::Cancelled));
            drop(call);
        }
        assert_eq!(dispatcher.cancels, 1);
        assert_eq!((dispatcher.resumes, dispatcher.commits), (0, 0));
        assert_eq!(read_u32(&component, 12), 0, "ambiguous call was not freed");
        assert!(component.is_poisoned());
    }
}

#[test]
fn immediate_prepared_uses_the_same_exact_commit_path() {
    let mut component = instantiate(HOST_STREAM_COMPONENT);
    let mut resources = ResourceTable::new(930, 8).unwrap();
    let mut dispatcher = StreamDispatcher::new(ReadBehavior::ImmediatePrepared, b"direct");
    let mut call = start(&mut component, &mut resources, &mut dispatcher);
    assert_eq!(drive_ready(&mut call), CanonicalValue::Tuple(Vec::new()));
    drop(call);
    assert_eq!((dispatcher.registrations, dispatcher.resumes), (0, 0));
    assert_eq!(dispatcher.commits, 1);
    assert_eq!(read_u32(&component, 8), 1);
    assert_eq!(read_u32(&component, 16), 0);
}

#[test]
fn moved_exact_shrink_must_be_disjoint_and_interior_pointer_fails_closed() {
    let moved = allocator_variant(
        r#"        i32.const 20
        i32.const 8192
        i32.store
        i32.const 24
        local.get $new-size
        i32.store
        i32.const 8192
        return"#,
    );
    let mut component = instantiate(&moved);
    let mut resources = ResourceTable::new(940, 8).unwrap();
    let mut dispatcher = StreamDispatcher::new(ReadBehavior::ImmediatePrepared, b"move");
    let mut call = start(&mut component, &mut resources, &mut dispatcher);
    assert_eq!(drive_ready(&mut call), CanonicalValue::Tuple(Vec::new()));
    drop(call);
    assert_eq!(dispatcher.commits, 1);
    assert_eq!(read_u32(&component, 16), 0);
    assert_eq!(read_u32(&component, 12), 1);

    let interior = allocator_variant(
        r#"        i32.const 24
        local.get $new-size
        i32.store
        local.get $old-pointer
        i32.const 1
        i32.add
        return"#,
    );
    let mut component = instantiate(&interior);
    let mut resources = ResourceTable::new(941, 8).unwrap();
    let mut dispatcher = StreamDispatcher::new(ReadBehavior::ImmediatePrepared, b"inside");
    let mut call = start(&mut component, &mut resources, &mut dispatcher);
    assert_eq!(drive_trap(&mut call), TrapCode::CanonicalAbi);
    drop(call);
    assert_eq!(dispatcher.commits, 0);
    assert_eq!(
        dispatcher.cancels, 1,
        "prepared token cancelled exactly once"
    );
    assert_eq!(
        read_u32(&component, 12),
        0,
        "ambiguous allocation not freed"
    );
    assert!(component.is_poisoned());
}

#[test]
fn shrink_trap_cancels_prepared_once_and_never_runs_rollback_free() {
    let trapping = allocator_variant("        unreachable");
    let mut component = instantiate(&trapping);
    let mut resources = ResourceTable::new(950, 8).unwrap();
    let mut dispatcher = StreamDispatcher::new(ReadBehavior::ImmediatePrepared, b"trap");
    let mut call = start(&mut component, &mut resources, &mut dispatcher);
    assert_eq!(drive_trap(&mut call), TrapCode::Unreachable);
    drop(call);
    assert_eq!(dispatcher.commits, 0);
    assert_eq!(dispatcher.cancels, 1);
    assert_eq!(read_u32(&component, 12), 0);
    assert!(component.is_poisoned());
}

#[test]
fn operation_and_prepared_envelopes_reject_zero_or_empty_shapes() {
    assert!(HostOperationToken::from_generation(0).is_none());
    let operation = HostOperationToken::from_generation(1).unwrap();
    assert!(matches!(
        HostPrepared::new(operation, Vec::new()),
        Err(HostError::InvalidArgument)
    ));
    assert!(matches!(
        HostPrepared::new(
            operation,
            vec![HostPayloadAllocation {
                size: 1,
                alignment: 3,
            }],
        ),
        Err(HostError::InvalidArgument)
    ));
    assert_eq!(
        core::mem::size_of::<HostWakeToken>(),
        core::mem::size_of::<[usize; 4]>() + core::mem::size_of::<fn([usize; 4])>()
    );
}

#[test]
fn a_second_pending_generation_requires_a_second_exact_wake_and_resume() {
    let mut component = instantiate(HOST_STREAM_COMPONENT);
    let mut resources = ResourceTable::new(960, 8).unwrap();
    let mut dispatcher = StreamDispatcher::new(ReadBehavior::FreshPendingThenPrepared, b"twice");
    let mut call = start(&mut component, &mut resources, &mut dispatcher);
    let first = poll_to_host_pending(&mut call);
    call.register_host_wake(first, HostWakeToken::new([0; 4], ignore_wake))
        .unwrap();
    call.resume_host(first).unwrap();
    let second = match call.poll() {
        TypedPoll::HostPending(operation) => operation,
        other => panic!("first resume did not return a new wait: {other:?}"),
    };
    assert_ne!(first, second);
    assert_eq!(
        call.register_host_wake(first, HostWakeToken::new([0; 4], ignore_wake)),
        Err(HostError::InvalidArgument)
    );
    assert_eq!(call.poll(), TypedPoll::HostPending(second));
    call.register_host_wake(second, HostWakeToken::new([0; 4], ignore_wake))
        .unwrap();
    call.resume_host(second).unwrap();
    assert_eq!(drive_ready(&mut call), CanonicalValue::Tuple(Vec::new()));
    drop(call);
    assert_eq!((dispatcher.registrations, dispatcher.resumes), (2, 2));
    assert_eq!(dispatcher.commits, 1);
}

#[test]
fn cancelling_prepared_before_shrink_never_commits_or_frees() {
    let mut component = instantiate(HOST_STREAM_COMPONENT);
    let mut resources = ResourceTable::new(970, 8).unwrap();
    let mut dispatcher = StreamDispatcher::new(ReadBehavior::PendingPrepared, b"prepared");
    let mut call = start(&mut component, &mut resources, &mut dispatcher);
    let operation = poll_to_host_pending(&mut call);
    call.register_host_wake(operation, HostWakeToken::new([0; 4], ignore_wake))
        .unwrap();
    call.resume_host(operation).unwrap();
    assert!(matches!(call.poll(), TypedPoll::Pending(_)));
    call.cancel();
    assert_eq!(call.poll(), TypedPoll::Trapped(TrapCode::Cancelled));
    drop(call);
    assert_eq!((dispatcher.resumes, dispatcher.commits), (1, 0));
    assert_eq!(dispatcher.cancels, 1);
    assert_eq!(read_u32(&component, 8), 0, "shrink never started");
    assert_eq!(read_u32(&component, 12), 0, "ambiguous span never freed");
}
