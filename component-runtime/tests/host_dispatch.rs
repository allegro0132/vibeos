use vibeos_component_format::{TrapCode, PROFILE_1_LIMITS};
use vibeos_component_runtime::{
    decode::inspect_component,
    host::{HostDispatcher, HostError, HostRequest, HostResponse},
    resource::{ResourceTable, ResourceTypeId},
    sync::{SynchronousComponent, TypedPoll},
    value::CanonicalValue,
    HostImportInfo,
};
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

const HOST_CLOCK_COMPONENT: &str = include_str!("fixtures/host-clock.component.wat");
const HOST_CLOCK_TRANSITIVE_COMPONENT: &str =
    include_str!("fixtures/host-clock-transitive.component.wat");
const HOST_PAIR_COMPONENT: &str = include_str!("fixtures/host-pair.component.wat");
const CLOCK: ResourceTypeId = ResourceTypeId(1);

struct ClockDispatcher {
    expected_authority: u32,
    calls: u32,
    observed_authority: Option<u32>,
    value: u64,
    work: u64,
}

impl HostDispatcher<u32> for ClockDispatcher {
    fn required_work(
        &self,
        _import: &HostImportInfo,
        _arguments: &[CanonicalValue],
    ) -> Result<u64, HostError> {
        Ok(self.work)
    }

    fn dispatch(&mut self, request: HostRequest<'_, u32>) -> Result<HostResponse, HostError> {
        assert_eq!(request.import().interface, "vibe:clock/monotonic@1.0.0");
        assert_eq!(request.import().function, "now");
        let authority = request.with_borrow_argument(0, |authority| *authority)?;
        if authority != self.expected_authority {
            return Err(HostError::Denied);
        }
        self.calls += 1;
        self.observed_authority = Some(authority);
        HostResponse::one(CanonicalValue::U64(self.value), self.work)
    }
}

struct PairDispatcher {
    calls: u32,
}

impl HostDispatcher<()> for PairDispatcher {
    fn required_work(
        &self,
        _import: &HostImportInfo,
        _arguments: &[CanonicalValue],
    ) -> Result<u64, HostError> {
        Ok(5)
    }

    fn dispatch(&mut self, request: HostRequest<'_, ()>) -> Result<HostResponse, HostError> {
        assert_eq!(request.import().interface, "vibe:test/pair@1.0.0");
        assert_eq!(request.import().function, "get");
        assert!(request.arguments().is_empty());
        self.calls += 1;
        HostResponse::one(
            CanonicalValue::Tuple(vec![CanonicalValue::U32(11), CanonicalValue::U32(22)]),
            5,
        )
    }
}

#[derive(Clone, Copy)]
enum FailurePoint {
    RequiredWork,
    Dispatch,
}

struct FailingDispatcher {
    error: HostError,
    point: FailurePoint,
    calls: u32,
}

impl HostDispatcher<u32> for FailingDispatcher {
    fn required_work(
        &self,
        _import: &HostImportInfo,
        _arguments: &[CanonicalValue],
    ) -> Result<u64, HostError> {
        match self.point {
            FailurePoint::RequiredWork => Err(self.error),
            FailurePoint::Dispatch => Ok(1),
        }
    }

    fn dispatch(&mut self, _request: HostRequest<'_, u32>) -> Result<HostResponse, HostError> {
        self.calls += 1;
        Err(self.error)
    }
}

fn instantiate() -> SynchronousComponent {
    let bytes = wat::parse_str(HOST_CLOCK_COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    SynchronousComponent::instantiate(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap()
}

#[test]
fn transform_host_call_lifts_borrow_dispatches_charges_and_resumes() {
    let mut component = instantiate();
    let mut resources = ResourceTable::new(300, 4).unwrap();
    let clock = resources.insert_owned(CLOCK, 0xfeed_beef).unwrap();
    let mut dispatcher = ClockDispatcher {
        expected_authority: 0xfeed_beef,
        calls: 0,
        observed_authority: None,
        value: 44,
        work: 17,
    };

    let mut call = component
        .start_typed_call_with_host(
            &mut resources,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(clock)],
            10_000,
            100,
        )
        .unwrap();
    let initial_work = call.metrics().consumed_work;
    let mut result = None;
    for _ in 0..100 {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(operation) => {
                panic!("synchronous clock unexpectedly suspended at {operation:?}")
            }
            TypedPoll::Ready(value) => {
                result = Some(value);
                break;
            }
            TypedPoll::HostFailed(error) => panic!("clock host failed: {error:?}"),
            TypedPoll::Trapped(trap) => panic!("clock call trapped: {trap:?}"),
        }
    }
    assert_eq!(result, Some(CanonicalValue::U64(44)));
    assert!(call.metrics().consumed_work >= initial_work + 17);
    drop(call);
    assert_eq!(dispatcher.calls, 1);
    assert_eq!(dispatcher.observed_authority, Some(0xfeed_beef));
    assert!(resources.contains(clock, CLOCK).is_ok());
}

#[test]
fn prior_instance_host_wrapper_resumes_the_outer_consumer() {
    let bytes = wat::parse_str(HOST_CLOCK_TRANSITIVE_COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let mut component = SynchronousComponent::instantiate(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap();
    let mut resources = ResourceTable::new(304, 4).unwrap();
    let clock = resources.insert_owned(CLOCK, 0x1234).unwrap();
    let mut dispatcher = ClockDispatcher {
        expected_authority: 0x1234,
        calls: 0,
        observed_authority: None,
        value: 91,
        work: 11,
    };
    let mut call = component
        .start_typed_call_with_host(
            &mut resources,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(clock)],
            10_000,
            100,
        )
        .unwrap();
    let result = loop {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(operation) => {
                panic!("transitive clock unexpectedly suspended at {operation:?}")
            }
            TypedPoll::Ready(value) => break value,
            TypedPoll::HostFailed(error) => {
                panic!("transitive host call failed: {error:?}")
            }
            TypedPoll::Trapped(trap) => panic!("transitive host call trapped: {trap:?}"),
        }
    };
    assert_eq!(result, CanonicalValue::U64(91));
    drop(call);
    assert_eq!(dispatcher.calls, 1);
    assert_eq!(dispatcher.observed_authority, Some(0x1234));
    assert!(resources.contains(clock, CLOCK).is_ok());
}

#[test]
fn absent_dispatcher_and_oversized_host_work_fail_closed() {
    let mut component = instantiate();
    let mut resources = ResourceTable::new(301, 4).unwrap();
    let clock = resources.insert_owned(CLOCK, 7).unwrap();
    let mut call = component
        .start_typed_call(
            &mut resources,
            "run",
            vec![CanonicalValue::Resource(clock)],
            10_000,
            100,
        )
        .unwrap();
    let trap = loop {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(operation) => {
                panic!("hostless call unexpectedly suspended at {operation:?}")
            }
            TypedPoll::Trapped(trap) => break trap,
            TypedPoll::HostFailed(error) => panic!("hostless call failed: {error:?}"),
            TypedPoll::Ready(value) => panic!("hostless call returned {value:?}"),
        }
    };
    assert_eq!(trap, TrapCode::Validation);
    drop(call);
    assert!(component.is_poisoned());

    let mut component = instantiate();
    let mut resources = ResourceTable::new(302, 4).unwrap();
    let clock = resources.insert_owned(CLOCK, 9).unwrap();
    let mut dispatcher = ClockDispatcher {
        expected_authority: 9,
        calls: 0,
        observed_authority: None,
        value: 1,
        work: PROFILE_1_LIMITS.total_fuel,
    };
    let mut call = component
        .start_typed_call_with_host(
            &mut resources,
            &mut dispatcher,
            "run",
            vec![CanonicalValue::Resource(clock)],
            PROFILE_1_LIMITS.total_fuel,
            PROFILE_1_LIMITS.poll_quantum,
        )
        .unwrap();
    let trap = loop {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(operation) => {
                panic!("over-budget call unexpectedly suspended at {operation:?}")
            }
            TypedPoll::Trapped(trap) => break trap,
            TypedPoll::HostFailed(error) => panic!("over-budget host call failed: {error:?}"),
            TypedPoll::Ready(value) => panic!("over-budget host call returned {value:?}"),
        }
    };
    assert_eq!(trap, TrapCode::FuelExhausted);
    drop(call);
    assert_eq!(dispatcher.calls, 0);
}

#[test]
fn indirect_host_result_uses_the_callers_retptr_in_its_bound_memory() {
    let bytes = wat::parse_str(HOST_PAIR_COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let mut component = SynchronousComponent::instantiate(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap();
    let mut resources = ResourceTable::new(303, 1).unwrap();
    let mut dispatcher = PairDispatcher { calls: 0 };
    let mut call = component
        .start_typed_call_with_host(
            &mut resources,
            &mut dispatcher,
            "run",
            Vec::new(),
            10_000,
            100,
        )
        .unwrap();
    let result = loop {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(operation) => {
                panic!("pair call unexpectedly suspended at {operation:?}")
            }
            TypedPoll::Ready(value) => break value,
            TypedPoll::HostFailed(error) => panic!("indirect host result failed: {error:?}"),
            TypedPoll::Trapped(trap) => panic!("indirect host result trapped: {trap:?}"),
        }
    };
    assert_eq!(result, CanonicalValue::U32(7));
    drop(call);
    assert_eq!(dispatcher.calls, 1);
}

#[test]
fn result_lowering_budget_is_reserved_before_dispatch() {
    let bytes = wat::parse_str(HOST_PAIR_COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let mut component = SynchronousComponent::instantiate(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap();
    let mut resources = ResourceTable::new(304, 1).unwrap();
    let mut dispatcher = PairDispatcher { calls: 0 };
    let mut call = component
        .start_typed_call_with_host(&mut resources, &mut dispatcher, "run", Vec::new(), 12, 12)
        .unwrap();
    let trap = loop {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(operation) => {
                panic!("under-budget call unexpectedly suspended at {operation:?}")
            }
            TypedPoll::Trapped(trap) => break trap,
            TypedPoll::HostFailed(error) => {
                panic!("under-budget pair call failed: {error:?}")
            }
            TypedPoll::Ready(value) => panic!("under-budget pair call returned {value:?}"),
        }
    };
    assert_eq!(trap, TrapCode::FuelExhausted);
    drop(call);
    assert_eq!(dispatcher.calls, 0);
}

#[test]
fn every_host_boundary_failure_remains_typed_at_the_supervisor_boundary() {
    const ERRORS: [HostError; 9] = [
        HostError::Denied,
        HostError::Unavailable,
        HostError::Exhausted,
        HostError::InvalidArgument,
        HostError::BackendFault,
        HostError::BudgetExceeded,
        HostError::Failed,
        HostError::Cancelled,
        HostError::InvalidState,
    ];

    for error in ERRORS {
        for point in [FailurePoint::RequiredWork, FailurePoint::Dispatch] {
            let mut component = instantiate();
            let mut resources = ResourceTable::new(400 + u64::from(error.code()), 4).unwrap();
            let clock = resources.insert_owned(CLOCK, 77).unwrap();
            let mut dispatcher = FailingDispatcher {
                error,
                point,
                calls: 0,
            };
            let mut call = component
                .start_typed_call_with_host(
                    &mut resources,
                    &mut dispatcher,
                    "run",
                    vec![CanonicalValue::Resource(clock)],
                    10_000,
                    100,
                )
                .unwrap();
            let observed = loop {
                match call.poll() {
                    TypedPoll::Pending(_) => {}
                    TypedPoll::HostPending(operation) => {
                        panic!("failing call unexpectedly suspended at {operation:?}")
                    }
                    TypedPoll::HostFailed(observed) => break observed,
                    TypedPoll::Ready(value) => panic!("failing host returned {value:?}"),
                    TypedPoll::Trapped(trap) => panic!("host failure collapsed to {trap:?}"),
                }
            };
            assert_eq!(observed, error);
            drop(call);
            assert!(component.is_poisoned());
            assert!(resources.contains(clock, CLOCK).is_ok());
            assert_eq!(
                dispatcher.calls,
                u32::from(matches!(point, FailurePoint::Dispatch))
            );
        }
    }
}

#[test]
fn owning_host_imports_are_not_admitted_before_consumption_is_explicit() {
    let source = HOST_CLOCK_COMPONENT.replace(
        "(type $borrow-clock (borrow 0))",
        "(type $borrow-clock (own 0))",
    );
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    assert!(matches!(
        SynchronousComponent::instantiate(
            &plan,
            &ProfileEngine::new(),
            OwnerAllocationReservation::profile_default(),
        ),
        Err(vibeos_component_runtime::sync::SyncError::InvalidWiring)
    ));
}
