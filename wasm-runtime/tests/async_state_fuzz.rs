//! Deterministic C5.7 fuzzing for suspended Core continuations.
//!
//! This is deliberately part of the ordinary test suite instead of a
//! sanitizer-only `cargo-fuzz` target. Every failure is reproducible from the
//! printed seed, step, and action, while the mandatory prefix proves that all
//! lifecycle transitions remain live even if a generated action is a no-op.

use vibeos_component_format::TrapCode;
use vibeos_wasm_runtime::{
    CoreComponentGroup, CoreHostCall, CoreHostImport, CoreModuleImport, CoreValue, CoreValueType,
    OwnerAllocationReservation, PollResult, ProfileEngine, ValidatedCore,
};

const TOTAL_FUEL: u64 = 10_000;
const POLL_QUANTUM: u64 = 1_000;
const STEPS: usize = 2_048;
const SEEDS: [u64; 5] = [
    1,
    0x0123_4567_89ab_cdef,
    0x9e37_79b9_7f4a_7c15,
    0xdead_beef_cafe_f00d,
    u64::MAX - 58,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallState {
    Idle,
    Started,
    Suspended,
    Resumed(i32),
    Cancelled,
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Start(usize),
    Poll(usize),
    ResumeCorrect(usize),
    ResumeWrongId(usize),
    ResumeWrongInstance(usize),
    Cancel(usize),
    Discard(usize),
    CancelAll,
    DiscardAll,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn action(&mut self) -> Action {
        let instance = (self.next() & 1) as usize;
        match self.next() % 9 {
            0 => Action::Start(instance),
            1 => Action::Poll(instance),
            2 => Action::ResumeCorrect(instance),
            3 => Action::ResumeWrongId(instance),
            4 => Action::ResumeWrongInstance(instance),
            5 => Action::Cancel(instance),
            6 => Action::Discard(instance),
            7 => Action::CancelAll,
            _ => Action::DiscardAll,
        }
    }
}

fn compile(engine: &ProfileEngine, source: &str) -> ValidatedCore {
    let bytes = wat::parse_str(source).expect("Core continuation fixture WAT");
    ValidatedCore::new_in(
        engine,
        &bytes,
        OwnerAllocationReservation::profile_default(),
    )
    .expect("Core continuation fixture validates")
}

fn build_group() -> CoreComponentGroup {
    let engine = ProfileEngine::new();
    let first = compile(
        &engine,
        r#"(module
              (import "host" "first" (func $host (result i32)))
              (func (export "run") (result i32) call $host))"#,
    );
    let second = compile(
        &engine,
        r#"(module
              (import "host" "nested" (func $host (result i32)))
              (func (export "run") (result i32) call $host))"#,
    );
    let results = [CoreValueType::I32];
    let mut group = CoreComponentGroup::new(&engine, 2).expect("bounded Core group");
    group
        .add_instance(
            &first,
            &[CoreModuleImport::Host(CoreHostImport {
                id: 91,
                module: "host",
                name: "first",
                params: &[],
                results: &results,
            })],
        )
        .expect("first suspended instance");
    group
        .add_instance(
            &second,
            &[CoreModuleImport::Host(CoreHostImport {
                id: 92,
                module: "host",
                name: "nested",
                params: &[],
                results: &results,
            })],
        )
        .expect("nested suspended instance");
    group.seal().expect("sealed Core group");
    group
}

fn host_id(instance: usize) -> u32 {
    [91, 92][instance]
}

fn result_value(instance: usize, step: usize) -> i32 {
    let step = i32::try_from(step).expect("bounded fuzz step");
    step.wrapping_mul(2).wrapping_add(instance as i32 + 1)
}

fn rejected_resume(state: CallState) -> Result<(), TrapCode> {
    if state == CallState::Cancelled {
        Err(TrapCode::Cancelled)
    } else {
        Err(TrapCode::Validation)
    }
}

fn assert_group_matches(
    group: &CoreComponentGroup,
    states: &[CallState; 2],
    seed: u64,
    step: usize,
    action: Action,
) {
    for (instance, expected) in states.iter().copied().enumerate() {
        assert_eq!(
            group.has_active_call(instance),
            expected != CallState::Idle,
            "seed={seed:#018x} step={step} action={action:?} instance={instance} state={expected:?}",
        );
        if expected != CallState::Idle {
            let metrics = group.call_metrics(instance).unwrap_or_else(|| {
                panic!(
                    "missing metrics: seed={seed:#018x} step={step} action={action:?} \
                     instance={instance} state={expected:?}"
                )
            });
            assert_eq!(
                metrics.consumed_fuel + metrics.remaining_fuel,
                TOTAL_FUEL,
                "seed={seed:#018x} step={step} action={action:?} instance={instance}",
            );
        }
    }
    assert_eq!(
        group.any_active_call(),
        states.iter().any(|state| *state != CallState::Idle),
        "seed={seed:#018x} step={step} action={action:?}",
    );
}

fn apply(
    group: &mut CoreComponentGroup,
    states: &mut [CallState; 2],
    action: Action,
    seed: u64,
    step: usize,
) {
    let context = || format!("seed={seed:#018x} step={step} action={action:?} states={states:?}");
    match action {
        Action::Start(instance) => {
            let result = group.start_call(instance, "run", &[], TOTAL_FUEL, POLL_QUANTUM);
            if states[instance] == CallState::Idle {
                result.unwrap_or_else(|error| panic!("{} error={error:?}", context()));
                states[instance] = CallState::Started;
            } else {
                assert_eq!(result, Err(TrapCode::Validation), "{}", context());
            }
        }
        Action::Poll(instance) => {
            let observed = group.poll_call(instance);
            match states[instance] {
                CallState::Idle => {
                    assert_eq!(
                        observed,
                        PollResult::Trapped(TrapCode::Validation),
                        "{}",
                        context()
                    );
                }
                CallState::Started => {
                    assert_eq!(
                        observed,
                        PollResult::HostCall(CoreHostCall {
                            origin_instance: instance,
                            id: host_id(instance),
                            arguments: vec![],
                        }),
                        "{}",
                        context(),
                    );
                    states[instance] = CallState::Suspended;
                }
                CallState::Suspended => {
                    assert_eq!(
                        observed,
                        PollResult::Trapped(TrapCode::Validation),
                        "{}",
                        context()
                    );
                    states[instance] = CallState::Idle;
                }
                CallState::Resumed(value) => {
                    assert_eq!(
                        observed,
                        PollResult::Ready(vec![CoreValue::I32(value)]),
                        "{}",
                        context(),
                    );
                    states[instance] = CallState::Idle;
                }
                CallState::Cancelled => {
                    assert_eq!(
                        observed,
                        PollResult::Trapped(TrapCode::Cancelled),
                        "{}",
                        context()
                    );
                    states[instance] = CallState::Idle;
                }
            }
        }
        Action::ResumeCorrect(instance) => {
            let value = result_value(instance, step);
            let result =
                group.resume_host_call(instance, host_id(instance), &[CoreValue::I32(value)]);
            if states[instance] == CallState::Suspended {
                result.unwrap_or_else(|error| panic!("{} error={error:?}", context()));
                states[instance] = CallState::Resumed(value);
            } else {
                assert_eq!(result, rejected_resume(states[instance]), "{}", context());
            }
        }
        Action::ResumeWrongId(instance) => {
            let result = group.resume_host_call(
                instance,
                host_id(instance) ^ 1,
                &[CoreValue::I32(result_value(instance, step))],
            );
            assert_eq!(result, rejected_resume(states[instance]), "{}", context());
        }
        Action::ResumeWrongInstance(instance) => {
            let peer = instance ^ 1;
            let result = group.resume_host_call(
                peer,
                host_id(instance),
                &[CoreValue::I32(result_value(instance, step))],
            );
            assert_eq!(result, rejected_resume(states[peer]), "{}", context());
        }
        Action::Cancel(instance) => {
            let result = group.cancel_call(instance);
            if states[instance] != CallState::Idle {
                result.unwrap_or_else(|error| panic!("{} error={error:?}", context()));
                states[instance] = CallState::Cancelled;
            } else {
                assert_eq!(result, Err(TrapCode::Validation), "{}", context());
            }
        }
        Action::Discard(instance) => {
            let result = group.discard_call(instance);
            if states[instance] != CallState::Idle {
                result.unwrap_or_else(|error| panic!("{} error={error:?}", context()));
                states[instance] = CallState::Idle;
            } else {
                assert_eq!(result, Err(TrapCode::Validation), "{}", context());
            }
        }
        Action::CancelAll => {
            group.cancel_all_calls();
            for state in &mut *states {
                if *state != CallState::Idle {
                    *state = CallState::Cancelled;
                }
            }
        }
        Action::DiscardAll => {
            group.discard_all_calls();
            *states = [CallState::Idle; 2];
        }
    }
    assert_group_matches(group, states, seed, step, action);
}

fn mandatory_prefix(group: &mut CoreComponentGroup, seed: u64) {
    let mut states = [CallState::Idle; 2];
    let actions = [
        Action::Start(0),
        Action::Poll(0),
        Action::Start(1),
        Action::Poll(1),
        Action::ResumeWrongId(0),
        Action::ResumeWrongInstance(0),
        Action::ResumeCorrect(1),
        Action::Poll(1),
        Action::ResumeCorrect(0),
        Action::Poll(0),
        Action::Start(0),
        Action::Poll(0),
        Action::Cancel(0),
        Action::Poll(0),
        Action::Start(1),
        Action::Poll(1),
        Action::Discard(1),
        Action::ResumeCorrect(1),
        Action::Start(0),
        Action::Poll(0),
        Action::Start(1),
        Action::Poll(1),
        Action::DiscardAll,
        Action::ResumeCorrect(0),
        Action::ResumeCorrect(1),
    ];
    for (step, action) in actions.into_iter().enumerate() {
        apply(group, &mut states, action, seed, step);
    }
}

#[test]
fn seeded_nested_continuations_never_panic_or_strand_active_calls() {
    for seed in SEEDS {
        let mut group = build_group();
        mandatory_prefix(&mut group, seed);
        let mut states = [CallState::Idle; 2];
        let mut rng = Rng(seed);
        for step in 0..STEPS {
            let action = rng.action();
            apply(&mut group, &mut states, action, seed, step);
        }

        group.discard_all_calls();
        assert!(!group.any_active_call(), "seed={seed:#018x} final cleanup");
        for instance in 0..2 {
            assert!(
                !group.has_active_call(instance),
                "seed={seed:#018x} instance={instance}"
            );
            assert_eq!(
                group.resume_host_call(instance, host_id(instance), &[CoreValue::I32(i32::MAX)],),
                Err(TrapCode::Validation),
                "seed={seed:#018x} stale completion instance={instance}",
            );
        }
    }
}
