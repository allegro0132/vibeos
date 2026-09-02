#![cfg(feature = "c84-profile-hooks")]

use vibeos_component_runtime::{
    decode::inspect_component,
    resource::{ResourceTable, ResourceToken, ResourceTypeId},
    sync::{ProfileClock, SyncCallProfile, SynchronousComponent, TypedPoll},
    value::CanonicalValue,
    world::WorldContract,
};
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

const COMPONENT: &str = include_str!("fixtures/rich.component.wat");
const WORLD: &str = include_str!("../../component-format/tests/corpus/wit/world.wit");
const EXACT_WORLD: &str = "vibe:fixture/typed-filter@1.0.0";
const TRANSFORM: &str = "vibe:fixture/filter@1.0.0#transform";
const RANDOM_SOURCE: ResourceTypeId = ResourceTypeId(1);

fn instantiate() -> SynchronousComponent {
    let bytes = wat::parse_str(COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let world = WorldContract::parse(WORLD, EXACT_WORLD).unwrap();
    plan.check_world(&world).unwrap();
    SynchronousComponent::instantiate(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap()
}

fn arguments(token: ResourceToken) -> Vec<CanonicalValue> {
    vec![
        CanonicalValue::Record(vec![
            CanonicalValue::String("profile".into()),
            CanonicalValue::List(vec![
                CanonicalValue::U8(1),
                CanonicalValue::U8(2),
                CanonicalValue::U8(3),
            ]),
            CanonicalValue::Flags(vec![0b11]),
        ]),
        CanonicalValue::Resource(token),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClockEvent {
    Tick(u64),
    CleanupStarted,
    CoreStarting,
    CoreFinished(u64),
}

struct TraceClock {
    next: u64,
    events: Vec<ClockEvent>,
}

impl TraceClock {
    fn new(next: u64) -> Self {
        Self {
            next,
            events: Vec::new(),
        }
    }

    fn sample(&mut self) -> u64 {
        let tick = self.next;
        self.next = self.next.wrapping_add(1);
        tick
    }
}

impl ProfileClock for TraceClock {
    fn ticks(&mut self) -> u64 {
        let tick = self.sample();
        self.events.push(ClockEvent::Tick(tick));
        tick
    }

    fn cleanup_started(&mut self) {
        self.events.push(ClockEvent::CleanupStarted);
    }

    fn core_poll_started(&mut self) -> u64 {
        self.events.push(ClockEvent::CoreStarting);
        self.ticks()
    }

    fn core_poll_finished(&mut self) -> u64 {
        // Model the platform's trap-aware operation as one observer event: the
        // same sample both closes interpretation and is returned to the runtime
        // aggregate. A runtime-owned `ticks()` call would add an unexpected
        // `ClockEvent::Tick` before this event and fail the ordering assertion.
        let tick = self.sample();
        self.events.push(ClockEvent::CoreFinished(tick));
        tick
    }
}

struct TicksOnlyClock(u64);

impl ProfileClock for TicksOnlyClock {
    fn ticks(&mut self) -> u64 {
        let tick = self.0;
        self.0 = self.0.wrapping_add(1);
        tick
    }
}

#[test]
fn profiled_poll_matches_plain_poll_and_uses_exact_phase_buckets() {
    let mut plain_component = instantiate();
    let mut profiled_component = instantiate();
    let mut plain_resources = ResourceTable::new(201, 4).unwrap();
    let mut profiled_resources = ResourceTable::new(201, 4).unwrap();
    let plain_token = plain_resources.insert_owned(RANDOM_SOURCE, 0x5a).unwrap();
    let profiled_token = profiled_resources
        .insert_owned(RANDOM_SOURCE, 0x5a)
        .unwrap();
    let mut plain = plain_component
        .start_typed_call(
            &mut plain_resources,
            TRANSFORM,
            arguments(plain_token),
            100_000,
            100,
        )
        .unwrap();
    let mut profiled = profiled_component
        .start_typed_call(
            &mut profiled_resources,
            TRANSFORM,
            arguments(profiled_token),
            100_000,
            100,
        )
        .unwrap();
    let planned = profiled.metrics().consumed_work;
    assert_eq!(plain.metrics(), profiled.metrics());

    let mut clock = TraceClock::new(10);
    let mut profile = SyncCallProfile::default();
    let mut saw_no_core = false;
    let mut saw_one_core = false;
    let mut cleanup_started_polls = 0;
    let mut prior_poll_was_pending = false;
    let mut reached_ready = false;

    for _ in 0..50_000 {
        let before_metrics = profiled.metrics();
        let before_profile = profile;
        let before_events = clock.events.len();
        let first_tick = clock.next;

        let plain_result = plain.poll();
        let profiled_result = profiled.poll_profiled(&mut clock, &mut profile);
        assert_eq!(profiled_result, plain_result);
        assert_eq!(profile.typed_polls - before_profile.typed_polls, 1);

        let core_polls = profile.core_polls - before_profile.core_polls;
        assert!(core_polls <= 1, "one typed poll drove multiple Core polls");
        let cleanup_callbacks = clock.events[before_events..]
            .iter()
            .filter(|event| matches!(event, ClockEvent::CleanupStarted))
            .count();
        assert!(cleanup_callbacks <= 1);
        let cleanup_started = cleanup_callbacks == 1;
        if cleanup_started {
            assert_eq!(cleanup_started_polls, 0, "cleanup callback repeated");
            assert!(
                prior_poll_was_pending,
                "successful cleanup must start on the poll after the transition"
            );
            cleanup_started_polls += 1;
        }
        let mut expected_events = vec![ClockEvent::Tick(first_tick)];
        if cleanup_started {
            expected_events.push(ClockEvent::CleanupStarted);
        }
        if core_polls == 0 {
            saw_no_core = true;
            expected_events.push(ClockEvent::Tick(first_tick + 1));
        } else {
            saw_one_core = true;
            expected_events.extend_from_slice(&[
                ClockEvent::CoreStarting,
                ClockEvent::Tick(first_tick + 1),
                ClockEvent::CoreFinished(first_tick + 2),
                ClockEvent::Tick(first_tick + 3),
            ]);
        }
        assert_eq!(&clock.events[before_events..], expected_events);
        assert_eq!(
            profile.core_interpreter_ticks - before_profile.core_interpreter_ticks,
            core_polls
        );
        assert_eq!(
            profile.outer_poll_ticks - before_profile.outer_poll_ticks,
            1 + core_polls * 2,
            "outer timing must inclusively contain the Core interval"
        );
        assert_eq!(plain.metrics(), profiled.metrics());
        assert_eq!(
            profile.consumed_work - before_profile.consumed_work,
            profiled.metrics().consumed_work - before_metrics.consumed_work
        );

        if matches!(profiled_result, TypedPoll::Ready(_)) {
            reached_ready = true;
            break;
        }
        assert!(matches!(profiled_result, TypedPoll::Pending(_)));
        prior_poll_was_pending = true;
    }

    assert!(reached_ready);
    assert!(saw_no_core && saw_one_core);
    assert_eq!(cleanup_started_polls, 1);
    assert_eq!(
        profile.consumed_work,
        profiled.metrics().consumed_work - planned
    );
    assert_eq!(
        profile.outer_poll_ticks,
        profile.typed_polls + profile.core_polls * 2
    );
    assert_eq!(
        clock.events.len() as u64,
        profile.typed_polls * 2 + profile.core_polls * 3 + 1
    );

    // The post-Ready terminal poll has no Core work, consumes no fuel, and is
    // bit-for-bit identical to the ordinary API.
    let before = profile;
    let before_metrics = profiled.metrics();
    let first_tick = clock.next;
    assert_eq!(
        plain.poll(),
        TypedPoll::Trapped(vibeos_component_format::TrapCode::Cancelled)
    );
    assert_eq!(
        profiled.poll_profiled(&mut clock, &mut profile),
        TypedPoll::Trapped(vibeos_component_format::TrapCode::Cancelled)
    );
    assert_eq!(profile.typed_polls, before.typed_polls + 1);
    assert_eq!(profile.core_polls, before.core_polls);
    assert_eq!(profile.outer_poll_ticks, before.outer_poll_ticks + 1);
    assert_eq!(
        profile.core_interpreter_ticks,
        before.core_interpreter_ticks
    );
    assert_eq!(profile.consumed_work, before.consumed_work);
    assert_eq!(profiled.metrics(), before_metrics);
    assert_eq!(
        &clock.events[clock.events.len() - 2..],
        [
            ClockEvent::Tick(first_tick),
            ClockEvent::Tick(first_tick + 1)
        ]
    );
}

#[test]
fn cleanup_callback_is_exactly_once_for_terminal_and_late_cancel_paths() {
    let mut terminal_component = instantiate();
    let mut terminal_resources = ResourceTable::new(202, 4).unwrap();
    let terminal_token = terminal_resources
        .insert_owned(RANDOM_SOURCE, 0x5a)
        .unwrap();
    let mut terminal = terminal_component
        .start_typed_call(
            &mut terminal_resources,
            TRANSFORM,
            arguments(terminal_token),
            1,
            1,
        )
        .unwrap();
    let mut terminal_clock = TraceClock::new(50);
    let mut terminal_profile = SyncCallProfile::default();

    assert_eq!(
        terminal.poll_profiled(&mut terminal_clock, &mut terminal_profile),
        TypedPoll::Trapped(vibeos_component_format::TrapCode::FuelExhausted)
    );
    assert_eq!(
        terminal_clock.events,
        [
            ClockEvent::Tick(50),
            ClockEvent::CleanupStarted,
            ClockEvent::Tick(51),
        ],
        "a terminal constructor must enter cleanup after outer start and before closure"
    );
    assert_eq!(
        terminal.poll_profiled(&mut terminal_clock, &mut terminal_profile),
        TypedPoll::Trapped(vibeos_component_format::TrapCode::Cancelled)
    );
    assert_eq!(
        &terminal_clock.events[3..],
        [ClockEvent::Tick(52), ClockEvent::Tick(53)],
        "a completed call must not repeat the cleanup callback"
    );

    let mut cancelled_component = instantiate();
    let mut cancelled_resources = ResourceTable::new(203, 4).unwrap();
    let cancelled_token = cancelled_resources
        .insert_owned(RANDOM_SOURCE, 0x5a)
        .unwrap();
    let mut cancelled = cancelled_component
        .start_typed_call(
            &mut cancelled_resources,
            TRANSFORM,
            arguments(cancelled_token),
            100_000,
            100,
        )
        .unwrap();
    cancelled.cancel();
    let mut cancelled_clock = TraceClock::new(70);
    let mut cancelled_profile = SyncCallProfile::default();

    assert_eq!(
        cancelled.poll_profiled(&mut cancelled_clock, &mut cancelled_profile),
        TypedPoll::Trapped(vibeos_component_format::TrapCode::Cancelled)
    );
    assert_eq!(
        cancelled_clock.events,
        [
            ClockEvent::Tick(70),
            ClockEvent::CleanupStarted,
            ClockEvent::Tick(71),
        ],
        "a failure discovered inside the poll must notify before the outer finish sample"
    );
    assert_eq!(
        cancelled.poll_profiled(&mut cancelled_clock, &mut cancelled_profile),
        TypedPoll::Trapped(vibeos_component_format::TrapCode::Cancelled)
    );
    assert_eq!(
        cancelled_clock
            .events
            .iter()
            .filter(|event| matches!(event, ClockEvent::CleanupStarted))
            .count(),
        1
    );
}

#[test]
fn wrapping_clock_intervals_and_profile_overflow_are_conservative() {
    let mut component = instantiate();
    let mut resources = ResourceTable::new(202, 4).unwrap();
    let token = resources.insert_owned(RANDOM_SOURCE, 0x5a).unwrap();
    let mut call = component
        .start_typed_call(&mut resources, TRANSFORM, arguments(token), 100_000, 100)
        .unwrap();
    let before_work = call.metrics().consumed_work;
    let mut clock = TicksOnlyClock(u64::MAX - 1);
    let mut profile = SyncCallProfile::default();

    assert!(matches!(
        call.poll_profiled(&mut clock, &mut profile),
        TypedPoll::Pending(_)
    ));
    assert_eq!(clock.0, 2, "the four-clock sequence must wrap exactly once");
    assert_eq!(profile.typed_polls, 1);
    assert_eq!(profile.core_polls, 1);
    assert_eq!(profile.outer_poll_ticks, 3);
    assert_eq!(profile.core_interpreter_ticks, 1);
    assert_eq!(
        profile.consumed_work,
        call.metrics().consumed_work - before_work
    );

    profile = SyncCallProfile {
        typed_polls: u64::MAX - 1,
        core_polls: u64::MAX - 1,
        outer_poll_ticks: u64::MAX - 1,
        core_interpreter_ticks: u64::MAX - 1,
        consumed_work: u64::MAX,
    };
    assert!(matches!(
        call.poll_profiled(&mut clock, &mut profile),
        TypedPoll::Pending(_)
    ));
    assert_eq!(
        profile,
        SyncCallProfile {
            typed_polls: u64::MAX,
            core_polls: u64::MAX,
            outer_poll_ticks: u64::MAX,
            core_interpreter_ticks: u64::MAX,
            consumed_work: u64::MAX,
        }
    );
}
