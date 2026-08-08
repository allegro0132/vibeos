//! Exhaustive single-hart scheduler lifecycle model.
//!
//! This deliberately does not call the global executor.  Instead it keeps the
//! lifecycle phase (what a retained handle may eventually observe) separate
//! from the scheduler location (where the future is owned), then explores all
//! wake/cancel/poll/fault/reclaim interleavings for two tasks to a fixed point.
//! Keeping the model pure makes an invariant failure reproducible as a short
//! event trace rather than as a timing-dependent host test.

use std::collections::{HashMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Outcome {
    Exited,
    Faulted,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Phase {
    Running,
    CancelRequested,
    ExitCommitted,
    CancelCommitted,
    FaultCommitted,
    Published(Outcome),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Location {
    /// Present in the task map and exactly once in the ready queue.
    Ready,
    /// Present in the task map and absent from the ready queue.
    Parked,
    /// Detached from the task map and owned by the one global poll slot.
    RunningSlot,
    /// Detached from all scheduler collections while Drop/raw reclaim runs.
    DetachedReclaim,
    /// The future is gone; only the retained status remains.
    Gone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Task {
    phase: Phase,
    location: Location,
    running_woken: bool,
}

impl Task {
    const fn spawned() -> Self {
        Self {
            phase: Phase::Running,
            location: Location::Ready,
            running_woken: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct State {
    tasks: [Task; 2],
}

impl State {
    const fn initial() -> Self {
        Self {
            tasks: [Task::spawned(), Task::spawned()],
        }
    }

    fn has_running_slot(self) -> bool {
        self.tasks
            .iter()
            .any(|task| task.location == Location::RunningSlot)
    }

    fn reclaim_active(self) -> bool {
        self.tasks
            .iter()
            .any(|task| task.location == Location::DetachedReclaim)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArenaLayout {
    Same,
    Different,
}

impl ArenaLayout {
    fn same_arena(self, left: usize, right: usize) -> bool {
        left == right || self == Self::Same
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Wake(usize),
    Cancel(usize),
    Dispatch(usize),
    PollPending(usize),
    PollReady(usize),
    PollFault(usize),
    FinishReclaim(usize),
    DestructorFault(usize),
}

fn all_events() -> impl Iterator<Item = Event> {
    (0..2).flat_map(|task| {
        [
            Event::Wake(task),
            Event::Cancel(task),
            Event::Dispatch(task),
            Event::PollPending(task),
            Event::PollReady(task),
            Event::PollFault(task),
            Event::FinishReclaim(task),
            Event::DestructorFault(task),
        ]
    })
}

/// Check the state-space representation of the concrete executor invariants.
fn check_invariants(state: State) -> Result<(), &'static str> {
    let running = state
        .tasks
        .iter()
        .filter(|task| task.location == Location::RunningSlot)
        .count();
    if running > 1 {
        return Err("a single hart has more than one running task");
    }

    // Reclamation may enter arbitrary user Drop code.  The implementation
    // therefore defers nested cancellation rather than running Drop while a
    // different poll is active.
    if running != 0 && state.reclaim_active() {
        return Err("poll and reclaim user code are active together");
    }

    for task in state.tasks {
        if task.running_woken && task.location != Location::RunningSlot {
            return Err("running_woken escaped the running slot");
        }

        let phase_location_valid = match task.phase {
            Phase::Running => matches!(
                task.location,
                Location::Ready | Location::Parked | Location::RunningSlot
            ),
            // A request made during another task's poll/reclaim is forced
            // ready so the next outer executor boundary consumes it.
            Phase::CancelRequested => {
                matches!(task.location, Location::Ready | Location::RunningSlot)
            }
            Phase::ExitCommitted | Phase::CancelCommitted | Phase::FaultCommitted => {
                task.location == Location::DetachedReclaim
            }
            Phase::Published(_) => task.location == Location::Gone,
        };
        if !phase_location_valid {
            return Err("lifecycle phase and future ownership location disagree");
        }
    }

    Ok(())
}

fn fault_arena(state: &mut State, source: usize, layout: ArenaLayout) {
    for task in 0..state.tasks.len() {
        if layout.same_arena(source, task)
            && !matches!(state.tasks[task].phase, Phase::Published(_))
        {
            state.tasks[task].phase = Phase::FaultCommitted;
            state.tasks[task].location = Location::DetachedReclaim;
            state.tasks[task].running_woken = false;
        }
    }
}

fn publish_fault_arena(state: &mut State, source: usize, layout: ArenaLayout) {
    for task in 0..state.tasks.len() {
        if layout.same_arena(source, task) && state.tasks[task].phase == Phase::FaultCommitted {
            state.tasks[task].phase = Phase::Published(Outcome::Faulted);
            state.tasks[task].location = Location::Gone;
            state.tasks[task].running_woken = false;
        }
    }
}

/// Apply one scheduler-visible transition.  `None` means the event is either
/// disabled or intentionally idempotent (for example a stale terminal wake).
fn apply(mut state: State, event: Event, layout: ArenaLayout) -> Option<State> {
    let before = state;
    match event {
        Event::Wake(id) => match state.tasks[id].location {
            Location::Parked => state.tasks[id].location = Location::Ready,
            Location::RunningSlot => state.tasks[id].running_woken = true,
            Location::Ready | Location::DetachedReclaim | Location::Gone => {}
        },
        Event::Cancel(id) => match state.tasks[id].phase {
            Phase::Running => match state.tasks[id].location {
                Location::RunningSlot => state.tasks[id].phase = Phase::CancelRequested,
                Location::Ready | Location::Parked => {
                    // A poll or Drop already active on this hart makes direct
                    // reclamation unsafe.  Record and queue the request.
                    if state.has_running_slot() || state.reclaim_active() {
                        state.tasks[id].phase = Phase::CancelRequested;
                        state.tasks[id].location = Location::Ready;
                    } else {
                        state.tasks[id].phase = Phase::CancelCommitted;
                        state.tasks[id].location = Location::DetachedReclaim;
                    }
                }
                Location::DetachedReclaim | Location::Gone => unreachable!(),
            },
            // Repeated requests are idempotent; after a claim they are TooLate,
            // and after publication they are AlreadyTerminal.
            Phase::CancelRequested
            | Phase::ExitCommitted
            | Phase::CancelCommitted
            | Phase::FaultCommitted
            | Phase::Published(_) => {}
        },
        Event::Dispatch(id) => {
            if state.has_running_slot()
                || state.reclaim_active()
                || state.tasks[id].location != Location::Ready
            {
                return None;
            }
            match state.tasks[id].phase {
                Phase::Running => {
                    state.tasks[id].location = Location::RunningSlot;
                    state.tasks[id].running_woken = false;
                }
                Phase::CancelRequested => {
                    state.tasks[id].phase = Phase::CancelCommitted;
                    state.tasks[id].location = Location::DetachedReclaim;
                }
                _ => return None,
            }
        }
        Event::PollPending(id) => {
            if state.tasks[id].location != Location::RunningSlot {
                return None;
            }
            match state.tasks[id].phase {
                Phase::Running => {
                    state.tasks[id].location = if state.tasks[id].running_woken {
                        Location::Ready
                    } else {
                        Location::Parked
                    };
                    state.tasks[id].running_woken = false;
                }
                Phase::CancelRequested => {
                    state.tasks[id].phase = Phase::CancelCommitted;
                    state.tasks[id].location = Location::DetachedReclaim;
                    state.tasks[id].running_woken = false;
                }
                _ => return None,
            }
        }
        Event::PollReady(id) => {
            if state.tasks[id].location != Location::RunningSlot {
                return None;
            }
            state.tasks[id].phase = match state.tasks[id].phase {
                Phase::Running => Phase::ExitCommitted,
                Phase::CancelRequested => Phase::CancelCommitted,
                _ => return None,
            };
            state.tasks[id].location = Location::DetachedReclaim;
            state.tasks[id].running_woken = false;
        }
        Event::PollFault(id) => {
            if state.tasks[id].location != Location::RunningSlot
                || !matches!(
                    state.tasks[id].phase,
                    Phase::Running | Phase::CancelRequested
                )
            {
                return None;
            }
            // Claim and running-slot detachment share one scheduler critical
            // section. A poll fault therefore wins over cancellation without
            // exposing a committed task in RunningSlot, then tears down every
            // still-live sibling in the audited arena.
            fault_arena(&mut state, id, layout);
        }
        Event::FinishReclaim(id) => {
            if state.tasks[id].location != Location::DetachedReclaim {
                return None;
            }
            match state.tasks[id].phase {
                Phase::ExitCommitted => {
                    state.tasks[id].phase = Phase::Published(Outcome::Exited);
                    state.tasks[id].location = Location::Gone;
                }
                Phase::CancelCommitted => {
                    state.tasks[id].phase = Phase::Published(Outcome::Cancelled);
                    state.tasks[id].location = Location::Gone;
                }
                Phase::FaultCommitted => publish_fault_arena(&mut state, id, layout),
                _ => return None,
            }
        }
        Event::DestructorFault(id) => {
            if state.tasks[id].location != Location::DetachedReclaim
                || !matches!(
                    state.tasks[id].phase,
                    Phase::ExitCommitted | Phase::CancelCommitted
                )
            {
                return None;
            }
            // A fault while dropping a normally returned/cancelled future
            // promotes its claim and switches the arena to raw teardown.
            fault_arena(&mut state, id, layout);
        }
    }

    (state != before).then_some(state)
}

fn phase_rank(phase: Phase) -> u8 {
    match phase {
        Phase::Running => 0,
        Phase::CancelRequested => 1,
        Phase::ExitCommitted | Phase::CancelCommitted | Phase::FaultCommitted => 2,
        Phase::Published(_) => 3,
    }
}

fn check_monotonic(before: State, after: State) -> Result<(), &'static str> {
    for task in 0..before.tasks.len() {
        let old = before.tasks[task].phase;
        let new = after.tasks[task].phase;
        if phase_rank(new) < phase_rank(old) {
            return Err("lifecycle phase moved backwards");
        }
        if let Phase::Published(outcome) = old {
            if new != Phase::Published(outcome) || after.tasks[task].location != Location::Gone {
                return Err("a published terminal task was revived or rewritten");
            }
        }
        match old {
            Phase::ExitCommitted
                if !matches!(
                    new,
                    Phase::ExitCommitted
                        | Phase::FaultCommitted
                        | Phase::Published(Outcome::Exited)
                ) =>
            {
                return Err("an exit claim was rewritten by something other than a fault")
            }
            Phase::CancelCommitted
                if !matches!(
                    new,
                    Phase::CancelCommitted
                        | Phase::FaultCommitted
                        | Phase::Published(Outcome::Cancelled)
                ) =>
            {
                return Err("a cancellation claim was rewritten by something other than a fault")
            }
            Phase::FaultCommitted
                if !matches!(
                    new,
                    Phase::FaultCommitted | Phase::Published(Outcome::Faulted)
                ) =>
            {
                return Err("a fault claim lost terminal precedence")
            }
            _ => {}
        }
    }
    Ok(())
}

fn trace_string(trace: &[Event], tail: Option<Event>) -> String {
    let mut rendered = trace
        .iter()
        .map(|event| format!("{event:?}"))
        .collect::<Vec<_>>();
    if let Some(event) = tail {
        rendered.push(format!("{event:?}"));
    }
    rendered.join(" -> ")
}

fn explore(layout: ArenaLayout) -> HashMap<State, Vec<Event>> {
    let initial = State::initial();
    let mut traces = HashMap::from([(initial, Vec::new())]);
    let mut frontier = VecDeque::from([initial]);

    while let Some(state) = frontier.pop_front() {
        let trace = traces
            .get(&state)
            .expect("frontier state has a trace")
            .clone();
        check_invariants(state).unwrap_or_else(|failure| {
            panic!(
                "{layout:?} arena invariant failed: {failure}; trace: {}\nstate: {state:#?}",
                trace_string(&trace, None)
            )
        });

        for event in all_events() {
            let Some(next) = apply(state, event, layout) else {
                continue;
            };
            check_monotonic(state, next).unwrap_or_else(|failure| {
                panic!(
                    "{layout:?} arena transition failed: {failure}; trace: {}\nfrom: {state:#?}\nto: {next:#?}",
                    trace_string(&trace, Some(event))
                )
            });
            check_invariants(next).unwrap_or_else(|failure| {
                panic!(
                    "{layout:?} arena invariant failed: {failure}; trace: {}\nstate: {next:#?}",
                    trace_string(&trace, Some(event))
                )
            });

            if !traces.contains_key(&next) {
                let mut next_trace = trace.clone();
                next_trace.push(event);
                traces.insert(next, next_trace);
                frontier.push_back(next);
            }
        }
    }

    traces
}

fn must_apply(state: State, event: Event, layout: ArenaLayout) -> State {
    apply(state, event, layout)
        .unwrap_or_else(|| panic!("event {event:?} was unexpectedly disabled in {state:#?}"))
}

#[test]
fn fixed_point_covers_same_and_different_arena_interleavings() {
    let same = explore(ArenaLayout::Same);
    let different = explore(ArenaLayout::Different);

    // These floors are intentionally loose: they catch accidentally disabling
    // an event family without coupling the test to harmless model refactors.
    assert!(
        same.len() >= 80,
        "same-arena state space shrank to {}",
        same.len()
    );
    assert!(
        different.len() >= 110,
        "different-arena state space shrank to {}",
        different.len()
    );
}

#[test]
fn wake_cancel_and_fault_boundary_regressions() {
    let initial = State::initial();

    let running = must_apply(initial, Event::Dispatch(0), ArenaLayout::Different);
    let self_woken = must_apply(running, Event::Wake(0), ArenaLayout::Different);
    let repoll = must_apply(self_woken, Event::PollPending(0), ArenaLayout::Different);
    assert_eq!(repoll.tasks[0].location, Location::Ready);
    assert!(!repoll.tasks[0].running_woken);

    let cancel_requested = must_apply(running, Event::Cancel(0), ArenaLayout::Different);
    assert_eq!(cancel_requested.tasks[0].phase, Phase::CancelRequested);
    assert_eq!(cancel_requested.tasks[0].location, Location::RunningSlot);
    let cancel_claimed = must_apply(
        cancel_requested,
        Event::PollPending(0),
        ArenaLayout::Different,
    );
    assert_eq!(cancel_claimed.tasks[0].phase, Phase::CancelCommitted);
    let cancelled = must_apply(
        cancel_claimed,
        Event::FinishReclaim(0),
        ArenaLayout::Different,
    );
    assert_eq!(
        cancelled.tasks[0].phase,
        Phase::Published(Outcome::Cancelled)
    );

    let faulted = must_apply(
        cancel_requested,
        Event::PollFault(0),
        ArenaLayout::Different,
    );
    assert_eq!(faulted.tasks[0].phase, Phase::FaultCommitted);
    let published_fault = must_apply(faulted, Event::FinishReclaim(0), ArenaLayout::Different);
    assert_eq!(
        published_fault.tasks[0].phase,
        Phase::Published(Outcome::Faulted),
        "a poll fault must beat a mid-poll cancellation"
    );

    assert_eq!(
        apply(published_fault, Event::Wake(0), ArenaLayout::Different),
        None,
        "a stale waker must not revive a published task"
    );
}

#[test]
fn fault_teardown_is_confined_to_the_audited_arena() {
    let initial = State::initial();
    let running_same = must_apply(initial, Event::Dispatch(0), ArenaLayout::Same);
    let same_fault = must_apply(running_same, Event::PollFault(0), ArenaLayout::Same);
    assert_eq!(same_fault.tasks[0].phase, Phase::FaultCommitted);
    assert_eq!(same_fault.tasks[0].location, Location::DetachedReclaim);
    assert_eq!(same_fault.tasks[1].phase, Phase::FaultCommitted);
    assert_eq!(same_fault.tasks[1].location, Location::DetachedReclaim);

    let running_different = must_apply(initial, Event::Dispatch(0), ArenaLayout::Different);
    let sibling_before = running_different.tasks[1];
    let different_fault = must_apply(
        running_different,
        Event::PollFault(0),
        ArenaLayout::Different,
    );
    assert_eq!(
        different_fault.tasks[1], sibling_before,
        "another arena must remain byte-for-byte unchanged"
    );
}

#[test]
fn committed_exit_resists_late_cancel_but_destructor_fault_promotes_it() {
    let initial = State::initial();
    let running = must_apply(initial, Event::Dispatch(0), ArenaLayout::Different);
    let exit_claimed = must_apply(running, Event::PollReady(0), ArenaLayout::Different);
    assert_eq!(exit_claimed.tasks[0].phase, Phase::ExitCommitted);
    assert_eq!(
        apply(exit_claimed, Event::Cancel(0), ArenaLayout::Different),
        None,
        "late cancel must not rewrite a committed return"
    );

    let exited = must_apply(
        exit_claimed,
        Event::FinishReclaim(0),
        ArenaLayout::Different,
    );
    assert_eq!(exited.tasks[0].phase, Phase::Published(Outcome::Exited));

    let promoted = must_apply(
        exit_claimed,
        Event::DestructorFault(0),
        ArenaLayout::Different,
    );
    assert_eq!(promoted.tasks[0].phase, Phase::FaultCommitted);
    let faulted = must_apply(promoted, Event::FinishReclaim(0), ArenaLayout::Different);
    assert_eq!(faulted.tasks[0].phase, Phase::Published(Outcome::Faulted));
}

#[test]
fn nested_cancel_is_deferred_until_the_outer_poll_boundary() {
    let initial = State::initial();
    let outer_running = must_apply(initial, Event::Dispatch(0), ArenaLayout::Different);
    let nested_cancel = must_apply(outer_running, Event::Cancel(1), ArenaLayout::Different);
    assert_eq!(nested_cancel.tasks[1].phase, Phase::CancelRequested);
    assert_eq!(nested_cancel.tasks[1].location, Location::Ready);
    assert!(
        apply(nested_cancel, Event::Dispatch(1), ArenaLayout::Different).is_none(),
        "nested cancellation must not enter Drop while another poll is active"
    );

    let outer_parked = must_apply(nested_cancel, Event::PollPending(0), ArenaLayout::Different);
    let cancel_claimed = must_apply(outer_parked, Event::Dispatch(1), ArenaLayout::Different);
    assert_eq!(cancel_claimed.tasks[1].phase, Phase::CancelCommitted);
    assert_eq!(cancel_claimed.tasks[1].location, Location::DetachedReclaim);
}

#[test]
fn cancel_during_drop_is_deferred_and_a_same_arena_drop_fault_still_wins() {
    let initial = State::initial();
    let first_reclaim = must_apply(initial, Event::Cancel(0), ArenaLayout::Same);
    assert_eq!(first_reclaim.tasks[0].phase, Phase::CancelCommitted);

    let nested_cancel = must_apply(first_reclaim, Event::Cancel(1), ArenaLayout::Same);
    assert_eq!(nested_cancel.tasks[1].phase, Phase::CancelRequested);
    assert_eq!(nested_cancel.tasks[1].location, Location::Ready);
    assert!(
        apply(nested_cancel, Event::Dispatch(1), ArenaLayout::Same).is_none(),
        "a second task must not poll or enter Drop during active reclamation"
    );

    let arena_fault = must_apply(nested_cancel, Event::DestructorFault(0), ArenaLayout::Same);
    assert_eq!(arena_fault.tasks[0].phase, Phase::FaultCommitted);
    assert_eq!(arena_fault.tasks[1].phase, Phase::FaultCommitted);
    let published = must_apply(arena_fault, Event::FinishReclaim(0), ArenaLayout::Same);
    assert_eq!(published.tasks[0].phase, Phase::Published(Outcome::Faulted));
    assert_eq!(published.tasks[1].phase, Phase::Published(Outcome::Faulted));
}
