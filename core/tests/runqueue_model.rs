//! Exhaustive small-state model for M5.1 ready ownership.
//!
//! The model deliberately stores both task metadata and queue membership. Each
//! transition must keep those two representations identical, making duplicate
//! or lost ownership fail with a short reproducible trace.

use std::collections::{HashMap, VecDeque};

const HARTS: usize = 4;
const TASKS: usize = 2;
const CAPACITY: usize = TASKS;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Outcome {
    Exited,
    Cancelled,
    Faulted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Phase {
    Running,
    CancelRequested,
    Published(Outcome),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Task {
    phase: Phase,
    owner: u8,
    present: bool,
    ready: bool,
    stealable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Running {
    task: u8,
    hart: u8,
    woken: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct State {
    tasks: [Task; TASKS],
    queues: [[bool; TASKS]; HARTS],
    running: Option<Running>,
}

impl State {
    const fn initial() -> Self {
        Self {
            tasks: [
                Task {
                    phase: Phase::Running,
                    owner: 1,
                    present: true,
                    ready: true,
                    stealable: true,
                },
                Task {
                    phase: Phase::Running,
                    owner: 2,
                    present: true,
                    ready: true,
                    stealable: true,
                },
            ],
            queues: [[false, false], [true, false], [false, true], [false, false]],
            running: None,
        }
    }

    fn enqueue(&mut self, task: usize) {
        let owner = usize::from(self.tasks[task].owner);
        assert!(!self.tasks[task].ready);
        assert!((0..HARTS).all(|hart| !self.queues[hart][task]));
        assert!(self.queues[owner].iter().filter(|queued| **queued).count() < CAPACITY);
        self.queues[owner][task] = true;
        self.tasks[task].ready = true;
    }

    fn remove_ready(&mut self, task: usize) {
        let owner = usize::from(self.tasks[task].owner);
        assert!(self.tasks[task].ready && self.queues[owner][task]);
        self.queues[owner][task] = false;
        self.tasks[task].ready = false;
    }

    fn publish(&mut self, task: usize, outcome: Outcome) {
        if self.tasks[task].ready {
            self.remove_ready(task);
        }
        self.tasks[task].phase = Phase::Published(outcome);
        self.tasks[task].present = false;
        self.tasks[task].ready = false;
        if self
            .running
            .is_some_and(|running| usize::from(running.task) == task)
        {
            self.running = None;
        }
    }

    fn dispatch_hart0(&mut self) -> Option<usize> {
        if self.running.is_some() {
            return None;
        }
        let task = (0..TASKS).find(|task| self.queues[0][*task]).or_else(|| {
            (1..HARTS).find_map(|hart| {
                (0..TASKS)
                    .rev()
                    .find(|task| self.queues[hart][*task] && self.tasks[*task].stealable)
            })
        })?;
        self.remove_ready(task);
        self.tasks[task].owner = 0;
        if self.tasks[task].phase == Phase::CancelRequested {
            self.publish(task, Outcome::Cancelled);
        } else {
            self.running = Some(Running {
                task: task as u8,
                hart: 0,
                woken: false,
            });
        }
        Some(task)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    DispatchHart0,
    Wake(usize),
    Cancel(usize),
    PollPending(usize),
    PollReady(usize),
    PollFault(usize),
}

fn events() -> impl Iterator<Item = Event> {
    core::iter::once(Event::DispatchHart0).chain((0..TASKS).flat_map(|task| {
        [
            Event::Wake(task),
            Event::Cancel(task),
            Event::PollPending(task),
            Event::PollReady(task),
            Event::PollFault(task),
        ]
    }))
}

fn apply(mut state: State, event: Event) -> Option<State> {
    let before = state;
    match event {
        Event::DispatchHart0 => {
            state.dispatch_hart0()?;
        }
        Event::Wake(task) => {
            if !state.tasks[task].present {
                return None;
            }
            if let Some(mut running) = state
                .running
                .filter(|running| usize::from(running.task) == task)
            {
                running.woken = true;
                state.running = Some(running);
            } else if !state.tasks[task].ready {
                state.enqueue(task);
            }
        }
        Event::Cancel(task) => match state.tasks[task].phase {
            Phase::Running => {
                if state
                    .running
                    .is_some_and(|running| usize::from(running.task) == task)
                {
                    state.tasks[task].phase = Phase::CancelRequested;
                } else if state.running.is_some() {
                    state.tasks[task].phase = Phase::CancelRequested;
                    if !state.tasks[task].ready {
                        state.enqueue(task);
                    }
                } else {
                    state.publish(task, Outcome::Cancelled);
                }
            }
            Phase::CancelRequested | Phase::Published(_) => return None,
        },
        Event::PollPending(task) => {
            let running = state.running?;
            if usize::from(running.task) != task {
                return None;
            }
            match state.tasks[task].phase {
                Phase::CancelRequested => state.publish(task, Outcome::Cancelled),
                Phase::Running => {
                    state.running = None;
                    if running.woken {
                        state.enqueue(task);
                    }
                }
                Phase::Published(_) => return None,
            }
        }
        Event::PollReady(task) => {
            let running = state.running?;
            if usize::from(running.task) != task {
                return None;
            }
            let outcome = if state.tasks[task].phase == Phase::CancelRequested {
                Outcome::Cancelled
            } else {
                Outcome::Exited
            };
            state.publish(task, outcome);
        }
        Event::PollFault(task) => {
            let running = state.running?;
            if usize::from(running.task) != task {
                return None;
            }
            state.publish(task, Outcome::Faulted);
        }
    }
    (state != before).then_some(state)
}

fn check(state: State) -> Result<(), &'static str> {
    for hart in 0..HARTS {
        if state.queues[hart].iter().filter(|queued| **queued).count() > CAPACITY {
            return Err("ready queue exceeded its reserved live-task capacity");
        }
    }
    for task in 0..TASKS {
        let memberships: Vec<_> = (0..HARTS)
            .filter(|hart| state.queues[*hart][task])
            .collect();
        if memberships.len() > 1 {
            return Err("task has duplicate ready ownership");
        }
        let running = state
            .running
            .is_some_and(|running| usize::from(running.task) == task);
        if running && !memberships.is_empty() {
            return Err("running task is also ready");
        }
        if state.tasks[task].ready != (memberships.len() == 1) {
            return Err("task ready metadata disagrees with queue membership");
        }
        if let Some(owner) = memberships.first() {
            if *owner != usize::from(state.tasks[task].owner) {
                return Err("task ready owner disagrees with its queue");
            }
        }
        match state.tasks[task].phase {
            Phase::Published(_) => {
                if state.tasks[task].present || state.tasks[task].ready || running {
                    return Err("published task retained scheduler ownership");
                }
            }
            Phase::Running | Phase::CancelRequested => {
                if !state.tasks[task].present {
                    return Err("live task was lost from scheduler ownership");
                }
                if !running && !state.tasks[task].ready {
                    // A live non-ready task is deliberately parked.
                }
            }
        }
    }
    Ok(())
}

fn render(trace: &[Event], tail: Option<Event>) -> String {
    let mut out = trace
        .iter()
        .map(|event| format!("{event:?}"))
        .collect::<Vec<_>>();
    if let Some(event) = tail {
        out.push(format!("{event:?}"));
    }
    out.join(" -> ")
}

fn explore() -> HashMap<State, Vec<Event>> {
    let initial = State::initial();
    let mut traces = HashMap::from([(initial, Vec::new())]);
    let mut frontier = VecDeque::from([initial]);
    while let Some(state) = frontier.pop_front() {
        let trace = traces.get(&state).unwrap().clone();
        check(state).unwrap_or_else(|error| {
            panic!(
                "{error}; trace: {}; state: {state:#?}",
                render(&trace, None)
            )
        });
        for event in events() {
            let Some(next) = apply(state, event) else {
                continue;
            };
            check(next).unwrap_or_else(|error| {
                panic!(
                    "{error}; trace: {}; state: {next:#?}",
                    render(&trace, Some(event))
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

#[test]
fn exhaustive_two_task_state_space_preserves_unique_ready_ownership() {
    let states = explore();
    assert!(
        states.len() >= 40,
        "state space unexpectedly shrank to {}",
        states.len()
    );
}

#[test]
fn steal_wake_during_poll_cancel_and_fault_regressions() {
    let initial = State::initial();
    let stolen = apply(initial, Event::DispatchHart0).unwrap();
    assert_eq!(stolen.running.unwrap().task, 0);
    assert_eq!(stolen.tasks[0].owner, 0);

    let woken = apply(stolen, Event::Wake(0)).unwrap();
    let ready = apply(woken, Event::PollPending(0)).unwrap();
    assert!(ready.tasks[0].ready && ready.queues[0][0]);
    let repoll = apply(ready, Event::DispatchHart0).unwrap();
    let cancelled = apply(repoll, Event::Cancel(0)).unwrap();
    let faulted = apply(cancelled, Event::PollFault(0)).unwrap();
    assert_eq!(faulted.tasks[0].phase, Phase::Published(Outcome::Faulted));

    let sibling_cancelled = apply(faulted, Event::Cancel(1)).unwrap();
    assert_eq!(
        sibling_cancelled.tasks[1].phase,
        Phase::Published(Outcome::Cancelled)
    );
    check(sibling_cancelled).unwrap();
}
