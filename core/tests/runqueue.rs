//! Pure M5.1 queue-layer tests. No global executor or host threads are used.

use vibeos_core::runqueue::{EnqueueError, HartId, RunQueues, MAX_HARTS};

fn hart(index: usize) -> HartId {
    HartId::new(index).unwrap()
}

#[test]
fn local_fifo_precedes_deterministic_remote_steal() {
    let mut queues = RunQueues::new();
    queues.reserve_live_bound(3).unwrap();
    queues.enqueue(hart(0), 10u8, true).unwrap();
    queues.enqueue(hart(1), 11u8, true).unwrap();
    queues.enqueue(hart(2), 12u8, true).unwrap();

    let local = queues.dispatch(hart(0)).unwrap();
    assert_eq!(
        (local.task, local.source, local.stolen),
        (10, hart(0), false)
    );
    let first_steal = queues.dispatch(hart(0)).unwrap();
    assert_eq!(
        (first_steal.task, first_steal.source, first_steal.stolen),
        (11, hart(1), true)
    );
    let second_steal = queues.dispatch(hart(0)).unwrap();
    assert_eq!(
        (second_steal.task, second_steal.source, second_steal.stolen,),
        (12, hart(2), true)
    );

    let stats = queues.stats();
    assert_eq!(stats[0].dispatches, 3);
    assert_eq!(stats[0].steals, 2);
    assert!(queues.hart_idle(hart(0)));
}

#[test]
fn nonstealable_remote_work_is_idle_for_other_harts_but_local_for_its_owner() {
    let mut queues = RunQueues::new();
    queues.reserve_live_bound(1).unwrap();
    queues.enqueue(hart(2), 7u8, false).unwrap();

    assert!(queues.hart_idle(hart(0)));
    assert!(queues.dispatch(hart(0)).is_none());
    assert!(!queues.hart_idle(hart(2)));
    let local = queues.dispatch(hart(2)).unwrap();
    assert_eq!(local.task, 7);
    assert!(!local.stolen);
}

#[test]
fn enqueue_has_one_owner_and_never_grows_past_reserved_capacity() {
    let mut queues = RunQueues::new();
    queues.reserve_live_bound(2).unwrap();
    assert_eq!(queues.enqueue(hart(0), 1u16, true), Ok(()));
    assert_eq!(queues.owner(1), Some(hart(0)));
    assert_eq!(
        queues.enqueue(hart(3), 1u16, true),
        Err(EnqueueError::Duplicate)
    );

    let capacity = queues.capacity(hart(0));
    for id in 2..=capacity as u16 {
        queues.enqueue(hart(0), id, true).unwrap();
    }
    assert_eq!(queues.queued_on(hart(0)), capacity);
    assert_eq!(
        queues.enqueue(hart(0), u16::MAX, true),
        Err(EnqueueError::CapacityExhausted)
    );
    assert_eq!(queues.capacity(hart(0)), capacity);
    assert!(queues.remove(hart(0), 1));
    assert_eq!(queues.owner(1), None);
}

#[test]
fn every_valid_hart_has_independent_stats_and_capacity() {
    let mut queues = RunQueues::new();
    queues.reserve_live_bound(MAX_HARTS).unwrap();
    for index in 0..MAX_HARTS {
        queues.enqueue(hart(index), index, true).unwrap();
    }
    let stats = queues.stats();
    for index in 0..MAX_HARTS {
        assert_eq!(stats[index].queued, 1);
        assert!(queues.capacity(hart(index)) >= MAX_HARTS);
    }
    assert_eq!(HartId::new(MAX_HARTS), None);
}

#[test]
fn ready_hint_mirrors_every_enqueue_remove_and_dispatch() {
    use vibeos_core::runqueue::ReadyHint;
    static HINT: ReadyHint = ReadyHint::new();
    let mut queues = RunQueues::with_hint(&HINT);
    queues.reserve_live_bound(4).unwrap();
    for index in 0..MAX_HARTS {
        assert!(HINT.hart_idle(hart(index)));
    }
    // A pinned entry on hart 1 only occupies hart 1.
    queues.enqueue(hart(1), 10, false).unwrap();
    assert!(!HINT.hart_idle(hart(1)));
    assert!(HINT.hart_idle(hart(0)));
    assert_eq!((HINT.queued_on(hart(1)), HINT.stealable()), (1, 0));
    // A stealable entry anywhere keeps every hart busy, exactly like hart_idle.
    queues.enqueue(hart(2), 11, true).unwrap();
    for index in 0..MAX_HARTS {
        assert!(!HINT.hart_idle(hart(index)));
        assert_eq!(HINT.hart_idle(hart(index)), queues.hart_idle(hart(index)));
    }
    assert_eq!((HINT.queued_on(hart(2)), HINT.stealable()), (1, 1));
    // Duplicates are rejected without touching the mirror.
    assert_eq!(queues.enqueue(hart(0), 11, true), Err(EnqueueError::Duplicate));
    assert_eq!(HINT.stealable(), 1);
    // A remote steal drains the stealable count from its source hart.
    let stolen = queues.dispatch(hart(3)).unwrap();
    assert!(stolen.stolen && stolen.task == 11);
    assert_eq!((HINT.queued_on(hart(2)), HINT.stealable()), (0, 0));
    assert!(HINT.hart_idle(hart(0)) && !HINT.hart_idle(hart(1)));
    // Explicit removal and local dispatch both release their entries.
    queues.enqueue(hart(1), 12, true).unwrap();
    assert!(queues.remove(hart(1), 12));
    assert!(!queues.remove(hart(1), 12));
    assert_eq!((HINT.queued_on(hart(1)), HINT.stealable()), (1, 0));
    assert_eq!(queues.dispatch(hart(1)).unwrap().task, 10);
    for index in 0..MAX_HARTS {
        assert!(HINT.hart_idle(hart(index)));
        assert_eq!(HINT.hart_idle(hart(index)), queues.hart_idle(hart(index)));
    }
    assert!(queues.dispatch(hart(1)).is_none());
}
