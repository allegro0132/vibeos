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
