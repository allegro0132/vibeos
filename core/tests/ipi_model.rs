//! Exhaustive small-state checks for the M5.2 queue/mailbox/SSIP protocol.
//!
//! The first model enumerates every legal merge of the producer's
//! enqueue/set/fence/send steps and the receiver's irq-off/check/check/WFI
//! steps. The second enumerates a concurrent publisher around the required
//! clear/fence/swap interrupt acknowledgement.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IdleModel {
    queued: bool,
    reason: bool,
    armed: bool,
    producer_kick: bool,
    ssip: bool,
    irq_off: bool,
    queue_was_empty: Option<bool>,
    mailbox_was_empty: Option<bool>,
    sleeping: bool,
    wfi_returned: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProducerStep {
    Enqueue,
    SetReason,
    PublishFence,
    Send,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdleStep {
    IrqOff,
    CheckQueue,
    CheckMailbox,
    Wfi,
}

fn producer_step(state: &mut IdleModel, step: ProducerStep, send_fails: bool) {
    match step {
        ProducerStep::Enqueue => state.queued = true,
        ProducerStep::SetReason => {
            assert!(state.queued, "reason publication preceded enqueue");
            state.reason = true;
            state.armed = true;
            state.producer_kick = true;
        }
        // A receiver may already have swapped the mailbox; the fence orders
        // this publisher's queue/reason operations even if their bits were
        // concurrently consumed.
        ProducerStep::PublishFence => assert!(state.producer_kick),
        ProducerStep::Send => {
            assert!(state.producer_kick, "doorbell preceded reason publication");
            if !send_fails {
                state.ssip = true;
                if state.sleeping {
                    state.sleeping = false;
                    state.wfi_returned = true;
                }
            }
        }
    }
}

fn idle_step(state: &mut IdleModel, step: IdleStep) {
    match step {
        IdleStep::IrqOff => state.irq_off = true,
        IdleStep::CheckQueue => {
            assert!(state.irq_off);
            state.queue_was_empty = Some(!state.queued);
        }
        IdleStep::CheckMailbox => {
            assert!(state.queue_was_empty.is_some());
            state.mailbox_was_empty = Some(!state.reason);
            // The production idle gate uses an Acquire swap, not a load. A
            // consumed stale reason prevents WFI for this iteration without
            // leaving the idle loop permanently busy.
            state.reason = false;
            state.armed = false;
        }
        IdleStep::Wfi => {
            assert!(state.mailbox_was_empty.is_some());
            if state.queue_was_empty == Some(true) && state.mailbox_was_empty == Some(true) {
                if state.ssip {
                    state.wfi_returned = true;
                } else {
                    state.sleeping = true;
                }
            }
        }
    }
}

fn enumerate_idle_merges(
    producer: usize,
    receiver: usize,
    state: IdleModel,
    send_fails: bool,
    visited: &mut usize,
) {
    const PRODUCER: [ProducerStep; 4] = [
        ProducerStep::Enqueue,
        ProducerStep::SetReason,
        ProducerStep::PublishFence,
        ProducerStep::Send,
    ];
    const RECEIVER: [IdleStep; 4] = [
        IdleStep::IrqOff,
        IdleStep::CheckQueue,
        IdleStep::CheckMailbox,
        IdleStep::Wfi,
    ];

    if producer == PRODUCER.len() && receiver == RECEIVER.len() {
        *visited += 1;
        assert!(state.queued);
        if send_fails {
            // Firmware failure may prevent a remote hardware wake, but it must
            // never strand a sleeping receiver without retry evidence. If the
            // idle swap consumed that evidence, it also skipped WFI.
            assert!(!state.sleeping || state.reason);
        } else {
            assert!(
                !state.sleeping,
                "successful SSIP left a hart permanently asleep: {state:?}"
            );
        }
        return;
    }

    if producer < PRODUCER.len() {
        let mut next = state;
        producer_step(&mut next, PRODUCER[producer], send_fails);
        enumerate_idle_merges(producer + 1, receiver, next, send_fails, visited);
    }
    if receiver < RECEIVER.len() {
        let mut next = state;
        idle_step(&mut next, RECEIVER[receiver]);
        enumerate_idle_merges(producer, receiver + 1, next, send_fails, visited);
    }
}

#[test]
fn every_enqueue_set_fence_send_and_idle_interleaving_is_safe() {
    let mut successful = 0;
    enumerate_idle_merges(0, 0, IdleModel::default(), false, &mut successful);
    assert_eq!(successful, 70); // C(8, 4), all order-preserving merges.

    let mut failed = 0;
    enumerate_idle_merges(0, 0, IdleModel::default(), true, &mut failed);
    assert_eq!(failed, 70);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AckStep {
    ClearSsip,
    DeviceFence,
    SwapAcquire,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConcurrentPublishStep {
    Enqueue,
    SetReasonRelease,
    DeviceFence,
    SendIfTransition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AckModel {
    queued: usize,
    reason: bool,
    armed: bool,
    ssip: bool,
    publisher_armed: bool,
    handled_queue_prefix: usize,
}

fn ack_step(state: &mut AckModel, step: AckStep) {
    match step {
        AckStep::ClearSsip => state.ssip = false,
        AckStep::DeviceFence => assert!(!state.ssip),
        AckStep::SwapAcquire => {
            if state.reason {
                // Acquire observes every enqueue sequenced before a Release
                // RMW in the reason's release sequence.
                state.handled_queue_prefix = state.queued;
            }
            state.reason = false;
            state.armed = false;
        }
    }
}

fn concurrent_publish_step(state: &mut AckModel, step: ConcurrentPublishStep) {
    match step {
        ConcurrentPublishStep::Enqueue => state.queued += 1,
        ConcurrentPublishStep::SetReasonRelease => {
            assert_eq!(state.queued, 2);
            state.reason = true;
            state.publisher_armed = !state.armed;
            state.armed = true;
        }
        // The receiver may swap the reason after this publisher's Release;
        // the fence orders the publication, it does not require the bit to
        // remain set while the handler consumes it.
        ConcurrentPublishStep::DeviceFence => {}
        ConcurrentPublishStep::SendIfTransition => {
            if state.publisher_armed {
                state.ssip = true;
            }
        }
    }
}

fn enumerate_ack_merges(ack: usize, publisher: usize, state: AckModel, visited: &mut usize) {
    const ACK: [AckStep; 3] = [
        AckStep::ClearSsip,
        AckStep::DeviceFence,
        AckStep::SwapAcquire,
    ];
    const PUBLISHER: [ConcurrentPublishStep; 4] = [
        ConcurrentPublishStep::Enqueue,
        ConcurrentPublishStep::SetReasonRelease,
        ConcurrentPublishStep::DeviceFence,
        ConcurrentPublishStep::SendIfTransition,
    ];

    if ack == ACK.len() && publisher == PUBLISHER.len() {
        *visited += 1;
        assert_eq!(state.queued, 2);
        assert!(
            state.handled_queue_prefix == 2 || (state.reason && state.armed && state.ssip),
            "concurrent publication was neither acquired nor left pending: {state:?}"
        );
        return;
    }
    if ack < ACK.len() {
        let mut next = state;
        ack_step(&mut next, ACK[ack]);
        enumerate_ack_merges(ack + 1, publisher, next, visited);
    }
    if publisher < PUBLISHER.len() {
        let mut next = state;
        concurrent_publish_step(&mut next, PUBLISHER[publisher]);
        enumerate_ack_merges(ack, publisher + 1, next, visited);
    }
}

#[test]
fn clear_fence_swap_coalesces_or_leaves_a_fresh_doorbell() {
    let mut visited = 0;
    enumerate_ack_merges(
        0,
        0,
        AckModel {
            queued: 1,
            reason: true,
            armed: true,
            ssip: true,
            publisher_armed: false,
            handled_queue_prefix: 0,
        },
        &mut visited,
    );
    assert_eq!(visited, 35); // C(7, 3), all order-preserving merges.
}

#[test]
fn stale_ipi_has_no_reason_and_no_scheduler_side_effect() {
    let mut state = AckModel {
        queued: 0,
        reason: false,
        armed: true,
        ssip: true,
        publisher_armed: false,
        handled_queue_prefix: 0,
    };
    ack_step(&mut state, AckStep::ClearSsip);
    ack_step(&mut state, AckStep::DeviceFence);
    ack_step(&mut state, AckStep::SwapAcquire);
    assert_eq!(state.queued, 0);
    assert!(!state.reason && !state.armed && !state.ssip);
    assert_eq!(state.handled_queue_prefix, 0);
}

#[test]
fn swap_before_clear_has_the_documented_lost_doorbell_counterexample() {
    let mut state = AckModel {
        queued: 1,
        reason: true,
        armed: true,
        ssip: true,
        publisher_armed: false,
        handled_queue_prefix: 0,
    };

    // Broken order: consume the old mailbox first. A concurrent publisher now
    // observes the released state, publishes new work, and sends a fresh SSIP.
    // Clearing SSIP last erases that only doorbell while its reason remains.
    ack_step(&mut state, AckStep::SwapAcquire);
    concurrent_publish_step(&mut state, ConcurrentPublishStep::Enqueue);
    concurrent_publish_step(&mut state, ConcurrentPublishStep::SetReasonRelease);
    concurrent_publish_step(&mut state, ConcurrentPublishStep::DeviceFence);
    concurrent_publish_step(&mut state, ConcurrentPublishStep::SendIfTransition);
    assert!(state.reason && state.armed && state.ssip);
    ack_step(&mut state, AckStep::ClearSsip);

    assert_eq!(state.queued, 2);
    assert!(state.reason && state.armed);
    assert!(!state.ssip, "a late clear erased the fresh doorbell");
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ArmedMailboxModel {
    queued: usize,
    reason: bool,
    armed: bool,
    ssip: bool,
    attempts: usize,
}

impl ArmedMailboxModel {
    fn publish(&mut self, send_succeeds: bool) {
        // Enqueue precedes the Release RMW. The state CAS atomically adds
        // armed, so a handler cannot clear reason separately and strand an
        // obsolete true armed bit.
        self.queued += 1;
        self.reason = true;
        if self.armed {
            return;
        }
        self.armed = true;
        self.attempts += 1;
        if send_succeeds {
            self.ssip = true;
        } else {
            // Failure clears only armed. The reason and queue publication stay
            // intact, making a later publication eligible to retry.
            self.armed = false;
        }
    }

    fn clear_fence_swap(&mut self) -> bool {
        self.ssip = false;
        let acquired = self.reason;
        self.reason = false;
        self.armed = false;
        acquired
    }
}

#[test]
fn failed_first_kick_is_retried_without_consuming_the_reason() {
    let mut state = ArmedMailboxModel::default();
    state.publish(false);
    assert_eq!(
        state,
        ArmedMailboxModel {
            queued: 1,
            reason: true,
            armed: false,
            ssip: false,
            attempts: 1,
        }
    );

    state.publish(true);
    assert_eq!(state.queued, 2);
    assert!(state.reason && state.armed && state.ssip);
    assert_eq!(state.attempts, 2);
    assert!(state.clear_fence_swap());
    assert!(!state.reason && !state.armed && !state.ssip);
}
