//! Endpoint behaviour that needs no scheduler.

use std::sync::Arc;

use vibeos_core::cap::{CSpace, CapError, Rights};
use vibeos_core::chan::Endpoint;

#[test]
fn messages_come_back_in_order() {
    let ep: Arc<Endpoint<u32>> = Endpoint::new("t", 8);
    for i in 0..5 {
        assert!(ep.try_send(i).is_ok());
    }
    assert_eq!(
        (0..5).map(|_| ep.try_recv().unwrap()).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(ep.try_recv(), None);
}

#[test]
fn the_bound_is_enforced_and_the_message_is_handed_back() {
    let ep: Arc<Endpoint<u32>> = Endpoint::new("t", 2);
    assert!(ep.try_send(1).is_ok());
    assert!(ep.try_send(2).is_ok());
    // A rejected send returns the payload rather than dropping it.
    assert_eq!(ep.try_send(3), Err(3));
    assert_eq!(ep.try_recv(), Some(1));
    assert!(ep.try_send(3).is_ok(), "space freed up");
}

#[test]
fn stats_count_both_directions() {
    let ep: Arc<Endpoint<u32>> = Endpoint::new("t", 4);
    ep.try_send(1).unwrap();
    ep.try_send(2).unwrap();
    ep.try_recv().unwrap();
    assert_eq!(ep.stats(), (2, 1, 1));
}

/// The design claim: one object serves both ends, and the *rights* on the
/// capability decide which end you are holding.
#[test]
fn rights_pick_the_direction() {
    let ep: Arc<Endpoint<u32>> = Endpoint::new("telemetry", 4);
    let mut producer = CSpace::new("producer");
    let mut consumer = CSpace::new("consumer");

    let tx = producer.mint(ep.clone(), Rights::SEND);
    let rx = consumer.mint(ep.clone(), Rights::RECV);

    assert!(producer
        .lookup_as::<Endpoint<u32>>(tx, Rights::SEND)
        .is_ok());
    assert_eq!(
        producer.lookup_as::<Endpoint<u32>>(tx, Rights::RECV).err(),
        Some(CapError::InsufficientRights),
        "a producer cannot read the channel it publishes to"
    );

    assert!(consumer
        .lookup_as::<Endpoint<u32>>(rx, Rights::RECV)
        .is_ok());
    assert_eq!(
        consumer.lookup_as::<Endpoint<u32>>(rx, Rights::SEND).err(),
        Some(CapError::InsufficientRights),
        "a consumer cannot forge a message"
    );
}

#[test]
fn an_endpoint_describes_itself_for_the_caps_listing() {
    let ep: Arc<Endpoint<u32>> = Endpoint::new("telemetry", 8);
    ep.try_send(1).unwrap();
    let mut cs = CSpace::new("s");
    let c = cs.mint(ep, Rights::ALL);
    let (_, kind, _, desc) = cs.list().into_iter().find(|(h, ..)| *h == c).unwrap();
    assert_eq!(kind, "endpoint");
    assert!(desc.contains("telemetry"), "{desc}");
    assert!(desc.contains("sent=1"), "{desc}");
}

#[test]
fn message_notification_covers_send_before_first_poll_without_consuming() {
    use std::{future::Future, pin::pin, task::{Context, Waker}};
    let ep = Endpoint::new("notification", 2);
    let notification = ep.message_event();
    let mut listener = pin!(notification.wait());
    assert!(!ep.has_message());
    ep.try_send(7u32).unwrap();
    assert!(listener.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_ready());
    assert!(ep.has_message());
    assert_eq!(ep.try_recv(), Some(7));
    assert!(!ep.has_message());
}


#[derive(Default)]
struct WakeCount(std::sync::atomic::AtomicUsize);
impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
}
#[test]
fn transition_notification_wakes_all_consumers_and_rearms_after_drain() {
    use std::{future::Future, pin::pin, task::{Context, Waker, Poll}};
    let ep = Endpoint::new("consumer-transitions", 2);
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(count.clone()); let mut cx = Context::from_waker(&waker);
    let mut first = pin!(ep.recv()); let mut second = pin!(ep.recv());
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    ep.try_send(1u32).unwrap(); ep.try_send(2).unwrap();
    assert_eq!(count.0.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(first.as_mut().poll(&mut cx), Poll::Ready(1));
    assert_eq!(second.as_mut().poll(&mut cx), Poll::Ready(2));
    let mut next = pin!(ep.recv());
    assert!(next.as_mut().poll(&mut cx).is_pending());
    ep.try_send(3).unwrap();
    assert_eq!(count.0.load(std::sync::atomic::Ordering::Relaxed), 3);
    assert_eq!(next.as_mut().poll(&mut cx), Poll::Ready(3));
}
#[test]
fn full_transition_wakes_all_producers_and_loser_rearms() {
    use std::{future::Future, pin::pin, task::{Context, Waker}};
    let ep = Endpoint::new("producer-transitions", 1); ep.try_send(0u32).unwrap();
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(count.clone()); let mut cx = Context::from_waker(&waker);
    let mut first = pin!(ep.send(1)); let mut second = pin!(ep.send(2));
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    assert_eq!(ep.try_recv(), Some(0));
    assert_eq!(count.0.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert!(first.as_mut().poll(&mut cx).is_ready());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    assert_eq!(ep.try_recv(), Some(1));
    assert_eq!(count.0.load(std::sync::atomic::Ordering::Relaxed), 3);
    assert!(second.as_mut().poll(&mut cx).is_ready());
    assert_eq!(ep.try_recv(), Some(2));
}

#[test]
#[cfg(feature = "rx-publish-batch")]
fn batch_moves_only_admitted_prefix_and_notifies_empty_transition() {
    use std::{future::Future, pin::pin, task::{Context,Waker}};
    let q=Endpoint::new("batch",2);
    let event=q.message_event();let mut wait=pin!(event.wait());
    let mut items=[Some(String::from("first")),None,Some(String::from("second")),Some(String::from("third"))];
    assert_eq!(q.try_send_batch(&mut items,0),0);
    assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    assert_eq!(q.try_send_batch(&mut items,1),1);
    assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_ready());
    assert!(items[0].is_none());assert_eq!(items[2].as_deref(),Some("second"));
    assert_eq!(q.try_send_batch(&mut items,32),1);
    assert_eq!(q.try_send_batch(&mut items,32),0);
    assert_eq!(items[3].as_deref(),Some("third"));assert_eq!(q.stats(),(2,0,2));
    assert_eq!(q.try_recv().as_deref(),Some("first"));
    assert_eq!(q.try_send_batch(&mut items,32),1);
    assert_eq!(q.try_recv().as_deref(),Some("second"));assert_eq!(q.try_recv().as_deref(),Some("third"));
    assert!(items.iter().all(Option::is_none));assert_eq!(q.stats(),(3,3,0));
}
