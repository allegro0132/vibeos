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
    assert_eq!((0..5).map(|_| ep.try_recv().unwrap()).collect::<Vec<_>>(), vec![0, 1, 2, 3, 4]);
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

    assert!(producer.lookup_as::<Endpoint<u32>>(tx, Rights::SEND).is_ok());
    assert_eq!(
        producer.lookup_as::<Endpoint<u32>>(tx, Rights::RECV).err(),
        Some(CapError::InsufficientRights),
        "a producer cannot read the channel it publishes to"
    );

    assert!(consumer.lookup_as::<Endpoint<u32>>(rx, Rights::RECV).is_ok());
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
