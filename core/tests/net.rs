//! Host-only evidence for the fixed packet and typed endpoint API.
//!
use std::future::Future;
use std::mem::size_of;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use vibeos_core::cap::{CSpace, CapError, Rights};
use vibeos_core::net::{
    directional, recv_only, send_only, DuplexEndpoint, Endpoint, Packet, PacketBufferTooSmall,
    PacketEndpoint, PacketError, RecvEndpoint, SendEndpoint, MAX_ETHERNET_FRAME_LEN,
    MAX_PACKET_LEN,
};

fn frame(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
        .collect()
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn expect_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("operation with a satisfied channel predicate unexpectedly parked"),
    }
}

#[test]
fn packet_accepts_every_representative_nonempty_boundary() {
    for len in [
        1, 2, 13, 14, 59, 60, 61, 511, 512, 1_499, 1_500, 1_513, 1_514,
    ] {
        let bytes = frame(len);
        let packet = Packet::copy_from(&bytes).unwrap();
        assert_eq!(packet.len(), len, "length {len}");
        assert!(!packet.is_empty(), "length {len}");
        assert_eq!(packet.as_bytes(), bytes, "length {len}");
        assert_eq!(packet.as_ref(), bytes, "length {len}");
    }
}

#[test]
fn packet_rejects_zero_and_every_representative_oversize() {
    assert_eq!(Packet::copy_from(&[]), Err(PacketError::Empty));

    for len in [
        MAX_ETHERNET_FRAME_LEN + 1,
        2_048,
        u16::MAX as usize,
        u16::MAX as usize + 1,
    ] {
        assert_eq!(
            Packet::copy_from(&vec![0xa5; len]),
            Err(PacketError::TooLong {
                len,
                max: MAX_ETHERNET_FRAME_LEN,
            })
        );
    }
}

#[test]
fn packet_storage_is_exactly_payload_plus_u16_length() {
    assert_eq!(Packet::MAX_LEN, MAX_ETHERNET_FRAME_LEN);
    assert_eq!(Packet::MAX_LEN, MAX_PACKET_LEN);
    assert_eq!(
        size_of::<Packet>(),
        MAX_ETHERNET_FRAME_LEN + size_of::<u16>()
    );
}

#[test]
fn construction_copies_instead_of_borrowing_the_source() {
    let mut source = frame(97);
    let expected = source.clone();
    let packet = Packet::copy_from(&source).unwrap();

    source.fill(0xff);
    assert_eq!(packet.as_bytes(), expected);
}

#[test]
fn access_exposes_exactly_the_logical_frame() {
    for len in [1, 64, MAX_ETHERNET_FRAME_LEN] {
        let packet = Packet::copy_from(&frame(len)).unwrap();
        assert_eq!(packet.as_bytes().len(), len);
        assert_eq!(packet.as_bytes().last(), frame(len).last());
    }
}

#[test]
fn copy_to_writes_the_frame_and_preserves_destination_tail() {
    let source = frame(257);
    let packet = Packet::copy_from(&source).unwrap();
    let mut destination = vec![0xcc; source.len() + 19];

    assert_eq!(packet.copy_to(&mut destination), Ok(source.len()));
    assert_eq!(&destination[..source.len()], source);
    assert_eq!(&destination[source.len()..], &[0xcc; 19]);

    destination[..source.len()].fill(0);
    assert_eq!(
        packet.as_bytes(),
        source,
        "destination does not alias packet"
    );
}

#[test]
fn copy_to_short_buffer_is_atomic() {
    let packet = Packet::copy_from(&frame(64)).unwrap();
    for provided in [0, 1, 31, 63] {
        let mut destination = vec![0x5a; provided];
        let before = destination.clone();
        assert_eq!(
            packet.copy_to(&mut destination),
            Err(PacketBufferTooSmall {
                required: 64,
                provided,
            })
        );
        assert_eq!(destination, before, "provided {provided}");
    }
}

#[test]
fn slice_conversion_and_clone_preserve_value_semantics() {
    let source = frame(128);
    let packet = Packet::try_from(source.as_slice()).unwrap();
    let clone = packet.clone();

    assert_eq!(clone, packet);
    assert_eq!(clone.as_bytes(), source);
    assert!(format!("{packet:?}").contains("len: 128"));
}

#[test]
fn bidirectional_packet_endpoint_preserves_frames_and_bound() {
    let endpoint: Arc<PacketEndpoint> = DuplexEndpoint::new("packet-duplex", 2);
    let first = Packet::copy_from(&frame(60)).unwrap();
    let second = Packet::copy_from(&frame(1_514)).unwrap();
    let rejected = Packet::copy_from(&frame(1)).unwrap();

    endpoint.try_send(first.clone()).unwrap();
    endpoint.try_send(second.clone()).unwrap();
    assert_eq!(endpoint.try_send(rejected.clone()), Err(rejected));
    assert_eq!(endpoint.try_recv(), Some(first));
    assert_eq!(endpoint.try_recv(), Some(second));
    assert_eq!(endpoint.try_recv(), None);
    assert_eq!(endpoint.stats(), (2, 2, 0));
}

#[test]
fn directional_views_share_one_queue_and_only_expose_their_operation() {
    let endpoint: Arc<Endpoint<Packet>> = Endpoint::new("packet-directional", 1);
    let (sender, receiver): (SendEndpoint<Packet>, RecvEndpoint<Packet>) = directional(endpoint);
    let packet = Packet::copy_from(&frame(151)).unwrap();

    sender.try_send(packet.clone()).unwrap();
    assert_eq!(sender.stats(), (1, 0, 1));
    assert_eq!(receiver.try_recv(), Some(packet));
    assert_eq!(receiver.stats(), (1, 1, 0));
}

#[test]
fn directional_async_methods_retain_the_same_message_type_and_direction() {
    let endpoint: Arc<Endpoint<Packet>> = Endpoint::new("packet-async-directional", 1);
    let (sender, receiver) = directional(endpoint);
    let packet = Packet::copy_from(&frame(512)).unwrap();

    expect_ready(sender.send(packet.clone()));
    assert_eq!(expect_ready(receiver.recv()), packet);
}

#[test]
fn independently_narrowed_and_cloned_views_remain_typed() {
    let endpoint: Arc<Endpoint<u32>> = Endpoint::new("typed-u32", 3);
    let sender: SendEndpoint<u32> = send_only(endpoint.clone());
    let receiver: RecvEndpoint<u32> = recv_only(endpoint);
    let other_sender = sender.clone();
    let other_receiver = receiver.clone();

    sender.try_send(0x1234_5678).unwrap();
    other_sender.try_send(0xfeed_beef).unwrap();
    assert_eq!(other_receiver.try_recv(), Some(0x1234_5678));
    assert_eq!(receiver.try_recv(), Some(0xfeed_beef));
}

#[test]
fn capability_rights_select_direction_on_endpoint_packet() {
    let endpoint: Arc<Endpoint<Packet>> = Endpoint::new("packet-caps", 2);
    let mut producer = CSpace::new("packet-producer");
    let mut consumer = CSpace::new("packet-consumer");

    let tx = producer.mint(endpoint.clone(), Rights::SEND);
    let rx = consumer.mint(endpoint, Rights::RECV);

    assert!(producer
        .lookup_as::<Endpoint<Packet>>(tx, Rights::SEND)
        .is_ok());
    assert_eq!(
        producer
            .lookup_as::<Endpoint<Packet>>(tx, Rights::RECV)
            .err(),
        Some(CapError::InsufficientRights)
    );
    assert!(consumer
        .lookup_as::<Endpoint<Packet>>(rx, Rights::RECV)
        .is_ok());
    assert_eq!(
        consumer
            .lookup_as::<Endpoint<Packet>>(rx, Rights::SEND)
            .err(),
        Some(CapError::InsufficientRights)
    );
}

#[test]
fn endpoint_message_type_is_part_of_capability_lookup() {
    let endpoint: Arc<Endpoint<Packet>> = Endpoint::new("packet-type", 1);
    let mut space = CSpace::new("packet-type-space");
    let cap = space.mint(endpoint, Rights::SEND);

    assert!(space
        .lookup_as::<Endpoint<Packet>>(cap, Rights::SEND)
        .is_ok());
    assert_eq!(
        space
            .lookup_as::<Endpoint<Vec<u8>>>(cap, Rights::SEND)
            .err(),
        Some(CapError::WrongType),
        "Endpoint<Packet> is not an Endpoint<Vec<u8>> byte stream"
    );
}

#[test]
fn packet_and_directional_handles_are_send_and_sync_without_payload_clone_bounds() {
    struct SendOnly(u8);

    fn assert_send_sync<T: Send + Sync>() {}
    fn clone_sender_without_t_clone(value: &SendEndpoint<SendOnly>) -> SendEndpoint<SendOnly> {
        value.clone()
    }
    fn clone_receiver_without_t_clone(value: &RecvEndpoint<SendOnly>) -> RecvEndpoint<SendOnly> {
        value.clone()
    }

    assert_send_sync::<Packet>();
    assert_send_sync::<SendEndpoint<Packet>>();
    assert_send_sync::<RecvEndpoint<Packet>>();

    let endpoint = Endpoint::new("send-only-payload", 1);
    let (sender, receiver) = directional(endpoint);
    let sender_clone = clone_sender_without_t_clone(&sender);
    let receiver_clone = clone_receiver_without_t_clone(&receiver);
    sender_clone
        .try_send(SendOnly(7))
        .map_err(|value| value.0)
        .unwrap();
    assert_eq!(receiver_clone.try_recv().unwrap().0, 7);
}
