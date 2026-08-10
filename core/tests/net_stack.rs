use std::sync::Arc;

use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device as _, RxToken as _, TxToken as _};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

use vibeos_core::cap::{CSpace, Cap, Revocable, Rights};
use vibeos_core::chan::Endpoint;
use vibeos_core::net::{
    PacketSessionError, PacketSessionFence, PacketStamp, PacketStampMismatch, StampedPacket,
};
use vibeos_core::net_stack::{
    PacketDevice, StackError, StaticIpv4Config, StaticIpv4EchoStack, StaticIpv4TcpStack,
    TcpIoResult, TcpStreamState, MAX_TCP_STREAM_BYTES_PER_CALL, TCP_BUFFER_BYTES,
};

const SERVER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const CLIENT_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
const SERVER_IP: [u8; 4] = [192, 0, 2, 1];
const CLIENT_IP: [u8; 4] = [192, 0, 2, 2];
const SERVER_PORT: u16 = 22_222;

fn authority(
    space: &mut CSpace,
    endpoint: &Arc<Endpoint<StampedPacket>>,
    rights: Rights,
) -> (Cap, Revocable<Endpoint<StampedPacket>>) {
    let root = space.mint(endpoint.clone(), rights.union(Rights::REVOKE));
    let token = space
        .lookup_revocable::<Endpoint<StampedPacket>>(root, rights)
        .unwrap();
    (root, token)
}

fn session_stamp() -> PacketStamp {
    PacketStamp::new(7, 11).unwrap()
}

fn server_config() -> StaticIpv4Config {
    StaticIpv4Config::new(SERVER_MAC, SERVER_IP, 24, SERVER_PORT, 0x5eed)
}

#[test]
fn packet_device_retains_one_frame_across_endpoint_backpressure() {
    let inbound = Endpoint::new("device-in", 1);
    let outbound = Endpoint::new("device-out", 1);
    let stamp = session_stamp();
    let blocker = StampedPacket::copy_from(&[0xaa; 60], stamp).unwrap();
    outbound.try_send(blocker.clone()).unwrap();

    let mut space = CSpace::new("packet-device");
    let (_, inbound_authority) = authority(&mut space, &inbound, Rights::RECV);
    let (_, outbound_authority) = authority(&mut space, &outbound, Rights::SEND);
    let mut device = PacketDevice::new(stamp, inbound_authority, outbound_authority);

    let token = device.transmit(Instant::ZERO).unwrap();
    token.consume(60, |frame| {
        for (index, byte) in frame.iter_mut().enumerate() {
            *byte = index as u8;
        }
    });

    assert!(device.stats().pending_egress);
    assert_eq!(outbound.stats().2, 1);
    assert_eq!(outbound.try_recv().unwrap(), blocker);
    assert_eq!(device.flush_egress(), Ok(true));

    let sent = outbound.try_recv().unwrap().into_packet(stamp).unwrap();
    assert_eq!(sent.len(), 60);
    assert_eq!(sent.as_bytes()[0], 0);
    assert_eq!(sent.as_bytes()[59], 59);
    assert_eq!(device.stats().tx_frames, 1);
    assert!(!device.stats().pending_egress);
}

#[test]
fn packet_device_rejects_stale_ingress_without_blocking_fresh_traffic() {
    let inbound = Endpoint::new("stale-device-in", 1);
    let outbound = Endpoint::new("stale-device-out", 1);
    let expected = session_stamp();
    let stale_device =
        PacketStamp::new(expected.device_epoch() - 1, expected.stack_generation()).unwrap();
    inbound
        .try_send(StampedPacket::copy_from(&[0x45; 60], stale_device).unwrap())
        .unwrap();

    let mut space = CSpace::new("stale-packet-device");
    let (inbound_root, inbound_authority) = authority(&mut space, &inbound, Rights::RECV);
    let (_, outbound_authority) = authority(&mut space, &outbound, Rights::SEND);
    let mut device = PacketDevice::new(expected, inbound_authority, outbound_authority);

    assert!(device.receive(Instant::ZERO).is_none());
    assert_eq!(device.revalidate_authority(), Ok(()));
    assert_eq!(device.stats().rx_frames, 0);
    assert_eq!(device.stats().rejected_ingress_frames, 1);
    assert_eq!(device.stats().rejected_device_epoch_frames, 1);
    assert_eq!(device.stats().rejected_stack_generation_frames, 0);

    let stale_stack =
        PacketStamp::new(expected.device_epoch(), expected.stack_generation() - 1).unwrap();
    inbound
        .try_send(StampedPacket::copy_from(&[0x47; 60], stale_stack).unwrap())
        .unwrap();
    assert!(device.receive(Instant::ZERO).is_none());
    assert_eq!(device.stats().rejected_ingress_frames, 2);
    assert_eq!(device.stats().rejected_device_epoch_frames, 1);
    assert_eq!(device.stats().rejected_stack_generation_frames, 1);

    inbound
        .try_send(StampedPacket::copy_from(&[0x46; 60], expected).unwrap())
        .unwrap();
    let (receive, _) = device.receive(Instant::ZERO).unwrap();
    receive.consume(|frame| assert_eq!(frame, &[0x46; 60]));
    assert_eq!(device.stats().rx_frames, 1);
    assert_eq!(device.stats().rejected_ingress_frames, 2);
    assert_eq!(device.stats().rejected_device_epoch_frames, 1);
    assert_eq!(device.stats().rejected_stack_generation_frames, 1);
    assert_eq!(inbound.stats().2, 0);

    space.revoke(inbound_root).unwrap();
    assert_eq!(
        device.revalidate_authority(),
        Err(StackError::AuthorityRevoked),
        "capability revocation remains terminal and takes precedence"
    );
}

#[test]
fn stack_egress_is_stamped_and_a_rebound_driver_rejects_it() {
    let inbound = Endpoint::new("stale-egress-in", 1);
    let outbound = Endpoint::new("stale-egress-out", 1);
    let old_stamp = session_stamp();
    let mut space = CSpace::new("stale-egress-device");
    let (_, inbound_authority) = authority(&mut space, &inbound, Rights::RECV);
    let (_, outbound_authority) = authority(&mut space, &outbound, Rights::SEND);
    let mut device = PacketDevice::new(old_stamp, inbound_authority, outbound_authority);

    device
        .transmit(Instant::ZERO)
        .unwrap()
        .consume(60, |frame| frame.fill(0x5a));
    let stale_egress = outbound.try_recv().unwrap();
    assert_eq!(stale_egress.stamp(), old_stamp);

    let mut driver = PacketSessionFence::from_history(
        old_stamp.device_epoch() - 1,
        old_stamp.stack_generation(),
    );
    assert_eq!(driver.attach_device(), Ok(old_stamp.device_epoch()));
    let current = driver.bind_stack(0).unwrap();
    assert_eq!(
        current,
        PacketStamp::new(old_stamp.device_epoch(), old_stamp.stack_generation() + 1).unwrap()
    );
    assert_eq!(
        driver.accept_egress(stale_egress),
        Err(PacketSessionError::StampMismatch(PacketStampMismatch {
            expected: current,
            observed: old_stamp,
        }))
    );
}

#[test]
fn transmit_token_cannot_outlive_revocation() {
    let inbound = Endpoint::new("revoked-device-in", 1);
    let outbound = Endpoint::new("revoked-device-out", 1);
    let mut space = CSpace::new("revoked-packet-device");
    let (_, inbound_authority) = authority(&mut space, &inbound, Rights::RECV);
    let (outbound_root, outbound_authority) = authority(&mut space, &outbound, Rights::SEND);
    let mut device = PacketDevice::new(session_stamp(), inbound_authority, outbound_authority);

    let token = device.transmit(Instant::ZERO).unwrap();
    space.revoke(outbound_root).unwrap();
    token.consume(60, |frame| frame.fill(0x5a));

    assert_eq!(outbound.stats().2, 0);
    assert_eq!(device.stats().tx_frames, 0);
    assert_eq!(
        device.revalidate_authority(),
        Err(StackError::AuthorityRevoked)
    );
}

#[test]
fn stack_revalidates_authority_and_monotonic_time() {
    let inbound = Endpoint::new("server-in", 4);
    let outbound = Endpoint::new("server-out", 4);
    let mut space = CSpace::new("server-caps");
    let (inbound_root, inbound_authority) = authority(&mut space, &inbound, Rights::RECV);
    let (_, outbound_authority) = authority(&mut space, &outbound, Rights::SEND);
    let mut stack = StaticIpv4EchoStack::new(
        server_config(),
        session_stamp(),
        inbound_authority,
        outbound_authority,
    )
    .unwrap();

    stack.step(10).unwrap();
    assert!(stack.is_listening());
    assert_eq!(
        stack.step(9),
        Err(StackError::ClockWentBackwards {
            previous_ms: 10,
            now_ms: 9,
        })
    );

    space.revoke(inbound_root).unwrap();
    assert_eq!(stack.step(11), Err(StackError::AuthorityRevoked));
    assert_eq!(stack.step(12), Err(StackError::AuthorityRevoked));
}

struct TestClient {
    device: PacketDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    tcp_handle: SocketHandle,
}

impl TestClient {
    fn new(
        inbound: Revocable<Endpoint<StampedPacket>>,
        outbound: Revocable<Endpoint<StampedPacket>>,
    ) -> Self {
        let mut device = PacketDevice::new(session_stamp(), inbound, outbound);
        device.revalidate_authority().unwrap();

        let mut config = InterfaceConfig::new(EthernetAddress(CLIENT_MAC).into());
        config.random_seed = 0xc1e17;
        let mut interface = Interface::new(config, &mut device, Instant::ZERO);
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(
                    IpAddress::v4(CLIENT_IP[0], CLIENT_IP[1], CLIENT_IP[2], CLIENT_IP[3]),
                    24,
                ))
                .unwrap();
        });

        let receive = tcp::SocketBuffer::new(vec![0; 4096]);
        let transmit = tcp::SocketBuffer::new(vec![0; 4096]);
        let socket = tcp::Socket::new(receive, transmit);
        let mut sockets = SocketSet::new(Vec::new());
        let tcp_handle = sockets.add(socket);
        sockets
            .get_mut::<tcp::Socket>(tcp_handle)
            .connect(
                interface.context(),
                (
                    IpAddress::v4(SERVER_IP[0], SERVER_IP[1], SERVER_IP[2], SERVER_IP[3]),
                    SERVER_PORT,
                ),
                49_152,
            )
            .unwrap();

        Self {
            device,
            interface,
            sockets,
            tcp_handle,
        }
    }

    fn poll(&mut self, now_ms: u64) {
        self.device.revalidate_authority().unwrap();
        self.interface.poll(
            Instant::from_millis(now_ms as i64),
            &mut self.device,
            &mut self.sockets,
        );
        assert_eq!(self.device.flush_egress(), Ok(true));
    }

    fn socket(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(self.tcp_handle)
    }
}

fn raw_tcp_pair() -> (StaticIpv4TcpStack, TestClient) {
    let client_to_server = Endpoint::new("raw-client-to-server", 64);
    let server_to_client = Endpoint::new("raw-server-to-client", 64);
    let mut space = CSpace::new("raw-test-link");

    let (_, server_in) = authority(&mut space, &client_to_server, Rights::RECV);
    let (_, server_out) = authority(&mut space, &server_to_client, Rights::SEND);
    let (_, client_in) = authority(&mut space, &server_to_client, Rights::RECV);
    let (_, client_out) = authority(&mut space, &client_to_server, Rights::SEND);

    (
        StaticIpv4TcpStack::new(server_config(), session_stamp(), server_in, server_out).unwrap(),
        TestClient::new(client_in, client_out),
    )
}

fn connect_raw_pair(server: &mut StaticIpv4TcpStack, client: &mut TestClient) -> u64 {
    for now_ms in 0..2_000 {
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        if server.stream_status().state == TcpStreamState::Established && client.socket().may_send()
        {
            return now_ms + 1;
        }
    }
    panic!("dual-smoltcp TCP handshake did not complete");
}

#[test]
fn static_ipv4_stack_resolves_arp_and_echoes_one_tcp_connection() {
    let client_to_server = Endpoint::new("client-to-server", 32);
    let server_to_client = Endpoint::new("server-to-client", 32);
    let mut space = CSpace::new("test-link");

    let (_, server_in) = authority(&mut space, &client_to_server, Rights::RECV);
    let (_, server_out) = authority(&mut space, &server_to_client, Rights::SEND);
    let (_, client_in) = authority(&mut space, &server_to_client, Rights::RECV);
    let (_, client_out) = authority(&mut space, &client_to_server, Rights::SEND);

    let mut server =
        StaticIpv4EchoStack::new(server_config(), session_stamp(), server_in, server_out).unwrap();
    let mut client = TestClient::new(client_in, client_out);

    // The first client egress is an ARP request for the on-link static address.
    client.poll(0);
    let request = client_to_server.try_recv().unwrap();
    let request_frame = request.clone().into_packet(session_stamp()).unwrap();
    assert_eq!(&request_frame.as_bytes()[0..6], &[0xff; 6]);
    assert_eq!(&request_frame.as_bytes()[12..14], &[0x08, 0x06]);
    client_to_server.try_send(request).unwrap();

    server.step(0).unwrap();
    let reply = server_to_client.try_recv().unwrap();
    let reply_frame = reply.clone().into_packet(session_stamp()).unwrap();
    assert_eq!(&reply_frame.as_bytes()[0..6], &CLIENT_MAC);
    assert_eq!(&reply_frame.as_bytes()[12..14], &[0x08, 0x06]);
    server_to_client.try_send(reply).unwrap();

    let payload: Vec<u8> = (0..3_000).map(|index| (index % 251) as u8).collect();
    let mut sent = false;
    let mut echoed = Vec::new();
    let mut saw_connection = false;

    for now_ms in 1..5_000 {
        client.poll(now_ms);
        let report = server.step(now_ms).unwrap();
        saw_connection |= report.connection_started || server.connection_active();
        client.poll(now_ms);

        let socket = client.socket();
        if !sent && socket.can_send() {
            assert_eq!(socket.send_slice(&payload).unwrap(), payload.len());
            sent = true;
        }
        if socket.can_recv() {
            let available = socket.recv_queue();
            let start = echoed.len();
            echoed.resize(start + available, 0);
            let received = socket.recv_slice(&mut echoed[start..]).unwrap();
            echoed.truncate(start + received);
        }
        if echoed.len() == payload.len() {
            break;
        }
    }

    assert!(saw_connection);
    assert!(sent);
    assert_eq!(echoed, payload);
    assert!(server.device_stats().rx_frames > 0);
    assert!(server.device_stats().tx_frames > 0);
}

#[test]
fn raw_tcp_stream_fragments_both_directions_and_reports_backpressure_and_eof() {
    let (mut server, mut client) = raw_tcp_pair();
    let mut now_ms = connect_raw_pair(&mut server, &mut client);

    assert_eq!(server.stream_status().state, TcpStreamState::Established);
    let mut empty = [0u8; 32];
    assert_eq!(server.try_recv(&mut empty), Ok(TcpIoResult::WouldBlock));

    let upstream: Vec<u8> = (0..3_571).map(|index| (index % 239) as u8).collect();
    let mut upstream_sent = 0;
    let mut upstream_received = Vec::new();
    for turn in 0..10_000 {
        if upstream_sent < upstream.len() && client.socket().can_send() {
            let fragment = (37 + turn % 211).min(upstream.len() - upstream_sent);
            let sent = client
                .socket()
                .send_slice(&upstream[upstream_sent..upstream_sent + fragment])
                .unwrap();
            upstream_sent += sent;
        }

        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        let mut fragment = [0u8; 257];
        match server.try_recv(&mut fragment).unwrap() {
            TcpIoResult::Progress(received) => {
                assert!(received <= fragment.len());
                assert!(received <= MAX_TCP_STREAM_BYTES_PER_CALL);
                upstream_received.extend_from_slice(&fragment[..received]);
            }
            TcpIoResult::WouldBlock => {}
            TcpIoResult::Closed => panic!("server receive half closed before the payload arrived"),
        }
        client.poll(now_ms);
        now_ms += 1;

        if upstream_sent == upstream.len() && upstream_received.len() == upstream.len() {
            break;
        }
    }
    assert_eq!(upstream_received, upstream);

    let downstream: Vec<u8> = (0..(TCP_BUFFER_BYTES + 2_731))
        .map(|index| (index % 251) as u8)
        .collect();
    let mut downstream_queued = 0;
    loop {
        match server.try_send(&downstream[downstream_queued..]).unwrap() {
            TcpIoResult::Progress(sent) => {
                assert!(sent <= MAX_TCP_STREAM_BYTES_PER_CALL);
                downstream_queued += sent;
            }
            TcpIoResult::WouldBlock => break,
            TcpIoResult::Closed => panic!("server transmit half closed while established"),
        }
    }
    assert_eq!(downstream_queued, TCP_BUFFER_BYTES);
    assert_eq!(server.stream_status().writable_bytes, 0);
    assert_eq!(
        server.try_send(&downstream[downstream_queued..]),
        Ok(TcpIoResult::WouldBlock)
    );

    let mut downstream_received = Vec::new();
    for _ in 0..20_000 {
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);

        if client.socket().can_recv() {
            let mut fragment = [0u8; 313];
            let received = client.socket().recv_slice(&mut fragment).unwrap();
            downstream_received.extend_from_slice(&fragment[..received]);
        }
        if downstream_queued < downstream.len() {
            match server.try_send(&downstream[downstream_queued..]).unwrap() {
                TcpIoResult::Progress(sent) => {
                    assert!(sent <= MAX_TCP_STREAM_BYTES_PER_CALL);
                    downstream_queued += sent;
                }
                TcpIoResult::WouldBlock => {}
                TcpIoResult::Closed => panic!("server transmit half closed before EOF"),
            }
        }

        client.poll(now_ms);
        now_ms += 1;
        if downstream_queued == downstream.len()
            && downstream_received.len() == downstream.len()
            && server.stream_status().queued_send_bytes == 0
        {
            break;
        }
    }
    assert_eq!(downstream_received, downstream);

    client.socket().close();
    let mut saw_eof = false;
    for _ in 0..5_000 {
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        now_ms += 1;
        if server.stream_status().state == TcpStreamState::PeerClosed {
            assert_eq!(server.try_recv(&mut empty), Ok(TcpIoResult::Closed));
            saw_eof = true;
            break;
        }
    }
    assert!(saw_eof, "server did not observe the client's FIN as EOF");
    assert_eq!(server.close(), Ok(TcpStreamState::Closing));

    let mut saw_connection_end = false;
    for _ in 0..5_000 {
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        let report = server.poll_network(now_ms).unwrap();
        saw_connection_end |= report.connection_ended;
        now_ms += 1;
        if server.stream_status().state == TcpStreamState::Listening {
            break;
        }
    }
    assert!(saw_connection_end);
    assert_eq!(server.stream_status().state, TcpStreamState::Listening);
}

#[test]
fn raw_tcp_reset_is_terminal_until_a_network_poll_rearms_the_listener() {
    let (mut server, mut client) = raw_tcp_pair();
    let now_ms = connect_raw_pair(&mut server, &mut client);

    assert_eq!(server.reset(), Ok(TcpStreamState::Reset));
    assert_eq!(server.stream_status().state, TcpStreamState::Reset);
    assert_eq!(server.try_send(b"stale"), Ok(TcpIoResult::Closed));
    let mut output = [0u8; 16];
    assert_eq!(server.try_recv(&mut output), Ok(TcpIoResult::Closed));

    let report = server.poll_network(now_ms).unwrap();
    assert!(report.connection_ended);
    assert_eq!(server.stream_status().state, TcpStreamState::Listening);
    client.poll(now_ms);
    assert!(!client.socket().may_send());
}
