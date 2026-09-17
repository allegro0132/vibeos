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
use vibeos_net_api::{TcpListener, TcpListenerId};
use vibeos_net_protocol::{
    Ipv4RuntimeStatus, Ipv4StackConfig, PacketDevice, SharedIpv4TcpStack, StackError,
    StaticIpv4Address, StaticIpv4Config, StaticIpv4EchoStack, StaticIpv4TcpStack, TcpIoResult,
    TcpStreamState, MAX_TCP_LISTENERS, MAX_TCP_STREAM_BYTES_PER_CALL, TCP_BUFFER_BYTES,
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
fn stack_switches_between_static_unconfigured_and_dhcp_discovery() {
    let inbound = Endpoint::new("dhcp-in", 4);
    let outbound = Endpoint::new("dhcp-out", 4);
    let stamp = session_stamp();
    let mut space = CSpace::new("dhcp-stack");
    let (_, inbound_authority) = authority(&mut space, &inbound, Rights::RECV);
    let (_, outbound_authority) = authority(&mut space, &outbound, Rights::SEND);
    let mut stack = StaticIpv4TcpStack::new(
        server_config(),
        stamp,
        inbound_authority,
        outbound_authority,
    )
    .unwrap();

    stack.start_dhcp().unwrap();
    assert_eq!(stack.ipv4_status(), Ipv4RuntimeStatus::DhcpDiscovering);
    stack.poll_network(0).unwrap();
    let discover = outbound.try_recv().unwrap().into_packet(stamp).unwrap();
    let frame = discover.as_bytes();
    assert_eq!(&frame[..6], &[0xff; 6]);
    assert_eq!(&frame[6..12], &SERVER_MAC);
    assert_eq!(&frame[12..14], &[0x08, 0x00]);
    assert_eq!(&frame[26..30], &[0, 0, 0, 0]);
    assert_eq!(&frame[30..34], &[255, 255, 255, 255]);
    assert_eq!(&frame[34..38], &[0, 68, 0, 67]);

    stack.clear_ipv4().unwrap();
    assert_eq!(stack.ipv4_status(), Ipv4RuntimeStatus::Unconfigured);
    let replacement =
        StaticIpv4Address::new([198, 51, 100, 9], 24).with_default_gateway([198, 51, 100, 1]);
    stack.configure_static_ipv4(replacement).unwrap();
    assert_eq!(stack.ipv4_status(), Ipv4RuntimeStatus::Static(replacement));
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
fn packet_device_only_suppresses_checksums_for_enabled_offloads() {
    let inbound = Endpoint::new("checksum-in", 1);
    let outbound = Endpoint::new("checksum-out", 1);
    let mut space = CSpace::new("checksum-device");
    let (_, inbound_authority) = authority(&mut space, &inbound, Rights::RECV);
    let (_, outbound_authority) = authority(&mut space, &outbound, Rights::SEND);
    let mut device = PacketDevice::new(session_stamp(), inbound_authority, outbound_authority);

    assert!(device.capabilities().checksum.tcp.tx());
    device.set_tx_checksum_offload(true);
    let checksum = device.capabilities().checksum;
    assert!(checksum.ipv4.rx() && !checksum.ipv4.tx());
    assert!(checksum.tcp.rx() && !checksum.tcp.tx());
    assert!(checksum.udp.rx() && !checksum.udp.tx());
    assert!(checksum.icmpv4.rx() && checksum.icmpv4.tx());

    device.set_tx_checksum_offload(false);
    device.set_rx_checksum_offload(true);
    let checksum = device.capabilities().checksum;
    assert!(!checksum.ipv4.rx() && checksum.ipv4.tx());
    assert!(!checksum.tcp.rx() && checksum.tcp.tx());
    assert!(!checksum.udp.rx() && checksum.udp.tx());

    device.set_tx_checksum_offload(true);
    let checksum = device.capabilities().checksum;
    assert!(!checksum.ipv4.rx() && !checksum.ipv4.tx());
    assert!(!checksum.tcp.rx() && !checksum.tcp.tx());
    assert!(!checksum.udp.rx() && !checksum.udp.tx());
    assert!(checksum.icmpv4.rx() && checksum.icmpv4.tx());
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
        Self::with_transmit_capacity(inbound, outbound, 4096)
    }

    fn with_transmit_capacity(
        inbound: Revocable<Endpoint<StampedPacket>>,
        outbound: Revocable<Endpoint<StampedPacket>>,
        transmit_capacity: usize,
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
        let transmit = tcp::SocketBuffer::new(vec![0; transmit_capacity]);
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

    fn reconnect(&mut self, local_port: u16) {
        self.sockets
            .get_mut::<tcp::Socket>(self.tcp_handle)
            .connect(
                self.interface.context(),
                (
                    IpAddress::v4(SERVER_IP[0], SERVER_IP[1], SERVER_IP[2], SERVER_IP[3]),
                    SERVER_PORT,
                ),
                local_port,
            )
            .unwrap();
    }

    fn open_connection(&mut self, local_port: u16) -> SocketHandle {
        self.open_connection_to(SERVER_PORT, local_port)
    }

    fn open_connection_to(&mut self, server_port: u16, local_port: u16) -> SocketHandle {
        let receive = tcp::SocketBuffer::new(vec![0; 4096]);
        let transmit = tcp::SocketBuffer::new(vec![0; 4096]);
        let handle = self.sockets.add(tcp::Socket::new(receive, transmit));
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(
                self.interface.context(),
                (
                    IpAddress::v4(SERVER_IP[0], SERVER_IP[1], SERVER_IP[2], SERVER_IP[3]),
                    server_port,
                ),
                local_port,
            )
            .unwrap();
        handle
    }

    fn socket_by_handle(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(handle)
    }
}

#[test]
fn one_interface_serves_two_independent_tcp_ports() {
    const SECOND_PORT: u16 = SERVER_PORT + 1;

    let client_to_server = Endpoint::new("shared-client-to-server", 128);
    let server_to_client = Endpoint::new("shared-server-to-client", 128);
    let mut space = CSpace::new("shared-test-link");
    let (_, server_in) = authority(&mut space, &client_to_server, Rights::RECV);
    let (_, server_out) = authority(&mut space, &server_to_client, Rights::SEND);
    let (_, client_in) = authority(&mut space, &server_to_client, Rights::RECV);
    let (_, client_out) = authority(&mut space, &client_to_server, Rights::SEND);

    let config = Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 0x5eed);
    let mut server =
        SharedIpv4TcpStack::new(config, session_stamp(), server_in, server_out).unwrap();
    let first = server.add_tcp_listener(SERVER_PORT).unwrap();
    let second = server.add_tcp_listener(SECOND_PORT).unwrap();
    assert_eq!(
        server.add_tcp_listener(SERVER_PORT),
        Err(StackError::ListenPortInUse)
    );
    assert_eq!(
        server.add_tcp_listener(0),
        Err(StackError::InvalidListenPort)
    );

    let mut client = TestClient::new(client_in, client_out);
    let second_client = client.open_connection_to(SECOND_PORT, 49_153);
    let first_payload = b"listener-22";
    let second_payload = b"listener-23";
    let mut first_sent = false;
    let mut second_sent = false;
    let mut first_server_received = Vec::new();
    let mut second_server_received = Vec::new();
    let mut first_client_received = Vec::new();
    let mut second_client_received = Vec::new();

    for now_ms in 0..5_000 {
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);

        if !first_sent && client.socket().can_send() {
            assert_eq!(
                client.socket().send_slice(first_payload).unwrap(),
                first_payload.len()
            );
            first_sent = true;
        }
        if !second_sent && client.socket_by_handle(second_client).can_send() {
            assert_eq!(
                client
                    .socket_by_handle(second_client)
                    .send_slice(second_payload)
                    .unwrap(),
                second_payload.len()
            );
            second_sent = true;
        }

        server.poll_network(now_ms).unwrap();
        let mut scratch = [0u8; 32];
        if first_server_received.len() < first_payload.len() {
            if let TcpIoResult::Progress(length) = server.tcp_try_recv(first, &mut scratch).unwrap()
            {
                first_server_received.extend_from_slice(&scratch[..length]);
            }
        }
        if second_server_received.len() < second_payload.len() {
            if let TcpIoResult::Progress(length) =
                server.tcp_try_recv(second, &mut scratch).unwrap()
            {
                second_server_received.extend_from_slice(&scratch[..length]);
            }
        }
        if first_server_received.len() == first_payload.len() && first_client_received.is_empty() {
            assert_eq!(
                server.tcp_try_send(first, b"first").unwrap(),
                TcpIoResult::Progress(5)
            );
        }
        if second_server_received.len() == second_payload.len() && second_client_received.is_empty()
        {
            assert_eq!(
                server.tcp_try_send(second, b"second").unwrap(),
                TcpIoResult::Progress(6)
            );
        }

        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        if client.socket().can_recv() {
            let length = client.socket().recv_slice(&mut scratch).unwrap();
            first_client_received.extend_from_slice(&scratch[..length]);
        }
        if client.socket_by_handle(second_client).can_recv() {
            let length = client
                .socket_by_handle(second_client)
                .recv_slice(&mut scratch)
                .unwrap();
            second_client_received.extend_from_slice(&scratch[..length]);
        }
        if first_client_received.len() >= 5 && second_client_received.len() >= 6 {
            break;
        }
    }

    assert_eq!(first_server_received, first_payload);
    assert_eq!(second_server_received, second_payload);
    assert_eq!(&first_client_received[..5], b"first");
    assert_eq!(&second_client_received[..6], b"second");
    assert_eq!(server.tcp_listener_port(first), Ok(SERVER_PORT));
    assert_eq!(server.tcp_listener_port(second), Ok(SECOND_PORT));
}

#[test]
fn explicit_port_group_accepts_two_simultaneous_tcp_connections() {
    const GROUP: u64 = 0x4950_4552_4633;
    let client_to_server = Endpoint::new("group-client-to-server", 128);
    let server_to_client = Endpoint::new("group-server-to-client", 128);
    let mut space = CSpace::new("group-test-link");
    let (_, server_in) = authority(&mut space, &client_to_server, Rights::RECV);
    let (_, server_out) = authority(&mut space, &server_to_client, Rights::SEND);
    let (_, client_in) = authority(&mut space, &server_to_client, Rights::RECV);
    let (_, client_out) = authority(&mut space, &client_to_server, Rights::SEND);

    let config = Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 0x5eed);
    let mut server =
        SharedIpv4TcpStack::new(config, session_stamp(), server_in, server_out).unwrap();
    let control = server.add_shared_tcp_listener(SERVER_PORT, GROUP).unwrap();
    let data = server.add_shared_tcp_listener(SERVER_PORT, GROUP).unwrap();
    assert_eq!(
        server.add_shared_tcp_listener(SERVER_PORT, GROUP + 1),
        Err(StackError::ListenPortInUse)
    );
    assert_eq!(
        server.add_tcp_listener(SERVER_PORT),
        Err(StackError::ListenPortInUse)
    );

    let mut client = TestClient::new(client_in, client_out);
    let second_client = client.open_connection_to(SERVER_PORT, 49_153);
    let mut both_active = false;
    for now_ms in 0..5_000 {
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        if server.tcp_connection_active(control).unwrap()
            && server.tcp_connection_active(data).unwrap()
        {
            both_active = true;
            break;
        }
        let _ = client.socket_by_handle(second_client);
    }

    assert!(
        both_active,
        "both sockets in the shared port group must accept"
    );
}

#[test]
fn two_capability_frontends_share_one_interface_without_crossing_streams() {
    const HTTP_PORT: u16 = 80;
    let client_to_server = Endpoint::new("frontend-client-to-server", 128);
    let server_to_client = Endpoint::new("frontend-server-to-client", 128);
    let mut space = CSpace::new("frontend-test-link");
    let (_, server_in) = authority(&mut space, &client_to_server, Rights::RECV);
    let (_, server_out) = authority(&mut space, &server_to_client, Rights::SEND);
    let (_, client_in) = authority(&mut space, &server_to_client, Rights::RECV);
    let (_, client_out) = authority(&mut space, &client_to_server, Rights::SEND);

    let config = Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 0x5eed);
    let mut server =
        SharedIpv4TcpStack::new(config, session_stamp(), server_in, server_out).unwrap();
    let ssh_socket = server.add_tcp_listener(SERVER_PORT).unwrap();
    let http_socket = server.add_tcp_listener(HTTP_PORT).unwrap();
    let ssh =
        TcpListener::new("ssh", TcpListenerId::new(1).unwrap(), SERVER_PORT, 128, 128).unwrap();
    let http =
        TcpListener::new("http", TcpListenerId::new(2).unwrap(), HTTP_PORT, 128, 128).unwrap();

    let mut client = TestClient::new(client_in, client_out);
    let http_client = client.open_connection_to(HTTP_PORT, 49_153);
    let mut ssh_connection = None;
    let mut http_connection = None;
    let mut ssh_request_sent = false;
    let mut http_request_sent = false;
    let mut ssh_request = Vec::new();
    let mut http_request = Vec::new();
    let mut ssh_response_sent = false;
    let mut http_response_sent = false;
    let mut ssh_response = Vec::new();
    let mut http_response = Vec::new();
    let mut scratch = [0u8; 64];

    for now_ms in 0..5_000 {
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        server.drive_tcp_frontend(ssh_socket, &ssh).unwrap();
        server.drive_tcp_frontend(http_socket, &http).unwrap();

        ssh_connection = ssh_connection.or_else(|| ssh.try_accept());
        http_connection = http_connection.or_else(|| http.try_accept());
        if !ssh_request_sent && client.socket().can_send() {
            assert_eq!(client.socket().send_slice(b"ssh").unwrap(), 3);
            ssh_request_sent = true;
        }
        if !http_request_sent && client.socket_by_handle(http_client).can_send() {
            assert_eq!(
                client
                    .socket_by_handle(http_client)
                    .send_slice(b"GET /")
                    .unwrap(),
                5
            );
            http_request_sent = true;
        }

        if let Some(connection) = ssh_connection {
            if ssh_request.len() < 3 {
                if let TcpIoResult::Progress(length) =
                    ssh.try_recv(connection, &mut scratch).unwrap()
                {
                    ssh_request.extend_from_slice(&scratch[..length]);
                }
            }
            if ssh_request.len() == 3 && !ssh_response_sent {
                assert_eq!(
                    ssh.try_send(connection, b"SSH-OK"),
                    Ok(TcpIoResult::Progress(6))
                );
                ssh_response_sent = true;
            }
        }
        if let Some(connection) = http_connection {
            if http_request.len() < 5 {
                if let TcpIoResult::Progress(length) =
                    http.try_recv(connection, &mut scratch).unwrap()
                {
                    http_request.extend_from_slice(&scratch[..length]);
                }
            }
            if http_request.len() == 5 && !http_response_sent {
                assert_eq!(
                    http.try_send(connection, b"HTTP-OK"),
                    Ok(TcpIoResult::Progress(7))
                );
                http_response_sent = true;
            }
        }

        server.drive_tcp_frontend(ssh_socket, &ssh).unwrap();
        server.drive_tcp_frontend(http_socket, &http).unwrap();
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        if client.socket().can_recv() {
            let length = client.socket().recv_slice(&mut scratch).unwrap();
            ssh_response.extend_from_slice(&scratch[..length]);
        }
        if client.socket_by_handle(http_client).can_recv() {
            let length = client
                .socket_by_handle(http_client)
                .recv_slice(&mut scratch)
                .unwrap();
            http_response.extend_from_slice(&scratch[..length]);
        }
        if ssh_response.len() == 6 && http_response.len() == 7 {
            break;
        }
    }

    assert_eq!(ssh_request, b"ssh");
    assert_eq!(http_request, b"GET /");
    assert_eq!(ssh_response, b"SSH-OK");
    assert_eq!(http_response, b"HTTP-OK");
}

#[test]
fn shared_stack_enforces_listener_budget() {
    let inbound = Endpoint::new("listener-budget-in", 4);
    let outbound = Endpoint::new("listener-budget-out", 4);
    let mut space = CSpace::new("listener-budget");
    let (_, server_in) = authority(&mut space, &inbound, Rights::RECV);
    let (_, server_out) = authority(&mut space, &outbound, Rights::SEND);
    let config = Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 0x5eed);
    let mut stack =
        SharedIpv4TcpStack::new(config, session_stamp(), server_in, server_out).unwrap();

    for index in 0..MAX_TCP_LISTENERS {
        stack
            .add_tcp_listener(SERVER_PORT + u16::try_from(index).unwrap())
            .unwrap();
    }
    assert_eq!(
        stack.add_tcp_listener(SERVER_PORT + u16::try_from(MAX_TCP_LISTENERS).unwrap()),
        Err(StackError::TcpListenerLimitReached)
    );
}

fn raw_tcp_pair() -> (StaticIpv4TcpStack, TestClient) {
    raw_tcp_pair_with_transmit_capacity(4096)
}

fn raw_tcp_pair_with_transmit_capacity(transmit_capacity: usize) -> (StaticIpv4TcpStack, TestClient) {
    let client_to_server = Endpoint::new("raw-client-to-server", 64);
    let server_to_client = Endpoint::new("raw-server-to-client", 64);
    let mut space = CSpace::new("raw-test-link");

    let (_, server_in) = authority(&mut space, &client_to_server, Rights::RECV);
    let (_, server_out) = authority(&mut space, &server_to_client, Rights::SEND);
    let (_, client_in) = authority(&mut space, &server_to_client, Rights::RECV);
    let (_, client_out) = authority(&mut space, &client_to_server, Rights::SEND);

    (
        StaticIpv4TcpStack::new(server_config(), session_stamp(), server_in, server_out).unwrap(),
        TestClient::with_transmit_capacity(client_in, client_out, transmit_capacity),
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
fn server_close_acknowledges_a_late_payload_and_fin_before_relisten() {
    let (mut server, mut client) = raw_tcp_pair();
    let mut now_ms = connect_raw_pair(&mut server, &mut client);

    // Exercise the close ordering observed with the physical OpenSSH peer:
    // the server sends FIN first, then the client sends one final 60-byte SSH
    // transport record together with its FIN.
    assert_eq!(server.close(), Ok(TcpStreamState::Closing));
    for _ in 0..1_000 {
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        now_ms += 1;
        if client.socket().state() == tcp::State::CloseWait {
            break;
        }
    }
    assert_eq!(client.socket().state(), tcp::State::CloseWait);

    let final_record = [0x5au8; 60];
    assert_eq!(
        client.socket().send_slice(&final_record).unwrap(),
        final_record.len()
    );
    client.socket().close();

    let mut received = Vec::new();
    for _ in 0..1_000 {
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        let mut fragment = [0u8; 128];
        match server.try_recv(&mut fragment).unwrap() {
            TcpIoResult::Progress(length) => received.extend_from_slice(&fragment[..length]),
            TcpIoResult::WouldBlock | TcpIoResult::Closed => {}
        }
        client.poll(now_ms);
        now_ms += 1;
        if client.socket().state() == tcp::State::Closed {
            break;
        }
    }

    assert_eq!(received, final_record);
    assert_eq!(
        client.socket().state(),
        tcp::State::Closed,
        "the delayed ACK for the final payload+FIN was lost"
    );
    assert_eq!(server.stream_status().state, TcpStreamState::Closing);
    assert!(
        !server.is_listening(),
        "TIME-WAIT was reset into LISTEN early"
    );

    // Once the old tuple's close timer really expires, the reusable socket may
    // become a passive listener again.
    for _ in 0..11_000 {
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        now_ms += 1;
        if server.is_listening() {
            break;
        }
    }
    assert_eq!(server.stream_status().state, TcpStreamState::Listening);
}

#[test]
fn peer_first_close_rearms_quickly_and_accepts_a_second_connection() {
    let (mut server, mut client) = raw_tcp_pair();
    let mut now_ms = connect_raw_pair(&mut server, &mut client);
    let final_record = [0xa5u8; 60];

    assert_eq!(
        client.socket().send_slice(&final_record).unwrap(),
        final_record.len()
    );
    client.socket().close();

    let mut received = Vec::new();
    for _ in 0..100 {
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        let mut fragment = [0u8; 128];
        match server.try_recv(&mut fragment).unwrap() {
            TcpIoResult::Progress(length) => received.extend_from_slice(&fragment[..length]),
            TcpIoResult::WouldBlock | TcpIoResult::Closed => {}
        }
        client.poll(now_ms);
        now_ms += 1;
        if server.stream_status().state == TcpStreamState::PeerClosed
            && received.len() == final_record.len()
        {
            break;
        }
    }
    assert_eq!(received, final_record);
    assert_eq!(server.stream_status().state, TcpStreamState::PeerClosed);

    // This is the SSH server's intended passive-close path: CloseWait ->
    // LastAck -> Closed -> Listen, with no server-side TIME-WAIT delay.
    assert_eq!(server.close(), Ok(TcpStreamState::Closing));
    let close_started = now_ms;
    for _ in 0..100 {
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        now_ms += 1;
        if server.is_listening() {
            break;
        }
    }
    assert!(server.is_listening());
    assert!(
        now_ms - close_started < 100,
        "passive close took {} ms",
        now_ms - close_started
    );

    // A real host opens the next SSH command on a fresh socket while the old
    // active closer remains in TIME-WAIT. Reuse the test socket only after
    // discarding that client-local state, then choose a new source port.
    client.socket().abort();
    client.reconnect(49_153);
    for _ in 0..2_000 {
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        now_ms += 1;
        if server.stream_status().state == TcpStreamState::Established && client.socket().may_send()
        {
            break;
        }
    }
    assert_eq!(server.stream_status().state, TcpStreamState::Established);
    assert!(client.socket().may_send());
}

#[test]
fn next_connection_waits_while_previous_peer_close_is_drained() {
    let (mut server, mut client) = raw_tcp_pair();
    let mut now = connect_raw_pair(&mut server, &mut client);
    client.socket().send_slice(b"old disconnect").unwrap();
    client.socket().close();
    for _ in 0..100 {
        client.poll(now);
        server.poll_network(now).unwrap();
        now += 1;
        if server.stream_status().state == TcpStreamState::PeerClosed { break; }
    }
    assert_eq!(server.stream_status().state, TcpStreamState::PeerClosed);
    // OpenSSH has exited, but the server application has not drained/closed
    // its old connection yet. This SYN must not receive a reset.
    let next = client.open_connection(49_153);
    for _ in 0..100 {
        client.poll(now);
        server.poll_network(now).unwrap();
        now += 1;
        if client.socket_by_handle(next).may_send() { break; }
    }
    assert!(client.socket_by_handle(next).may_send());
    client.socket_by_handle(next).send_slice(b"new identification").unwrap();
    for _ in 0..5 {
        client.poll(now);
        server.poll_network(now).unwrap();
        now += 1;
    }
    let mut bytes = [0; 64];
    assert_eq!(server.try_recv(&mut bytes).unwrap(), TcpIoResult::Progress(14));
    assert_eq!(&bytes[..14], b"old disconnect");
    server.close().unwrap();
    let mut ended = false;
    let mut started = false;
    for _ in 0..100 {
        client.poll(now);
        let report = server.poll_network(now).unwrap();
        if report.connection_started {
            assert!(ended, "successor exposed before old connection ended");
            started = true;
            break;
        }
        ended |= report.connection_ended;
        now += 1;
    }
    assert!(ended && started);
    assert_eq!(server.try_recv(&mut bytes).unwrap(), TcpIoResult::Progress(18));
    assert_eq!(&bytes[..18], b"new identification");
}

#[test]
fn final_ack_and_queued_next_syn_keep_distinct_connection_edges() {
    let (mut server, mut client) = raw_tcp_pair();
    let mut now_ms = connect_raw_pair(&mut server, &mut client);

    client.socket().close();
    for _ in 0..100 {
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        now_ms += 1;
        if server.stream_status().state == TcpStreamState::PeerClosed {
            break;
        }
    }
    assert_eq!(server.stream_status().state, TcpStreamState::PeerClosed);
    assert_eq!(server.close(), Ok(TcpStreamState::Closing));

    // Queue the old tuple's final ACK and a fresh socket's SYN before giving
    // the server another ingress turn.
    server.poll_network(now_ms).unwrap();
    client.poll(now_ms);
    assert_eq!(client.socket().state(), tcp::State::TimeWait);
    let second = client.open_connection(49_153);
    client.poll(now_ms);

    let ended = server.poll_network(now_ms).unwrap();
    assert!(ended.connection_ended);
    assert!(ended.more_work, "the queued next SYN was not retained");
    assert_eq!(server.stream_status().state, TcpStreamState::Listening);
    now_ms += 1;

    for _ in 0..2_000 {
        server.poll_network(now_ms).unwrap();
        client.poll(now_ms);
        server.poll_network(now_ms).unwrap();
        now_ms += 1;
        if server.stream_status().state == TcpStreamState::Established
            && client.socket_by_handle(second).may_send()
        {
            break;
        }
    }
    assert_eq!(server.stream_status().state, TcpStreamState::Established);
    assert!(client.socket_by_handle(second).may_send());
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

#[test]
fn idle_control_connection_survives_long_transfer_but_dead_peer_expires() {
    let (mut server, mut client) = raw_tcp_pair();
    let start = connect_raw_pair(&mut server, &mut client);
    for now in (start..start + 75_000).step_by(100) {
        server.poll_network(now).unwrap();
        client.poll(now);
        server.poll_network(now).unwrap();
        assert_eq!(server.stream_status().state, TcpStreamState::Established);
    }
    // No client polling means no probe acknowledgements: keep the original
    // bounded expiry rather than making idle connections immortal.
    for now in (start + 75_000..start + 110_000).step_by(100) {
        server.poll_network(now).unwrap();
    }
    assert_ne!(server.stream_status().state, TcpStreamState::Established);
}

#[test]
fn frontend_direct_transfer_preserves_bytes_across_wrap_and_backpressure() {
    let to_server = Endpoint::new("direct-to-server", 128);
    let to_client = Endpoint::new("direct-to-client", 128);
    let mut space = CSpace::new("direct-transfer");
    let (server_in_root, server_in) = authority(&mut space, &to_server, Rights::RECV);
    let (_, server_out) = authority(&mut space, &to_client, Rights::SEND);
    let (_, client_in) = authority(&mut space, &to_client, Rights::RECV);
    let (_, client_out) = authority(&mut space, &to_server, Rights::SEND);
    let config = Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 0x5eed);
    let mut server = SharedIpv4TcpStack::new(config, session_stamp(), server_in, server_out).unwrap();
    let socket = server.add_tcp_listener(SERVER_PORT).unwrap();
    // Odd, small capacities force wrapped frontend storage and partial writes.
    let frontend = TcpListener::new("direct", TcpListenerId::new(1).unwrap(), SERVER_PORT, 127, 191).unwrap();
    let mut client = TestClient::new(client_in, client_out);
    // Exceeds both the default and large TCP windows to wrap transport storage.
    let request: Vec<u8> = (0..600_007).map(|i| (i * 37 + i / 251) as u8).collect();
    let response: Vec<u8> = request.iter().map(|b| b ^ 0xa5).collect();
    let (mut request_sent, mut response_sent) = (0, 0);
    let (mut received_request, mut received_response) = (Vec::new(), Vec::new());
    let mut connection = None;
    let mut scratch = [0u8; 997];
    for now in 0..100_000 {
        client.poll(now);
        server.poll_network(now).unwrap();
        let report = server.drive_tcp_frontend(socket, &frontend).unwrap();
        assert!(report.received_bytes <= 4 * 32768);
        assert!(report.transmitted_bytes <= 4 * 32768);
        connection = connection.or_else(|| frontend.try_accept());
        if client.socket().can_send() && request_sent < request.len() {
            request_sent += client.socket().send_slice(&request[request_sent..]).unwrap();
        }
        if let Some(peer) = connection {
            // Leave receive queues full on alternate turns to exercise backpressure.
            if now % 2 == 0 {
                if let TcpIoResult::Progress(n) = frontend.try_recv(peer, &mut scratch[..61]).unwrap() {
                    received_request.extend_from_slice(&scratch[..n]);
                }
            }
            if response_sent < response.len() {
                if let TcpIoResult::Progress(n) = frontend.try_send(peer, &response[response_sent..]).unwrap() {
                    response_sent += n;
                }
            }
        }
        if now % 5 == 0 && client.socket().can_recv() {
            let n = client.socket().recv_slice(&mut scratch).unwrap();
            received_response.extend_from_slice(&scratch[..n]);
        }
        if received_request.len() == request.len() && received_response.len() == response.len() {
            break;
        }
    }
    assert_eq!(received_request, request);
    assert_eq!(received_response, response);
    #[cfg(feature = "native-tcp-segmentation")]
    assert!(client.device.stats().tx_segmented_requests > 0,
        "the real TCP transfer must exercise native large-send generation");
    space.revoke(server_in_root).unwrap();
    assert_eq!(
        server.drive_tcp_frontend(socket, &frontend),
        Err(vibeos_net_protocol::TcpFrontendDriveError::Stack(StackError::AuthorityRevoked))
    );
}

#[test]
fn icmp_echo_preserves_changing_payloads_and_rejects_bad_checksums() {
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            sum += ((pair[0] as u32) << 8) | pair.get(1).copied().unwrap_or(0) as u32;
        }
        while sum >> 16 != 0 { sum = (sum & 65535) + (sum >> 16); }
        !(sum as u16)
    }
    let inbound = Endpoint::new("icmp-in", 4);
    let outbound = Endpoint::new("icmp-out", 4);
    let stamp = session_stamp();
    let mut space = CSpace::new("icmp-stack");
    let (_, rx) = authority(&mut space, &inbound, Rights::RECV);
    let (_, tx) = authority(&mut space, &outbound, Rights::SEND);
    let mut stack = StaticIpv4TcpStack::new(server_config(), stamp, rx, tx).unwrap();
    let mut arp = vec![0; 42];
    arp[..6].copy_from_slice(&SERVER_MAC);
    arp[6..12].copy_from_slice(&CLIENT_MAC);
    arp[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    arp[22..28].copy_from_slice(&CLIENT_MAC);
    arp[28..32].copy_from_slice(&CLIENT_IP);
    arp[38..42].copy_from_slice(&SERVER_IP);
    inbound.try_send(StampedPacket::copy_from(&arp, stamp).unwrap()).unwrap();
    stack.poll_network(0).unwrap();
    while outbound.try_recv().is_some() {}
    for (seq, length) in [1472usize, 1, 81, 82, 83, 511, 512, 513, 1471].into_iter().enumerate() {
        let mut frame = vec![0; 42 + length];
        frame[..6].copy_from_slice(&SERVER_MAC);
        frame[6..12].copy_from_slice(&CLIENT_MAC);
        frame[12..14].copy_from_slice(&[8, 0]);
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&((28 + length) as u16).to_be_bytes());
        frame[22] = 64;
        frame[23] = 1;
        frame[26..30].copy_from_slice(&CLIENT_IP);
        frame[30..34].copy_from_slice(&SERVER_IP);
        let check = checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&check.to_be_bytes());
        frame[34] = 8;
        frame[38..40].copy_from_slice(&0x4d52u16.to_be_bytes());
        frame[40..42].copy_from_slice(&(seq as u16).to_be_bytes());
        for (i, b) in frame[42..].iter_mut().enumerate() { *b = (i.wrapping_mul(73) ^ seq) as u8; }
        let check = checksum(&frame[34..]);
        frame[36..38].copy_from_slice(&check.to_be_bytes());
        inbound.try_send(StampedPacket::copy_from(&frame, stamp).unwrap()).unwrap();
        stack.poll_network((seq * 2 + 1) as u64).unwrap();
        let reply = outbound.try_recv().unwrap().into_packet(stamp).unwrap();
        let bytes = reply.as_bytes();
        assert_eq!(&bytes[26..30], &SERVER_IP);
        assert_eq!(&bytes[30..34], &CLIENT_IP);
        assert_eq!(&bytes[34..36], &[0, 0]);
        assert_eq!(&bytes[38..42 + length], &frame[38..]);
        assert_eq!(checksum(&bytes[34..42 + length]), 0);
        frame[36] ^= 1;
        inbound.try_send(StampedPacket::copy_from(&frame, stamp).unwrap()).unwrap();
        stack.poll_network((seq * 2 + 2) as u64).unwrap();
        assert!(outbound.try_recv().is_none());
    }
}

#[test]
fn graceful_frontend_close_drains_bytes_behind_full_transport() {
    frontend_shutdown_behind_full_transport(false);
}

#[test]
fn frontend_reset_does_not_wait_for_queued_payload() {
    frontend_shutdown_behind_full_transport(true);
}

fn frontend_shutdown_behind_full_transport(reset: bool) {
    let to_server = Endpoint::new("close-in", 128);
    let to_client = Endpoint::new("close-out", 128);
    let mut space = CSpace::new("close-drain");
    let (_, server_in) = authority(&mut space, &to_server, Rights::RECV);
    let (_, server_out) = authority(&mut space, &to_client, Rights::SEND);
    let (_, client_in) = authority(&mut space, &to_client, Rights::RECV);
    let (_, client_out) = authority(&mut space, &to_server, Rights::SEND);
    let config = Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 0x5eed);
    let mut server = SharedIpv4TcpStack::new(config, session_stamp(), server_in, server_out).unwrap();
    let socket = server.add_tcp_listener(SERVER_PORT).unwrap();
    let frontend = TcpListener::new("close", TcpListenerId::new(1).unwrap(), SERVER_PORT, 65536, 65536).unwrap();
    let mut client = TestClient::new(client_in, client_out);
    let mut connection = None;
    let mut now = 0;
    while connection.is_none() && now < 1000 {
        // Queue more than one emission before polling the receiver. Without
        // native segmentation, one client poll may expose only a single frame.
        client.poll(now); client.poll(now); server.poll_network(now).unwrap();
        server.drive_tcp_frontend(socket, &frontend).unwrap();
        connection = frontend.try_accept(); now += 1;
    }
    let connection = connection.expect("connected");
    let expected: Vec<u8> = (0..TCP_BUFFER_BYTES + 10037).map(|i| (i * 37 + i / 251) as u8).collect();
    let mut queued = 0;
    while queued < TCP_BUFFER_BYTES {
        match server.tcp_try_send(socket, &expected[queued..TCP_BUFFER_BYTES]).unwrap() {
            TcpIoResult::Progress(n) if n > 0 => queued += n,
            other => panic!("could not fill socket: {other:?}"),
        }
    }
    assert_eq!(frontend.try_send(connection, &expected[queued..]).unwrap(), TcpIoResult::Progress(10037));
    if reset {
        frontend.request_reset(connection).unwrap();
        let report = server.drive_tcp_frontend(socket, &frontend).unwrap();
        assert_eq!(report.close_applied, Some(vibeos_net_api::TcpCloseRequest::Reset));
        assert_eq!(frontend.snapshot().queued_send_bytes, 0);
        return;
    }
    frontend.request_close(connection).unwrap();
    let report = server.drive_tcp_frontend(socket, &frontend).unwrap();
    assert_eq!(report.close_applied, None, "close must wait for frontend bytes behind a full socket");
    assert_eq!(frontend.try_send(connection, b"late"), Ok(TcpIoResult::Closed));
    let mut received = Vec::new();
    let mut scratch = [0; 997];
    for tick in now..now + 10000 {
        client.poll(tick); server.poll_network(tick).unwrap();
        server.drive_tcp_frontend(socket, &frontend).unwrap();
        if client.socket().can_recv() {
            let n = client.socket().recv_slice(&mut scratch).unwrap();
            received.extend_from_slice(&scratch[..n]);
        }
        if !client.socket().may_recv() && !client.socket().can_recv() { break; }
    }
    assert_eq!(received, expected);
    assert!(!client.socket().may_recv(), "FIN must follow all payload bytes");
}

// Characterizes why a successful TCP connect is not a service-ready timestamp.
// Keep old and new tuples separate while the active closer retains TIME-WAIT.
#[test]
fn pending_handshake_can_precede_application_admission_during_time_wait() {
    let (mut server, mut client) = raw_tcp_pair();
    let mut now = connect_raw_pair(&mut server, &mut client);
    server.close().unwrap();
    for _ in 0..200 {
        client.poll(now);
        server.poll_network(now).unwrap();
        now += 1;
        if client.socket().state() == tcp::State::CloseWait { break; }
    }
    assert_eq!(client.socket().state(), tcp::State::CloseWait);
    client.socket().close();
    for _ in 0..200 {
        client.poll(now);
        server.poll_network(now).unwrap();
        now += 1;
    }
    assert_eq!(server.stream_status().state, TcpStreamState::Closing);
    let prior = now;
    now += 2000; // same inter-test pause used by the physical probe
    let next = client.open_connection(49_153);
    let opened = now;
    for _ in 0..200 {
        client.poll(now);
        server.poll_network(now).unwrap();
        now += 1;
        if client.socket_by_handle(next).may_send() { break; }
    }
    assert!(client.socket_by_handle(next).may_send());
    assert_eq!(server.stream_status().state, TcpStreamState::Closing);
    client.socket_by_handle(next).send_slice(b"next request").unwrap();
    let handshake = now;
    let mut admitted = None;
    for _ in 0..12000 {
        client.poll(now);
        server.poll_network(now).unwrap();
        now += 1;
        if server.stream_status().state == TcpStreamState::Established {
            admitted = Some(now);
            break;
        }
    }
    let admitted = admitted.expect("successor eventually admitted");
    let mut payload = [0; 64];
    assert_eq!(server.try_recv(&mut payload).unwrap(), TcpIoResult::Progress(12));
    assert_eq!(&payload[..12], b"next request");
    assert!(admitted > handshake, "wire handshake and application admission are separate events");
    println!("pending admission model: handshake={} ms, application wait={} ms, since prior-close observation={} ms",
        handshake-opened, admitted-handshake, admitted-prior);
}

#[cfg(feature = "bounded-gro")]
fn gro_test_data(seq: u32) -> Vec<u8> {
        let mut b=vec![0u8;154];
        b[12..14].copy_from_slice(&[8,0]); b[14]=0x45;
        b[16..18].copy_from_slice(&140u16.to_be_bytes());
        b[20]=0x40; b[22]=64; b[23]=6;
        b[38..42].copy_from_slice(&seq.to_be_bytes()); b[46]=0x50;b[47]=0x10;
        b[54..].fill(seq as u8); b
    }

#[cfg(feature = "bounded-gro")]
#[test]
fn gro_preserves_order_stamp_checks_and_pending_packet_revocation() {
    let inbound=Endpoint::new("gro-in",16); let outbound=Endpoint::new("gro-out",16);
    let mut space=CSpace::new("gro"); let stamp=session_stamp();
    let (root,ia)=authority(&mut space,&inbound,Rights::RECV);
    let (_,oa)=authority(&mut space,&outbound,Rights::SEND);
    let mut d=PacketDevice::new(stamp,ia,oa);
    // Synthetic frames use the already-verified ingress contract.
    d.set_rx_checksum_offload(true);
    for seq in [0,100,500] {
        inbound.try_send(StampedPacket::copy_from(&gro_test_data(seq),stamp).unwrap()).unwrap();
    }
    let (rx,tx)=d.receive(Instant::ZERO).unwrap(); drop(tx);
    rx.consume(|b| {assert_eq!(b.len(),254);assert_eq!(&b[54..154],&[0;100]);assert_eq!(&b[154..],&[100;100]);});
    assert_eq!(d.stats().gro_merged_segments,1);
    assert_eq!(d.stats().gro_aggregates,1);
    assert!(d.has_immediate_work().unwrap());
    let (rx,tx)=d.receive(Instant::ZERO).unwrap();drop(tx);
    rx.consume(|b|assert_eq!(b,gro_test_data(500)));
    let stale=stamp.next_stack_generation().unwrap();
    inbound.try_send(StampedPacket::copy_from(&gro_test_data(600),stale).unwrap()).unwrap();
    assert!(d.receive(Instant::ZERO).is_none());
    assert_eq!(d.stats().rejected_stack_generation_frames,1);
    for seq in [700,1000] {
        inbound.try_send(StampedPacket::copy_from(&gro_test_data(seq),stamp).unwrap()).unwrap();
    }
    drop(d.receive(Instant::ZERO).unwrap()); // 1000 retained behind a sequence gap.
    space.revoke(root).unwrap();
    assert!(d.receive(Instant::ZERO).is_none());
    assert_eq!(d.revalidate_authority(),Err(StackError::AuthorityRevoked));
}

#[cfg(feature = "bounded-gro")]
#[test]
fn gro_keeps_wire_frame_budget_and_requests_another_poll() {
    let inbound=Endpoint::new("gro-budget-in",64);
    let outbound=Endpoint::new("gro-budget-out",64);
    let mut space=CSpace::new("gro-budget"); let stamp=session_stamp();
    let (_,ia)=authority(&mut space,&inbound,Rights::RECV);
    let (_,oa)=authority(&mut space,&outbound,Rights::SEND);
    let config=Ipv4StackConfig::from(server_config()).with_rx_checksum_offload(true);
    let mut stack=SharedIpv4TcpStack::new(config,stamp,ia,oa).unwrap();
    for i in 0..64 {
        inbound.try_send(StampedPacket::copy_from(&gro_test_data(i*100),stamp).unwrap()).unwrap();
    }
    stack.poll_network(0).unwrap();
    assert_eq!(stack.device_stats().rx_frames,32);
    assert_eq!(inbound.stats().2,32);
    assert_eq!(stack.device_stats().gro_aggregates,2);
    stack.poll_network(1).unwrap();
    assert_eq!(stack.device_stats().rx_frames,64);
    assert_eq!(inbound.stats().2,0);
}

#[cfg(feature = "bounded-gro")]
#[test]
fn gro_delivers_changing_tcp_payload_through_real_socket() {
    // Keep a sustained sender backlog so ordinary MTU emission does not put
    // PSH on every refill. GRO deliberately stops at each PSH boundary.
    let (mut server,mut client)=raw_tcp_pair_with_transmit_capacity(65536);
    let mut now=connect_raw_pair(&mut server,&mut client);
    let expected: Vec<u8>=(0..96_731).map(|i| ((i*17+i/251)%253) as u8).collect();
    let mut sent=0; let mut received=Vec::new();
    for _ in 0..10_000 {
        if sent<expected.len() && client.socket().can_send() {
            sent+=client.socket().send_slice(&expected[sent..]).unwrap();
        }
        client.poll(now); server.poll_network(now).unwrap();
        let mut bytes=[0u8;4096];
        if let TcpIoResult::Progress(n)=server.try_recv(&mut bytes).unwrap() {
            received.extend_from_slice(&bytes[..n]);
        }
        now+=1;
        if received.len()==expected.len() {break;}
    }
    assert_eq!(received,expected);
    assert!(server.device_stats().gro_merged_segments>0,"test must exercise actual coalescing");
}

#[cfg(feature = "native-tcp-segmentation")]
fn logical_tcp_payload(n: usize) -> Vec<u8> {
    let mut p = vec![0; n + 54];
    p[0] = 2; p[6] = 2; p[12..14].copy_from_slice(&[8, 0]);
    p[14] = 0x45; p[16..18].copy_from_slice(&((n+40) as u16).to_be_bytes());
    p[20] = 0x40; p[22] = 64; p[23] = 6;
    p[26..30].copy_from_slice(&SERVER_IP); p[30..34].copy_from_slice(&CLIENT_IP);
    p[38..42].copy_from_slice(&0xfffffff0u32.to_be_bytes());
    p[46] = 0x50; p[47] = 0x18; p[48] = 0x7f;
    for (i,b) in p[54..].iter_mut().enumerate() { *b = (i % 251) as u8; }
    p
}

#[test]
#[cfg(feature = "native-tcp-segmentation")]
fn native_software_fallback_retains_order_through_one_slot_queue() {
    use smoltcp::wire::{Ipv4Packet, TcpPacket};
    let inbound = Endpoint::new("native-in", 1);
    let outbound = Endpoint::new("native-out", 1);
    let mut space = CSpace::new("native-test");
    let (_, ia) = authority(&mut space, &inbound, Rights::RECV);
    let (_, oa) = authority(&mut space, &outbound, Rights::SEND);
    let mut device = PacketDevice::new(session_stamp(), ia, oa);
    let original = logical_tcp_payload(4097);
    let mut token = device.transmit(Instant::ZERO).unwrap();
    let mut meta = smoltcp::phy::PacketMeta::default(); meta.tcp_segment_size = Some(64);
    token.set_meta(meta);
    token.consume(original.len(), |out| out.copy_from_slice(&original));
    let mut payload = Vec::new(); let mut frames = 0;
    while device.stats().pending_egress {
        let complete = device.flush_egress().unwrap();
        if !complete { assert!(device.transmit(Instant::ZERO).is_none()); }
        let packet = outbound.try_recv().unwrap().into_packet(session_stamp()).unwrap();
        let bytes = packet.as_bytes();
        let ip = Ipv4Packet::new_checked(&bytes[14..]).unwrap();
        assert!(ip.verify_checksum()); assert!(ip.total_len() <= 1500);
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.verify_checksum(&IpAddress::v4(192,0,2,1), &IpAddress::v4(192,0,2,2)));
        assert_eq!(u32::from_be_bytes(bytes[38..42].try_into().unwrap()),
            0xfffffff0u32.wrapping_add(payload.len() as u32));
        assert_eq!(bytes[47] & 8 != 0, payload.len() + tcp.payload().len() == 4097);
        payload.extend_from_slice(tcp.payload()); frames += 1;
        assert!(frames <= 65);
    }
    assert_eq!(payload, &original[54..]);
    assert_eq!(device.stats().tx_frames, 65);
    assert_eq!(device.stats().tx_segmented_requests, 1);
    assert_eq!(device.capabilities().max_transmission_unit, 1514);
}

#[test]
#[cfg(feature = "native-tcp-segmentation")]
fn native_pending_send_stops_on_revocation() {
    let inbound = Endpoint::new("native-revoke-in", 1);
    let outbound = Endpoint::new("native-revoke-out", 1);
    let mut space = CSpace::new("native-revoke");
    let (_, ia) = authority(&mut space, &inbound, Rights::RECV);
    let (root, oa) = authority(&mut space, &outbound, Rights::SEND);
    let mut device = PacketDevice::new(session_stamp(), ia, oa);
    let original = logical_tcp_payload(4097);
    let mut token = device.transmit(Instant::ZERO).unwrap();
    let mut meta = smoltcp::phy::PacketMeta::default(); meta.tcp_segment_size = Some(1460);
    token.set_meta(meta); token.consume(original.len(), |out| out.copy_from_slice(&original));
    assert_eq!(device.flush_egress(), Ok(false));
    space.revoke(root).unwrap();
    assert_eq!(device.flush_egress(), Err(StackError::AuthorityRevoked));
    assert_eq!(outbound.stats().2, 1); // Only the already-admitted first segment.
    assert!(!device.stats().pending_egress);
}

#[test]
#[cfg(feature = "native-tcp-segmentation")]
fn native_transmit_token_cannot_outlive_revocation() {
    let inbound = Endpoint::new("native-token-in", 1);
    let outbound = Endpoint::new("native-token-out", 1);
    let mut space = CSpace::new("native-token");
    let (_, ia) = authority(&mut space, &inbound, Rights::RECV);
    let (root, oa) = authority(&mut space, &outbound, Rights::SEND);
    let mut device = PacketDevice::new(session_stamp(), ia, oa);
    let original = logical_tcp_payload(4097);
    let mut token = device.transmit(Instant::ZERO).unwrap();
    let mut meta = smoltcp::phy::PacketMeta::default(); meta.tcp_segment_size = Some(1460);
    token.set_meta(meta);
    space.revoke(root).unwrap();
    token.consume(original.len(), |out| out.copy_from_slice(&original));
    assert_eq!(device.flush_egress(), Err(StackError::AuthorityRevoked));
    assert_eq!(outbound.stats().2, 0);
    assert!(!device.stats().pending_egress);
}

#[cfg(feature = "native-tcp-segmentation")]
fn pooled_device(depth:usize, slots:usize) -> (PacketDevice, Arc<vibeos_core::net_transmit::TransmitEndpoint>, CSpace, Cap) {
    use vibeos_core::{heap::{AllocationDomain,OwnerId,ArenaId},net_transmit::TransmitEndpoint};
    let inbound=Endpoint::new("pooled-in",1);let q=TransmitEndpoint::new("pooled-out",depth,slots).unwrap();
    let mut space=CSpace::new("pooled-producer");
    let (_,ia)=authority(&mut space,&inbound,Rights::RECV);
    let root=space.mint(q.clone(),Rights::SEND.union(Rights::REVOKE));
    let authority=space.lookup_revocable::<TransmitEndpoint>(root,Rights::SEND).unwrap();
    let outbound=vibeos_net_protocol::PacketTransmit::Pooled {authority,
        domain:AllocationDomain::new(OwnerId::new(17),ArenaId::new(1))};
    (PacketDevice::new(session_stamp(),ia,outbound),q,space,root)
}
#[test]
#[cfg(feature = "native-tcp-segmentation")]
fn pooled_token_reserves_before_serialization_and_returns_unused_slot() {
    let (mut device,q,_,_)=pooled_device(2,1);
    let token=device.transmit(Instant::ZERO).unwrap();assert_eq!(q.pool().in_use(),1);
    drop(token);assert_eq!(q.pool().in_use(),0);
    let original=logical_tcp_payload(32714);
    let mut token=device.transmit(Instant::ZERO).unwrap();
    let mut meta=smoltcp::phy::PacketMeta::default();meta.tcp_segment_size=Some(1460);
    token.set_meta(meta);assert_eq!(token.consume(original.len(),|p|{p.copy_from_slice(&original);42}),42);
    assert!(device.transmit(Instant::ZERO).is_none()); // Pool full, despite queue space.
    let Some(vibeos_core::net_transmit::Transmit::Segments(ticket))=q.try_recv() else {panic!("large send was split into frames")};
    assert_eq!(q.pool().try_consume(ticket,session_stamp(),|r|{
        assert_eq!(r.bytes(),original);Ok::<_,()>(r.wire_segments())
    }),Ok(Ok(23)));
    assert!(q.try_recv().is_none());
    assert_eq!(device.stats().tx_segmented_requests,1);
    assert_eq!(device.stats().tx_frames,23);
    assert!(device.transmit(Instant::ZERO).is_some());
}
#[test]
#[cfg(feature = "native-tcp-segmentation")]
fn pooled_large_send_keeps_order_and_ownership_when_queue_is_full() {
    use vibeos_core::net_transmit::Transmit;
    let (mut device,q,_,_)=pooled_device(1,1);
    q.try_send(Transmit::Frame(StampedPacket::copy_from(&[1;60],session_stamp()).unwrap())).unwrap();
    let original=logical_tcp_payload(4097);
    let mut token=device.transmit(Instant::ZERO).unwrap();
    let mut meta=smoltcp::phy::PacketMeta::default();meta.tcp_segment_size=Some(1460);
    token.set_meta(meta);token.consume(original.len(),|p|p.copy_from_slice(&original));
    assert!(device.stats().pending_egress);
    for _ in 0..3 {assert!(device.transmit(Instant::ZERO).is_none());}
    assert!(matches!(q.try_recv(),Some(Transmit::Frame(_))));
    assert_eq!(device.flush_egress(),Ok(true));
    let Some(Transmit::Segments(ticket))=q.try_recv() else {panic!()};
    assert_eq!(q.pool().try_consume(ticket,session_stamp(),|r| {assert_eq!(r.bytes(),original);Ok::<_,()>(())}),Ok(Ok(())));
    assert!(q.try_recv().is_none());assert_eq!(q.pool().in_use(),0);
}
#[test]
#[cfg(feature = "native-tcp-segmentation")]
fn pooled_token_revocation_never_publishes_and_supervisor_retires_lease() {
    use vibeos_core::heap::{AllocationDomain,OwnerId,ArenaId};
    let (mut device,q,mut space,root)=pooled_device(1,1);
    let original=logical_tcp_payload(4097);
    let mut token=device.transmit(Instant::ZERO).unwrap();
    let mut meta=smoltcp::phy::PacketMeta::default();meta.tcp_segment_size=Some(1460);token.set_meta(meta);
    space.revoke(root).unwrap();
    assert_eq!(token.consume(original.len(),|p|{p.copy_from_slice(&original);42}),42);
    assert!(q.try_recv().is_none());assert_eq!(device.flush_egress(),Err(StackError::AuthorityRevoked));
    // Revoked component code cannot cancel through the resource. Trusted policy
    // retirement, required before rebinding, releases its outstanding reservation.
    assert_eq!(q.pool().invalidate_domain(AllocationDomain::new(OwnerId::new(17),ArenaId::new(1))),1);
    assert_eq!(q.pool().in_use(),0);
}

#[test]
#[cfg(feature = "native-tcp-segmentation")]
fn real_tcp_pooled_producer_preserves_changing_payloads() {
    let to_server = Endpoint::new("direct-to-server", 128);
    let to_client = Endpoint::new("direct-to-client", 128);
    let mut space = CSpace::new("direct-transfer");
    let (server_in_root, server_in) = authority(&mut space, &to_server, Rights::RECV);
    let pooled = vibeos_core::net_transmit::TransmitEndpoint::new("tcp-pooled", 128, 8).unwrap();
    let pool_root = space.mint(pooled.clone(), Rights::SEND.union(Rights::REVOKE));
    let server_out = vibeos_net_protocol::PacketTransmit::Pooled {
        authority: space.lookup_revocable(pool_root, Rights::SEND).unwrap(),
        domain: vibeos_core::heap::AllocationDomain::new(vibeos_core::heap::OwnerId::new(17), vibeos_core::heap::ArenaId::new(1)),
    };
    let mut observed_large = 0;
    let (_, client_in) = authority(&mut space, &to_client, Rights::RECV);
    let (_, client_out) = authority(&mut space, &to_server, Rights::SEND);
    let config = Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 0x5eed);
    let mut server = SharedIpv4TcpStack::new(config, session_stamp(), server_in, server_out).unwrap();
    let socket = server.add_tcp_listener(SERVER_PORT).unwrap();
    // Odd, small capacities force wrapped frontend storage and partial writes.
    let frontend = TcpListener::new("direct", TcpListenerId::new(1).unwrap(), SERVER_PORT, 32768, 32768).unwrap();
    let mut client = TestClient::new(client_in, client_out);
    // Exceeds both the default and large TCP windows to wrap transport storage.
    let request: Vec<u8> = (0..600_007).map(|i| (i * 37 + i / 251) as u8).collect();
    let response: Vec<u8> = request.iter().map(|b| b ^ 0xa5).collect();
    let (mut request_sent, mut response_sent) = (0, 0);
    let (mut received_request, mut received_response) = (Vec::new(), Vec::new());
    let mut connection = None;
    let mut scratch = [0u8; 997];
    for now in 0..100_000 {
        client.poll(now);
        server.poll_network(now).unwrap();
        while let Some(message) = pooled.try_recv() {
            match message {
                vibeos_core::net_transmit::Transmit::Frame(frame) => to_client.try_send(frame).unwrap(),
                vibeos_core::net_transmit::Transmit::Segments(ticket) => {
                    observed_large += 1;
                    pooled.pool().try_consume(ticket, session_stamp(), |request| {
                        let mut wire = [0; 1514];
                        for index in 0..request.wire_segments() {
                            let length = request.write_segment(index, &mut wire).unwrap();
                            to_client.try_send(StampedPacket::copy_from(&wire[..length], session_stamp()).unwrap()).unwrap();
                        }
                        Ok::<_, ()>(())
                    }).unwrap().unwrap();
                }
            }
        }
        let report = server.drive_tcp_frontend(socket, &frontend).unwrap();
        assert!(report.received_bytes <= 4 * 32768);
        assert!(report.transmitted_bytes <= 4 * 32768);
        connection = connection.or_else(|| frontend.try_accept());
        if client.socket().can_send() && request_sent < request.len() {
            request_sent += client.socket().send_slice(&request[request_sent..]).unwrap();
        }
        if let Some(peer) = connection {
            // Leave receive queues full on alternate turns to exercise backpressure.
            if now % 2 == 0 {
                if let TcpIoResult::Progress(n) = frontend.try_recv(peer, &mut scratch[..61]).unwrap() {
                    received_request.extend_from_slice(&scratch[..n]);
                }
            }
            if response_sent < response.len() {
                if let TcpIoResult::Progress(n) = frontend.try_send(peer, &response[response_sent..]).unwrap() {
                    response_sent += n;
                }
            }
        }
        if now % 5 == 0 && client.socket().can_recv() {
            let n = client.socket().recv_slice(&mut scratch).unwrap();
            received_response.extend_from_slice(&scratch[..n]);
        }
        if received_request.len() == request.len() && received_response.len() == response.len() {
            break;
        }
    }
    assert!(observed_large > 0, "real TCP must use pooled requests");
    assert_eq!(pooled.pool().in_use(), 0);
    assert_eq!(received_request, request);
    assert_eq!(received_response, response);
    #[cfg(feature = "native-tcp-segmentation")]
    assert!(client.device.stats().tx_segmented_requests > 0,
        "the real TCP transfer must exercise native large-send generation");
    space.revoke(server_in_root).unwrap();
    assert_eq!(
        server.drive_tcp_frontend(socket, &frontend),
        Err(vibeos_net_protocol::TcpFrontendDriveError::Stack(StackError::AuthorityRevoked))
    );
}


#[cfg(feature = "pooled-rx")]
mod pooled_receive {
    use super::*;
    use std::{collections::BTreeMap, sync::{Mutex, OnceLock, atomic::{AtomicU64, Ordering}}};
    use vibeos_core::{heap::{AllocationDomain, OwnerId, ArenaId}, net_receive::*};
    use vibeos_net_protocol::{PacketReceive, PacketRxToken};
    struct Record { batch_size: usize, bytes: &'static [u8], borrower: Option<Owner>, released: bool }
    fn records() -> &'static Mutex<BTreeMap<u64, Record>> {
        static R: OnceLock<Mutex<BTreeMap<u64, Record>>> = OnceLock::new();
        R.get_or_init(|| Mutex::new(BTreeMap::new()))
    }
    unsafe fn release(borrow: Borrow) {
        let mut records = records().lock().unwrap();
        let record = records.get_mut(&borrow.ticket().pool()).unwrap();
        assert_eq!(record.borrower, Some(borrow.owner()));
        record.borrower = None; record.released = true;
    }
    #[cfg(feature = "gro-batch-release")]
    unsafe fn release_many(borrows: &mut [Option<Borrow>]) {
        let size = borrows.len(); let mut records = records().lock().unwrap();
        for b in borrows.iter_mut().filter_map(Option::take) {
            let r = records.get_mut(&b.ticket().pool()).unwrap();
            assert_eq!(r.borrower, Some(b.owner())); assert!(!r.released);
            r.borrower=None; r.released=true; r.batch_size=size;
        }
    }
    static OPS: Operations = Operations {
        #[cfg(feature = "rx-admission-batch")]
        acquire_batch: None,
        poll_batch: None,
        stats: Default::default,
        poll: || Ok(None),
        acquire: |ticket, owner| {
            let mut records = records().lock().unwrap();
            let r = records.get_mut(&ticket.pool()).ok_or(DeviceError::InvalidDescription)?;
            if ticket.index() != 0 || ticket.generation() != 1 || r.released || r.borrower.is_some() {
                return Err(DeviceError::Busy);
            }
            r.borrower = Some(owner);
            let loan = unsafe { Loan::new(Borrow::from_owned(ticket, owner), r.bytes.as_ptr(), r.bytes.len(), release).unwrap() };
            #[cfg(feature = "gro-batch-release")]
            let loan = unsafe { loan.with_batch_release(release_many) };
            Ok(loan)
        },
        discard: |ticket| {
            let mut records = records().lock().unwrap();
            let Some(r) = records.get_mut(&ticket.pool()) else { return false; };
            if r.borrower.is_some() || r.released { return false; }
            r.released = true; true
        },
        recover: |_| panic!("this test uses normal loan release"),
    };
    fn inject(q: &ReceiveEndpoint, bytes: &[u8]) -> Ticket {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        // Synthetic DMA reception happens here; no copy is allowed after acquire.
        let bytes = Box::leak(bytes.to_vec().into_boxed_slice());
        records().lock().unwrap().insert(id, Record { batch_size: 0, bytes, borrower: None, released: false });
        let ticket = Ticket::from_parts(id, 0, 1);
        q.try_send(Stamped::new(ticket, session_stamp())).unwrap(); ticket
    }
    fn receive(space: &mut CSpace, q: Arc<ReceiveEndpoint>) -> (Cap, PacketReceive) {
        let cap = space.mint(q, Rights::ALL);
        let authority = space.lookup_revocable::<ReceiveEndpoint>(cap, Rights::RECV).unwrap();
        (cap, PacketReceive::Pooled { authority,
            domain: AllocationDomain::new(OwnerId::new(33), ArenaId::new(44)) })
    }
    #[cfg(feature = "gro-batch-release")]
    #[test]
    fn gro_batches_only_merged_followers_and_revocation_releases_retained_loans() {
        let q=unsafe { ReceiveEndpoint::new("bulk-gro",16,&OPS).unwrap() };
        let out=Endpoint::new("bulk-out",16);let mut cs=CSpace::new("bulk");
        let (root,rx)=receive(&mut cs,q.clone());let (_,tx)=authority(&mut cs,&out,Rights::SEND);
        let mut device=PacketDevice::new(session_stamp(),rx,tx);device.set_rx_checksum_offload(true);
        let tickets:Vec<_>=[0,100,200,500].map(|seq|inject(&q,&gro_test_data(seq))).into();
        let (rx,tx)=device.receive(Instant::ZERO).unwrap();drop(tx);
        rx.consume(|bytes| assert_eq!(bytes.len(),54+300));
        {
            let r=records().lock().unwrap();
            assert!(!r[&tickets[0].pool()].released);assert!(!r[&tickets[3].pool()].released);
            for ticket in &tickets[1..3] { assert!(r[&ticket.pool()].released);assert_eq!(r[&ticket.pool()].batch_size,2); }
        }
        cs.revoke(root).unwrap();assert!(device.receive(Instant::from_millis(1)).is_none());
        let r=records().lock().unwrap();for t in tickets { assert!(r[&t.pool()].released);assert!(r[&t.pool()].borrower.is_none()); }
    }
    #[test]
    fn pooled_token_is_a_slice_of_original_storage_and_revocation_releases_it() {
        assert_eq!(core::mem::size_of::<PacketRxToken<'_>>(), 2 * core::mem::size_of::<usize>());
        let q = unsafe { ReceiveEndpoint::new("loan-token", 4, &OPS).unwrap() };
        let out = Endpoint::new("loan-out", 4); let mut cs = CSpace::new("loan-test");
        let (cap, rx) = receive(&mut cs, q.clone());
        let (_, tx) = authority(&mut cs, &out, Rights::SEND);
        let mut device = PacketDevice::new(session_stamp(), rx, tx);
        let ticket = inject(&q, &[0x39; 64]);
        let original = records().lock().unwrap()[&ticket.pool()].bytes.as_ptr();
        let (rx, tx) = device.receive(Instant::ZERO).unwrap();
        rx.consume(|bytes| { assert_eq!(bytes.as_ptr(), original); assert_eq!(bytes, &[0x39; 64]); });
        drop(tx);
        cs.revoke(cap).unwrap();
        assert!(device.receive(Instant::from_millis(1)).is_none());
        assert!(records().lock().unwrap()[&ticket.pool()].released);
    }
    #[test]
    fn real_arp_tcp_and_changing_payloads_flow_through_dma_loans() {
        let to_server = Endpoint::new("client-wire", 128);
        let to_client = Endpoint::new("server-wire", 128);
        let q = unsafe { ReceiveEndpoint::new("server-loans", 128, &OPS).unwrap() };
        let mut cs = CSpace::new("pooled-tcp");
        let (_, rx) = receive(&mut cs, q.clone());
        let (_, server_tx) = authority(&mut cs, &to_client, Rights::SEND);
        let (_, client_rx) = authority(&mut cs, &to_client, Rights::RECV);
        let (_, client_tx) = authority(&mut cs, &to_server, Rights::SEND);
        let mut server = StaticIpv4TcpStack::new(server_config(), session_stamp(), rx, server_tx).unwrap();
        let mut client = TestClient::with_transmit_capacity(client_rx, client_tx, 65536);
        let payload: Vec<u8> = (0..65537).map(|i| (i % 251) as u8).collect();
        let mut sent = 0; let mut received = Vec::new(); let mut echoed = 0; let mut replies = Vec::new();
        let mut tickets = Vec::new();
        for now in 0..20000 {
            client.poll(now);
            client.poll(now);
            while let Some(frame) = to_server.try_recv() {
                let packet = frame.into_packet(session_stamp()).unwrap();
                tickets.push(inject(&q, packet.as_bytes()));
            }
            server.poll_network(now).unwrap();
            if client.socket().can_send() && sent < payload.len() {
                sent += client.socket().send_slice(&payload[sent..]).unwrap();
            }
            let mut scratch = [0; 257];
            if let TcpIoResult::Progress(n) = server.try_recv(&mut scratch).unwrap() { received.extend_from_slice(&scratch[..n]); }
            if echoed < received.len() {
                if let TcpIoResult::Progress(n) = server.try_send(&received[echoed..]).unwrap() { echoed += n; }
            }
            client.poll(now);
            if client.socket().can_recv() {
                let n = client.socket().recv_slice(&mut scratch).unwrap(); replies.extend_from_slice(&scratch[..n]);
            }
            if replies.len() == payload.len() { break; }
        }
        assert_eq!(received, payload); assert_eq!(replies, payload);
        assert!(tickets.len() > 40, "must cover ARP, TCP setup, ACKs and many payload frames");
        #[cfg(feature = "bounded-gro")]
        assert!(server.device_stats().gro_merged_segments > 0, "real TCP must use pooled GRO");
        drop(server); q.retire_queued();
        let records = records().lock().unwrap();
        for ticket in tickets { assert!(records[&ticket.pool()].released); }
    }
    #[cfg(feature = "bounded-gro")]
    #[test]
    fn pooled_gro_keeps_order_releases_merged_loans_and_revokes_lookahead() {
        let q = unsafe { ReceiveEndpoint::new("gro-loans", 16, &OPS).unwrap() };
        let out = Endpoint::new("gro-loan-out", 16);
        let mut cs = CSpace::new("gro-loan-test");
        let (root, rx) = receive(&mut cs, q.clone());
        let (_, tx) = authority(&mut cs, &out, Rights::SEND);
        let mut d = PacketDevice::new(session_stamp(), rx, tx);
        d.set_rx_checksum_offload(true);
        let tickets: Vec<_> = [0, 100, 500].map(|seq| inject(&q, &gro_test_data(seq))).into();
        let (rx, tx) = d.receive(Instant::ZERO).unwrap(); drop(tx);
        rx.consume(|bytes| {
            assert_eq!(bytes.len(), 254);
            assert_eq!(&bytes[54..154], &[0; 100]);
            assert_eq!(&bytes[154..], &[100; 100]);
        });
        assert!(records().lock().unwrap()[&tickets[1].pool()].released);
        assert!(!records().lock().unwrap()[&tickets[2].pool()].released);
        assert!(d.has_immediate_work().unwrap());
        let (rx, tx) = d.receive(Instant::ZERO).unwrap(); drop(tx);
        rx.consume(|bytes| assert_eq!(bytes, gro_test_data(500)));
        // An ineligible frame following an aggregate must never expose stale GRO bytes.
        let raw = inject(&q, &[0x39; 64]);
        let original = records().lock().unwrap()[&raw.pool()].bytes.as_ptr();
        let (rx, tx) = d.receive(Instant::ZERO).unwrap(); drop(tx);
        rx.consume(|bytes| { assert_eq!(bytes.as_ptr(), original); assert_eq!(bytes, &[0x39; 64]); });
        let held = [700, 1000].map(|seq| inject(&q, &gro_test_data(seq)));
        drop(d.receive(Instant::ZERO).unwrap());
        cs.revoke(root).unwrap();
        assert!(d.receive(Instant::ZERO).is_none());
        for ticket in tickets.into_iter().chain([raw]).chain(held) {
            assert!(records().lock().unwrap()[&ticket.pool()].released);
        }
    }

    #[cfg(feature = "bounded-gro")]
    #[test]
    fn pooled_gro_counts_wire_frames_toward_poll_budget() {
        let q = unsafe { ReceiveEndpoint::new("gro-budget-loans", 64, &OPS).unwrap() };
        let out = Endpoint::new("gro-budget-out", 64);
        let mut cs = CSpace::new("gro-budget");
        let (_, rx) = receive(&mut cs, q.clone());
        let (_, tx) = authority(&mut cs, &out, Rights::SEND);
        let config = Ipv4StackConfig::from(server_config()).with_rx_checksum_offload(true);
        let mut stack = SharedIpv4TcpStack::new(config, session_stamp(), rx, tx).unwrap();
        let tickets: Vec<_> = (0..64).map(|i| inject(&q, &gro_test_data(i * 100))).collect();
        stack.poll_network(0).unwrap();
        assert_eq!(stack.device_stats().rx_frames, 32);
        assert_eq!(stack.device_stats().gro_aggregates, 2);
        assert!(q.has_message());
        stack.poll_network(1).unwrap();
        assert_eq!(stack.device_stats().rx_frames, 64);
        assert!(!q.has_message());
        drop(stack);
        for ticket in tickets { assert!(records().lock().unwrap()[&ticket.pool()].released); }
    }

    #[cfg(feature = "gro-end-profile")]
    #[test]
    fn gro_none_distinguishes_poll_budget_from_empty_endpoint() {
        let q = unsafe { ReceiveEndpoint::new("gro-none-loans", 64, &OPS).unwrap() };
        let out = Endpoint::new("gro-none-out", 64);
        let mut cs = CSpace::new("gro-none");
        let (_, rx) = receive(&mut cs, q.clone());
        let (_, tx) = authority(&mut cs, &out, Rights::SEND);
        let config = Ipv4StackConfig::from(server_config()).with_rx_checksum_offload(true);
        let mut stack = SharedIpv4TcpStack::new(config, session_stamp(), rx, tx).unwrap();
        let tickets: Vec<_> = (0..33).map(|i| {
            let mut frame = gro_test_data(i * 100);
            // Close the first group after one packet so the 32-frame poll
            // budget splits a later group, despite another queued packet.
            if i == 0 { frame[47] |= 8; }
            inject(&q, &frame)
        }).collect();
        stack.poll_network(0).unwrap();
        let before = stack.device_stats();
        assert_eq!(before.rx_frames, 32);
        assert!(q.has_message());
        assert_eq!(&before.gro_end_profile[26..], &[1, 0, 0, 0, 0]);
        assert_eq!(before.gro_end_profile[3], 1);
        stack.poll_network(1).unwrap();
        let after = stack.device_stats();
        assert_eq!(after.rx_frames, 33);
        assert!(!q.has_message());
        assert_eq!(&after.gro_end_profile[26..], &[1, 1, 0, 0, 0]);
        assert_eq!(after.gro_end_profile[3], 2);
        assert_eq!(after.gro_end_profile[..9].iter().sum::<u64>(),
                   after.gro_end_profile[9..26].iter().sum::<u64>());
        drop(stack);
        for ticket in tickets { assert!(records().lock().unwrap()[&ticket.pool()].released); }
    }

    #[cfg(feature = "bounded-gro")]
    #[test]
    fn revocation_during_pooled_gro_collection_publishes_no_token() {
        type Revoke = (u64, Arc<Mutex<CSpace>>, Cap);
        static ACTION: OnceLock<Mutex<Option<Revoke>>> = OnceLock::new();
        static REVOKING: Operations = Operations {
        #[cfg(feature = "rx-admission-batch")]
        acquire_batch: None,
        poll_batch: None,
            stats: Default::default,
            poll: || Ok(None),
            acquire: |ticket, owner| {
                // Forward the same endpoint-validated ticket and owner to the
                // synthetic DMA backend; its storage remains alive for the loan.
                let loan = unsafe { (OPS.acquire)(ticket, owner)? };
                let action = {
                    let mut action = ACTION.get_or_init(|| Mutex::new(None)).lock().unwrap();
                    if action.as_ref().is_some_and(|(pool, _, _)| *pool == ticket.pool()) {
                        action.take()
                    } else { None }
                };
                if let Some((_, space, cap)) = action { space.lock().unwrap().revoke(cap).unwrap(); }
                Ok(loan)
            },
            discard: OPS.discard,
            recover: OPS.recover,
        };
        let q = unsafe { ReceiveEndpoint::new("gro-revoke-collect", 4, &REVOKING).unwrap() };
        let out = Endpoint::new("gro-revoke-out", 4);
        let cs = Arc::new(Mutex::new(CSpace::new("gro-revoke")));
        let (root, rx) = receive(&mut cs.lock().unwrap(), q.clone());
        let (_, tx) = authority(&mut cs.lock().unwrap(), &out, Rights::SEND);
        let mut d = PacketDevice::new(session_stamp(), rx, tx);
        d.set_rx_checksum_offload(true);
        let tickets = [0, 100].map(|seq| inject(&q, &gro_test_data(seq)));
        *ACTION.get_or_init(|| Mutex::new(None)).lock().unwrap() = Some((tickets[1].pool(), cs, root));
        assert!(d.receive(Instant::ZERO).is_none());
        assert_eq!(d.revalidate_authority(), Err(StackError::AuthorityRevoked));
        for ticket in tickets { assert!(records().lock().unwrap()[&ticket.pool()].released); }
    }

}

#[cfg(feature = "receive-buffer-exchange")]
fn exercise_receive_exchange<const N: usize>(reorder: bool, make_frontend: impl FnOnce(&'static vibeos_net_api::receive_storage::Storage<N>) -> Option<Arc<TcpListener>>) -> usize {
    use std::{collections::VecDeque, num::NonZeroU64};
    use vibeos_core::{
        heap::{AllocationDomain, ArenaId, OwnerId},
        sync::TaskRecoveryKey,
    };
    use vibeos_net_api::{receive_ownership::Owner, receive_storage::Storage};
    use vibeos_net_protocol::receive_exchange::Binding;
    let producer = Owner {
        domain: AllocationDomain::new(OwnerId::new(71), ArenaId::new(1)),
        task: TaskRecoveryKey::new(71).unwrap(),
    };
    let consumer = Owner {
        domain: AllocationDomain::new(OwnerId::new(72), ArenaId::new(2)),
        task: TaskRecoveryKey::new(72).unwrap(),
    };
    let connection = NonZeroU64::new(1).unwrap();
    let pool = Storage::<N>::new_static(4096, 4096).unwrap();
    let frontend = make_frontend(pool);
    let mut accepted = None;
    let (mut binding, receive) = Binding::new(pool, producer).unwrap();
    let mut server_socket = tcp::Socket::new(receive, tcp::SocketBuffer::new(vec![0; 4096]));
    server_socket.listen(SERVER_PORT).unwrap();
    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(server_socket);
    let to_server = Endpoint::new("exchange-server", 128);
    let to_client = Endpoint::new("exchange-client", 128);
    let mut space = CSpace::new("exchange-pair");
    let (_, si) = authority(&mut space, &to_server, Rights::RECV);
    let (_, so) = authority(&mut space, &to_client, Rights::SEND);
    let (_, ci) = authority(&mut space, &to_client, Rights::RECV);
    let (_, co) = authority(&mut space, &to_server, Rights::SEND);
    let mut device = PacketDevice::new(session_stamp(), si, so);
    let mut cfg = InterfaceConfig::new(EthernetAddress(SERVER_MAC).into());
    cfg.random_seed = 0x5566;
    let mut interface = Interface::new(cfg, &mut device, Instant::ZERO);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(
                IpAddress::v4(SERVER_IP[0], SERVER_IP[1], SERVER_IP[2], SERVER_IP[3]),
                24,
            ))
            .unwrap();
    });
    let mut client = TestClient::new(ci, co);
    if reorder {
        client.socket().set_nagle_enabled(false);
    }
    let expected: Vec<u8> = (0..300_007).map(|i| (i * 37 + i / 251) as u8).collect();
    let mut sent = 0;
    let mut observed = Vec::new();
    let mut queued = VecDeque::new();
    let mut scratch = [0u8; 997];
    let mut exchanged = 0;
    let mut fallback = 0;
    let mut backpressure = 0;
    let mut held = None;
    let mut hole_refusals = 0;
    let mut max_batch = 0;
    let mut withheld = 0;
    for now in 0..100_000 {
        if let Some(packet) = held.take() {
            to_server.try_send(packet).unwrap();
        }
        client.poll(now);
        for _ in 0..if reorder { 4 } else { 1 } {
            if sent < expected.len() && client.socket().can_send() {
                let end = if reorder {
                    (sent + 512).min(expected.len())
                } else {
                    expected.len()
                };
                sent += client.socket().send_slice(&expected[sent..end]).unwrap();
            }
            if reorder {
                client.poll(now);
            }
        }
        if reorder && queued.is_empty() && frontend.as_ref().is_none_or(|f| f.snapshot().readable_bytes == 0) && now % 13 != 0 {
            let mut packets = Vec::new();
            while let Some(packet) = to_server.try_recv() {
                packets.push(packet.into_packet(session_stamp()).unwrap());
            }
            let data_indices: Vec<_> = packets
                .iter()
                .enumerate()
                .filter_map(|(index, packet)| {
                    let bytes = packet.as_bytes();
                    if bytes.len() < 54 || bytes[12..14] != [8, 0] || bytes[23] != 6 {
                        return None;
                    }
                    let ip = usize::from(bytes[14] & 15) * 4;
                    let tcp = 14 + ip;
                    let tcp_header = usize::from(*bytes.get(tcp + 12)? >> 4) * 4;
                    let total = usize::from(u16::from_be_bytes([bytes[16], bytes[17]]));
                    (total > ip + tcp_header).then_some(index)
                })
                .collect();
            max_batch = max_batch.max(data_indices.len());
            if data_indices.len() >= 3 {
                held = Some(StampedPacket::new(
                    packets.remove(data_indices[1]),
                    session_stamp(),
                ));
                withheld += 1;
            }
            for packet in packets {
                to_server
                    .try_send(StampedPacket::new(packet, session_stamp()))
                    .unwrap();
            }
        }
        interface.poll(Instant::from_millis(now as i64), &mut device, &mut sockets);
        device.flush_egress().unwrap();
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        if let Some(frontend) = &frontend {
            let state = match socket.state() {
                tcp::State::Listen => TcpStreamState::Listening,
                tcp::State::SynReceived => TcpStreamState::Handshake,
                tcp::State::Established => TcpStreamState::Established,
                _ => panic!("unexpected fixture socket state"),
            };
            frontend.network_begin_drive(state).unwrap();
            accepted = accepted.or_else(|| frontend.try_accept());
        }
        let before = socket.recv_queue();
        let budget = frontend.as_ref().map_or(4096, |f| f.network_receive_capacity());
        // A zero turn budget also exercises a non-consuming copied fallback.
        let result =
            unsafe { binding.exchange(socket, connection, if now % 13 == 0 { 0 } else { budget }) }
                .unwrap();
        if let Some(transfer) = result {
            assert_eq!(socket.recv_queue(), 0);
            assert_eq!(transfer.length, before);
            if let Some(frontend) = &frontend {
                assert_eq!(frontend.network_exchange_generation(), Some(connection));
                assert_eq!(frontend.network_publish_exchange(transfer.ticket, producer, connection), Ok(transfer.length));
            } else {
                pool.publish(transfer.ticket, producer, connection).unwrap();
                queued.push_back((transfer.ticket, transfer.length));
            }
            exchanged += 1;
        } else {
            assert_eq!(
                socket.recv_queue(),
                before,
                "failed exchange must preserve stream bytes"
            );
            if held.is_some() && before != 0 {
                hole_refusals += 1;
            }
            if before != 0 && (pool.available_bytes() < before || budget < before) {
                backpressure += 1;
            }
            // Preserve ordering with previously published chunks.
            if let Some(frontend) = &frontend {
                if before != 0 && budget != 0 {
                    let maximum = scratch.len().min(budget);
                    let length = socket.recv_slice(&mut scratch[..maximum]).unwrap();
                    assert_eq!(frontend.network_receive(&scratch[..length]), length);
                    fallback += 1;
                }
            } else if queued.is_empty() && before != 0 {
                let length = socket.recv_slice(&mut scratch).unwrap();
                observed.extend_from_slice(&scratch[..length]);
                fallback += 1;
            }
        }
        assert!(pool.queued_bytes() <= 4096);
        // Delayed, partial application reads exercise byte budget and pool reuse.
        if let Some(frontend) = &frontend {
            assert!(frontend.snapshot().readable_bytes <= 4096);
        }
        if now % 5 == 0 {
            if let (Some(frontend), Some(peer)) = (&frontend, accepted) {
                match frontend.try_recv_for(peer, consumer, &mut scratch).unwrap() {
                    TcpIoResult::Progress(length) => observed.extend_from_slice(&scratch[..length]),
                    TcpIoResult::WouldBlock => {},
                    TcpIoResult::Closed => panic!("fixture unexpectedly closed"),
                }
            } else if let Some((ticket, remaining)) = queued.front_mut() {
                let length = pool
                    .read(*ticket, connection, consumer, &mut scratch)
                    .unwrap();
                observed.extend_from_slice(&scratch[..length]);
                *remaining -= length;
                if *remaining == 0 {
                    queued.pop_front();
                }
            }
        }
        if observed.len() == expected.len() {
            break;
        }
    }
    assert_eq!(observed, expected);
    assert_eq!(sent, expected.len());
    assert!(fallback > 0);
    if reorder {
        assert!(hole_refusals > 0, "must reject an exchange with an actual TCP hole: max_batch={max_batch}, withheld={withheld}");
    }
    if N > 1 {
        assert!(backpressure > 0);
    }
    assert!(queued.is_empty());
    assert_eq!(pool.queued_bytes(), 0);
    // All socket borrows end before trusted cleanup of its last writer.
    drop(sockets);
    assert_eq!(
        unsafe { pool.retire_stopped_owner(producer) },
        1,
        "unused spares must not leak"
    );
    exchanged
}

#[test]
#[cfg(feature = "receive-buffer-exchange")]
fn real_tcp_receive_exchange_preserves_stream_under_backpressure() {
    assert!(exercise_receive_exchange::<3>(false, |_| None) > 0);
}

#[test]
#[cfg(feature = "receive-buffer-exchange")]
fn no_spare_receive_pool_keeps_legacy_tcp_receive_working() {
    assert_eq!(exercise_receive_exchange::<1>(false, |_| None), 0);
}

#[test]
#[cfg(feature = "receive-buffer-exchange")]
fn real_tcp_holes_release_unused_exchange_spares() {
    assert!(exercise_receive_exchange::<3>(true, |_| None) > 0);
}

#[test]
#[cfg(feature = "receive-buffer-exchange")]
fn real_tcp_exchange_through_listener_preserves_mixed_stream() {
    for reorder in [false, true] {
        assert!(exercise_receive_exchange::<3>(reorder, |pool| {
            Some(TcpListener::new_with_receive_storage("real-exchange", TcpListenerId::new(97).unwrap(),
                SERVER_PORT, 4096, 4096, pool).unwrap())
        }) > 0);
    }
}

#[test]
#[cfg(feature = "receive-buffer-exchange")]
fn shared_stack_exchange_transfers_and_promotes_pending_connection() {
    use vibeos_core::{heap::{AllocationDomain, ArenaId, OwnerId}, sync::TaskRecoveryKey};
    use vibeos_net_api::{receive_ownership::Owner, receive_storage::Storage};
    let owner = Owner { domain: AllocationDomain::new(OwnerId::new(81), ArenaId::new(81)), task: TaskRecoveryKey::new(81).unwrap() };
    let consumer = Owner { domain: AllocationDomain::new(OwnerId::new(82), ArenaId::new(82)), task: TaskRecoveryKey::new(82).unwrap() };
    let pool = Storage::<3>::new_static(4096, 8192).unwrap();
    let to_server = Endpoint::new("direct-to-server", 128);
    let to_client = Endpoint::new("direct-to-client", 128);
    let mut space = CSpace::new("direct-transfer");
    let (server_in_root, server_in) = authority(&mut space, &to_server, Rights::RECV);
    let (_, server_out) = authority(&mut space, &to_client, Rights::SEND);
    let (_, client_in) = authority(&mut space, &to_client, Rights::RECV);
    let (_, client_out) = authority(&mut space, &to_server, Rights::SEND);
    let config = Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 0x5eed);
    let mut server = SharedIpv4TcpStack::new(config, session_stamp(), server_in, server_out).unwrap();
    let socket = server.add_tcp_listener(SERVER_PORT).unwrap();
    // Odd, small capacities force wrapped frontend storage and partial writes.
    let frontend = TcpListener::new_with_receive_storage("exchange-shared", TcpListenerId::new(1).unwrap(), SERVER_PORT, 8192, 191, pool).unwrap();
    // Force installation to fail after preparing its first socket buffer.
    let occupied = [pool.reserve(consumer).unwrap(), pool.reserve(consumer).unwrap()];
    assert!(unsafe { server.enable_receive_exchange(socket, frontend.clone(), owner) }.is_err());
    assert_eq!(server.tcp_listener_port(socket), Ok(SERVER_PORT));
    for ticket in occupied { unsafe { pool.release_writer(ticket, consumer).unwrap(); } }
    unsafe { server.enable_receive_exchange(socket, frontend.clone(), owner).unwrap(); }
    assert!(unsafe { server.enable_receive_exchange(socket, frontend.clone(), owner) }.is_err());
    let impostor = TcpListener::new("same-id", TcpListenerId::new(1).unwrap(), SERVER_PORT, 8192, 191).unwrap();
    assert_eq!(server.drive_tcp_frontend(socket, &impostor), Err(vibeos_net_protocol::TcpFrontendDriveError::QueueInvariant));
    let mut exchange_observed = false;
    let mut next_time = 0;
    let mut client = TestClient::new(client_in, client_out);
    // Exceeds both the default and large TCP windows to wrap transport storage.
    let request: Vec<u8> = (0..600_007).map(|i| (i * 37 + i / 251) as u8).collect();
    let response: Vec<u8> = request.iter().map(|b| b ^ 0xa5).collect();
    let (mut request_sent, mut response_sent) = (0, 0);
    let (mut received_request, mut received_response) = (Vec::new(), Vec::new());
    let mut connection = None;
    let mut scratch = [0u8; 997];
    for now in 0..100_000 {
        next_time = now + 1;
        client.poll(now);
        server.poll_network(now).unwrap();
        let report = server.drive_tcp_frontend(socket, &frontend).unwrap();
        exchange_observed |= pool.queued_bytes() != 0;
        assert!(report.received_bytes <= 4 * 32768);
        assert!(report.transmitted_bytes <= 4 * 32768);
        connection = connection.or_else(|| frontend.try_accept());
        if client.socket().can_send() && request_sent < request.len() {
            request_sent += client.socket().send_slice(&request[request_sent..]).unwrap();
        }
        if let Some(peer) = connection {
            // Leave receive queues full on alternate turns to exercise backpressure.
            if now % 2 == 0 {
                if let TcpIoResult::Progress(n) = frontend.try_recv_for(peer, consumer, &mut scratch[..61]).unwrap() {
                    received_request.extend_from_slice(&scratch[..n]);
                }
            }
            if response_sent < response.len() {
                if let TcpIoResult::Progress(n) = frontend.try_send(peer, &response[response_sent..]).unwrap() {
                    response_sent += n;
                }
            }
        }
        if now % 5 == 0 && client.socket().can_recv() {
            let n = client.socket().recv_slice(&mut scratch).unwrap();
            received_response.extend_from_slice(&scratch[..n]);
        }
        if received_request.len() == request.len() && received_response.len() == response.len() {
            break;
        }
    }
    assert_eq!(received_request, request);
    assert_eq!(received_response, response);
    #[cfg(feature = "native-tcp-segmentation")]
    assert!(client.device.stats().tx_segmented_requests > 0,
        "the real TCP transfer must exercise native large-send generation");
    assert!(exchange_observed, "must use pool exchange, not only copied fallback");
    let old = connection.unwrap();
    client.socket().close();
    for _ in 0..100 {
        client.poll(next_time); server.poll_network(next_time).unwrap();
        server.drive_tcp_frontend(socket, &frontend).unwrap(); next_time += 1;
        if frontend.snapshot().state == TcpStreamState::PeerClosed { break; }
    }
    assert_eq!(frontend.snapshot().state, TcpStreamState::PeerClosed);
    // A successor can handshake on the pending socket before the old frontend closes.
    let next = client.open_connection(49_153);
    for _ in 0..100 {
        client.poll(next_time); server.poll_network(next_time).unwrap();
        server.drive_tcp_frontend(socket, &frontend).unwrap(); next_time += 1;
        if client.socket_by_handle(next).may_send() { break; }
    }
    assert!(client.socket_by_handle(next).may_send());
    client.socket_by_handle(next).send_slice(b"pending-buffer").unwrap();
    frontend.request_close(old).unwrap();
    let mut fresh = None;
    let mut second = Vec::new();
    let mut promoted_exchange = false;
    for _ in 0..1000 {
        client.poll(next_time); server.poll_network(next_time).unwrap();
        server.drive_tcp_frontend(socket, &frontend).unwrap(); next_time += 1;
        promoted_exchange |= pool.queued_bytes() != 0;
        fresh = fresh.or_else(|| frontend.try_accept());
        if let Some(peer) = fresh {
            if let TcpIoResult::Progress(n) = frontend.try_recv_for(peer, consumer, &mut scratch).unwrap() {
                second.extend_from_slice(&scratch[..n]);
            }
        }
        if second.len() == 14 { break; }
    }
    assert_eq!(second, b"pending-buffer");
    assert!(promoted_exchange);
    assert_ne!(old.generation(), fresh.unwrap().generation());
    assert_eq!(pool.queued_bytes(), 0);
    space.revoke(server_in_root).unwrap();
    assert_eq!(
        server.drive_tcp_frontend(socket, &frontend),
        Err(vibeos_net_protocol::TcpFrontendDriveError::Stack(StackError::AuthorityRevoked))
    );
    drop(server); // Ends both active and pending socket references.
    assert_eq!(unsafe { pool.retire_stopped_owner(owner) }, 0, "normal stack drop must release both writers");
}


#[test]
#[cfg(feature = "receive-buffer-exchange")]
fn normal_stack_rebuild_reuses_writers_and_preserves_unrelated_leases() {
    use std::num::NonZeroU64;
    use vibeos_core::{heap::{AllocationDomain, ArenaId, OwnerId}, sync::TaskRecoveryKey};
    use vibeos_net_api::{receive_ownership::Owner, receive_storage::Storage};
    let owner = Owner { domain: AllocationDomain::new(OwnerId::new(91), ArenaId::new(91)), task: TaskRecoveryKey::new(91).unwrap() };
    let consumer = Owner { domain: AllocationDomain::new(OwnerId::new(92), ArenaId::new(92)), task: TaskRecoveryKey::new(92).unwrap() };
    let pool = Storage::<3>::new_static(4096, 8192).unwrap();
    let frontend = TcpListener::new_with_receive_storage("rebuild", TcpListenerId::new(92).unwrap(), SERVER_PORT, 8192, 4096, pool).unwrap();
    let to_server = Endpoint::new("rebuild-in", 8);
    let to_client = Endpoint::new("rebuild-out", 8);
    let mut space = CSpace::new("rebuild");
    let (_, inbound) = authority(&mut space, &to_server, Rights::RECV);
    let (_, outbound) = authority(&mut space, &to_client, Rights::SEND);
    for iteration in 0..100 {
        let mut stack = SharedIpv4TcpStack::new(
            Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 92), session_stamp(),
            inbound.clone(), outbound.clone()).unwrap();
        let handle = stack.add_tcp_listener(SERVER_PORT).unwrap();
        unsafe { stack.enable_receive_exchange(handle, frontend.clone(), owner).unwrap(); }
        let spare = pool.reserve(owner).unwrap();
        if iteration % 2 == 0 {
            // A distinct live writer with the same exact task identity must not
            // be swept up by a whole-owner retirement in stack destruction.
            drop(stack);
            assert!(pool.writer_address(spare, owner).is_ok());
            unsafe { pool.release_writer(spare, owner).unwrap(); }
        } else {
            frontend.network_update_state(TcpStreamState::Established).unwrap();
            let peer = frontend.try_accept().unwrap();
            let generation = NonZeroU64::new(peer.generation()).unwrap();
            let (pointer, _) = pool.writer_address(spare, owner).unwrap();
            unsafe {
                core::ptr::copy_nonoverlapping(b"survives".as_ptr(), pointer.as_ptr(), 8);
                pool.prepare(spare, owner, generation, 0, 8).unwrap();
            }
            frontend.network_publish_exchange(spare, owner, generation).unwrap();
            drop(stack);
            assert_eq!(pool.queued_bytes(), 8);
            let mut bytes = [0; 8];
            assert_eq!(frontend.try_recv_for(peer, consumer, &mut bytes), Ok(TcpIoResult::Progress(8)));
            assert_eq!(&bytes, b"survives");
            frontend.network_update_state(TcpStreamState::Listening).unwrap();
        }
        assert_eq!(pool.queued_bytes(), 0);
        assert_eq!(unsafe { pool.retire_stopped_owner(owner) }, 0, "drop must release exactly its own two writers");
    }
}

#[test]
#[cfg(all(feature = "receive-buffer-exchange", feature = "activity-events"))]
fn rejected_exchange_aborts_stream_and_cannot_be_retried() {
    use std::{future::Future, pin::pin, sync::atomic::{AtomicBool, Ordering}, task::{Context, Wake, Waker}};
    use vibeos_core::{heap::{AllocationDomain, ArenaId, OwnerId}, sync::TaskRecoveryKey};
    use vibeos_net_api::{receive_ownership::Owner, receive_storage::Storage};
    let owner = Owner { domain: AllocationDomain::new(OwnerId::new(121), ArenaId::new(121)), task: TaskRecoveryKey::new(121).unwrap() };
    let pool = Storage::<3>::new_static(4096, 8192).unwrap();
    let frontend = TcpListener::new_with_receive_storage("reject", TcpListenerId::new(121).unwrap(), SERVER_PORT, 256, 256, pool).unwrap();
    let mut caps = CSpace::new("reject-exchange");
    let to_server = Endpoint::new("reject-in", 128);
    let to_client = Endpoint::new("reject-out", 128);
    let (_, input) = authority(&mut caps, &to_server, Rights::RECV);
    let (_, output) = authority(&mut caps, &to_client, Rights::SEND);
    let (_, client_in) = authority(&mut caps, &to_client, Rights::RECV);
    let (_, client_out) = authority(&mut caps, &to_server, Rights::SEND);
    let mut server = SharedIpv4TcpStack::new(Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 121), session_stamp(), input, output).unwrap();
    let handle = server.add_tcp_listener(SERVER_PORT).unwrap();
    unsafe { server.enable_receive_exchange(handle, frontend.clone(), owner).unwrap(); }
    let mut client = TestClient::new(client_in, client_out);
    let mut sent = false;
    let mut now = 0;
    while now < 1000 {
        client.poll(now);
        if !sent && client.socket().can_send() {
            assert_eq!(client.socket().send_slice(b"data").unwrap(), 4);
            sent = true;
            client.poll(now);
        }
        server.poll_network(now).unwrap();
        now += 1;
        if server.tcp_stream_status(handle).unwrap().readable_bytes == 4 { break; }
    }
    assert_eq!(server.tcp_stream_status(handle).unwrap().readable_bytes, 4);
    struct Fill { frontend: Arc<TcpListener>, fired: AtomicBool }
    impl Wake for Fill {
        fn wake(self: Arc<Self>) {
            if !self.fired.swap(true, Ordering::Relaxed) {
                // Consume the capacity after network_begin_drive snapshots it,
                // but before the exchange publication rechecks admission.
                assert_eq!(self.frontend.network_receive(&[7; 256]), 256);
            }
        }
    }
    let fill = Arc::new(Fill { frontend: frontend.clone(), fired: AtomicBool::new(false) });
    let event = frontend.network_event();
    let waker = Waker::from(fill.clone());
    let mut cx = Context::from_waker(&waker);
    let mut waiting = pin!(event.wait());
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    assert!(server.drive_tcp_frontend(handle, &frontend).is_err());
    assert!(fill.fired.load(Ordering::Relaxed));
    assert_eq!(frontend.snapshot().state, TcpStreamState::Reset);
    assert_eq!(frontend.snapshot().readable_bytes, 0);
    assert_eq!(pool.queued_bytes(), 0);
    assert!(server.drive_tcp_frontend(handle, &frontend).is_err());
    // Even after ordinary network polling, neither socket may auto-relisten.
    for _ in 0..10 {
        client.poll(now); server.poll_network(now).unwrap(); now += 1;
        assert!(!server.tcp_is_listening(handle).unwrap());
        assert!(server.drive_tcp_frontend(handle, &frontend).is_err());
    }
    drop(server);
    assert_eq!(unsafe { pool.retire_stopped_owner(owner) }, 0);
}

#[test]
#[cfg(feature = "receive-buffer-exchange")]
fn shared_port_exchange_keeps_simultaneous_streams_in_separate_pools() {
    use vibeos_core::{heap::{AllocationDomain, ArenaId, OwnerId}, sync::TaskRecoveryKey};
    use vibeos_net_api::{receive_ownership::Owner, receive_storage::Storage, TcpPortGroupId};
    let owner = Owner { domain: AllocationDomain::new(OwnerId::new(131), ArenaId::new(131)), task: TaskRecoveryKey::new(131).unwrap() };
    let consumer = Owner { domain: AllocationDomain::new(OwnerId::new(132), ArenaId::new(132)), task: TaskRecoveryKey::new(132).unwrap() };
    let pools = [Storage::<3>::new_static(4096, 8192).unwrap(), Storage::<3>::new_static(4096, 8192).unwrap()];
    let group = TcpPortGroupId::new(131).unwrap();
    let frontends: Vec<_> = (0..2).map(|i| TcpListener::new_shared_with_receive_storage("shared-exchange", TcpListenerId::new(131+i as u64).unwrap(), SERVER_PORT, 8192, 4096, group, pools[i]).unwrap()).collect();
    let mut caps = CSpace::new("shared-exchange");
    let incoming = Endpoint::new("shared-in", 128);
    let outgoing = Endpoint::new("shared-out", 128);
    let (_, input) = authority(&mut caps, &incoming, Rights::RECV);
    let (_, output) = authority(&mut caps, &outgoing, Rights::SEND);
    let (_, client_in) = authority(&mut caps, &outgoing, Rights::RECV);
    let (_, client_out) = authority(&mut caps, &incoming, Rights::SEND);
    let mut server = SharedIpv4TcpStack::new(Ipv4StackConfig::new(SERVER_MAC, SERVER_IP, 24, 131), session_stamp(), input, output).unwrap();
    let handles = [server.add_shared_tcp_listener(SERVER_PORT, group.get()).unwrap(), server.add_shared_tcp_listener(SERVER_PORT, group.get()).unwrap()];
    let mut frontend_roots = Vec::new();
    for i in 0..2 {
        let root = caps.mint(frontends[i].clone(), Rights::ALL_VOLATILE);
        let capability = caps.lookup_revocable::<TcpListener>(root, Rights::RECV).unwrap();
        unsafe { server.enable_receive_exchange_capability(handles[i], capability, owner).unwrap(); }
        frontend_roots.push(root);
    }
    assert!(server.drive_tcp_frontend(handles[0], &frontends[1]).is_err());
    let mut client = TestClient::new(client_in, client_out);
    let second = client.open_connection_to(SERVER_PORT, 49_153);
    let expected: [Vec<u8>; 2] = core::array::from_fn(|stream| (0..300_007).map(|i| (i * 37 + i / 251 + stream * 73) as u8).collect());
    let mut sent = [0; 2];
    let mut observed: [Vec<u8>; 2] = core::array::from_fn(|_| Vec::new());
    let mut connections = [None; 2];
    let mut exchanges = [false; 2];
    for now in 0..100_000 {
        client.poll(now);
        for i in 0..2 {
            let socket = if i == 0 { client.socket() } else { client.socket_by_handle(second) };
            if socket.can_send() && sent[i] < expected[i].len() {
                sent[i] += socket.send_slice(&expected[i][sent[i]..]).unwrap();
            }
        }
        client.poll(now);
        server.poll_network(now).unwrap();
        for i in 0..2 {
            server.drive_tcp_frontend(handles[i], &frontends[i]).unwrap();
            connections[i] = connections[i].or_else(|| frontends[i].try_accept());
            exchanges[i] |= pools[i].queued_bytes() != 0;
            assert!(frontends[i].snapshot().readable_bytes <= 8192);
            if now % (3+i as u64) == 0 {
                if let Some(peer) = connections[i] {
                    let mut bytes = [0; 997];
                    if let TcpIoResult::Progress(n) = frontends[i].try_recv_for(peer, consumer, &mut bytes).unwrap() {
                        observed[i].extend_from_slice(&bytes[..n]);
                    }
                }
            }
        }
        if observed.iter().all(|v| v.len() == expected[0].len()) { break; }
    }
    assert_eq!(sent, [300_007; 2]);
    assert!(exchanges.into_iter().all(|v| v));
    // Shared-port socket selection need not assign the first SYN to slot zero.
    assert!((observed[0] == expected[0] && observed[1] == expected[1]) || (observed[0] == expected[1] && observed[1] == expected[0]));
    caps.revoke(frontend_roots[0]).unwrap();
    // Retaining an external Arc must not bypass the stored capability's
    // revocation, and the independent sibling capability remains usable.
    assert!(server.drive_tcp_frontend(handles[0], &frontends[0]).is_err());
    assert!(server.drive_tcp_frontend(handles[1], &frontends[1]).is_ok());
    drop(server);
    for pool in pools {
        assert_eq!(pool.queued_bytes(), 0);
        assert_eq!(unsafe { pool.retire_stopped_owner(owner) }, 0);
    }
}
