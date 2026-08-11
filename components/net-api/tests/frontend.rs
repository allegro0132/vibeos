use vibeos_core::cap::{CSpace, Rights};
use vibeos_net_api::{TcpFrontendError, TcpIoResult, TcpListener, TcpListenerId, TcpStreamState};

fn listener(name: &str, id: u64, port: u16, capacity: usize) -> std::sync::Arc<TcpListener> {
    TcpListener::new(
        name,
        TcpListenerId::new(id).unwrap(),
        port,
        capacity,
        capacity,
    )
    .unwrap()
}

#[test]
fn connection_generation_prevents_listener_reuse_aba() {
    let listener = listener("ssh", 1, 22, 16);
    assert_eq!(listener.try_accept(), None);
    listener
        .network_update_state(TcpStreamState::Handshake)
        .unwrap();
    assert_eq!(listener.try_accept(), None);
    listener
        .network_update_state(TcpStreamState::Established)
        .unwrap();
    let first = listener.try_accept().unwrap();
    assert_eq!(listener.try_accept(), None);

    assert_eq!(listener.network_receive(b"hello"), 5);
    let mut receive = [0u8; 8];
    assert_eq!(
        listener.try_recv(first, &mut receive),
        Ok(TcpIoResult::Progress(5))
    );
    assert_eq!(&receive[..5], b"hello");
    assert_eq!(
        listener.try_send(first, b"world"),
        Ok(TcpIoResult::Progress(5))
    );
    let mut transmit = [0u8; 8];
    assert_eq!(listener.network_transmit(&mut transmit), 5);
    assert_eq!(&transmit[..5], b"world");

    listener
        .network_update_state(TcpStreamState::Listening)
        .unwrap();
    listener
        .network_update_state(TcpStreamState::Established)
        .unwrap();
    let second = listener.try_accept().unwrap();
    assert_ne!(first.generation(), second.generation());
    assert_eq!(
        listener.try_send(first, b"stale"),
        Err(TcpFrontendError::StaleConnection)
    );
    assert_eq!(
        listener.try_send(second, b"fresh"),
        Ok(TcpIoResult::Progress(5))
    );
}

#[test]
fn listener_identity_prevents_cross_port_connection_substitution() {
    let ssh = listener("ssh", 1, 22, 16);
    let http = listener("http", 2, 80, 16);
    ssh.network_update_state(TcpStreamState::Established)
        .unwrap();
    http.network_update_state(TcpStreamState::Established)
        .unwrap();
    let ssh_connection = ssh.try_accept().unwrap();
    let _http_connection = http.try_accept().unwrap();
    assert_eq!(
        http.try_send(ssh_connection, b"wrong port"),
        Err(TcpFrontendError::WrongListener)
    );
}

#[test]
fn queues_are_bounded_and_close_requests_are_explicit() {
    let listener = listener("bounded", 3, 8080, 4);
    listener
        .network_update_state(TcpStreamState::Established)
        .unwrap();
    let connection = listener.try_accept().unwrap();
    assert_eq!(listener.network_receive(b"abcdef"), 4);
    assert_eq!(listener.network_receive(b"z"), 0);
    assert_eq!(
        listener.try_send(connection, b"abcdef"),
        Ok(TcpIoResult::Progress(4))
    );
    assert_eq!(
        listener.try_send(connection, b"z"),
        Ok(TcpIoResult::WouldBlock)
    );
    listener.request_close(connection).unwrap();
    assert!(listener.take_close_request().is_some());
    assert_eq!(listener.take_close_request(), None);
}

#[test]
fn cspace_rights_and_root_revocation_confine_listener_access() {
    let listener = listener("rights", 4, 443, 16);
    let mut policy = CSpace::new("network-policy");
    let root = policy.mint(listener, Rights::ALL_VOLATILE);
    let mut ssh = CSpace::new("sshd");
    let accept = vibeos_core::cap::grant(&policy, root, Rights::RECV, &mut ssh).unwrap();

    assert!(ssh
        .lookup_revocable::<TcpListener>(accept, Rights::RECV)
        .is_ok());
    assert!(ssh
        .lookup_revocable::<TcpListener>(accept, Rights::READ)
        .is_err());
    let token = ssh
        .lookup_revocable::<TcpListener>(accept, Rights::RECV)
        .unwrap();
    policy.revoke(root).unwrap();
    assert!(token.try_with(|listener| listener.port()).is_err());
}
