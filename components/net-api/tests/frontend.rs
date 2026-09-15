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
fn bulk_frontend_copies_preserve_wrapped_queue_order() {
    let listener = listener("wrapped", 5, 5201, 8);
    listener
        .network_update_state(TcpStreamState::Established)
        .unwrap();
    let connection = listener.try_accept().unwrap();

    assert_eq!(listener.network_receive(b"abcdef"), 6);
    let mut first = [0u8; 4];
    assert_eq!(
        listener.try_recv(connection, &mut first),
        Ok(TcpIoResult::Progress(4))
    );
    assert_eq!(listener.network_receive(b"ghijkl"), 6);
    let mut wrapped_receive = [0u8; 8];
    assert_eq!(
        listener.try_recv(connection, &mut wrapped_receive),
        Ok(TcpIoResult::Progress(8))
    );
    assert_eq!(&wrapped_receive, b"efghijkl");

    assert_eq!(
        listener.try_send(connection, b"mnopqr"),
        Ok(TcpIoResult::Progress(6))
    );
    listener.network_consume_transmit(4);
    assert_eq!(
        listener.try_send(connection, b"stuvwx"),
        Ok(TcpIoResult::Progress(6))
    );
    let mut wrapped_transmit = [0u8; 8];
    assert_eq!(
        listener.network_copy_transmit(&mut wrapped_transmit),
        wrapped_transmit.len()
    );
    assert_eq!(&wrapped_transmit, b"qrstuvwx");
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

#[cfg(feature = "activity-events")]
#[test]
fn application_events_cover_send_receive_close_and_reject_stale_tokens() {
    use std::{future::Future, pin::pin, task::{Context, Waker}};
    let listener = listener("events", 81, 8081, 16);
    listener.network_update_state(TcpStreamState::Established).unwrap();
    let token = listener.try_accept().unwrap();
    let event = listener.application_event();
    let mut cx = Context::from_waker(Waker::noop());
    // Prepare before checking/polling: writes before registration are observed.
    let mut write = pin!(event.wait());
    assert_eq!(listener.try_send(token, b"abcd"), Ok(TcpIoResult::Progress(4)));
    assert!(write.as_mut().poll(&mut cx).is_ready());
    let mut read = pin!(event.wait());
    assert_eq!(listener.try_recv(token, &mut [0;4]), Ok(TcpIoResult::WouldBlock));
    assert!(read.as_mut().poll(&mut cx).is_pending());
    listener.network_receive(b"data");
    assert_eq!(listener.try_recv(token, &mut [0;4]), Ok(TcpIoResult::Progress(4)));
    assert!(read.as_mut().poll(&mut cx).is_ready());
    let mut close = pin!(event.wait());
    listener.request_close(token).unwrap();
    assert!(close.as_mut().poll(&mut cx).is_ready());
    listener.network_update_state(TcpStreamState::Listening).unwrap();
    listener.network_update_state(TcpStreamState::Established).unwrap();
    let fresh = listener.try_accept().unwrap();
    let mut stale = pin!(event.wait());
    assert!(listener.try_send(token, b"old").is_err());
    assert!(stale.as_mut().poll(&mut cx).is_pending());
    listener.request_reset(fresh).unwrap();
    assert!(stale.as_mut().poll(&mut cx).is_ready());
}

#[cfg(feature = "activity-events")]
#[test]
fn application_notification_invokes_wakers_outside_listener_lock() {
    use std::{future::Future, pin::pin, sync::{Arc, atomic::{AtomicUsize, Ordering}}, task::{Context, Wake, Waker}};
    struct Reenter { listener: Arc<TcpListener>, count: AtomicUsize }
    impl Wake for Reenter {
        fn wake(self: Arc<Self>) {
            let _ = self.listener.snapshot();
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }
    let listener = listener("reenter-events", 82, 8082, 16);
    listener.network_update_state(TcpStreamState::Established).unwrap();
    let token = listener.try_accept().unwrap();
    let event = listener.application_event();
    let callback = Arc::new(Reenter { listener: listener.clone(), count: AtomicUsize::new(0) });
    let waker = Waker::from(callback.clone()); let mut cx = Context::from_waker(&waker);
    let mut wait = pin!(event.wait());
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    listener.try_send(token, b"wake").unwrap();
    assert_eq!(callback.count.load(Ordering::Relaxed), 1);
    assert!(wait.as_mut().poll(&mut cx).is_ready());
}

#[cfg(feature = "activity-events")]
#[test]
fn network_readiness_transitions_wake_without_per_packet_notifications() {
    use std::{future::Future, pin::pin, task::{Context, Waker}};
    let listener = listener("network-events", 83, 8083, 4);
    let event = listener.network_event();
    let mut cx = Context::from_waker(Waker::noop());
    let mut established = pin!(event.wait());
    listener.network_update_state(TcpStreamState::Established).unwrap();
    assert!(established.as_mut().poll(&mut cx).is_ready());
    let token = listener.try_accept().unwrap();
    let mut readable = pin!(event.wait());
    assert!(readable.as_mut().poll(&mut cx).is_pending());
    assert_eq!(listener.network_receive(b"ab"), 2);
    assert!(readable.as_mut().poll(&mut cx).is_ready());
    let mut unchanged = pin!(event.wait());
    listener.network_update_state(TcpStreamState::Established).unwrap();
    assert_eq!(listener.network_receive(b"cd"), 2);
    assert_eq!(listener.network_receive(b"e"), 0);
    assert!(unchanged.as_mut().poll(&mut cx).is_pending());
    assert_eq!(listener.try_recv(token, &mut [0; 4]), Ok(TcpIoResult::Progress(4)));
    assert_eq!(listener.network_receive(b"e"), 1);
    assert!(unchanged.as_mut().poll(&mut cx).is_ready());
    assert_eq!(listener.try_send(token, b"1234"), Ok(TcpIoResult::Progress(4)));
    let mut writable = pin!(event.wait());
    listener.network_consume_transmit(0);
    assert!(writable.as_mut().poll(&mut cx).is_pending());
    listener.network_consume_transmit(1);
    assert!(writable.as_mut().poll(&mut cx).is_ready());
    let mut still_writable = pin!(event.wait());
    listener.network_consume_transmit(1);
    assert!(still_writable.as_mut().poll(&mut cx).is_pending());
    listener.network_update_state(TcpStreamState::PeerClosed).unwrap();
    assert!(still_writable.as_mut().poll(&mut cx).is_ready());
}

#[cfg(feature = "activity-events")]
#[test]
fn network_notification_allows_reentrant_application_reads() {
    use std::{future::Future, pin::pin, sync::Arc, task::{Context, Wake, Waker}};
    struct ReadOnWake { listener: Arc<TcpListener>, token: vibeos_net_api::TcpConnectionToken }
    impl Wake for ReadOnWake {
        fn wake(self: Arc<Self>) {
            assert_eq!(self.listener.try_recv(self.token, &mut [0; 4]), Ok(TcpIoResult::Progress(4)));
        }
    }
    let listener = listener("network-reenter", 84, 8084, 4);
    listener.network_update_state(TcpStreamState::Established).unwrap();
    let token = listener.try_accept().unwrap();
    let event = listener.network_event();
    let waker = Waker::from(Arc::new(ReadOnWake { listener: listener.clone(), token }));
    let mut cx = Context::from_waker(&waker);
    let mut wait = pin!(event.wait());
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    assert_eq!(listener.network_receive(b"wake"), 4);
    assert!(wait.as_mut().poll(&mut cx).is_ready());
    assert_eq!(listener.snapshot().readable_bytes, 0);
}
