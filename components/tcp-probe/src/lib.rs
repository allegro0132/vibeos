//! Diagnostic byte-count TCP source/sink; independent of the iperf protocol.
#![no_std]
extern crate alloc;
use alloc::{vec, vec::Vec};
use vibeos_core::cap::Cap;
use vibeos_net_api::{TcpConnectionToken, TcpIoResult};

pub const FIRST_PORT: u16 = 5300;
pub const FLOW_COUNT: usize = 4;
pub const CHUNK: usize = 32 * 1024;
const LIMIT: u64 = 16 * 1024 * 1024 * 1024;
const DEADLINE_MS: u64 = 300_000;
static PAYLOAD: [u8; CHUNK] = [0xa5; CHUNK];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketError {
    AuthorityRevoked,
    StaleConnection,
    Failed,
}

/// The adapter checks the listener capability on every operation.
pub trait Platform: Sync {
    #[cfg(feature = "event-driven")]
    fn tcp_activity(&self, _listener: Cap) -> Result<Option<vibeos_core::chan::MessageEvent>, SocketError> {
        Ok(None)
    }
    fn tcp_accept(&self, listener: Cap) -> Result<Option<TcpConnectionToken>, SocketError>;
    fn tcp_recv(
        &self,
        listener: Cap,
        connection: TcpConnectionToken,
        output: &mut [u8],
    ) -> Result<TcpIoResult, SocketError>;
    fn tcp_send(
        &self,
        listener: Cap,
        connection: TcpConnectionToken,
        input: &[u8],
    ) -> Result<TcpIoResult, SocketError>;
    fn tcp_close(&self, listener: Cap, connection: TcpConnectionToken) -> Result<(), SocketError>;
    fn tcp_reset(&self, listener: Cap, connection: TcpConnectionToken) -> Result<(), SocketError>;
    fn now_ms(&self) -> u64;
}

/// Header: VBENCH01, mode (0 sink/1 source/2 V2 verified sink), seven zero bytes, u64 BE count.
fn request(header: &[u8; 24]) -> Result<(bool, u64), SocketError> {
    let size = u64::from_be_bytes(header[16..24].try_into().unwrap());
    if (&header[..8] != b"VBENCH01" && &header[..8] != b"VBENCH02")
        || header[8] > 2
        || (header[8] == 2 && header[7] != b'2')
        || header[9..16] != [0; 7]
        || size == 0
        || size > LIMIT
    {
        return Err(SocketError::Failed);
    }
    Ok((header[8] == 1, size))
}

struct Flow {
    connection: Option<TcpConnectionToken>,
    header: [u8; 24],
    header_used: usize,
    source: bool,
    ready_sent: bool,
    go_received: bool,
    size: u64,
    done: u64,
    accepted_ms: u64,
    started_ms: Option<u64>,
    result: [u8; 16],
    result_used: usize,
    buffer: Vec<u8>,
}
impl Flow {
    fn new() -> Self {
        Self {
            connection: None,
            header: [0; 24],
            header_used: 0,
            source: false,
            ready_sent: false,
            go_received: false,
            size: 0,
            done: 0,
            accepted_ms: 0,
            started_ms: None,
            result: [0; 16],
            result_used: 0,
            buffer: vec![0; CHUNK],
        }
    }
    fn clear(&mut self) {
        self.connection = None;
        self.header_used = 0;
        self.ready_sent = false;
        self.go_received = false;
        self.size = 0;
        self.done = 0;
        self.started_ms = None;
        self.result_used = 0;
    }
    fn drive(&mut self, p: &dyn Platform, listener: Cap) -> Result<bool, SocketError> {
        if self.connection.is_none() {
            self.connection = p.tcp_accept(listener)?;
            if self.connection.is_none() {
                return Ok(false);
            }
            self.accepted_ms = p.now_ms();
        }
        let connection = self.connection.unwrap();
        if p.now_ms().saturating_sub(self.accepted_ms) >= DEADLINE_MS {
            return Err(SocketError::Failed);
        }
        if self.header_used < 24 {
            match p.tcp_recv(listener, connection, &mut self.header[self.header_used..])? {
                TcpIoResult::Progress(n) => {
                    self.header_used += n;
                    if self.header_used == 24 {
                        (self.source, self.size) = request(&self.header)?;
                    }
                    return Ok(n != 0);
                }
                TcpIoResult::WouldBlock => return Ok(false),
                TcpIoResult::Closed => return Err(SocketError::Failed),
            }
        }
        // V2 makes application admission explicit before a host-wide GO.
        // V1 remains accepted for existing captures and clients.
        if self.header[7] == b'2' && !self.ready_sent {
            match p.tcp_send(listener, connection, b"R")? {
                TcpIoResult::Progress(1) => {
                    self.ready_sent = true;
                    return Ok(true);
                }
                TcpIoResult::WouldBlock | TcpIoResult::Progress(0) => return Ok(false),
                _ => return Err(SocketError::Failed),
            }
        }
        if self.header[7] == b'2' && !self.go_received {
            let mut signal = [0];
            match p.tcp_recv(listener, connection, &mut signal)? {
                TcpIoResult::Progress(1) if signal[0] == b'G' => {
                    self.go_received = true;
                    return Ok(true);
                }
                TcpIoResult::WouldBlock | TcpIoResult::Progress(0) => return Ok(false),
                _ => return Err(SocketError::Failed),
            }
        }
        if self.done < self.size {
            let budget = if cfg!(feature = "receive-batch") && !self.source { 4 } else { 1 };
            let mut worked = false;
            for _ in 0..budget {
                if self.done == self.size { break; }
                let len = (self.size - self.done).min(CHUNK as u64) as usize;
                let now = p.now_ms();
                let io = if self.source {
                    p.tcp_send(listener, connection, &PAYLOAD[..len])?
                } else {
                    p.tcp_recv(listener, connection, &mut self.buffer[..len])?
                };
                match io {
                    TcpIoResult::Progress(n) => {
                        // Diagnostic mode verifies application-visible bytes, after
                        // DMA, GRO, TCP reassembly and frontend queue delivery. It
                        // is deliberately separate from throughput-only mode 0.
                        if self.header[8] == 2 {
                            let mut expected = (self.done % 251) as u8;
                            for byte in &self.buffer[..n] {
                                if *byte != expected {
                                    return Err(SocketError::Failed);
                                }
                                expected = if expected == 250 { 0 } else { expected + 1 };
                            }
                        }
                        if n != 0 {
                            self.started_ms.get_or_insert(now);
                        }
                        self.done += n as u64;
                        if self.done == self.size {
                            self.result[..8].copy_from_slice(&self.done.to_be_bytes());
                            self.result[8..].copy_from_slice(
                                &p.now_ms()
                                    .saturating_sub(self.started_ms.unwrap_or(now))
                                    .to_be_bytes(),
                            );
                        }
                        if n == 0 { break; }
                        worked = true;
                    }
                    TcpIoResult::WouldBlock => break,
                    TcpIoResult::Closed => return Err(SocketError::Failed),
                }
            }
            return Ok(worked);
        }
        match p.tcp_send(listener, connection, &self.result[self.result_used..])? {
            TcpIoResult::Progress(n) => {
                self.result_used += n;
                if self.result_used == self.result.len() {
                    // Frontend close drains queued payload and result before FIN.
                    p.tcp_close(listener, connection)?;
                    self.clear();
                }
                Ok(n != 0)
            }
            TcpIoResult::WouldBlock => Ok(false),
            TcpIoResult::Closed => Err(SocketError::Failed),
        }
    }
}

pub async fn task(p: &dyn Platform, listeners: [Cap; FLOW_COUNT]) {
    // Allocate after the supervised task starts, charged to its arena.
    let mut flows: Vec<Flow> = (0..FLOW_COUNT).map(|_| Flow::new()).collect();
    let mut budget = vibeos_core::poll_budget::PollBudget::new(1, 64);
    #[cfg(feature = "event-driven")]
    let notifications = {
        let mut events: [Option<vibeos_core::chan::MessageEvent>; FLOW_COUNT] = core::array::from_fn(|_| None);
        for (slot, listener) in events.iter_mut().zip(listeners) {
            match p.tcp_activity(listener) {
                Ok(event) => *slot = event,
                Err(_) => return,
            }
        }
        if events.iter().all(Option::is_some) { Some(events.map(Option::unwrap)) } else { None }
    };
    #[cfg(feature = "event-driven")]
    let mut armed = false;
    loop {
        // Prepare listeners before the second complete idle check. Busy turns
        // avoid queue registration; notifications carry no data authority.
        #[cfg(feature = "event-driven")]
        let waits = if armed {
            notifications.as_ref().map(|events| events.each_ref().map(|event| event.wait()))
        } else { None };
        let mut worked = false;
        for (flow, listener) in flows.iter_mut().zip(listeners) {
            match flow.drive(p, listener) {
                Ok(progress) => worked |= progress,
                Err(SocketError::AuthorityRevoked) => return,
                Err(_) => {
                    if let Some(connection) = flow.connection {
                        if p.tcp_reset(listener, connection) == Err(SocketError::AuthorityRevoked) {
                            return;
                        }
                    }
                    flow.clear();
                    worked = true;
                }
            }
        }
        #[cfg(feature = "event-driven")]
        if notifications.is_some() {
            vibeos_core::net_profile::poll_decision(worked, worked || waits.is_none());
            if worked {
                armed = false;
                vibeos_core::exec::yield_now().await;
            } else if let Some(mut waits) = waits {
                use core::{future::{poll_fn, Future}, pin::{pin, Pin}, task::Poll};
                // Keep deadline and revocation observation bounded even if
                // a notification is unavailable because its producer retired.
                let mut timer = pin!(vibeos_core::exec::sleep_ms(1));
                poll_fn(|cx| {
                    if timer.as_mut().poll(cx).is_ready() { return Poll::Ready(()); }
                    for waiter in &mut waits {
                        if Pin::new(waiter).poll(cx).is_ready() { return Poll::Ready(()); }
                    }
                    Poll::Pending
                }).await;
                armed = false;
            } else {
                armed = true;
            }
            continue;
        }
        if budget.runnable(p.now_ms(), worked) {
            vibeos_core::exec::yield_now().await;
        } else {
            vibeos_core::exec::sleep_ms(1).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};
    use vibeos_core::cap::{CSpace, Rights};
    use vibeos_net_api::{TcpListener, TcpListenerId, TcpStreamState};
    #[cfg(feature = "event-driven")]
    #[test]
    fn idle_task_checks_twice_then_observes_revocation_on_notification() {
        use core::{future::Future, pin::pin, sync::atomic::AtomicBool, task::{Context, Waker}};
        struct Idle {
            listener: alloc::sync::Arc<TcpListener>,
            calls: AtomicU64,
            revoked: AtomicBool,
        }
        impl Platform for Idle {
            fn tcp_activity(&self, _: Cap) -> Result<Option<vibeos_core::chan::MessageEvent>, SocketError> {
                Ok(Some(self.listener.network_event()))
            }
            fn tcp_accept(&self, _: Cap) -> Result<Option<TcpConnectionToken>, SocketError> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                if self.revoked.load(Ordering::Relaxed) { Err(SocketError::AuthorityRevoked) } else { Ok(None) }
            }
            fn tcp_recv(&self, _: Cap, _: TcpConnectionToken, _: &mut [u8]) -> Result<TcpIoResult, SocketError> { unreachable!() }
            fn tcp_send(&self, _: Cap, _: TcpConnectionToken, _: &[u8]) -> Result<TcpIoResult, SocketError> { unreachable!() }
            fn tcp_close(&self, _: Cap, _: TcpConnectionToken) -> Result<(), SocketError> { unreachable!() }
            fn tcp_reset(&self, _: Cap, _: TcpConnectionToken) -> Result<(), SocketError> { unreachable!() }
            fn now_ms(&self) -> u64 { 0 }
        }
        let (model, cap) = Model::new();
        let p = Idle { listener: model.listener, calls: AtomicU64::new(0), revoked: AtomicBool::new(false) };
        let mut future = pin!(task(&p, [cap; FLOW_COUNT]));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(p.calls.load(Ordering::Relaxed), (FLOW_COUNT * 2) as u64);
        p.revoked.store(true, Ordering::Relaxed);
        p.listener.network_update_state(TcpStreamState::PeerClosed).unwrap();
        assert!(future.as_mut().poll(&mut cx).is_ready());
        assert_eq!(p.calls.load(Ordering::Relaxed), (FLOW_COUNT * 2 + 1) as u64);
    }
    struct Model {
        listener: alloc::sync::Arc<TcpListener>,
        now: AtomicU64,
        read_limit: usize,
    }
    impl Model {
        fn new() -> (Self, Cap) {
            let cap = CSpace::new("probe-test").mint(
                TcpListener::new("dummy", TcpListenerId::new(2).unwrap(), 5301, 64, 64).unwrap(),
                Rights::ALL_VOLATILE,
            );
            let listener =
                TcpListener::new("probe", TcpListenerId::new(1).unwrap(), 5300, 64, 7).unwrap();
            listener
                .network_update_state(TcpStreamState::Established)
                .unwrap();
            (
                Self {
                    listener,
                    now: AtomicU64::new(1),
                    read_limit: usize::MAX,
                },
                cap,
            )
        }
    }
    impl Platform for Model {
        fn tcp_accept(&self, _: Cap) -> Result<Option<TcpConnectionToken>, SocketError> {
            Ok(self.listener.try_accept())
        }
        fn tcp_recv(
            &self,
            _: Cap,
            c: TcpConnectionToken,
            b: &mut [u8],
        ) -> Result<TcpIoResult, SocketError> {
            let length = b.len().min(self.read_limit);
            self.listener
                .try_recv(c, &mut b[..length])
                .map_err(|_| SocketError::StaleConnection)
        }
        fn tcp_send(
            &self,
            _: Cap,
            c: TcpConnectionToken,
            b: &[u8],
        ) -> Result<TcpIoResult, SocketError> {
            self.listener
                .try_send(c, b)
                .map_err(|_| SocketError::StaleConnection)
        }
        fn tcp_close(&self, _: Cap, c: TcpConnectionToken) -> Result<(), SocketError> {
            self.listener
                .request_close(c)
                .map_err(|_| SocketError::StaleConnection)
        }
        fn tcp_reset(&self, _: Cap, c: TcpConnectionToken) -> Result<(), SocketError> {
            self.listener
                .request_reset(c)
                .map_err(|_| SocketError::StaleConnection)
        }
        fn now_ms(&self) -> u64 {
            self.now.load(Ordering::Relaxed)
        }
    }
    fn header(source: bool, size: u64) -> [u8; 24] {
        let mut h = [0; 24];
        h[..8].copy_from_slice(b"VBENCH01");
        h[8] = source as u8;
        h[16..].copy_from_slice(&size.to_be_bytes());
        h
    }
    #[test]
    fn rejects_invalid_requests() {
        for size in [0, LIMIT + 1, u64::MAX] {
            assert!(request(&header(false, size)).is_err());
        }
        for index in 0..16 {
            let mut h = header(false, 1);
            h[index] = 255;
            assert!(request(&h).is_err());
        }
    }
    #[test]
    #[cfg(feature = "receive-batch")]
    fn ready_sink_is_bounded_even_when_short_reads_keep_succeeding() {
        let (mut p, cap) = Model::new();
        p.read_limit = 1;
        let mut flow = Flow::new();
        flow.connection = p.listener.try_accept();
        flow.header = header(false, 32);
        flow.header_used = 24;
        flow.size = 32;
        assert_eq!(p.listener.network_receive(&[0xa5; 32]), 32);
        assert!(flow.drive(&p, cap).unwrap());
        assert_eq!(flow.done, 4);
        assert_eq!(p.listener.snapshot().readable_bytes, 28);
        assert!(flow.drive(&p, cap).unwrap());
        assert_eq!(flow.done, 8);
    }

    #[test]
    fn fragmented_sink_and_source_preserve_exact_count_and_drain_result() {
        for source in [false, true] {
            let (p, cap) = Model::new();
            let mut f = Flow::new();
            for byte in header(source, 101) {
                assert_eq!(p.listener.network_receive(&[byte]), 1);
                assert!(f.drive(&p, cap).unwrap());
            }
            assert_eq!(f.header_used, 24);
            let mut received = Vec::new();
            let mut supplied = 0;
            for _ in 0..1000 {
                if !source && supplied < 101 {
                    supplied += p
                        .listener
                        .network_receive(&PAYLOAD[..(101 - supplied).min(11)]);
                }
                f.drive(&p, cap).unwrap();
                let mut b = [0; 3];
                let n = p.listener.network_transmit(&mut b);
                received.extend_from_slice(&b[..n]);
                if f.connection.is_none() {
                    loop {
                        let n = p.listener.network_transmit(&mut b);
                        if n == 0 {
                            break;
                        }
                        received.extend_from_slice(&b[..n]);
                    }
                    break;
                }
            }
            assert!(f.connection.is_none());
            assert!(p.listener.close_request().is_some());
            let payload_len = if source { 101 } else { 0 };
            assert_eq!(received.len(), payload_len + 16);
            assert!(received[..payload_len].iter().all(|b| *b == 0xa5));
            assert_eq!(
                u64::from_be_bytes(received[payload_len..payload_len + 8].try_into().unwrap()),
                101
            );
            if !source {
                assert_eq!(&f.buffer[..2], &[0xa5, 0xa5]);
            }
        }
    }
    #[test]
    fn stalled_header_times_out_and_old_generation_is_rejected() {
        let (p, cap) = Model::new();
        let mut f = Flow::new();
        assert!(!f.drive(&p, cap).unwrap());
        p.now.store(DEADLINE_MS + 1, Ordering::Relaxed);
        assert_eq!(f.drive(&p, cap), Err(SocketError::Failed));
        p.now.store(1, Ordering::Relaxed);
        p.listener
            .network_update_state(TcpStreamState::Reset)
            .unwrap();
        p.listener
            .network_update_state(TcpStreamState::Established)
            .unwrap();
        assert_eq!(f.drive(&p, cap), Err(SocketError::StaleConnection));
    }
    #[test]
    fn v2_waits_for_application_go_and_rejects_invalid_signal() {
        for source in [false, true] {
            for valid in [false, true] {
                let (p, cap) = Model::new();
                let mut f = Flow::new();
                let mut h = header(source, 101);
                h[7] = b'2';
                p.listener.network_receive(&h);
                assert!(f.drive(&p, cap).unwrap());
                assert!(f.drive(&p, cap).unwrap());
                let mut ready = [0; 1];
                assert_eq!(p.listener.network_transmit(&mut ready), 1);
                assert_eq!(ready, [b'R']);
                assert!(!f.drive(&p, cap).unwrap());
                assert_eq!(f.done, 0);
                assert!(f.started_ms.is_none());
                p.listener.network_receive(if valid { b"G" } else { b"X" });
                if valid {
                    assert!(f.drive(&p, cap).unwrap());
                    if !source {
                        p.listener.network_receive(b"payload");
                    }
                    assert!(f.drive(&p, cap).unwrap());
                    assert_eq!(f.done, 7);
                } else {
                    assert_eq!(f.drive(&p, cap), Err(SocketError::Failed));
                }
                f.clear();
                assert!(!f.ready_sent && !f.go_received);
            }
        }
    }
    #[test]
    fn verified_sink_checks_pattern_across_reads_and_rejects_corruption() {
        for corrupt in [false, true] {
            let (p, cap) = Model::new();
            let mut f = Flow::new();
            let mut h = header(false, 1003);
            h[8] = 2;
            assert!(request(&h).is_err()); // V1 has no verification mode.
            h[7] = b'2';
            assert_eq!(p.listener.network_receive(&h), h.len());
            f.drive(&p, cap).unwrap();
            f.drive(&p, cap).unwrap();
            let mut result = Vec::new();
            let mut output = [0; 3];
            assert_eq!(p.listener.network_transmit(&mut output), 1);
            assert_eq!(output[0], b'R');
            p.listener.network_receive(b"G");
            f.drive(&p, cap).unwrap();
            let mut supplied = 0;
            let mut rejected = false;
            for _ in 0..2000 {
                if supplied < 1003 {
                    let bytes: Vec<u8> = (supplied..(supplied + 11).min(1003))
                        .map(|i| {
                            if corrupt && i == 257 {
                                255
                            } else {
                                (i % 251) as u8
                            }
                        })
                        .collect();
                    supplied += p.listener.network_receive(&bytes);
                }
                match f.drive(&p, cap) {
                    Err(SocketError::Failed) => {
                        rejected = true;
                        break;
                    }
                    result => {
                        result.unwrap();
                    }
                }
                let n = p.listener.network_transmit(&mut output);
                result.extend_from_slice(&output[..n]);
                if f.connection.is_none() {
                    loop {
                        let n = p.listener.network_transmit(&mut output);
                        if n == 0 {
                            break;
                        }
                        result.extend_from_slice(&output[..n]);
                    }
                    break;
                }
            }
            assert_eq!(rejected, corrupt);
            if corrupt {
                assert!(result.is_empty());
                assert!(f.done <= 257);
                assert!(p.listener.close_request().is_none());
            } else {
                assert!(f.connection.is_none());
                assert_eq!(result.len(), 16);
                assert_eq!(u64::from_be_bytes(result[..8].try_into().unwrap()), 1003);
            }
        }
    }
}
