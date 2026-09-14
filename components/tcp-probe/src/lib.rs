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

/// Header: VBENCH01, mode (0 sink/1 source), seven zero bytes, u64 BE count.
fn request(header: &[u8; 24]) -> Result<(bool, u64), SocketError> {
    let size = u64::from_be_bytes(header[16..24].try_into().unwrap());
    if &header[..8] != b"VBENCH01"
        || header[8] > 1
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
        if self.done < self.size {
            let len = (self.size - self.done).min(CHUNK as u64) as usize;
            let now = p.now_ms();
            let io = if self.source {
                p.tcp_send(listener, connection, &PAYLOAD[..len])?
            } else {
                p.tcp_recv(listener, connection, &mut self.buffer[..len])?
            };
            match io {
                TcpIoResult::Progress(n) => {
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
                    return Ok(n != 0);
                }
                TcpIoResult::WouldBlock => return Ok(false),
                TcpIoResult::Closed => return Err(SocketError::Failed),
            }
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
    loop {
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
    struct Model {
        listener: alloc::sync::Arc<TcpListener>,
        now: AtomicU64,
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
            self.listener
                .try_recv(c, b)
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
}
