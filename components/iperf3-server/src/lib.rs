//! Bounded, capability-confined iperf3 TCP server.
//!
//! The implementation intentionally supports one TCP data stream, in either
//! normal or reverse direction. UDP, SCTP, bidirectional and parallel tests are
//! rejected. It implements the iperf3 control protocol directly and has no
//! POSIX socket or libc dependency.

#![no_std]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::format;
use alloc::vec::Vec;

use vibeos_core::cap::Cap;
use vibeos_net_api::{TcpConnectionToken, TcpIoResult};

pub const DEFAULT_PORT: u16 = 5201;
pub const COOKIE_BYTES: usize = 37;
pub const MAX_CONTROL_JSON_BYTES: usize = 4 * 1024;
pub const MAX_TEST_SECONDS: u64 = 60;

const IO_CHUNK_BYTES: usize = 32 * 1024;
const IDLE_POLL_MS: u64 = 1;
const TEST_END_GRACE_MS: u64 = 5_000;

const TEST_START: u8 = 1;
const TEST_RUNNING: u8 = 2;
const TEST_END: u8 = 4;
const PARAM_EXCHANGE: u8 = 9;
const CREATE_STREAMS: u8 = 10;
const CLIENT_TERMINATE: u8 = 12;
const EXCHANGE_RESULTS: u8 = 13;
const DISPLAY_RESULTS: u8 = 14;
const IPERF_DONE: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketError {
    AuthorityRevoked,
    StaleConnection,
    Failed,
}

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
    fn tcp_reset(&self, listener: Cap, connection: TcpConnectionToken) -> Result<(), SocketError>;
    fn now_ms(&self) -> u64;
    fn event(&self, event: &'static str);
}

type Space = dyn Platform;

pub async fn task(space: &Space, control_listener: Cap, data_listener: Cap) {
    let mut server = Server::new();
    loop {
        match server.drive(space, control_listener, data_listener) {
            Ok(true) => vibeos_core::exec::yield_now().await,
            Ok(false) => vibeos_core::exec::sleep_ms(IDLE_POLL_MS).await,
            Err(SocketError::AuthorityRevoked) => return,
            Err(SocketError::StaleConnection | SocketError::Failed) => {
                space.event(server.phase_name());
                server.abort(space, control_listener, data_listener);
                server = Server::new();
                vibeos_core::exec::yield_now().await;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    AcceptControl,
    ControlCookie,
    Parameters,
    AcceptData,
    DataCookie,
    Running,
    DrainData,
    ClientResults,
    AwaitDone,
    Closing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Parameters {
    reverse: bool,
    duration_seconds: u64,
}

pub struct Server {
    phase: Phase,
    control: Option<TcpConnectionToken>,
    data: Option<TcpConnectionToken>,
    control_on_first: bool,
    cookie: [u8; COOKIE_BYTES],
    cookie_received: usize,
    data_cookie_received: usize,
    control_rx: Vec<u8>,
    control_tx: VecDeque<u8>,
    parameters: Parameters,
    test_started_ms: u64,
    test_elapsed_ms: u64,
    bytes_transferred: u64,
}

impl Server {
    pub const fn new() -> Self {
        Self {
            phase: Phase::AcceptControl,
            control: None,
            data: None,
            control_on_first: true,
            cookie: [0; COOKIE_BYTES],
            cookie_received: 0,
            data_cookie_received: 0,
            control_rx: Vec::new(),
            control_tx: VecDeque::new(),
            parameters: Parameters {
                reverse: false,
                duration_seconds: 0,
            },
            test_started_ms: 0,
            test_elapsed_ms: 0,
            bytes_transferred: 0,
        }
    }

    fn drive(
        &mut self,
        space: &Space,
        first_listener: Cap,
        second_listener: Cap,
    ) -> Result<bool, SocketError> {
        let mut worked = self.flush_control(space, first_listener, second_listener)?;

        match self.phase {
            Phase::AcceptControl => {
                self.control = space.tcp_accept(first_listener)?;
                self.control_on_first = true;
                if self.control.is_none() {
                    self.control = space.tcp_accept(second_listener)?;
                    self.control_on_first = false;
                }
                if self.control.is_some() {
                    self.phase = Phase::ControlCookie;
                    worked = true;
                }
            }
            Phase::ControlCookie => {
                let Some(control) = self.control else {
                    return Err(SocketError::Failed);
                };
                let control_listener = self.control_listener(first_listener, second_listener);
                let mut scratch = [0u8; IO_CHUNK_BYTES];
                match space.tcp_recv(control_listener, control, &mut scratch)? {
                    TcpIoResult::Progress(length) => {
                        worked |= length != 0;
                        let needed = COOKIE_BYTES - self.cookie_received;
                        let copied = needed.min(length);
                        self.cookie[self.cookie_received..self.cookie_received + copied]
                            .copy_from_slice(&scratch[..copied]);
                        self.cookie_received += copied;
                        if self.cookie_received == COOKIE_BYTES {
                            self.control_rx.extend_from_slice(&scratch[copied..length]);
                            self.control_tx.push_back(PARAM_EXCHANGE);
                            self.phase = Phase::Parameters;
                        }
                    }
                    TcpIoResult::WouldBlock => {}
                    TcpIoResult::Closed => return self.restart_closed(space, control_listener),
                }
            }
            Phase::Parameters => {
                let control_listener = self.control_listener(first_listener, second_listener);
                worked |= self.read_control(space, control_listener)?;
                if let Some(json) = take_json_frame(&mut self.control_rx)? {
                    self.parameters = parse_parameters(&json)?;
                    self.control_tx.push_back(CREATE_STREAMS);
                    self.phase = Phase::AcceptData;
                    worked = true;
                }
            }
            Phase::AcceptData => {
                let data_listener = self.data_listener(first_listener, second_listener);
                self.data = space.tcp_accept(data_listener)?;
                if self.data.is_some() {
                    self.phase = Phase::DataCookie;
                    worked = true;
                }
            }
            Phase::DataCookie => {
                let Some(data) = self.data else {
                    return Err(SocketError::Failed);
                };
                let data_listener = self.data_listener(first_listener, second_listener);
                let mut scratch = [0u8; IO_CHUNK_BYTES];
                match space.tcp_recv(data_listener, data, &mut scratch)? {
                    TcpIoResult::Progress(length) => {
                        worked |= length != 0;
                        let needed = COOKIE_BYTES - self.data_cookie_received;
                        let copied = needed.min(length);
                        if scratch[..copied]
                            != self.cookie
                                [self.data_cookie_received..self.data_cookie_received + copied]
                        {
                            return Err(SocketError::Failed);
                        }
                        self.data_cookie_received += copied;
                        if self.data_cookie_received == COOKIE_BYTES {
                            self.control_tx.push_back(TEST_START);
                            self.control_tx.push_back(TEST_RUNNING);
                            self.test_started_ms = space.now_ms();
                            self.phase = Phase::Running;
                        }
                    }
                    TcpIoResult::WouldBlock => {}
                    TcpIoResult::Closed => return self.restart_closed(space, data_listener),
                }
            }
            Phase::Running => {
                let control_listener = self.control_listener(first_listener, second_listener);
                let data_listener = self.data_listener(first_listener, second_listener);
                let maximum_ms = self
                    .parameters
                    .duration_seconds
                    .saturating_mul(1_000)
                    .saturating_add(TEST_END_GRACE_MS);
                if space.now_ms().saturating_sub(self.test_started_ms) > maximum_ms {
                    return Err(SocketError::Failed);
                }
                worked |= self.read_control(space, control_listener)?;
                if self.control_rx.first().copied() == Some(CLIENT_TERMINATE) {
                    self.control_rx.remove(0);
                    self.phase = Phase::Closing;
                    worked = true;
                } else if self.control_rx.first().copied() == Some(TEST_END) {
                    self.control_rx.remove(0);
                    // Freeze the data-test interval at TEST_END.  The result
                    // exchange may arrive much later (iperf3 commonly waits
                    // about ten seconds for the reverse sender), and charging
                    // that protocol tail to end_time makes the sender bitrate
                    // appear far lower than the bytes actually put on wire.
                    self.test_elapsed_ms = space.now_ms().saturating_sub(self.test_started_ms);
                    if self.parameters.reverse {
                        self.control_tx.push_back(EXCHANGE_RESULTS);
                        self.phase = Phase::ClientResults;
                    } else {
                        self.phase = Phase::DrainData;
                    }
                    worked = true;
                } else if self.parameters.reverse {
                    worked |= self.send_payload(space, data_listener)?;
                } else {
                    worked |= self.receive_payload(space, data_listener)?;
                }
            }
            Phase::DrainData => {
                let data_listener = self.data_listener(first_listener, second_listener);
                let Some(connection) = self.data else {
                    return Err(SocketError::Failed);
                };
                let mut scratch = [0u8; IO_CHUNK_BYTES];
                match space.tcp_recv(data_listener, connection, &mut scratch)? {
                    TcpIoResult::Progress(length) => {
                        self.bytes_transferred =
                            self.bytes_transferred.saturating_add(length as u64);
                        worked |= length != 0;
                    }
                    TcpIoResult::WouldBlock | TcpIoResult::Closed => {
                        self.control_tx.push_back(EXCHANGE_RESULTS);
                        self.phase = Phase::ClientResults;
                        worked = true;
                    }
                }
            }
            Phase::ClientResults => {
                let control_listener = self.control_listener(first_listener, second_listener);
                worked |= self.read_control(space, control_listener)?;
                if take_json_frame(&mut self.control_rx)?.is_some() {
                    let result = result_json(
                        self.bytes_transferred,
                        self.test_elapsed_ms,
                        self.parameters.reverse,
                    );
                    queue_json_frame(&mut self.control_tx, result.as_bytes())?;
                    self.control_tx.push_back(DISPLAY_RESULTS);
                    self.phase = Phase::AwaitDone;
                    worked = true;
                }
            }
            Phase::AwaitDone => {
                let control_listener = self.control_listener(first_listener, second_listener);
                worked |= self.read_control(space, control_listener)?;
                if self.control_rx.first().copied() == Some(IPERF_DONE) {
                    self.control_rx.remove(0);
                    self.phase = Phase::Closing;
                    worked = true;
                }
            }
            Phase::Closing => {
                if self.control_tx.is_empty() {
                    if let Some(control) = self.control {
                        let control_listener =
                            self.control_listener(first_listener, second_listener);
                        let _ = space.tcp_reset(control_listener, control);
                    }
                    if let Some(data) = self.data {
                        let data_listener = self.data_listener(first_listener, second_listener);
                        let _ = space.tcp_reset(data_listener, data);
                    }
                    *self = Self::new();
                    worked = true;
                }
            }
        }

        Ok(worked)
    }

    fn abort(&mut self, space: &Space, first_listener: Cap, second_listener: Cap) {
        if let Some(control) = self.control {
            let _ = space.tcp_reset(
                self.control_listener(first_listener, second_listener),
                control,
            );
        }
        if let Some(data) = self.data {
            let _ = space.tcp_reset(self.data_listener(first_listener, second_listener), data);
        }
    }

    const fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::AcceptControl => "iperf3 reset while accepting control",
            Phase::ControlCookie => "iperf3 reset while reading control cookie",
            Phase::Parameters => "iperf3 reset while reading parameters",
            Phase::AcceptData => "iperf3 reset while accepting data stream",
            Phase::DataCookie => "iperf3 reset while reading data cookie",
            Phase::Running => "iperf3 reset while running test",
            Phase::DrainData => "iperf3 reset while draining data",
            Phase::ClientResults => "iperf3 reset while reading client results",
            Phase::AwaitDone => "iperf3 reset while awaiting done",
            Phase::Closing => "iperf3 reset while closing",
        }
    }

    fn control_listener(&self, first: Cap, second: Cap) -> Cap {
        if self.control_on_first {
            first
        } else {
            second
        }
    }

    fn data_listener(&self, first: Cap, second: Cap) -> Cap {
        if self.control_on_first {
            second
        } else {
            first
        }
    }

    fn flush_control(
        &mut self,
        space: &Space,
        first_listener: Cap,
        second_listener: Cap,
    ) -> Result<bool, SocketError> {
        let Some(connection) = self.control else {
            return Ok(false);
        };
        if self.control_tx.is_empty() {
            return Ok(false);
        }
        let listener = self.control_listener(first_listener, second_listener);
        let mut chunk = [0u8; IO_CHUNK_BYTES];
        let length = chunk.len().min(self.control_tx.len());
        for (output, queued) in chunk[..length].iter_mut().zip(self.control_tx.iter()) {
            *output = *queued;
        }
        match space.tcp_send(listener, connection, &chunk[..length])? {
            TcpIoResult::Progress(sent) => {
                self.control_tx.drain(..sent);
                Ok(sent != 0)
            }
            TcpIoResult::WouldBlock => Ok(false),
            TcpIoResult::Closed => Err(SocketError::StaleConnection),
        }
    }

    fn read_control(&mut self, space: &Space, listener: Cap) -> Result<bool, SocketError> {
        let Some(connection) = self.control else {
            return Err(SocketError::Failed);
        };
        if self.control_rx.len() >= MAX_CONTROL_JSON_BYTES + 4 {
            return Err(SocketError::Failed);
        }
        let mut scratch = [0u8; IO_CHUNK_BYTES];
        match space.tcp_recv(listener, connection, &mut scratch)? {
            TcpIoResult::Progress(length) => {
                self.control_rx.extend_from_slice(&scratch[..length]);
                Ok(length != 0)
            }
            TcpIoResult::WouldBlock => Ok(false),
            TcpIoResult::Closed => Err(SocketError::StaleConnection),
        }
    }

    fn receive_payload(&mut self, space: &Space, listener: Cap) -> Result<bool, SocketError> {
        let Some(connection) = self.data else {
            return Err(SocketError::Failed);
        };
        let mut scratch = [0u8; IO_CHUNK_BYTES];
        match space.tcp_recv(listener, connection, &mut scratch)? {
            TcpIoResult::Progress(length) => {
                self.bytes_transferred = self.bytes_transferred.saturating_add(length as u64);
                Ok(length != 0)
            }
            TcpIoResult::WouldBlock | TcpIoResult::Closed => Ok(false),
        }
    }

    fn send_payload(&mut self, space: &Space, listener: Cap) -> Result<bool, SocketError> {
        let Some(connection) = self.data else {
            return Err(SocketError::Failed);
        };
        // iperf3 measures byte transport and does not validate payload entropy.
        // A fixed pattern avoids spending three xorshift operations per byte on
        // the small core while retaining a full-sized, deterministic payload.
        let payload = [0xa5u8; IO_CHUNK_BYTES];
        match space.tcp_send(listener, connection, &payload)? {
            TcpIoResult::Progress(length) => {
                self.bytes_transferred = self.bytes_transferred.saturating_add(length as u64);
                Ok(length != 0)
            }
            TcpIoResult::WouldBlock | TcpIoResult::Closed => Ok(false),
        }
    }

    fn restart_closed<T>(&mut self, _space: &Space, _listener: Cap) -> Result<T, SocketError> {
        Err(SocketError::StaleConnection)
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

fn take_json_frame(input: &mut Vec<u8>) -> Result<Option<Vec<u8>>, SocketError> {
    if input.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as usize;
    if length == 0 || length > MAX_CONTROL_JSON_BYTES {
        return Err(SocketError::Failed);
    }
    if input.len() < length + 4 {
        return Ok(None);
    }
    let json = input[4..4 + length].to_vec();
    input.drain(..4 + length);
    Ok(Some(json))
}

fn queue_json_frame(output: &mut VecDeque<u8>, json: &[u8]) -> Result<(), SocketError> {
    let length = u32::try_from(json.len()).map_err(|_| SocketError::Failed)?;
    output.extend(length.to_be_bytes());
    output.extend(json);
    Ok(())
}

fn parse_parameters(json: &[u8]) -> Result<Parameters, SocketError> {
    if !json_flag(json, b"tcp")
        || json_flag(json, b"udp")
        || json_flag(json, b"sctp")
        || json_flag(json, b"bidirectional")
        || json_number(json, b"parallel").unwrap_or(1) != 1
        || json_number(json, b"omit").unwrap_or(0) != 0
    {
        return Err(SocketError::Failed);
    }
    let duration_seconds = json_number(json, b"time").unwrap_or(10);
    if duration_seconds == 0 || duration_seconds > MAX_TEST_SECONDS {
        return Err(SocketError::Failed);
    }
    Ok(Parameters {
        reverse: json_flag(json, b"reverse"),
        duration_seconds,
    })
}

fn json_flag(json: &[u8], key: &[u8]) -> bool {
    json_value_start(json, key).is_some_and(|value| value.starts_with(b"true"))
}

fn json_number(json: &[u8], key: &[u8]) -> Option<u64> {
    let value = json_value_start(json, key)?;
    let mut number = 0u64;
    let mut digits = 0usize;
    for byte in value.iter().copied() {
        if !byte.is_ascii_digit() {
            break;
        }
        number = number
            .checked_mul(10)?
            .checked_add(u64::from(byte - b'0'))?;
        digits += 1;
    }
    (digits != 0).then_some(number)
}

fn json_value_start<'a>(json: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut pattern = Vec::with_capacity(key.len() + 2);
    pattern.push(b'"');
    pattern.extend_from_slice(key);
    pattern.push(b'"');
    let offset = json
        .windows(pattern.len())
        .position(|window| window == pattern)?;
    let mut value = &json[offset + pattern.len()..];
    value = trim_ascii(value);
    value = value.strip_prefix(b":")?;
    Some(trim_ascii(value))
}

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    input
}

fn result_json(bytes: u64, elapsed_ms: u64, reverse: bool) -> alloc::string::String {
    let retransmits = if reverse { 0 } else { -1 };
    let sender_has_retransmits = if reverse { 1 } else { -1 };
    format!(
        "{{\"cpu_util_total\":0,\"cpu_util_user\":0,\"cpu_util_system\":0,\"sender_has_retransmits\":{},\"congestion_used\":\"reno\",\"streams\":[{{\"id\":1,\"bytes\":{},\"retransmits\":{},\"jitter\":0,\"errors\":0,\"omitted_errors\":0,\"packets\":0,\"omitted_packets\":0,\"start_time\":0,\"end_time\":{}.{:03}}}]}}",
        sender_has_retransmits,
        bytes,
        retransmits,
        elapsed_ms / 1000,
        elapsed_ms % 1000,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_forward_and_reverse_parameters() {
        assert_eq!(
            parse_parameters(br#"{"tcp":true,"omit":0,"time":10,"parallel":1}"#),
            Ok(Parameters {
                reverse: false,
                duration_seconds: 10,
            })
        );
        assert_eq!(
            parse_parameters(br#"{"tcp":true,"time":3,"parallel":1,"reverse":true}"#),
            Ok(Parameters {
                reverse: true,
                duration_seconds: 3,
            })
        );
    }

    #[test]
    fn rejects_unbounded_or_unsupported_tests() {
        for json in [
            br#"{"udp":true,"time":10,"parallel":1}"#.as_slice(),
            br#"{"tcp":true,"time":10,"parallel":2}"#.as_slice(),
            br#"{"tcp":true,"time":10,"parallel":1,"bidirectional":true}"#.as_slice(),
            br#"{"tcp":true,"time":61,"parallel":1}"#.as_slice(),
            br#"{"tcp":true,"time":10,"parallel":1,"omit":1}"#.as_slice(),
        ] {
            assert_eq!(parse_parameters(json), Err(SocketError::Failed));
        }
    }

    #[test]
    fn json_frames_are_bounded_and_network_ordered() {
        let mut output = VecDeque::new();
        queue_json_frame(&mut output, br#"{"tcp":true}"#).unwrap();
        let mut input: Vec<u8> = output.into_iter().collect();
        assert_eq!(
            take_json_frame(&mut input).unwrap().unwrap(),
            br#"{"tcp":true}"#
        );
        assert!(input.is_empty());

        let mut oversized = (u32::try_from(MAX_CONTROL_JSON_BYTES + 1).unwrap())
            .to_be_bytes()
            .to_vec();
        oversized.push(0);
        assert_eq!(take_json_frame(&mut oversized), Err(SocketError::Failed));
    }

    #[test]
    fn result_schema_contains_required_stream_fields() {
        let json = result_json(123_456, 2_345, false);
        assert!(json.contains("\"cpu_util_total\":0"));
        assert!(json.contains("\"id\":1"));
        assert!(json.contains("\"bytes\":123456"));
        assert!(json.contains("\"end_time\":2.345"));
    }
}
