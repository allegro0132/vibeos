//! Capability-facing network resources shared by protocol stacks and services.
//!
//! This crate deliberately has no dependency on smoltcp or a device driver.
//! A [`TcpListener`] is a stable, bounded frontend. The netstack owns its
//! network-facing methods; a component adapter resolves capability rights and
//! invokes the application-facing methods. Connection generations prevent a
//! token accepted for one peer from naming the next peer after listener reuse.

#![no_std]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::any::Any;
use core::num::NonZeroU64;

use vibeos_core::cap::Resource;
use vibeos_core::heap::{self, OwnerId};
use vibeos_core::sync::SpinLock;

pub const DEFAULT_TCP_FRONTEND_BUFFER_BYTES: usize = 4 * 1024;
pub const MAX_TCP_FRONTEND_BUFFER_BYTES: usize = 64 * 1024;
pub const MAX_TCP_IO_BYTES_PER_CALL: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpStreamState {
    Listening,
    Handshake,
    Established,
    PeerClosed,
    Closing,
    Reset,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpIoResult {
    Progress(usize),
    WouldBlock,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpStreamStatus {
    pub state: TcpStreamState,
    pub readable_bytes: usize,
    pub queued_send_bytes: usize,
    pub writable_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpFrontendError {
    InvalidIdentity,
    InvalidPort,
    InvalidBufferSize,
    GenerationExhausted,
    WrongListener,
    StaleConnection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpCloseRequest {
    Close,
    Reset,
}

/// Image-policy identity of one stable listener frontend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpListenerId(NonZeroU64);

impl TcpListenerId {
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Image-policy identity for a bounded set of sockets sharing one TCP port.
///
/// A shared group is required by protocols such as iperf3 which use one
/// control connection and one or more data connections on the same port. The
/// identifier is policy metadata, not a network-visible or forgeable socket
/// handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpPortGroupId(NonZeroU64);

impl TcpPortGroupId {
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// An unforgeable-in-safe-Rust reference to the currently accepted peer.
///
/// It is intentionally not a reusable integer socket id. Listener identity
/// prevents cross-listener substitution; generation prevents connection ABA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpConnectionToken {
    listener: TcpListenerId,
    generation: u64,
}

impl TcpConnectionToken {
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpListenerSnapshot {
    pub id: TcpListenerId,
    pub port: u16,
    pub state: TcpStreamState,
    pub connection_generation: u64,
    pub accepted: bool,
    pub readable_bytes: usize,
    pub queued_send_bytes: usize,
    pub writable_bytes: usize,
    pub close_request: Option<TcpCloseRequest>,
}

struct Inner {
    state: TcpStreamState,
    generation: u64,
    accepted: bool,
    receive: VecDeque<u8>,
    transmit: VecDeque<u8>,
    close_request: Option<TcpCloseRequest>,
}

/// Stable capability resource for one exclusive local TCP port.
///
/// The resource contains only bounded byte queues and lifecycle metadata. The
/// corresponding smoltcp socket remains private to the netstack task.
pub struct TcpListener {
    name: String,
    id: TcpListenerId,
    port: u16,
    port_group: Option<TcpPortGroupId>,
    receive_capacity: usize,
    transmit_capacity: usize,
    inner: SpinLock<Inner>,
}

impl TcpListener {
    pub fn new(
        name: &str,
        id: TcpListenerId,
        port: u16,
        receive_capacity: usize,
        transmit_capacity: usize,
    ) -> Result<Arc<Self>, TcpFrontendError> {
        Self::new_with_port_group(name, id, port, receive_capacity, transmit_capacity, None)
    }

    pub fn new_shared(
        name: &str,
        id: TcpListenerId,
        port: u16,
        receive_capacity: usize,
        transmit_capacity: usize,
        port_group: TcpPortGroupId,
    ) -> Result<Arc<Self>, TcpFrontendError> {
        Self::new_with_port_group(
            name,
            id,
            port,
            receive_capacity,
            transmit_capacity,
            Some(port_group),
        )
    }

    fn new_with_port_group(
        name: &str,
        id: TcpListenerId,
        port: u16,
        receive_capacity: usize,
        transmit_capacity: usize,
        port_group: Option<TcpPortGroupId>,
    ) -> Result<Arc<Self>, TcpFrontendError> {
        if port == 0 {
            return Err(TcpFrontendError::InvalidPort);
        }
        if receive_capacity == 0
            || transmit_capacity == 0
            || receive_capacity > MAX_TCP_FRONTEND_BUFFER_BYTES
            || transmit_capacity > MAX_TCP_FRONTEND_BUFFER_BYTES
        {
            return Err(TcpFrontendError::InvalidBufferSize);
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let listener = Arc::new(Self {
            name: name.to_string(),
            id,
            port,
            port_group,
            receive_capacity,
            transmit_capacity,
            inner: SpinLock::new(Inner {
                state: TcpStreamState::Listening,
                generation: 0,
                accepted: false,
                receive: VecDeque::with_capacity(receive_capacity),
                transmit: VecDeque::with_capacity(transmit_capacity),
                close_request: None,
            }),
        });
        system.restore();
        Ok(listener)
    }

    pub const fn id(&self) -> TcpListenerId {
        self.id
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub const fn port_group(&self) -> Option<TcpPortGroupId> {
        self.port_group
    }

    pub fn snapshot(&self) -> TcpListenerSnapshot {
        let inner = self.inner.lock();
        TcpListenerSnapshot {
            id: self.id,
            port: self.port,
            state: inner.state,
            connection_generation: inner.generation,
            accepted: inner.accepted,
            readable_bytes: inner.receive.len(),
            queued_send_bytes: inner.transmit.len(),
            writable_bytes: self.transmit_capacity.saturating_sub(inner.transmit.len()),
            close_request: inner.close_request,
        }
    }

    /// Application side: accept the current established peer exactly once.
    pub fn try_accept(&self) -> Option<TcpConnectionToken> {
        let mut inner = self.inner.lock();
        if inner.accepted
            || !matches!(
                inner.state,
                TcpStreamState::Established | TcpStreamState::PeerClosed
            )
        {
            return None;
        }
        inner.accepted = true;
        Some(TcpConnectionToken {
            listener: self.id,
            generation: inner.generation,
        })
    }

    /// Application side: receive one bounded fragment for an accepted peer.
    pub fn try_recv(
        &self,
        connection: TcpConnectionToken,
        output: &mut [u8],
    ) -> Result<TcpIoResult, TcpFrontendError> {
        let mut inner = self.inner.lock();
        validate_connection(self.id, &inner, connection)?;
        if output.is_empty() {
            return Ok(TcpIoResult::Progress(0));
        }
        let length = output
            .len()
            .min(MAX_TCP_IO_BYTES_PER_CALL)
            .min(inner.receive.len());
        if length != 0 {
            let (first, second) = inner.receive.as_slices();
            let first_length = length.min(first.len());
            output[..first_length].copy_from_slice(&first[..first_length]);
            let second_length = length - first_length;
            output[first_length..length].copy_from_slice(&second[..second_length]);
            inner.receive.drain(..length);
            return Ok(TcpIoResult::Progress(length));
        }
        if matches!(
            inner.state,
            TcpStreamState::PeerClosed
                | TcpStreamState::Reset
                | TcpStreamState::Closed
                | TcpStreamState::Listening
        ) {
            Ok(TcpIoResult::Closed)
        } else {
            Ok(TcpIoResult::WouldBlock)
        }
    }

    /// Application side: queue one bounded fragment for an accepted peer.
    pub fn try_send(
        &self,
        connection: TcpConnectionToken,
        input: &[u8],
    ) -> Result<TcpIoResult, TcpFrontendError> {
        let mut inner = self.inner.lock();
        validate_connection(self.id, &inner, connection)?;
        if input.is_empty() {
            return Ok(TcpIoResult::Progress(0));
        }
        if !matches!(
            inner.state,
            TcpStreamState::Established | TcpStreamState::PeerClosed
        ) {
            return Ok(TcpIoResult::Closed);
        }
        let length = input
            .len()
            .min(MAX_TCP_IO_BYTES_PER_CALL)
            .min(self.transmit_capacity.saturating_sub(inner.transmit.len()));
        if length == 0 {
            return Ok(TcpIoResult::WouldBlock);
        }
        inner
            .transmit
            .extend(input[..length].iter().copied());
        Ok(TcpIoResult::Progress(length))
    }

    pub fn request_close(&self, connection: TcpConnectionToken) -> Result<(), TcpFrontendError> {
        self.request(connection, TcpCloseRequest::Close)
    }

    pub fn request_reset(&self, connection: TcpConnectionToken) -> Result<(), TcpFrontendError> {
        self.request(connection, TcpCloseRequest::Reset)
    }

    fn request(
        &self,
        connection: TcpConnectionToken,
        request: TcpCloseRequest,
    ) -> Result<(), TcpFrontendError> {
        let mut inner = self.inner.lock();
        validate_connection(self.id, &inner, connection)?;
        inner.close_request = Some(request);
        Ok(())
    }

    /// Netstack side: publish the current transport state.
    pub fn network_update_state(&self, state: TcpStreamState) -> Result<(), TcpFrontendError> {
        let mut inner = self.inner.lock();
        let was_active = is_connection_state(inner.state);
        let becomes_active = is_connection_state(state);
        if !was_active && becomes_active {
            inner.generation = inner
                .generation
                .checked_add(1)
                .ok_or(TcpFrontendError::GenerationExhausted)?;
            inner.accepted = false;
            inner.receive.clear();
            inner.transmit.clear();
            inner.close_request = None;
        }
        if matches!(state, TcpStreamState::Listening | TcpStreamState::Reset) {
            inner.receive.clear();
            inner.transmit.clear();
            inner.close_request = None;
            if state == TcpStreamState::Listening {
                inner.accepted = false;
            }
        }
        inner.state = state;
        Ok(())
    }

    /// Netstack side: copy received transport bytes toward the application.
    pub fn network_receive(&self, input: &[u8]) -> usize {
        let mut inner = self.inner.lock();
        if !matches!(
            inner.state,
            TcpStreamState::Established | TcpStreamState::PeerClosed | TcpStreamState::Closing
        ) {
            return 0;
        }
        let length = input
            .len()
            .min(MAX_TCP_IO_BYTES_PER_CALL)
            .min(self.receive_capacity.saturating_sub(inner.receive.len()));
        inner.receive.extend(input[..length].iter().copied());
        length
    }

    pub fn network_receive_capacity(&self) -> usize {
        let inner = self.inner.lock();
        self.receive_capacity.saturating_sub(inner.receive.len())
    }

    /// Netstack side: inspect queued transmit bytes without consuming them.
    pub fn network_copy_transmit(&self, output: &mut [u8]) -> usize {
        let inner = self.inner.lock();
        let length = output
            .len()
            .min(MAX_TCP_IO_BYTES_PER_CALL)
            .min(inner.transmit.len());
        let (first, second) = inner.transmit.as_slices();
        let first_length = length.min(first.len());
        output[..first_length].copy_from_slice(&first[..first_length]);
        let second_length = length - first_length;
        output[first_length..length].copy_from_slice(&second[..second_length]);
        length
    }

    /// Netstack side: commit bytes accepted by the transport after a peek.
    pub fn network_consume_transmit(&self, length: usize) {
        let mut inner = self.inner.lock();
        let length = length.min(inner.transmit.len());
        inner.transmit.drain(..length);
    }

    /// Convenience operation for tests or transports which accept the entire
    /// copied fragment atomically.
    pub fn network_transmit(&self, output: &mut [u8]) -> usize {
        let length = self.network_copy_transmit(output);
        self.network_consume_transmit(length);
        length
    }

    /// Netstack side: consume one application shutdown request.
    pub fn take_close_request(&self) -> Option<TcpCloseRequest> {
        self.inner.lock().close_request.take()
    }

    pub fn close_request(&self) -> Option<TcpCloseRequest> {
        self.inner.lock().close_request
    }

    pub fn clear_close_request(&self, completed: TcpCloseRequest) {
        let mut inner = self.inner.lock();
        if inner.close_request == Some(completed) {
            inner.close_request = None;
        }
    }
}

impl Resource for TcpListener {
    fn kind(&self) -> &'static str {
        "tcp-listener"
    }

    fn describe(&self) -> String {
        let snapshot = self.snapshot();
        format!(
            "{} tcp :{} {:?} generation={} group={} rx={}/{} tx={}/{}",
            self.name,
            self.port,
            snapshot.state,
            snapshot.connection_generation,
            match self.port_group {
                Some(group) => group.get(),
                None => 0,
            },
            snapshot.readable_bytes,
            self.receive_capacity,
            snapshot.queued_send_bytes,
            self.transmit_capacity,
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn validate_connection(
    listener: TcpListenerId,
    inner: &Inner,
    connection: TcpConnectionToken,
) -> Result<(), TcpFrontendError> {
    if connection.listener != listener {
        return Err(TcpFrontendError::WrongListener);
    }
    if !inner.accepted || connection.generation != inner.generation {
        return Err(TcpFrontendError::StaleConnection);
    }
    Ok(())
}

fn is_connection_state(state: TcpStreamState) -> bool {
    matches!(
        state,
        TcpStreamState::Handshake
            | TcpStreamState::Established
            | TcpStreamState::PeerClosed
            | TcpStreamState::Closing
    )
}
