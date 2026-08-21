//! SYSTEM-owned, allocation-independent byte streams for Component commands.
//!
//! The queue is a fixed eight-by-one-KiB ring.  A future never owns the stream
//! or a queued chunk: it retains only an opaque, boot-global operation token.
//! Receive is deliberately two phase.  Observing a front chunk publishes a
//! fresh [`StreamPreparedReceive`], but neither changes depth nor wakes a
//! writer; only an exact-token [`ByteStreamReader::commit`] copies and pops it.

use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use vibeos_component_runtime::host::{HostOperationToken, HostWakeToken};
use vibeos_core::cap::{Resource, Rights};
use vibeos_core::heap::{self, OwnerId};
use vibeos_core::sync::SpinLock;

use crate::{ComponentHostResource, HostResourceKind};

/// Maximum bytes admitted by one stream operation.
pub const MAX_STREAM_CHUNK_BYTES: usize = 1024;
/// Exact number of chunks retained by one bounded stream.
pub const STREAM_BUFFER_CHUNKS: usize = 8;

/// Stable terminal values shared with the exact `vibe:stream` WIT enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamCloseReason {
    Normal = 0,
    Failure = 1,
    Cancelled = 2,
    Denied = 3,
    Unavailable = 4,
    Exhausted = 5,
    Invalid = 6,
    BackendFault = 7,
}

impl StreamCloseReason {
    const fn is_normal(self) -> bool {
        matches!(self, Self::Normal)
    }
}

/// Fail-closed protocol errors.  Token errors never mutate a live operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    InvalidChunk,
    Busy,
    TokenMismatch,
    WakeAlreadyRegistered,
    InvalidCommitLength,
    EndpointClosed,
    TokenExhausted,
    FailStopped,
}

/// Result of a producer send attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamSendDispatch {
    Sent,
    Waiting(HostOperationToken),
    Closed(StreamCloseReason),
}

/// Exact, non-owning reservation for the current front chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPreparedReceive {
    operation: HostOperationToken,
    length: u16,
    head: u8,
    incarnation: u64,
}

impl StreamPreparedReceive {
    pub const fn operation(self) -> HostOperationToken {
        self.operation
    }

    pub const fn length(self) -> usize {
        self.length as usize
    }
}

/// Result of observing the consumer side without consuming bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamReceiveDispatch {
    Waiting(HostOperationToken),
    Prepared(StreamPreparedReceive),
    Closed(StreamCloseReason),
}

/// Result of observing the immutable terminal reason without consuming bytes.
///
/// A terminal wait is independent from both the producer and consumer
/// operation slots. In particular, a reader may retain a prepared receive
/// while the supervisor waits for lifecycle finalization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamTerminalDispatch {
    Waiting(HostOperationToken),
    Ready(StreamCloseReason),
}

/// Result of committing an exact prepared receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamReceiveCommit {
    Received(usize),
    Closed(StreamCloseReason),
}

/// Monotonic close publication outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamCloseOutcome {
    Published,
    AlreadyPublished,
    /// A different immutable final reason already won.  The stream is now
    /// fail-stopped, while the original reason remains intact for auditing.
    Conflict,
}

/// One close publication and the effective lifecycle reason observed in the
/// same stream-lock critical section.
///
/// `effective_reason` is `None` only when the stream had already fail-stopped
/// before any lifecycle reason could be published.  In particular, an
/// endpoint-side provisional `Normal` is reported as `Some(Normal)`, while a
/// late endpoint-side `Normal` observes the immutable non-normal reason that
/// won instead of requiring a racy follow-up query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamCloseObservation {
    outcome: StreamCloseOutcome,
    effective_reason: Option<StreamCloseReason>,
}

impl StreamCloseObservation {
    pub const fn outcome(self) -> StreamCloseOutcome {
        self.outcome
    }

    pub const fn effective_reason(self) -> Option<StreamCloseReason> {
        self.effective_reason
    }
}

#[derive(Clone, Copy)]
struct Chunk {
    length: u16,
    incarnation: u64,
    bytes: [u8; MAX_STREAM_CHUNK_BYTES],
}

impl Chunk {
    const EMPTY: Self = Self {
        length: 0,
        incarnation: 0,
        bytes: [0; MAX_STREAM_CHUNK_BYTES],
    };
}

struct ChunkRing {
    chunks: [Chunk; STREAM_BUFFER_CHUNKS],
    head: usize,
    depth: usize,
    peak_depth: usize,
    next_incarnation: u64,
}

impl ChunkRing {
    const fn new() -> Self {
        Self {
            chunks: [Chunk::EMPTY; STREAM_BUFFER_CHUNKS],
            head: 0,
            depth: 0,
            peak_depth: 0,
            next_incarnation: 1,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        debug_assert!(!bytes.is_empty());
        debug_assert!(bytes.len() <= MAX_STREAM_CHUNK_BYTES);
        debug_assert!(self.depth < STREAM_BUFFER_CHUNKS);
        if self.next_incarnation == 0 {
            return Err(StreamError::TokenExhausted);
        }
        let tail = (self.head + self.depth) % STREAM_BUFFER_CHUNKS;
        self.chunks[tail].bytes[..bytes.len()].copy_from_slice(bytes);
        self.chunks[tail].length = bytes.len() as u16;
        self.chunks[tail].incarnation = self.next_incarnation;
        self.next_incarnation = self.next_incarnation.checked_add(1).unwrap_or(0);
        self.depth += 1;
        self.peak_depth = self.peak_depth.max(self.depth);
        Ok(())
    }

    fn front_length(&self) -> Option<usize> {
        (self.depth != 0).then(|| self.chunks[self.head].length as usize)
    }

    fn front_seal(&self) -> Option<(u8, u64, usize)> {
        (self.depth != 0).then(|| {
            let chunk = &self.chunks[self.head];
            (self.head as u8, chunk.incarnation, chunk.length as usize)
        })
    }

    fn pop_into(&mut self, output: &mut [u8]) -> bool {
        let Some(length) = self.front_length() else {
            return false;
        };
        if length != output.len() {
            return false;
        }
        output.copy_from_slice(&self.chunks[self.head].bytes[..length]);
        self.chunks[self.head].length = 0;
        self.chunks[self.head].incarnation = 0;
        self.head = (self.head + 1) % STREAM_BUFFER_CHUNKS;
        self.depth -= 1;
        true
    }

    fn clear(&mut self) {
        for chunk in &mut self.chunks {
            chunk.length = 0;
            chunk.incarnation = 0;
        }
        self.head = 0;
        self.depth = 0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    Open,
    NormalProvisional,
    Final(StreamCloseReason),
}

#[derive(Clone, Copy)]
struct WaitingOperation {
    token: HostOperationToken,
    wake: Option<HostWakeToken>,
}

#[derive(Clone, Copy)]
enum ReceiveOperation {
    Waiting(WaitingOperation),
    Prepared(StreamPreparedReceive),
}

struct StreamState {
    ring: ChunkRing,
    lifecycle: Lifecycle,
    send: Option<WaitingOperation>,
    receive: Option<ReceiveOperation>,
    terminal: Option<WaitingOperation>,
    consumer_stopped: bool,
    fail_stopped: bool,
}

impl StreamState {
    const fn new() -> Self {
        Self {
            ring: ChunkRing::new(),
            lifecycle: Lifecycle::Open,
            send: None,
            receive: None,
            terminal: None,
            consumer_stopped: false,
            fail_stopped: false,
        }
    }

    fn check_live(&self) -> Result<(), StreamError> {
        if self.fail_stopped {
            Err(StreamError::FailStopped)
        } else {
            Ok(())
        }
    }

    fn take_ready_sender_wake(&mut self) -> Option<HostWakeToken> {
        let ready = self.ring.depth < STREAM_BUFFER_CHUNKS
            || !matches!(self.lifecycle, Lifecycle::Open)
            || self.fail_stopped;
        if !ready {
            return None;
        }
        self.send.as_mut().and_then(|pending| pending.wake.take())
    }

    fn take_ready_receiver_wake(&mut self) -> Option<HostWakeToken> {
        let ready = self.ring.depth != 0
            // A provisional producer close is not EOF by itself, but the
            // registry-owned dispatcher must be scheduled once so it can
            // revalidate the exact instance/CSpace and, after the queue is
            // drained, promote the source close through its supervisor cap.
            || matches!(
                self.lifecycle,
                Lifecycle::NormalProvisional | Lifecycle::Final(_)
            )
            || self.consumer_stopped
            || self.fail_stopped;
        if !ready {
            return None;
        }
        match self.receive.as_mut() {
            Some(ReceiveOperation::Waiting(pending)) => pending.wake.take(),
            _ => None,
        }
    }

    fn take_ready_terminal_wake(&mut self) -> Option<HostWakeToken> {
        if !matches!(self.lifecycle, Lifecycle::Final(_)) && !self.fail_stopped {
            return None;
        }
        self.terminal
            .as_mut()
            .and_then(|pending| pending.wake.take())
    }

    fn fail_stop(&mut self) -> [Option<HostWakeToken>; 3] {
        self.fail_stopped = true;
        self.ring.clear();
        let send = self.send.as_mut().and_then(|pending| pending.wake.take());
        let receive = match self.receive.as_mut() {
            Some(ReceiveOperation::Waiting(pending)) => pending.wake.take(),
            _ => None,
        };
        let terminal = self.terminal.take().and_then(|pending| pending.wake);
        [send, receive, terminal]
    }
}

/// The fixed queue and lifecycle state.  A stable registry or supervisor owns
/// this object; guest futures receive only operation tokens.
pub struct ByteStream {
    state: SpinLock<StreamState>,
}

impl ByteStream {
    pub fn new() -> Arc<Self> {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let stream = Arc::new(Self {
            state: SpinLock::new(StreamState::new()),
        });
        system.restore();
        stream
    }

    pub fn reader(self: &Arc<Self>) -> Arc<ByteStreamReader> {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let reader = Arc::new(ByteStreamReader {
            stream: self.clone(),
        });
        system.restore();
        reader
    }

    pub fn writer(self: &Arc<Self>) -> Arc<ByteStreamWriter> {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let writer = Arc::new(ByteStreamWriter {
            stream: self.clone(),
        });
        system.restore();
        writer
    }

    /// Create the terminal authority for installation into the stable
    /// instance CSpace. Endpoints deliberately expose no equivalent method.
    pub fn supervisor(self: &Arc<Self>) -> Arc<ByteStreamSupervisor> {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let supervisor = Arc::new(ByteStreamSupervisor {
            stream: self.clone(),
        });
        system.restore();
        supervisor
    }

    pub fn depth(&self) -> usize {
        self.state.lock().ring.depth
    }

    pub fn peak_depth(&self) -> usize {
        self.state.lock().ring.peak_depth
    }

    /// Only immutable final publication is visible as a terminal reason.
    pub fn final_reason(&self) -> Option<StreamCloseReason> {
        match self.state.lock().lifecycle {
            Lifecycle::Final(reason) => Some(reason),
            Lifecycle::Open | Lifecycle::NormalProvisional => None,
        }
    }

    pub fn is_normal_provisional(&self) -> bool {
        matches!(self.state.lock().lifecycle, Lifecycle::NormalProvisional)
    }

    pub fn is_fail_stopped(&self) -> bool {
        self.state.lock().fail_stopped
    }
}

/// Consumer capability resource.  Rights and the nominal WIT resource type
/// distinguish it from the producer endpoint.
pub struct ByteStreamReader {
    stream: Arc<ByteStream>,
}

impl ByteStreamReader {
    /// Redacted object-identity comparison for installer validation.
    pub fn same_stream_as(&self, writer: &ByteStreamWriter) -> bool {
        Arc::ptr_eq(&self.stream, &writer.stream)
    }

    pub fn start(&self) -> Result<StreamReceiveDispatch, StreamError> {
        let mut state = self.stream.state.lock();
        state.check_live()?;
        if state.receive.is_some() {
            return Err(StreamError::Busy);
        }
        if state.consumer_stopped {
            return match state.lifecycle {
                Lifecycle::Final(reason) => Ok(StreamReceiveDispatch::Closed(reason)),
                Lifecycle::Open | Lifecycle::NormalProvisional => Err(StreamError::EndpointClosed),
            };
        }
        if let Lifecycle::Final(reason) = state.lifecycle {
            if !reason.is_normal() || state.ring.depth == 0 {
                return Ok(StreamReceiveDispatch::Closed(reason));
            }
        }
        if let Some((head, incarnation, length)) = state.ring.front_seal() {
            let token = match next_operation_token() {
                Ok(token) => token,
                Err(error) => {
                    let wakes = state.fail_stop();
                    drop(state);
                    wake_all(wakes);
                    return Err(error);
                }
            };
            let prepared = StreamPreparedReceive {
                operation: token,
                length: length as u16,
                head,
                incarnation,
            };
            state.receive = Some(ReceiveOperation::Prepared(prepared));
            return Ok(StreamReceiveDispatch::Prepared(prepared));
        }
        let token = match next_operation_token() {
            Ok(token) => token,
            Err(error) => {
                let wakes = state.fail_stop();
                drop(state);
                wake_all(wakes);
                return Err(error);
            }
        };
        state.receive = Some(ReceiveOperation::Waiting(WaitingOperation {
            token,
            wake: None,
        }));
        Ok(StreamReceiveDispatch::Waiting(token))
    }

    pub fn resume(
        &self,
        operation: HostOperationToken,
    ) -> Result<StreamReceiveDispatch, StreamError> {
        let mut state = self.stream.state.lock();
        state.check_live()?;
        let Some(ReceiveOperation::Waiting(waiting)) = state.receive else {
            return Err(StreamError::TokenMismatch);
        };
        if waiting.token != operation {
            return Err(StreamError::TokenMismatch);
        }
        if state.consumer_stopped {
            state.receive = None;
            return match state.lifecycle {
                Lifecycle::Final(reason) => Ok(StreamReceiveDispatch::Closed(reason)),
                Lifecycle::Open | Lifecycle::NormalProvisional => Err(StreamError::EndpointClosed),
            };
        }
        if let Lifecycle::Final(reason) = state.lifecycle {
            if !reason.is_normal() || state.ring.depth == 0 {
                state.receive = None;
                return Ok(StreamReceiveDispatch::Closed(reason));
            }
        }
        let Some((head, incarnation, length)) = state.ring.front_seal() else {
            let fresh = match next_operation_token() {
                Ok(token) => token,
                Err(error) => {
                    let wakes = state.fail_stop();
                    drop(state);
                    wake_all(wakes);
                    return Err(error);
                }
            };
            state.receive = Some(ReceiveOperation::Waiting(WaitingOperation {
                token: fresh,
                wake: None,
            }));
            return Ok(StreamReceiveDispatch::Waiting(fresh));
        };
        let fresh = match next_operation_token() {
            Ok(token) => token,
            Err(error) => {
                let wakes = state.fail_stop();
                drop(state);
                wake_all(wakes);
                return Err(error);
            }
        };
        let prepared = StreamPreparedReceive {
            operation: fresh,
            length: length as u16,
            head,
            incarnation,
        };
        state.receive = Some(ReceiveOperation::Prepared(prepared));
        Ok(StreamReceiveDispatch::Prepared(prepared))
    }

    pub fn register_wake(
        &self,
        operation: HostOperationToken,
        wake: HostWakeToken,
    ) -> Result<(), StreamError> {
        let mut state = self.stream.state.lock();
        state.check_live()?;
        let Some(ReceiveOperation::Waiting(pending)) = state.receive.as_mut() else {
            return Err(StreamError::TokenMismatch);
        };
        if pending.token != operation {
            return Err(StreamError::TokenMismatch);
        }
        if pending.wake.is_some() {
            return Err(StreamError::WakeAlreadyRegistered);
        }
        pending.wake = Some(wake);
        let ready = state.take_ready_receiver_wake();
        drop(state);
        wake_one(ready);
        Ok(())
    }

    pub fn commit(
        &self,
        operation: HostOperationToken,
        output: &mut [u8],
    ) -> Result<StreamReceiveCommit, StreamError> {
        let mut state = self.stream.state.lock();
        state.check_live()?;
        let Some(ReceiveOperation::Prepared(prepared)) = state.receive else {
            return Err(StreamError::TokenMismatch);
        };
        if prepared.operation != operation {
            return Err(StreamError::TokenMismatch);
        }
        if prepared.length() != output.len() {
            return Err(StreamError::InvalidCommitLength);
        }
        if state.consumer_stopped {
            return match state.lifecycle {
                Lifecycle::Final(reason) => Ok(StreamReceiveCommit::Closed(reason)),
                Lifecycle::Open | Lifecycle::NormalProvisional => Err(StreamError::EndpointClosed),
            };
        }
        if let Lifecycle::Final(reason) = state.lifecycle {
            if !reason.is_normal() {
                return Ok(StreamReceiveCommit::Closed(reason));
            }
        }
        if state.ring.front_seal() != Some((prepared.head, prepared.incarnation, prepared.length()))
        {
            let wakes = state.fail_stop();
            drop(state);
            wake_all(wakes);
            return Err(StreamError::FailStopped);
        }
        if !state.ring.pop_into(output) {
            let wakes = state.fail_stop();
            drop(state);
            wake_all(wakes);
            return Err(StreamError::FailStopped);
        }
        state.receive = None;
        let sender = state.take_ready_sender_wake();
        drop(state);
        wake_one(sender);
        Ok(StreamReceiveCommit::Received(output.len()))
    }

    pub fn cancel(&self, operation: HostOperationToken) -> Result<(), StreamError> {
        cancel_reader_operation_exact(&self.stream, operation)
    }

    /// Consumer-done publication. Normal remains provisional until the
    /// SYSTEM supervisor publishes the immutable terminal reason. Buffered
    /// input is discarded so a blocked producer cannot be stranded.
    pub fn close(&self, reason: StreamCloseReason) -> StreamCloseOutcome {
        self.close_observed(reason).outcome()
    }

    /// Publishes consumer-done and atomically observes the effective reason.
    pub fn close_observed(&self, reason: StreamCloseReason) -> StreamCloseObservation {
        publish_close_observed(&self.stream, reason, false, true)
    }
}

impl Resource for ByteStreamReader {
    fn kind(&self) -> &'static str {
        "component-byte-stream-reader"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for ByteStreamReader {
    const HOST_KIND: HostResourceKind = HostResourceKind::ByteStreamReader;
    const OPERATION_RIGHTS: Rights = Rights::RECV;
}

/// Producer capability resource.
pub struct ByteStreamWriter {
    stream: Arc<ByteStream>,
}

impl ByteStreamWriter {
    /// Redacted object-identity comparison for installer validation.
    pub fn same_stream_as(&self, reader: &ByteStreamReader) -> bool {
        Arc::ptr_eq(&self.stream, &reader.stream)
    }

    pub fn start(&self, bytes: &[u8]) -> Result<StreamSendDispatch, StreamError> {
        validate_chunk(bytes)?;
        let mut state = self.stream.state.lock();
        state.check_live()?;
        if state.send.is_some() {
            return Err(StreamError::Busy);
        }
        if let Some(reason) = producer_closed(state.lifecycle) {
            return Ok(StreamSendDispatch::Closed(reason));
        }
        if state.ring.depth == STREAM_BUFFER_CHUNKS {
            let token = match next_operation_token() {
                Ok(token) => token,
                Err(error) => {
                    let wakes = state.fail_stop();
                    drop(state);
                    wake_all(wakes);
                    return Err(error);
                }
            };
            state.send = Some(WaitingOperation { token, wake: None });
            return Ok(StreamSendDispatch::Waiting(token));
        }
        if state.ring.push(bytes).is_err() {
            let wakes = state.fail_stop();
            drop(state);
            wake_all(wakes);
            return Err(StreamError::TokenExhausted);
        }
        let receiver = state.take_ready_receiver_wake();
        drop(state);
        wake_one(receiver);
        Ok(StreamSendDispatch::Sent)
    }

    pub fn resume(
        &self,
        operation: HostOperationToken,
        bytes: &[u8],
    ) -> Result<StreamSendDispatch, StreamError> {
        validate_chunk(bytes)?;
        let mut state = self.stream.state.lock();
        state.check_live()?;
        let Some(pending) = state.send else {
            return Err(StreamError::TokenMismatch);
        };
        if pending.token != operation {
            return Err(StreamError::TokenMismatch);
        }
        if let Some(reason) = producer_closed(state.lifecycle) {
            state.send = None;
            return Ok(StreamSendDispatch::Closed(reason));
        }
        if state.ring.depth == STREAM_BUFFER_CHUNKS {
            let fresh = match next_operation_token() {
                Ok(token) => token,
                Err(error) => {
                    let wakes = state.fail_stop();
                    drop(state);
                    wake_all(wakes);
                    return Err(error);
                }
            };
            state.send = Some(WaitingOperation {
                token: fresh,
                wake: None,
            });
            return Ok(StreamSendDispatch::Waiting(fresh));
        }
        state.send = None;
        if state.ring.push(bytes).is_err() {
            let wakes = state.fail_stop();
            drop(state);
            wake_all(wakes);
            return Err(StreamError::TokenExhausted);
        }
        let receiver = state.take_ready_receiver_wake();
        drop(state);
        wake_one(receiver);
        Ok(StreamSendDispatch::Sent)
    }

    pub fn register_wake(
        &self,
        operation: HostOperationToken,
        wake: HostWakeToken,
    ) -> Result<(), StreamError> {
        let mut state = self.stream.state.lock();
        state.check_live()?;
        let Some(pending) = state.send.as_mut() else {
            return Err(StreamError::TokenMismatch);
        };
        if pending.token != operation {
            return Err(StreamError::TokenMismatch);
        }
        if pending.wake.is_some() {
            return Err(StreamError::WakeAlreadyRegistered);
        }
        pending.wake = Some(wake);
        let ready = state.take_ready_sender_wake();
        drop(state);
        wake_one(ready);
        Ok(())
    }

    pub fn cancel(&self, operation: HostOperationToken) -> Result<(), StreamError> {
        cancel_writer_operation_exact(&self.stream, operation)
    }

    /// Producer-done publication.  Normal is provisional until supervisor
    /// finalization; a non-normal reason is immediately immutable final.
    pub fn close(&self, reason: StreamCloseReason) -> StreamCloseOutcome {
        self.close_observed(reason).outcome()
    }

    /// Publishes producer-done and atomically observes the effective reason.
    pub fn close_observed(&self, reason: StreamCloseReason) -> StreamCloseObservation {
        publish_close_observed(&self.stream, reason, false, false)
    }
}

impl Resource for ByteStreamWriter {
    fn kind(&self) -> &'static str {
        "component-byte-stream-writer"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for ByteStreamWriter {
    const HOST_KIND: HostResourceKind = HostResourceKind::ByteStreamWriter;
    const OPERATION_RIGHTS: Rights = Rights::SEND;
}

/// Out-of-band lifecycle handle retained by the SYSTEM registry, never by a
/// component future.
pub struct ByteStreamSupervisor {
    stream: Arc<ByteStream>,
}

impl Resource for ByteStreamSupervisor {
    fn kind(&self) -> &'static str {
        "component-byte-stream-supervisor"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ByteStreamSupervisor {
    /// Redacted association check used by trusted installers. No stream
    /// identity or object address is exposed to the caller.
    pub fn same_stream_as_reader(&self, reader: &ByteStreamReader) -> bool {
        Arc::ptr_eq(&self.stream, &reader.stream)
    }

    /// Redacted association check used by trusted installers. No stream
    /// identity or object address is exposed to the caller.
    pub fn same_stream_as_writer(&self, writer: &ByteStreamWriter) -> bool {
        Arc::ptr_eq(&self.stream, &writer.stream)
    }

    /// Revokes the exact current reader operation after the reader capability
    /// itself may already have been removed from its CSpace.
    ///
    /// This supervisor retains the stream object's unforgeable incarnation;
    /// `operation` is the independent operation-generation seal. Both must
    /// identify the current reader slot. A stale, foreign, or pre-restart token
    /// is inert. Successful cancellation drops any registered wake authority
    /// without invoking it and does not consume buffered bytes or alter the
    /// immutable close winner.
    pub fn cancel_reader_operation_exact(
        &self,
        operation: HostOperationToken,
    ) -> Result<(), StreamError> {
        cancel_reader_operation_exact(&self.stream, operation)
    }

    /// Revokes the exact current writer operation after the writer capability
    /// itself may already have been removed from its CSpace.
    ///
    /// The supervisor-bound stream incarnation and `operation` generation must
    /// both match the current writer slot. Cancellation is otherwise inert;
    /// success drops, but never invokes, the slot's registered wake authority.
    pub fn cancel_writer_operation_exact(
        &self,
        operation: HostOperationToken,
    ) -> Result<(), StreamError> {
        cancel_writer_operation_exact(&self.stream, operation)
    }

    /// Starts an observation of the one immutable terminal reason.
    ///
    /// This operation uses a dedicated fixed slot and therefore neither
    /// reserves nor consumes a byte-stream send or receive operation. Endpoint
    /// publication of provisional `Normal` is deliberately not terminal.
    pub fn start_terminal(&self) -> Result<StreamTerminalDispatch, StreamError> {
        let mut state = self.stream.state.lock();
        state.check_live()?;
        if state.terminal.is_some() {
            return Err(StreamError::Busy);
        }
        if let Lifecycle::Final(reason) = state.lifecycle {
            return Ok(StreamTerminalDispatch::Ready(reason));
        }
        let token = match next_operation_token() {
            Ok(token) => token,
            Err(error) => {
                let wakes = state.fail_stop();
                drop(state);
                wake_all(wakes);
                return Err(error);
            }
        };
        state.terminal = Some(WaitingOperation { token, wake: None });
        Ok(StreamTerminalDispatch::Waiting(token))
    }

    /// Resumes one exact terminal observation. A still-pending observation
    /// consumes its supplied token and publishes a fresh generation.
    pub fn resume_terminal(
        &self,
        operation: HostOperationToken,
    ) -> Result<StreamTerminalDispatch, StreamError> {
        let mut state = self.stream.state.lock();
        state.check_live()?;
        let Some(pending) = state.terminal else {
            return Err(StreamError::TokenMismatch);
        };
        if pending.token != operation {
            return Err(StreamError::TokenMismatch);
        }
        if let Lifecycle::Final(reason) = state.lifecycle {
            state.terminal = None;
            return Ok(StreamTerminalDispatch::Ready(reason));
        }
        let fresh = match next_operation_token() {
            Ok(token) => token,
            Err(error) => {
                let wakes = state.fail_stop();
                drop(state);
                wake_all(wakes);
                return Err(error);
            }
        };
        state.terminal = Some(WaitingOperation {
            token: fresh,
            wake: None,
        });
        Ok(StreamTerminalDispatch::Waiting(fresh))
    }

    /// Registers one wake authority for the exact current terminal wait.
    /// Readiness is rechecked while holding the stream lock and the callback is
    /// invoked only after releasing it, making late and reentrant listeners
    /// safe.
    pub fn register_terminal_wake(
        &self,
        operation: HostOperationToken,
        wake: HostWakeToken,
    ) -> Result<(), StreamError> {
        let mut state = self.stream.state.lock();
        state.check_live()?;
        let Some(pending) = state.terminal.as_mut() else {
            return Err(StreamError::TokenMismatch);
        };
        if pending.token != operation {
            return Err(StreamError::TokenMismatch);
        }
        if pending.wake.is_some() {
            return Err(StreamError::WakeAlreadyRegistered);
        }
        pending.wake = Some(wake);
        let ready = state.take_ready_terminal_wake();
        drop(state);
        wake_one(ready);
        Ok(())
    }

    /// Cancels one exact terminal observation without affecting send, receive,
    /// buffered chunks, or lifecycle state.
    pub fn cancel_terminal(&self, operation: HostOperationToken) -> Result<(), StreamError> {
        let mut state = self.stream.state.lock();
        state.check_live()?;
        if state.terminal.map(|pending| pending.token) != Some(operation) {
            return Err(StreamError::TokenMismatch);
        }
        state.terminal = None;
        Ok(())
    }

    /// Publish the one immutable terminal reason.  Finalizing `Normal` is the
    /// only transition which makes drained EOF observable to the reader.
    pub fn finalize(&self, reason: StreamCloseReason) -> StreamCloseOutcome {
        self.finalize_observed(reason).outcome()
    }

    /// Publishes the terminal reason and atomically observes the effective
    /// immutable reason.
    pub fn finalize_observed(&self, reason: StreamCloseReason) -> StreamCloseObservation {
        publish_close_observed(&self.stream, reason, true, false)
    }

    /// Publishes `reason` only while the lifecycle is still open or
    /// provisional, otherwise atomically observes the immutable first winner.
    ///
    /// Unlike [`Self::finalize_observed`], a different reason which already
    /// won is not a conflicting second publication. This is reserved for a
    /// trusted lifecycle finalizer which must close an unclaimed stream but
    /// preserve any endpoint or fault terminal that linearized first.
    pub fn finalize_preserving_first_observed(
        &self,
        reason: StreamCloseReason,
    ) -> StreamCloseObservation {
        let mut state = self.stream.state.lock();
        if state.fail_stopped {
            return close_observation(StreamCloseOutcome::Conflict, state.lifecycle);
        }
        let outcome = match state.lifecycle {
            Lifecycle::Final(_) => StreamCloseOutcome::AlreadyPublished,
            Lifecycle::Open | Lifecycle::NormalProvisional => {
                state.lifecycle = Lifecycle::Final(reason);
                if !reason.is_normal() {
                    state.ring.clear();
                }
                StreamCloseOutcome::Published
            }
        };
        let sender = state.take_ready_sender_wake();
        let receiver = state.take_ready_receiver_wake();
        let terminal = state.take_ready_terminal_wake();
        let observation = close_observation(outcome, state.lifecycle);
        drop(state);
        wake_all([sender, receiver, terminal]);
        observation
    }

    /// Atomically promotes a drained endpoint-side `Normal` publication to the
    /// immutable terminal reason.
    ///
    /// `None` means either no endpoint has published provisional `Normal` yet,
    /// or buffered bytes still need to be drained. An existing final reason is
    /// only observed and is never republished, so a failure which already won
    /// cannot be turned into a conflicting `Normal` publication.
    pub fn promote_normal_if_drained_observed(&self) -> Option<StreamCloseObservation> {
        let mut state = self.stream.state.lock();
        let observation = if state.fail_stopped {
            close_observation(StreamCloseOutcome::Conflict, state.lifecycle)
        } else {
            match state.lifecycle {
                Lifecycle::Open => return None,
                Lifecycle::NormalProvisional if state.ring.depth != 0 => return None,
                Lifecycle::NormalProvisional => {
                    state.lifecycle = Lifecycle::Final(StreamCloseReason::Normal);
                    close_observation(StreamCloseOutcome::Published, state.lifecycle)
                }
                Lifecycle::Final(_) => {
                    close_observation(StreamCloseOutcome::AlreadyPublished, state.lifecycle)
                }
            }
        };
        let sender = state.take_ready_sender_wake();
        let receiver = state.take_ready_receiver_wake();
        let terminal = state.take_ready_terminal_wake();
        drop(state);
        wake_all([sender, receiver, terminal]);
        Some(observation)
    }

    pub fn final_reason(&self) -> Option<StreamCloseReason> {
        self.stream.final_reason()
    }

    pub fn depth(&self) -> usize {
        self.stream.depth()
    }

    /// Whether an endpoint published producer-done Normal but the trusted
    /// lifecycle has not yet made EOF observable.
    pub fn is_normal_provisional(&self) -> bool {
        self.stream.is_normal_provisional()
    }

    pub fn is_fail_stopped(&self) -> bool {
        self.stream.is_fail_stopped()
    }
}

fn cancel_reader_operation_exact(
    stream: &ByteStream,
    operation: HostOperationToken,
) -> Result<(), StreamError> {
    let mut state = stream.state.lock();
    state.check_live()?;
    let matches = match state.receive {
        Some(ReceiveOperation::Waiting(waiting)) => waiting.token == operation,
        Some(ReceiveOperation::Prepared(prepared)) => prepared.operation == operation,
        None => false,
    };
    if !matches {
        return Err(StreamError::TokenMismatch);
    }
    // Dropping the slot revokes its wake authority. Cancellation never wakes:
    // a callback already taken by a readiness winner is necessarily late and
    // still carries only the stale operation generation.
    state.receive = None;
    Ok(())
}

fn cancel_writer_operation_exact(
    stream: &ByteStream,
    operation: HostOperationToken,
) -> Result<(), StreamError> {
    let mut state = stream.state.lock();
    state.check_live()?;
    if state.send.map(|pending| pending.token) != Some(operation) {
        return Err(StreamError::TokenMismatch);
    }
    // As for readers, dropping a registered wake is revocation, not a wakeup.
    state.send = None;
    Ok(())
}

fn publish_close_observed(
    stream: &ByteStream,
    reason: StreamCloseReason,
    supervisor: bool,
    discard_buffer: bool,
) -> StreamCloseObservation {
    let mut state = stream.state.lock();
    if state.fail_stopped {
        return close_observation(StreamCloseOutcome::Conflict, state.lifecycle);
    }
    if discard_buffer {
        state.consumer_stopped = true;
    }
    let outcome = match state.lifecycle {
        // Endpoint-side Normal is only a source/consumer-done
        // acknowledgement. A lifecycle failure may have won immediately
        // before that acknowledgement; it cannot replace the immutable
        // failure or turn the stream into a fail-stop. A late consumer close
        // still discards bytes which that endpoint can no longer receive.
        Lifecycle::Final(_) if reason.is_normal() && !supervisor => {
            if discard_buffer {
                state.ring.clear();
            }
            StreamCloseOutcome::AlreadyPublished
        }
        Lifecycle::Final(established) if established == reason => {
            StreamCloseOutcome::AlreadyPublished
        }
        Lifecycle::Final(_) => {
            let observation = close_observation(StreamCloseOutcome::Conflict, state.lifecycle);
            let wakes = state.fail_stop();
            drop(state);
            wake_all(wakes);
            return observation;
        }
        Lifecycle::Open | Lifecycle::NormalProvisional if reason.is_normal() && !supervisor => {
            let was_provisional = matches!(state.lifecycle, Lifecycle::NormalProvisional);
            state.lifecycle = Lifecycle::NormalProvisional;
            if discard_buffer {
                state.ring.clear();
            }
            if was_provisional {
                StreamCloseOutcome::AlreadyPublished
            } else {
                StreamCloseOutcome::Published
            }
        }
        Lifecycle::Open | Lifecycle::NormalProvisional => {
            state.lifecycle = Lifecycle::Final(reason);
            if !reason.is_normal() || discard_buffer {
                state.ring.clear();
            }
            StreamCloseOutcome::Published
        }
    };
    let sender = state.take_ready_sender_wake();
    let receiver = state.take_ready_receiver_wake();
    let terminal = state.take_ready_terminal_wake();
    let observation = close_observation(outcome, state.lifecycle);
    drop(state);
    wake_all([sender, receiver, terminal]);
    observation
}

const fn close_observation(
    outcome: StreamCloseOutcome,
    lifecycle: Lifecycle,
) -> StreamCloseObservation {
    let effective_reason = match lifecycle {
        Lifecycle::Open => None,
        Lifecycle::NormalProvisional => Some(StreamCloseReason::Normal),
        Lifecycle::Final(reason) => Some(reason),
    };
    StreamCloseObservation {
        outcome,
        effective_reason,
    }
}

fn producer_closed(lifecycle: Lifecycle) -> Option<StreamCloseReason> {
    match lifecycle {
        Lifecycle::Open => None,
        Lifecycle::NormalProvisional => Some(StreamCloseReason::Normal),
        Lifecycle::Final(reason) => Some(reason),
    }
}

fn validate_chunk(bytes: &[u8]) -> Result<(), StreamError> {
    if bytes.is_empty() || bytes.len() > MAX_STREAM_CHUNK_BYTES {
        Err(StreamError::InvalidChunk)
    } else {
        Ok(())
    }
}

static NEXT_OPERATION_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_operation_token() -> Result<HostOperationToken, StreamError> {
    take_operation_token(&NEXT_OPERATION_GENERATION)
}

fn take_operation_token(counter: &AtomicU64) -> Result<HostOperationToken, StreamError> {
    loop {
        let generation = counter.load(Ordering::Acquire);
        if generation == 0 {
            return Err(StreamError::TokenExhausted);
        }
        let next = generation.checked_add(1).unwrap_or(0);
        if counter
            .compare_exchange_weak(generation, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return HostOperationToken::from_generation(generation)
                .ok_or(StreamError::TokenExhausted);
        }
    }
}

fn wake_one(wake: Option<HostWakeToken>) {
    if let Some(wake) = wake {
        wake.wake();
    }
}

fn wake_all(wakes: [Option<HostWakeToken>; 3]) {
    for wake in wakes {
        wake_one(wake);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_test_wake(words: [usize; 4]) {
        let count = unsafe { &*(words[0] as *const core::sync::atomic::AtomicUsize) };
        count.fetch_add(1, Ordering::SeqCst);
    }

    fn test_wake(count: &Arc<core::sync::atomic::AtomicUsize>) -> HostWakeToken {
        HostWakeToken::new([Arc::as_ptr(count) as usize, 0, 0, 0], count_test_wake)
    }

    #[test]
    fn local_generation_exhaustion_never_wraps_or_reuses_zero() {
        let counter = AtomicU64::new(u64::MAX);
        let last = take_operation_token(&counter).unwrap();
        assert_eq!(HostOperationToken::from_generation(u64::MAX), Some(last));
        assert_eq!(
            take_operation_token(&counter),
            Err(StreamError::TokenExhausted)
        );
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn prepared_head_incarnation_seal_detects_explicit_aba_without_pop() {
        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        assert_eq!(writer.start(&[7]), Ok(StreamSendDispatch::Sent));
        let StreamReceiveDispatch::Prepared(prepared) = reader.start().unwrap() else {
            panic!("front chunk must prepare")
        };

        // Model a corrupted/reused physical ring slot with the same head and
        // length.  Token equality alone would miss this explicit ABA.
        {
            let mut state = stream.state.lock();
            let head = state.ring.head;
            state.ring.chunks[head].incarnation =
                state.ring.chunks[head].incarnation.checked_add(1).unwrap();
        }
        let mut output = [0_u8];
        assert_eq!(
            reader.commit(prepared.operation(), &mut output),
            Err(StreamError::FailStopped)
        );
        assert_eq!(output, [0]);
        assert_eq!(stream.depth(), 0);
        assert!(stream.is_fail_stopped());
    }

    #[test]
    fn chunk_incarnation_exhaustion_is_sticky_and_never_wraps() {
        let mut ring = ChunkRing::new();
        ring.next_incarnation = u64::MAX;
        ring.push(&[1]).unwrap();
        assert_eq!(ring.next_incarnation, 0);
        assert!(ring.pop_into(&mut [0]));
        assert_eq!(ring.push(&[2]), Err(StreamError::TokenExhausted));
        assert_eq!(ring.depth, 0);
    }

    #[test]
    fn fail_stop_wakes_and_removes_the_exact_terminal_waiter_once() {
        let stream = ByteStream::new();
        let supervisor = stream.supervisor();
        let count = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let StreamTerminalDispatch::Waiting(operation) = supervisor.start_terminal().unwrap()
        else {
            panic!("open stream must publish a terminal wait")
        };
        supervisor
            .register_terminal_wake(
                operation,
                HostWakeToken::new([Arc::as_ptr(&count) as usize, 0, 0, 0], count_test_wake),
            )
            .unwrap();

        let wakes = {
            let mut state = stream.state.lock();
            let wakes = state.fail_stop();
            assert!(state.terminal.is_none());
            wakes
        };
        wake_all(wakes);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        let repeated = {
            let mut state = stream.state.lock();
            state.fail_stop()
        };
        wake_all(repeated);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(
            supervisor.resume_terminal(operation),
            Err(StreamError::FailStopped)
        );
    }

    #[test]
    fn wrong_supervisor_and_rotated_token_are_inert() {
        let stream = ByteStream::new();
        let reader = stream.reader();
        let supervisor = stream.supervisor();
        let StreamReceiveDispatch::Waiting(old) = reader.start().unwrap() else {
            panic!("empty stream must publish a reader wait")
        };

        let foreign_stream = ByteStream::new();
        let foreign_reader = foreign_stream.reader();
        let foreign_supervisor = foreign_stream.supervisor();
        let StreamReceiveDispatch::Waiting(foreign) = foreign_reader.start().unwrap() else {
            panic!("empty foreign stream must publish a reader wait")
        };
        assert_eq!(
            foreign_supervisor.cancel_reader_operation_exact(old),
            Err(StreamError::TokenMismatch)
        );
        foreign_supervisor
            .cancel_reader_operation_exact(foreign)
            .expect("foreign cancellation changed its exact current operation");

        let StreamReceiveDispatch::Waiting(current) = reader.resume(old).unwrap() else {
            panic!("an empty resumed reader must rotate to a fresh wait")
        };
        assert_ne!(old, current);
        assert_eq!(
            supervisor.cancel_reader_operation_exact(old),
            Err(StreamError::TokenMismatch)
        );
        supervisor
            .cancel_reader_operation_exact(current)
            .expect("stale cancellation changed the exact current operation");
        assert_eq!(stream.depth(), 0);
        assert_eq!(stream.final_reason(), None);
        assert!(!stream.is_fail_stopped());
    }

    #[test]
    fn exact_cancellation_drops_registered_wakes_without_invoking_them() {
        let reader_stream = ByteStream::new();
        let reader = reader_stream.reader();
        let writer = reader_stream.writer();
        let supervisor = reader_stream.supervisor();
        let reader_wakes = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let StreamReceiveDispatch::Waiting(reader_operation) = reader.start().unwrap() else {
            panic!("empty stream must publish a reader wait")
        };
        reader
            .register_wake(reader_operation, test_wake(&reader_wakes))
            .unwrap();
        supervisor
            .cancel_reader_operation_exact(reader_operation)
            .unwrap();
        assert_eq!(reader_wakes.load(Ordering::SeqCst), 0);
        assert_eq!(writer.start(&[1]), Ok(StreamSendDispatch::Sent));
        assert_eq!(reader_wakes.load(Ordering::SeqCst), 0);

        let writer_stream = ByteStream::new();
        let reader = writer_stream.reader();
        let writer = writer_stream.writer();
        let supervisor = writer_stream.supervisor();
        for byte in 0..STREAM_BUFFER_CHUNKS {
            assert_eq!(writer.start(&[byte as u8]), Ok(StreamSendDispatch::Sent));
        }
        let writer_wakes = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let StreamSendDispatch::Waiting(writer_operation) = writer.start(&[0xff]).unwrap() else {
            panic!("a full stream must publish a writer wait")
        };
        writer
            .register_wake(writer_operation, test_wake(&writer_wakes))
            .unwrap();
        supervisor
            .cancel_writer_operation_exact(writer_operation)
            .unwrap();
        assert_eq!(writer_wakes.load(Ordering::SeqCst), 0);
        let StreamReceiveDispatch::Prepared(prepared) = reader.start().unwrap() else {
            panic!("the full stream must expose its front chunk")
        };
        let mut output = [0_u8];
        assert_eq!(
            reader.commit(prepared.operation(), &mut output),
            Ok(StreamReceiveCommit::Received(1))
        );
        assert_eq!(writer_wakes.load(Ordering::SeqCst), 0);

        let terminal_stream = ByteStream::new();
        let terminal_supervisor = terminal_stream.supervisor();
        let terminal_wakes = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let StreamTerminalDispatch::Waiting(terminal_operation) =
            terminal_supervisor.start_terminal().unwrap()
        else {
            panic!("open stream must publish a terminal wait")
        };
        terminal_supervisor
            .register_terminal_wake(terminal_operation, test_wake(&terminal_wakes))
            .unwrap();
        terminal_supervisor
            .cancel_terminal(terminal_operation)
            .unwrap();
        assert_eq!(terminal_wakes.load(Ordering::SeqCst), 0);
        assert_eq!(
            terminal_supervisor.finalize(StreamCloseReason::Failure),
            StreamCloseOutcome::Published
        );
        assert_eq!(terminal_wakes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn close_observation_has_no_reason_when_fail_stop_precedes_publication() {
        let stream = ByteStream::new();
        let supervisor = stream.supervisor();
        let wakes = stream.state.lock().fail_stop();
        wake_all(wakes);

        let promoted = supervisor
            .promote_normal_if_drained_observed()
            .expect("fail-stop must be observed rather than treated as pending");
        assert_eq!(promoted.outcome(), StreamCloseOutcome::Conflict);
        assert_eq!(promoted.effective_reason(), None);

        let observed = supervisor.finalize_observed(StreamCloseReason::Failure);
        assert_eq!(observed.outcome(), StreamCloseOutcome::Conflict);
        assert_eq!(observed.effective_reason(), None);
    }

    #[test]
    fn lifecycle_finalizer_observes_a_different_first_winner_without_conflict() {
        let stream = ByteStream::new();
        let supervisor = stream.supervisor();

        let first = supervisor.finalize_preserving_first_observed(StreamCloseReason::Failure);
        assert_eq!(first.outcome(), StreamCloseOutcome::Published);
        assert_eq!(first.effective_reason(), Some(StreamCloseReason::Failure));

        let late = supervisor.finalize_preserving_first_observed(StreamCloseReason::Cancelled);
        assert_eq!(late.outcome(), StreamCloseOutcome::AlreadyPublished);
        assert_eq!(late.effective_reason(), Some(StreamCloseReason::Failure));
        assert_eq!(stream.final_reason(), Some(StreamCloseReason::Failure));
        assert!(!stream.is_fail_stopped());
    }

    #[test]
    fn endpoint_close_first_winner_survives_late_lifecycle_finalization() {
        let stream = ByteStream::new();
        let writer = stream.writer();
        let supervisor = stream.supervisor();

        let first = writer.close_observed(StreamCloseReason::Failure);
        assert_eq!(first.outcome(), StreamCloseOutcome::Published);
        assert_eq!(first.effective_reason(), Some(StreamCloseReason::Failure));

        let late = supervisor.finalize_preserving_first_observed(StreamCloseReason::Cancelled);
        assert_eq!(late.outcome(), StreamCloseOutcome::AlreadyPublished);
        assert_eq!(late.effective_reason(), Some(StreamCloseReason::Failure));
        assert_eq!(stream.final_reason(), Some(StreamCloseReason::Failure));
        assert!(!stream.is_fail_stopped());
    }
}
