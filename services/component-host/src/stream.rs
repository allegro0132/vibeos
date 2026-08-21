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

    fn fail_stop(&mut self) -> (Option<HostWakeToken>, Option<HostWakeToken>) {
        self.fail_stopped = true;
        self.ring.clear();
        let send = self.send.as_mut().and_then(|pending| pending.wake.take());
        let receive = match self.receive.as_mut() {
            Some(ReceiveOperation::Waiting(pending)) => pending.wake.take(),
            _ => None,
        };
        (send, receive)
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
                    wake_pair(wakes);
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
                wake_pair(wakes);
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
                    wake_pair(wakes);
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
                wake_pair(wakes);
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
            wake_pair(wakes);
            return Err(StreamError::FailStopped);
        }
        if !state.ring.pop_into(output) {
            let wakes = state.fail_stop();
            drop(state);
            wake_pair(wakes);
            return Err(StreamError::FailStopped);
        }
        state.receive = None;
        let sender = state.take_ready_sender_wake();
        drop(state);
        wake_one(sender);
        Ok(StreamReceiveCommit::Received(output.len()))
    }

    pub fn cancel(&self, operation: HostOperationToken) -> Result<(), StreamError> {
        let mut state = self.stream.state.lock();
        state.check_live()?;
        let matches = match state.receive {
            Some(ReceiveOperation::Waiting(waiting)) => waiting.token == operation,
            Some(ReceiveOperation::Prepared(prepared)) => prepared.operation == operation,
            None => false,
        };
        if !matches {
            return Err(StreamError::TokenMismatch);
        }
        state.receive = None;
        Ok(())
    }

    /// Consumer-done publication. Normal remains provisional until the
    /// SYSTEM supervisor publishes the immutable terminal reason. Buffered
    /// input is discarded so a blocked producer cannot be stranded.
    pub fn close(&self, reason: StreamCloseReason) -> StreamCloseOutcome {
        publish_close(&self.stream, reason, false, true)
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
                    wake_pair(wakes);
                    return Err(error);
                }
            };
            state.send = Some(WaitingOperation { token, wake: None });
            return Ok(StreamSendDispatch::Waiting(token));
        }
        if state.ring.push(bytes).is_err() {
            let wakes = state.fail_stop();
            drop(state);
            wake_pair(wakes);
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
                    wake_pair(wakes);
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
            wake_pair(wakes);
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
        let mut state = self.stream.state.lock();
        state.check_live()?;
        if state.send.map(|pending| pending.token) != Some(operation) {
            return Err(StreamError::TokenMismatch);
        }
        state.send = None;
        Ok(())
    }

    /// Producer-done publication.  Normal is provisional until supervisor
    /// finalization; a non-normal reason is immediately immutable final.
    pub fn close(&self, reason: StreamCloseReason) -> StreamCloseOutcome {
        publish_close(&self.stream, reason, false, false)
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

    /// Publish the one immutable terminal reason.  Finalizing `Normal` is the
    /// only transition which makes drained EOF observable to the reader.
    pub fn finalize(&self, reason: StreamCloseReason) -> StreamCloseOutcome {
        publish_close(&self.stream, reason, true, false)
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

fn publish_close(
    stream: &ByteStream,
    reason: StreamCloseReason,
    supervisor: bool,
    discard_buffer: bool,
) -> StreamCloseOutcome {
    let mut state = stream.state.lock();
    if state.fail_stopped {
        return StreamCloseOutcome::Conflict;
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
            let wakes = state.fail_stop();
            drop(state);
            wake_pair(wakes);
            return StreamCloseOutcome::Conflict;
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
    drop(state);
    wake_pair((sender, receiver));
    outcome
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

fn wake_pair(wakes: (Option<HostWakeToken>, Option<HostWakeToken>)) {
    wake_one(wakes.0);
    wake_one(wakes.1);
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
