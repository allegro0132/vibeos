use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use vibeos_component_host::{
    ByteStream, ByteStreamReader, ByteStreamSupervisor, ByteStreamWriter, StreamCloseOutcome,
    StreamCloseReason, StreamError, StreamReceiveCommit, StreamReceiveDispatch, StreamSendDispatch,
    StreamTerminalDispatch, STREAM_BUFFER_CHUNKS,
};
use vibeos_component_runtime::host::{HostOperationToken, HostWakeToken};

const SEEDS: [u64; 4] = [
    1,
    0x243f_6a88_85a3_08d3,
    0x9e37_79b9_7f4a_7c15,
    0xffff_ffff_ffff_ffc5,
];
const EPISODES_PER_SEED: usize = 6;
const STEPS_PER_EPISODE: usize = 96;
const MAX_WAKE_PROBES: usize = 4_096;

static NEXT_WAKE_PROBE: AtomicUsize = AtomicUsize::new(0);
static WAKE_COUNTS: [AtomicUsize; MAX_WAKE_PROBES] =
    [const { AtomicUsize::new(0) }; MAX_WAKE_PROBES];

fn count_wake(words: [usize; 4]) {
    WAKE_COUNTS[words[0]].fetch_add(1, Ordering::SeqCst);
}

fn wake_token(index: usize) -> HostWakeToken {
    HostWakeToken::new([index, 0, 0, 0], count_wake)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WakeDisposition {
    Live,
    Woken,
    Cancelled,
}

struct WakeRecord {
    index: usize,
    disposition: WakeDisposition,
}

#[derive(Clone, Copy, Debug)]
struct WaitSlot {
    token: HostOperationToken,
    wake: Option<usize>,
}

#[derive(Debug)]
enum ReceiveSlot {
    Waiting(WaitSlot),
    Prepared {
        token: HostOperationToken,
        bytes: Vec<u8>,
    },
}

impl ReceiveSlot {
    fn token(&self) -> HostOperationToken {
        match self {
            Self::Waiting(waiting) => waiting.token,
            Self::Prepared { token, .. } => *token,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelLifecycle {
    Open,
    NormalProvisional,
    Final(StreamCloseReason),
}

#[derive(Debug)]
struct Model {
    queue: VecDeque<Vec<u8>>,
    peak_depth: usize,
    lifecycle: ModelLifecycle,
    consumer_stopped: bool,
    send: Option<WaitSlot>,
    receive: Option<ReceiveSlot>,
    terminal: Option<WaitSlot>,
    stale_send: Vec<HostOperationToken>,
    stale_receive: Vec<HostOperationToken>,
    stale_terminal: Vec<HostOperationToken>,
}

impl Model {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            peak_depth: 0,
            lifecycle: ModelLifecycle::Open,
            consumer_stopped: false,
            send: None,
            receive: None,
            terminal: None,
            stale_send: Vec::new(),
            stale_receive: Vec::new(),
            stale_terminal: Vec::new(),
        }
    }

    fn final_reason(&self) -> Option<StreamCloseReason> {
        match self.lifecycle {
            ModelLifecycle::Final(reason) => Some(reason),
            ModelLifecycle::Open | ModelLifecycle::NormalProvisional => None,
        }
    }

    fn producer_closed(&self) -> Option<StreamCloseReason> {
        match self.lifecycle {
            ModelLifecycle::Open => None,
            ModelLifecycle::NormalProvisional => Some(StreamCloseReason::Normal),
            ModelLifecycle::Final(reason) => Some(reason),
        }
    }

    fn receiver_ready(&self) -> bool {
        !self.queue.is_empty()
            || !matches!(self.lifecycle, ModelLifecycle::Open)
            || self.consumer_stopped
    }

    fn sender_ready(&self) -> bool {
        self.queue.len() < STREAM_BUFFER_CHUNKS || !matches!(self.lifecycle, ModelLifecycle::Open)
    }
}

#[derive(Clone, Copy, Debug)]
struct Payload {
    tag: u8,
    len: u8,
}

impl Payload {
    fn bytes(self) -> Vec<u8> {
        (0..self.len)
            .map(|offset| self.tag.wrapping_add(offset))
            .collect()
    }
}

#[derive(Clone, Copy, Debug)]
enum Action {
    SendStart(Payload),
    SendResume(Payload),
    SendRegisterWake,
    SendCancel,
    ReplayStaleSend,
    ReceiveStart,
    ReceiveResume,
    ReceiveRegisterWake,
    ReceiveCommit { wrong_length: bool },
    ReceiveCancel,
    ReplayStaleReceive,
    TerminalStart,
    TerminalResume,
    TerminalRegisterWake,
    TerminalCancel,
    ReplayStaleTerminal,
    WriterCloseNormal,
    ReaderCloseNormal,
    Finalize(StreamCloseReason),
}

struct Harness {
    stream: Arc<ByteStream>,
    reader: Arc<ByteStreamReader>,
    writer: Arc<ByteStreamWriter>,
    supervisor: Arc<ByteStreamSupervisor>,
    model: Model,
    wakes: Vec<WakeRecord>,
}

impl Harness {
    fn new() -> Self {
        let stream = ByteStream::new();
        Self {
            reader: stream.reader(),
            writer: stream.writer(),
            supervisor: stream.supervisor(),
            stream,
            model: Model::new(),
            wakes: Vec::new(),
        }
    }

    fn new_wake(&mut self) -> (usize, HostWakeToken) {
        let probe_index = NEXT_WAKE_PROBE.fetch_add(1, Ordering::SeqCst);
        assert!(
            probe_index < MAX_WAKE_PROBES,
            "C5.7 byte-stream trace exceeded its fixed wake-probe bank"
        );
        WAKE_COUNTS[probe_index].store(0, Ordering::SeqCst);
        let token = wake_token(probe_index);
        let record_index = self.wakes.len();
        self.wakes.push(WakeRecord {
            index: probe_index,
            disposition: WakeDisposition::Live,
        });
        (record_index, token)
    }

    fn mark_woken(&mut self, wake: Option<usize>) {
        if let Some(index) = wake {
            let record = &mut self.wakes[index];
            assert_eq!(record.disposition, WakeDisposition::Live);
            record.disposition = WakeDisposition::Woken;
        }
    }

    fn mark_cancelled(&mut self, wake: Option<usize>) {
        if let Some(index) = wake {
            let record = &mut self.wakes[index];
            assert_eq!(record.disposition, WakeDisposition::Live);
            record.disposition = WakeDisposition::Cancelled;
        }
    }

    fn wake_sender_if_ready(&mut self) {
        if !self.model.sender_ready() {
            return;
        }
        let wake = self
            .model
            .send
            .as_mut()
            .and_then(|waiting| waiting.wake.take());
        self.mark_woken(wake);
    }

    fn wake_receiver_if_ready(&mut self) {
        if !self.model.receiver_ready() {
            return;
        }
        let wake = match self.model.receive.as_mut() {
            Some(ReceiveSlot::Waiting(waiting)) => waiting.wake.take(),
            Some(ReceiveSlot::Prepared { .. }) | None => None,
        };
        self.mark_woken(wake);
    }

    fn wake_terminal_if_ready(&mut self) {
        if self.model.final_reason().is_none() {
            return;
        }
        let wake = self
            .model
            .terminal
            .as_mut()
            .and_then(|waiting| waiting.wake.take());
        self.mark_woken(wake);
    }

    fn apply(&mut self, action: Action) {
        match action {
            Action::SendStart(payload) => self.send_start(payload),
            Action::SendResume(payload) => self.send_resume(payload),
            Action::SendRegisterWake => self.send_register_wake(),
            Action::SendCancel => self.send_cancel(),
            Action::ReplayStaleSend => self.replay_stale_send(),
            Action::ReceiveStart => self.receive_start(),
            Action::ReceiveResume => self.receive_resume(),
            Action::ReceiveRegisterWake => self.receive_register_wake(),
            Action::ReceiveCommit { wrong_length } => self.receive_commit(wrong_length),
            Action::ReceiveCancel => self.receive_cancel(),
            Action::ReplayStaleReceive => self.replay_stale_receive(),
            Action::TerminalStart => self.terminal_start(),
            Action::TerminalResume => self.terminal_resume(),
            Action::TerminalRegisterWake => self.terminal_register_wake(),
            Action::TerminalCancel => self.terminal_cancel(),
            Action::ReplayStaleTerminal => self.replay_stale_terminal(),
            Action::WriterCloseNormal => self.writer_close_normal(),
            Action::ReaderCloseNormal => self.reader_close_normal(),
            Action::Finalize(reason) => self.finalize(reason),
        }
        self.assert_invariants();
    }

    fn send_start(&mut self, payload: Payload) {
        let bytes = payload.bytes();
        let actual = self.writer.start(&bytes);
        if self.model.send.is_some() {
            assert_eq!(actual, Err(StreamError::Busy));
        } else if let Some(reason) = self.model.producer_closed() {
            assert_eq!(actual, Ok(StreamSendDispatch::Closed(reason)));
        } else if self.model.queue.len() == STREAM_BUFFER_CHUNKS {
            let token = match actual {
                Ok(StreamSendDispatch::Waiting(token)) => token,
                other => panic!("full model ring expected a send wait, got {other:?}"),
            };
            self.model.send = Some(WaitSlot { token, wake: None });
        } else {
            assert_eq!(actual, Ok(StreamSendDispatch::Sent));
            self.model.queue.push_back(bytes);
            self.model.peak_depth = self.model.peak_depth.max(self.model.queue.len());
            self.wake_receiver_if_ready();
        }
    }

    fn send_resume(&mut self, payload: Payload) {
        let Some(current) = self.model.send else {
            self.replay_stale_send();
            return;
        };
        let bytes = payload.bytes();
        let actual = self.writer.resume(current.token, &bytes);
        let old = self.model.send.take().unwrap();
        self.model.stale_send.push(old.token);
        self.mark_cancelled(old.wake);

        if let Some(reason) = self.model.producer_closed() {
            assert_eq!(actual, Ok(StreamSendDispatch::Closed(reason)));
        } else if self.model.queue.len() == STREAM_BUFFER_CHUNKS {
            let token = match actual {
                Ok(StreamSendDispatch::Waiting(token)) => token,
                other => panic!("full model ring expected a fresh send wait, got {other:?}"),
            };
            assert_ne!(token, old.token);
            self.model.send = Some(WaitSlot { token, wake: None });
        } else {
            assert_eq!(actual, Ok(StreamSendDispatch::Sent));
            self.model.queue.push_back(bytes);
            self.model.peak_depth = self.model.peak_depth.max(self.model.queue.len());
            self.wake_receiver_if_ready();
        }
    }

    fn send_register_wake(&mut self) {
        let Some(current) = self.model.send else {
            self.replay_stale_send();
            return;
        };
        let (wake_index, wake) = self.new_wake();
        let actual = self.writer.register_wake(current.token, wake);
        if current.wake.is_some() {
            assert_eq!(actual, Err(StreamError::WakeAlreadyRegistered));
            self.mark_cancelled(Some(wake_index));
        } else {
            assert_eq!(actual, Ok(()));
            self.model.send.as_mut().unwrap().wake = Some(wake_index);
            self.wake_sender_if_ready();
        }
    }

    fn send_cancel(&mut self) {
        let Some(current) = self.model.send.take() else {
            self.replay_stale_send();
            return;
        };
        assert_eq!(self.writer.cancel(current.token), Ok(()));
        self.model.stale_send.push(current.token);
        self.mark_cancelled(current.wake);
    }

    fn replay_stale_send(&mut self) {
        let Some(token) = self.model.stale_send.last().copied() else {
            return;
        };
        assert_eq!(
            self.writer
                .resume(token, &Payload { tag: 0xee, len: 1 }.bytes(),),
            Err(StreamError::TokenMismatch)
        );
    }

    fn receive_start(&mut self) {
        let actual = self.reader.start();
        if self.model.receive.is_some() {
            assert_eq!(actual, Err(StreamError::Busy));
        } else if self.model.consumer_stopped {
            match self.model.final_reason() {
                Some(reason) => assert_eq!(actual, Ok(StreamReceiveDispatch::Closed(reason))),
                None => assert_eq!(actual, Err(StreamError::EndpointClosed)),
            }
        } else if let Some(reason) = self.model.final_reason() {
            if reason != StreamCloseReason::Normal || self.model.queue.is_empty() {
                assert_eq!(actual, Ok(StreamReceiveDispatch::Closed(reason)));
            } else {
                self.install_prepared(actual);
            }
        } else if self.model.queue.is_empty() {
            let token = match actual {
                Ok(StreamReceiveDispatch::Waiting(token)) => token,
                other => panic!("empty model queue expected a receive wait, got {other:?}"),
            };
            self.model.receive = Some(ReceiveSlot::Waiting(WaitSlot { token, wake: None }));
        } else {
            self.install_prepared(actual);
        }
    }

    fn install_prepared(&mut self, actual: Result<StreamReceiveDispatch, StreamError>) {
        let prepared = match actual {
            Ok(StreamReceiveDispatch::Prepared(prepared)) => prepared,
            other => panic!("nonempty model queue expected a prepared receive, got {other:?}"),
        };
        let bytes = self.model.queue.front().unwrap().clone();
        assert_eq!(prepared.length(), bytes.len());
        self.model.receive = Some(ReceiveSlot::Prepared {
            token: prepared.operation(),
            bytes,
        });
    }

    fn receive_resume(&mut self) {
        let Some(ReceiveSlot::Waiting(current)) = self.model.receive.as_ref() else {
            self.replay_stale_receive();
            return;
        };
        let current = *current;
        let actual = self.reader.resume(current.token);
        let Some(ReceiveSlot::Waiting(old)) = self.model.receive.take() else {
            unreachable!()
        };
        self.model.stale_receive.push(old.token);
        self.mark_cancelled(old.wake);

        if self.model.consumer_stopped {
            match self.model.final_reason() {
                Some(reason) => assert_eq!(actual, Ok(StreamReceiveDispatch::Closed(reason))),
                None => assert_eq!(actual, Err(StreamError::EndpointClosed)),
            }
        } else if let Some(reason) = self.model.final_reason() {
            if reason != StreamCloseReason::Normal || self.model.queue.is_empty() {
                assert_eq!(actual, Ok(StreamReceiveDispatch::Closed(reason)));
            } else {
                self.install_prepared(actual);
            }
        } else if self.model.queue.is_empty() {
            let token = match actual {
                Ok(StreamReceiveDispatch::Waiting(token)) => token,
                other => panic!("empty model queue expected a rotated receive wait, got {other:?}"),
            };
            assert_ne!(token, old.token);
            self.model.receive = Some(ReceiveSlot::Waiting(WaitSlot { token, wake: None }));
        } else {
            self.install_prepared(actual);
        }
    }

    fn receive_register_wake(&mut self) {
        let Some(ReceiveSlot::Waiting(current)) = self.model.receive.as_ref() else {
            self.replay_stale_receive();
            return;
        };
        let current = *current;
        let (wake_index, wake) = self.new_wake();
        let actual = self.reader.register_wake(current.token, wake);
        if current.wake.is_some() {
            assert_eq!(actual, Err(StreamError::WakeAlreadyRegistered));
            self.mark_cancelled(Some(wake_index));
        } else {
            assert_eq!(actual, Ok(()));
            let Some(ReceiveSlot::Waiting(waiting)) = self.model.receive.as_mut() else {
                unreachable!()
            };
            waiting.wake = Some(wake_index);
            self.wake_receiver_if_ready();
        }
    }

    fn receive_commit(&mut self, wrong_length: bool) {
        let Some(ReceiveSlot::Prepared { token, bytes }) = self.model.receive.as_ref() else {
            self.replay_stale_receive();
            return;
        };
        let token = *token;
        let expected_bytes = bytes.clone();
        let length = if wrong_length {
            if expected_bytes.len() == 1 {
                2
            } else {
                expected_bytes.len() - 1
            }
        } else {
            expected_bytes.len()
        };
        let mut output = vec![0xa5; length];
        let actual = self.reader.commit(token, &mut output);

        if wrong_length {
            assert_eq!(actual, Err(StreamError::InvalidCommitLength));
            assert!(output.iter().all(|byte| *byte == 0xa5));
            return;
        }
        if self.model.consumer_stopped {
            match self.model.final_reason() {
                Some(reason) => assert_eq!(actual, Ok(StreamReceiveCommit::Closed(reason))),
                None => assert_eq!(actual, Err(StreamError::EndpointClosed)),
            }
            assert!(output.iter().all(|byte| *byte == 0xa5));
            return;
        }
        if let Some(reason) = self.model.final_reason() {
            if reason != StreamCloseReason::Normal {
                assert_eq!(actual, Ok(StreamReceiveCommit::Closed(reason)));
                assert!(output.iter().all(|byte| *byte == 0xa5));
                return;
            }
        }

        assert_eq!(actual, Ok(StreamReceiveCommit::Received(length)));
        assert_eq!(output, expected_bytes);
        assert_eq!(self.model.queue.pop_front(), Some(output));
        let completed = self.model.receive.take().unwrap();
        self.model.stale_receive.push(completed.token());
        self.wake_sender_if_ready();
    }

    fn receive_cancel(&mut self) {
        let Some(current) = self.model.receive.take() else {
            self.replay_stale_receive();
            return;
        };
        assert_eq!(self.reader.cancel(current.token()), Ok(()));
        self.model.stale_receive.push(current.token());
        if let ReceiveSlot::Waiting(waiting) = current {
            self.mark_cancelled(waiting.wake);
        }
    }

    fn replay_stale_receive(&mut self) {
        let Some(token) = self.model.stale_receive.last().copied() else {
            return;
        };
        assert_eq!(self.reader.cancel(token), Err(StreamError::TokenMismatch));
    }

    fn terminal_start(&mut self) {
        let actual = self.supervisor.start_terminal();
        if self.model.terminal.is_some() {
            assert_eq!(actual, Err(StreamError::Busy));
        } else if let Some(reason) = self.model.final_reason() {
            assert_eq!(actual, Ok(StreamTerminalDispatch::Ready(reason)));
        } else {
            let token = match actual {
                Ok(StreamTerminalDispatch::Waiting(token)) => token,
                other => panic!("open model lifecycle expected a terminal wait, got {other:?}"),
            };
            self.model.terminal = Some(WaitSlot { token, wake: None });
        }
    }

    fn terminal_resume(&mut self) {
        let Some(current) = self.model.terminal.take() else {
            self.replay_stale_terminal();
            return;
        };
        let actual = self.supervisor.resume_terminal(current.token);
        self.model.stale_terminal.push(current.token);
        self.mark_cancelled(current.wake);
        if let Some(reason) = self.model.final_reason() {
            assert_eq!(actual, Ok(StreamTerminalDispatch::Ready(reason)));
        } else {
            let token = match actual {
                Ok(StreamTerminalDispatch::Waiting(token)) => token,
                other => {
                    panic!("open model lifecycle expected a rotated terminal wait, got {other:?}")
                }
            };
            assert_ne!(token, current.token);
            self.model.terminal = Some(WaitSlot { token, wake: None });
        }
    }

    fn terminal_register_wake(&mut self) {
        let Some(current) = self.model.terminal else {
            self.replay_stale_terminal();
            return;
        };
        let (wake_index, wake) = self.new_wake();
        let actual = self.supervisor.register_terminal_wake(current.token, wake);
        if current.wake.is_some() {
            assert_eq!(actual, Err(StreamError::WakeAlreadyRegistered));
            self.mark_cancelled(Some(wake_index));
        } else {
            assert_eq!(actual, Ok(()));
            self.model.terminal.as_mut().unwrap().wake = Some(wake_index);
            self.wake_terminal_if_ready();
        }
    }

    fn terminal_cancel(&mut self) {
        let Some(current) = self.model.terminal.take() else {
            self.replay_stale_terminal();
            return;
        };
        assert_eq!(self.supervisor.cancel_terminal(current.token), Ok(()));
        self.model.stale_terminal.push(current.token);
        self.mark_cancelled(current.wake);
    }

    fn replay_stale_terminal(&mut self) {
        let Some(token) = self.model.stale_terminal.last().copied() else {
            return;
        };
        assert_eq!(
            self.supervisor.resume_terminal(token),
            Err(StreamError::TokenMismatch)
        );
    }

    fn writer_close_normal(&mut self) {
        let actual = self.writer.close(StreamCloseReason::Normal);
        let expected = match self.model.lifecycle {
            ModelLifecycle::Open => {
                self.model.lifecycle = ModelLifecycle::NormalProvisional;
                StreamCloseOutcome::Published
            }
            ModelLifecycle::NormalProvisional | ModelLifecycle::Final(_) => {
                StreamCloseOutcome::AlreadyPublished
            }
        };
        assert_eq!(actual, expected);
        self.wake_sender_if_ready();
        self.wake_receiver_if_ready();
        self.wake_terminal_if_ready();
    }

    fn reader_close_normal(&mut self) {
        let actual = self.reader.close(StreamCloseReason::Normal);
        let expected = match self.model.lifecycle {
            ModelLifecycle::Open => {
                self.model.lifecycle = ModelLifecycle::NormalProvisional;
                StreamCloseOutcome::Published
            }
            ModelLifecycle::NormalProvisional | ModelLifecycle::Final(_) => {
                StreamCloseOutcome::AlreadyPublished
            }
        };
        self.model.consumer_stopped = true;
        self.model.queue.clear();
        assert_eq!(actual, expected);
        self.wake_sender_if_ready();
        self.wake_receiver_if_ready();
        self.wake_terminal_if_ready();
    }

    fn finalize(&mut self, requested: StreamCloseReason) {
        let reason = self.model.final_reason().unwrap_or(requested);
        let actual = self.supervisor.finalize(reason);
        let expected = match self.model.lifecycle {
            ModelLifecycle::Final(established) => {
                assert_eq!(established, reason);
                StreamCloseOutcome::AlreadyPublished
            }
            ModelLifecycle::Open | ModelLifecycle::NormalProvisional => {
                self.model.lifecycle = ModelLifecycle::Final(reason);
                if reason != StreamCloseReason::Normal {
                    self.model.queue.clear();
                }
                StreamCloseOutcome::Published
            }
        };
        assert_eq!(actual, expected);
        self.wake_sender_if_ready();
        self.wake_receiver_if_ready();
        self.wake_terminal_if_ready();
    }

    fn assert_invariants(&self) {
        assert_eq!(self.stream.depth(), self.model.queue.len());
        assert_eq!(self.stream.peak_depth(), self.model.peak_depth);
        assert!(self.stream.depth() <= STREAM_BUFFER_CHUNKS);
        assert!(self.stream.peak_depth() <= STREAM_BUFFER_CHUNKS);
        assert_eq!(self.stream.final_reason(), self.model.final_reason());
        assert_eq!(
            self.stream.is_normal_provisional(),
            matches!(self.model.lifecycle, ModelLifecycle::NormalProvisional)
        );
        assert!(!self.stream.is_fail_stopped());

        // A live modeled slot must be the real slot: a second start can only
        // report Busy and must not allocate, enqueue, or replace its token.
        if self.model.send.is_some() {
            assert_eq!(self.writer.start(&[0xfe]), Err(StreamError::Busy));
        }
        if self.model.receive.is_some() {
            assert_eq!(self.reader.start(), Err(StreamError::Busy));
        }
        if self.model.terminal.is_some() {
            assert_eq!(self.supervisor.start_terminal(), Err(StreamError::Busy));
        }

        for record in &self.wakes {
            let expected = usize::from(record.disposition == WakeDisposition::Woken);
            assert_eq!(WAKE_COUNTS[record.index].load(Ordering::SeqCst), expected);
            assert!(WAKE_COUNTS[record.index].load(Ordering::SeqCst) <= 1);
        }
    }

    fn assert_settled(&self) {
        self.assert_invariants();
        assert!(self.model.send.is_none());
        assert!(self.model.receive.is_none());
        assert!(self.model.terminal.is_none());
        assert!(self.model.queue.is_empty());
        assert!(self.model.final_reason().is_some());
        assert!(
            self.wakes
                .iter()
                .all(|record| record.disposition != WakeDisposition::Live),
            "a registered wake remained owned by no settle action"
        );
    }
}

fn execute(harness: &mut Harness, seed: u64, step: usize, action: Action) {
    let result = catch_unwind(AssertUnwindSafe(|| harness.apply(action)));
    if let Err(payload) = result {
        let detail = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&'static str>().copied())
            .unwrap_or("non-string panic");
        panic!("seed={seed:#018x} step={step} action={action:?}: {detail}");
    }
}

fn payload(tag: u8) -> Payload {
    Payload { tag, len: 1 }
}

fn mandatory_prefix() {
    let seed = 0;
    let mut step = 0;
    let mut harness = Harness::new();
    let mut run = |harness: &mut Harness, action| {
        execute(harness, seed, step, action);
        step += 1;
    };

    // Empty receive suspension, wake registration, readiness, resume, and
    // two-phase prepared receive commit.
    run(&mut harness, Action::ReceiveStart);
    run(&mut harness, Action::ReceiveRegisterWake);
    run(&mut harness, Action::SendStart(payload(1)));
    run(&mut harness, Action::ReceiveResume);
    run(&mut harness, Action::ReceiveCommit { wrong_length: true });
    run(
        &mut harness,
        Action::ReceiveCommit {
            wrong_length: false,
        },
    );

    // Fill the exact ring, suspend a producer, register its wake, make one
    // slot available, and resume the producer back to a full ring.
    for value in 10..10 + STREAM_BUFFER_CHUNKS as u8 {
        run(&mut harness, Action::SendStart(payload(value)));
    }
    run(&mut harness, Action::SendStart(payload(99)));
    run(&mut harness, Action::SendRegisterWake);
    run(&mut harness, Action::ReceiveStart);
    run(
        &mut harness,
        Action::ReceiveCommit {
            wrong_length: false,
        },
    );
    run(&mut harness, Action::SendResume(payload(99)));

    // Cancellation revokes an installed wake without invoking it, and both a
    // blocked-send token and a prepared-receive token become inert.
    run(&mut harness, Action::SendStart(payload(100)));
    run(&mut harness, Action::SendRegisterWake);
    run(&mut harness, Action::SendCancel);
    run(&mut harness, Action::ReplayStaleSend);
    run(&mut harness, Action::ReceiveStart);
    run(&mut harness, Action::ReceiveCancel);
    run(&mut harness, Action::ReplayStaleReceive);

    // Terminal wait is independent from send/receive slots. Producer close is
    // provisional; supervisor finalization publishes EOF and wakes it.
    run(&mut harness, Action::TerminalStart);
    run(&mut harness, Action::TerminalRegisterWake);
    run(&mut harness, Action::WriterCloseNormal);
    run(&mut harness, Action::Finalize(StreamCloseReason::Normal));
    run(&mut harness, Action::TerminalResume);
    run(&mut harness, Action::ReplayStaleTerminal);

    while !harness.model.queue.is_empty() {
        run(&mut harness, Action::ReceiveStart);
        run(
            &mut harness,
            Action::ReceiveCommit {
                wrong_length: false,
            },
        );
    }

    // Explicit endpoint closure models drop-like consumer teardown. After it,
    // all three public starts are terminal rather than stranded Busy slots.
    run(&mut harness, Action::ReaderCloseNormal);
    run(&mut harness, Action::ReceiveStart);
    run(&mut harness, Action::SendStart(payload(200)));
    run(&mut harness, Action::TerminalStart);
    harness.assert_settled();
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn payload(&mut self) -> Payload {
        let bits = self.next();
        Payload {
            tag: bits as u8,
            len: ((bits >> 8) as u8 % 8) + 1,
        }
    }
}

fn choose_action(harness: &Harness, rng: &mut Rng, episode_step: usize) -> Action {
    let roll = (rng.next() % 64) as u8;
    match roll {
        0..=7 => Action::SendStart(rng.payload()),
        8..=11 if harness.model.send.is_some() => Action::SendResume(rng.payload()),
        12..=14 if harness.model.send.is_some() => Action::SendRegisterWake,
        15..=17 if harness.model.send.is_some() => Action::SendCancel,
        18 if !harness.model.stale_send.is_empty() => Action::ReplayStaleSend,
        19..=26 => Action::ReceiveStart,
        27..=30 if matches!(harness.model.receive, Some(ReceiveSlot::Waiting(_))) => {
            Action::ReceiveResume
        }
        31..=33 if matches!(harness.model.receive, Some(ReceiveSlot::Waiting(_))) => {
            Action::ReceiveRegisterWake
        }
        34..=38 if matches!(harness.model.receive, Some(ReceiveSlot::Prepared { .. })) => {
            Action::ReceiveCommit {
                wrong_length: roll == 34,
            }
        }
        39..=41 if harness.model.receive.is_some() => Action::ReceiveCancel,
        42 if !harness.model.stale_receive.is_empty() => Action::ReplayStaleReceive,
        43..=46 => Action::TerminalStart,
        47..=49 if harness.model.terminal.is_some() => Action::TerminalResume,
        50..=51 if harness.model.terminal.is_some() => Action::TerminalRegisterWake,
        52 if harness.model.terminal.is_some() => Action::TerminalCancel,
        53 if !harness.model.stale_terminal.is_empty() => Action::ReplayStaleTerminal,
        54..=56 if episode_step >= 24 => Action::WriterCloseNormal,
        57 if episode_step >= 40 => Action::ReaderCloseNormal,
        58..=60 if episode_step >= 32 => {
            let reason = harness
                .model
                .final_reason()
                .unwrap_or(if rng.next() & 1 == 0 {
                    StreamCloseReason::Normal
                } else {
                    StreamCloseReason::Cancelled
                });
            Action::Finalize(reason)
        }
        _ if harness.model.send.is_some() => Action::SendResume(rng.payload()),
        _ if harness.model.receive.is_some() => Action::ReceiveCancel,
        _ => Action::SendStart(rng.payload()),
    }
}

fn settle(harness: &mut Harness, seed: u64, step: &mut usize) {
    if harness.model.send.is_some() {
        execute(harness, seed, *step, Action::SendCancel);
        *step += 1;
    }
    if harness.model.receive.is_some() {
        execute(harness, seed, *step, Action::ReceiveCancel);
        *step += 1;
    }
    if harness.model.terminal.is_some() {
        execute(harness, seed, *step, Action::TerminalCancel);
        *step += 1;
    }
    if harness.model.final_reason().is_none() {
        execute(
            harness,
            seed,
            *step,
            Action::Finalize(StreamCloseReason::Cancelled),
        );
        *step += 1;
    }
    while !harness.model.queue.is_empty() {
        // Only a normal final preserves buffered data; a stopped reader has
        // already discarded it. Drain it through real prepared commits.
        assert_eq!(
            harness.model.final_reason(),
            Some(StreamCloseReason::Normal)
        );
        execute(harness, seed, *step, Action::ReceiveStart);
        *step += 1;
        execute(
            harness,
            seed,
            *step,
            Action::ReceiveCommit {
                wrong_length: false,
            },
        );
        *step += 1;
    }
    harness.assert_settled();
}

#[test]
fn seeded_real_byte_stream_state_machine_never_panics_or_strands_state() {
    mandatory_prefix();

    for seed in SEEDS {
        let mut rng = Rng::new(seed);
        let mut global_step = 0;
        for _episode in 0..EPISODES_PER_SEED {
            let mut harness = Harness::new();
            for episode_step in 0..STEPS_PER_EPISODE {
                let action = choose_action(&harness, &mut rng, episode_step);
                execute(&mut harness, seed, global_step, action);
                global_step += 1;
            }
            settle(&mut harness, seed, &mut global_step);
        }
    }
}
