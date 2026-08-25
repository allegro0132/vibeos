use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use vibeos_component_host::{
    ByteStream, StreamCloseOutcome, StreamCloseReason, StreamError, StreamReceiveCommit,
    StreamReceiveDispatch, StreamSealedWakeToken, StreamSendDispatch, StreamTerminalDispatch,
    StreamWakeSignal, MAX_STREAM_CHUNK_BYTES, STREAM_BUFFER_CHUNKS,
};
use vibeos_component_runtime::host::HostWakeToken;
use vibeos_core::cap::{CSpace, Resource, Rights};

struct WakeProbe {
    count: AtomicUsize,
}

struct ReentrantWakeProbe {
    stream: Arc<ByteStream>,
    count: AtomicUsize,
}

struct DelayedWakeProbe {
    entered: Barrier,
    release: Barrier,
    count: AtomicUsize,
}

struct DelayedSealedWakeProbe {
    entered: Barrier,
    release: Barrier,
    count: AtomicUsize,
    signal: Mutex<Option<StreamWakeSignal>>,
}

fn count_wake(words: [usize; 4]) {
    // The test keeps the Arc containing this allocation alive until every
    // registered operation is either woken or cancelled.
    let probe = unsafe { &*(words[0] as *const WakeProbe) };
    probe.count.fetch_add(1, Ordering::SeqCst);
}

fn wake_token(probe: &Arc<WakeProbe>) -> HostWakeToken {
    HostWakeToken::new([Arc::as_ptr(probe) as usize, 0, 0, 0], count_wake)
}

fn reentrant_wake(words: [usize; 4]) {
    // Taking the stream lock here proves dispatch happened after the producer
    // released it. An in-lock callback would deadlock this acceptance test.
    let probe = unsafe { &*(words[0] as *const ReentrantWakeProbe) };
    assert!(probe.stream.depth() <= STREAM_BUFFER_CHUNKS);
    probe.count.fetch_add(1, Ordering::SeqCst);
}

fn reentrant_wake_token(probe: &Arc<ReentrantWakeProbe>) -> HostWakeToken {
    HostWakeToken::new([Arc::as_ptr(probe) as usize, 0, 0, 0], reentrant_wake)
}

fn delayed_wake(words: [usize; 4]) {
    // The producer has already released the stream lock and detached this
    // callback from the old operation slot. Hold it outside the lock so the
    // test can cancel that slot and publish a replacement before this late
    // wake returns.
    let probe = unsafe { &*(words[0] as *const DelayedWakeProbe) };
    probe.count.fetch_add(1, Ordering::SeqCst);
    probe.entered.wait();
    probe.release.wait();
}

fn delayed_wake_token(probe: &Arc<DelayedWakeProbe>) -> HostWakeToken {
    HostWakeToken::new([Arc::as_ptr(probe) as usize, 0, 0, 0], delayed_wake)
}

fn delayed_sealed_wake(words: [usize; 4], signal: StreamWakeSignal) {
    let probe = unsafe { &*(words[0] as *const DelayedSealedWakeProbe) };
    // The callback owns the only readiness proof while it is held here. A
    // task which retained only registration metadata has no value accepted by
    // resume_after_wake and therefore cannot poll across this gap.
    probe.entered.wait();
    probe.release.wait();
    let mut stored = probe.signal.lock().unwrap();
    assert!(stored.is_none());
    *stored = Some(signal);
    probe.count.fetch_add(1, Ordering::SeqCst);
}

fn delayed_sealed_wake_token(probe: &Arc<DelayedSealedWakeProbe>) -> StreamSealedWakeToken {
    StreamSealedWakeToken::new([Arc::as_ptr(probe) as usize, 0, 0, 0], delayed_sealed_wake)
}

fn receive_one(reader: &vibeos_component_host::ByteStreamReader) -> Vec<u8> {
    let prepared = match reader.start().unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("expected prepared receive, got {other:?}"),
    };
    let mut bytes = vec![0; prepared.length()];
    assert_eq!(
        reader.commit(prepared.operation(), &mut bytes),
        Ok(StreamReceiveCommit::Received(bytes.len()))
    );
    bytes
}

#[test]
fn full_ring_applies_backpressure_and_prepared_cancel_preserves_fifo() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let probe = Arc::new(WakeProbe {
        count: AtomicUsize::new(0),
    });

    for byte in 0..STREAM_BUFFER_CHUNKS as u8 {
        assert_eq!(writer.start(&[byte]), Ok(StreamSendDispatch::Sent));
    }
    assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS);
    assert_eq!(stream.peak_depth(), STREAM_BUFFER_CHUNKS);

    let blocked = match writer.start(&[99]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected writer backpressure, got {other:?}"),
    };
    writer.register_wake(blocked, wake_token(&probe)).unwrap();

    let first = match reader.start().unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("expected prepared front, got {other:?}"),
    };
    assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS);
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);
    reader.cancel(first.operation()).unwrap();
    assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS);
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);

    let replacement = match reader.start().unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("expected replacement reservation, got {other:?}"),
    };
    assert_ne!(first.operation(), replacement.operation());
    let mut first_byte = [0];
    assert_eq!(
        reader.commit(replacement.operation(), &mut first_byte),
        Ok(StreamReceiveCommit::Received(1))
    );
    assert_eq!(first_byte, [0]);
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert_eq!(writer.resume(blocked, &[99]), Ok(StreamSendDispatch::Sent));
    assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS);

    for expected in 1..STREAM_BUFFER_CHUNKS as u8 {
        assert_eq!(receive_one(&reader), [expected]);
    }
    assert_eq!(receive_one(&reader), [99]);
    assert_eq!(stream.depth(), 0);
}

#[test]
fn prefix_commit_preserves_remainder_and_releases_backpressure_only_at_chunk_end() {
    for prefix_limit in [1_usize, 257] {
        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let probe = Arc::new(WakeProbe {
            count: AtomicUsize::new(0),
        });
        let first = (0..MAX_STREAM_CHUNK_BYTES)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        assert_eq!(writer.start(&first), Ok(StreamSendDispatch::Sent));
        for value in 1..STREAM_BUFFER_CHUNKS {
            assert_eq!(writer.start(&[value as u8]), Ok(StreamSendDispatch::Sent));
        }
        let blocked = match writer.start(&[0xee]).unwrap() {
            StreamSendDispatch::Waiting(operation) => operation,
            other => panic!("full stream must backpressure its writer: {other:?}"),
        };
        writer.register_wake(blocked, wake_token(&probe)).unwrap();

        let mut received = Vec::new();
        while received.len() < first.len() {
            let prepared = match reader.start().unwrap() {
                StreamReceiveDispatch::Prepared(prepared) => prepared,
                other => panic!("front remainder must prepare: {other:?}"),
            };
            assert_eq!(prepared.length(), first.len() - received.len());

            if received.is_empty() {
                assert_eq!(
                    reader.commit_prefix(prepared.operation(), &mut []),
                    Err(StreamError::InvalidCommitLength)
                );
                let mut oversized = vec![0xcc; prepared.length() + 1];
                assert_eq!(
                    reader.commit_prefix(prepared.operation(), &mut oversized),
                    Err(StreamError::InvalidCommitLength)
                );
                assert!(oversized.iter().all(|byte| *byte == 0xcc));
            }

            let count = prefix_limit.min(prepared.length());
            let offset = received.len();
            received.resize(offset + count, 0);
            assert_eq!(
                reader.commit_prefix(prepared.operation(), &mut received[offset..]),
                Ok(StreamReceiveCommit::Received(count))
            );
            let mut stale_output = [0xa5];
            assert_eq!(
                reader.commit_prefix(prepared.operation(), &mut stale_output),
                Err(StreamError::TokenMismatch)
            );
            assert_eq!(stale_output, [0xa5]);

            if received.len() < first.len() {
                assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS);
                assert_eq!(probe.count.load(Ordering::SeqCst), 0);
            }
        }

        assert_eq!(received, first);
        assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS - 1);
        assert_eq!(probe.count.load(Ordering::SeqCst), 1);
        assert_eq!(
            writer.resume(blocked, &[0xee]),
            Ok(StreamSendDispatch::Sent)
        );
        assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS);
        for expected in 1..STREAM_BUFFER_CHUNKS as u8 {
            assert_eq!(receive_one(&reader), [expected]);
        }
        assert_eq!(receive_one(&reader), [0xee]);
        assert_eq!(stream.depth(), 0);
        assert!(!stream.is_fail_stopped());
    }
}

#[test]
fn waiting_to_prepared_uses_fresh_token_and_stale_or_cross_tokens_are_inert() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let other = ByteStream::new();
    let other_reader = other.reader();
    let other_writer = other.writer();
    let probe = Arc::new(WakeProbe {
        count: AtomicUsize::new(0),
    });

    let waiting = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected empty wait, got {other:?}"),
    };
    reader.register_wake(waiting, wake_token(&probe)).unwrap();
    assert_eq!(writer.start(&[7, 8, 9]), Ok(StreamSendDispatch::Sent));
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);

    let prepared = match reader.resume(waiting).unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("expected fresh reservation, got {other:?}"),
    };
    assert_ne!(waiting, prepared.operation());
    assert_eq!(stream.depth(), 1);
    assert_eq!(reader.resume(waiting), Err(StreamError::TokenMismatch));
    assert_eq!(reader.cancel(waiting), Err(StreamError::TokenMismatch));
    assert_eq!(
        writer.cancel(prepared.operation()),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(
        other_reader.cancel(prepared.operation()),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(stream.depth(), 1);

    let mut wrong_length = [0_u8; 2];
    assert_eq!(
        reader.commit(prepared.operation(), &mut wrong_length),
        Err(StreamError::InvalidCommitLength)
    );
    assert_eq!(stream.depth(), 1);
    let mut bytes = [0_u8; 3];
    assert_eq!(
        reader.commit(prepared.operation(), &mut bytes),
        Ok(StreamReceiveCommit::Received(3))
    );
    assert_eq!(bytes, [7, 8, 9]);
    assert_eq!(
        reader.commit(prepared.operation(), &mut bytes),
        Err(StreamError::TokenMismatch)
    );

    // A cross-stream send token is equally inert on both consumer slots.
    for value in 0..STREAM_BUFFER_CHUNKS {
        assert_eq!(
            other_writer.start(&[value as u8]),
            Ok(StreamSendDispatch::Sent)
        );
    }
    let other_send = match other_writer.start(&[42]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected full other stream, got {other:?}"),
    };
    assert_eq!(reader.cancel(other_send), Err(StreamError::TokenMismatch));
    assert_eq!(other.depth(), STREAM_BUFFER_CHUNKS);
    other_writer.cancel(other_send).unwrap();
}

#[test]
fn supervisor_reader_cancel_is_exact_across_incarnation_token_and_restart() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();
    let foreign_stream = ByteStream::new();
    let foreign_reader = foreign_stream.reader();
    let foreign_supervisor = foreign_stream.supervisor();
    let probe = Arc::new(WakeProbe {
        count: AtomicUsize::new(0),
    });

    let first = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected reader wait, got {other:?}"),
    };
    let foreign = match foreign_reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected foreign reader wait, got {other:?}"),
    };
    reader.register_wake(first, wake_token(&probe)).unwrap();

    // The operation token alone is not authority: the wrong supervisor names
    // a different stream incarnation and cannot revoke this slot.
    assert_eq!(
        foreign_supervisor.cancel_reader_operation_exact(first),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(reader.start(), Err(StreamError::Busy));
    assert_eq!(foreign_reader.start(), Err(StreamError::Busy));
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);

    supervisor.cancel_reader_operation_exact(first).unwrap();
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);
    assert_eq!(reader.resume(first), Err(StreamError::TokenMismatch));

    let restarted = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected restarted reader wait, got {other:?}"),
    };
    assert_ne!(first, restarted);
    reader.register_wake(restarted, wake_token(&probe)).unwrap();
    assert_eq!(
        supervisor.cancel_reader_operation_exact(first),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(writer.start(&[7, 8, 9]), Ok(StreamSendDispatch::Sent));
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);

    let prepared = match reader.resume(restarted).unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("expected prepared restart, got {other:?}"),
    };
    assert_ne!(restarted, prepared.operation());
    supervisor
        .cancel_reader_operation_exact(prepared.operation())
        .unwrap();
    assert_eq!(stream.depth(), 1);

    let replacement = match reader.start().unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("cancelled preparation must restart, got {other:?}"),
    };
    let mut bytes = [0_u8; 3];
    assert_eq!(
        reader.commit(replacement.operation(), &mut bytes),
        Ok(StreamReceiveCommit::Received(3))
    );
    assert_eq!(bytes, [7, 8, 9]);
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    foreign_supervisor
        .cancel_reader_operation_exact(foreign)
        .unwrap();
}

#[test]
fn supervisor_writer_cancel_is_exact_and_never_wakes_the_revoked_slot() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();
    let foreign_stream = ByteStream::new();
    let foreign_writer = foreign_stream.writer();
    let foreign_supervisor = foreign_stream.supervisor();
    let probe = Arc::new(WakeProbe {
        count: AtomicUsize::new(0),
    });

    for value in 0..STREAM_BUFFER_CHUNKS {
        assert_eq!(writer.start(&[value as u8]), Ok(StreamSendDispatch::Sent));
    }
    let first = match writer.start(&[99]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected writer backpressure, got {other:?}"),
    };
    for value in 0..STREAM_BUFFER_CHUNKS {
        assert_eq!(
            foreign_writer.start(&[value as u8]),
            Ok(StreamSendDispatch::Sent)
        );
    }
    let foreign = match foreign_writer.start(&[101]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected foreign writer wait, got {other:?}"),
    };
    writer.register_wake(first, wake_token(&probe)).unwrap();
    assert_eq!(
        foreign_supervisor.cancel_writer_operation_exact(first),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(
        supervisor.cancel_reader_operation_exact(first),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(writer.start(&[100]), Err(StreamError::Busy));
    assert_eq!(foreign_writer.start(&[102]), Err(StreamError::Busy));

    supervisor.cancel_writer_operation_exact(first).unwrap();
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);
    assert_eq!(writer.resume(first, &[99]), Err(StreamError::TokenMismatch));

    let restarted = match writer.start(&[100]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected restarted writer wait, got {other:?}"),
    };
    assert_ne!(first, restarted);
    writer.register_wake(restarted, wake_token(&probe)).unwrap();
    assert_eq!(
        supervisor.cancel_writer_operation_exact(first),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(receive_one(&reader), [0]);
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        writer.resume(restarted, &[100]),
        Ok(StreamSendDispatch::Sent)
    );
    assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS);
    foreign_supervisor
        .cancel_writer_operation_exact(foreign)
        .unwrap();
}

#[test]
fn late_listener_recheck_never_loses_readable_or_writable_wake() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let probe = Arc::new(ReentrantWakeProbe {
        stream: stream.clone(),
        count: AtomicUsize::new(0),
    });

    let read_wait = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected wait, got {other:?}"),
    };
    // Readiness wins before listener installation. register_wake must install
    // then recheck under the lock and invoke the callback only after unlock.
    assert_eq!(writer.start(&[11]), Ok(StreamSendDispatch::Sent));
    reader
        .register_wake(read_wait, reentrant_wake_token(&probe))
        .unwrap();
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    let prepared = match reader.resume(read_wait).unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("expected prepared, got {other:?}"),
    };
    let mut byte = [0_u8];
    reader.commit(prepared.operation(), &mut byte).unwrap();

    for value in 0..STREAM_BUFFER_CHUNKS {
        writer.start(&[value as u8]).unwrap();
    }
    let send_wait = match writer.start(&[77]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected writer wait, got {other:?}"),
    };
    // Space wins before listener installation on the reverse edge.
    assert_eq!(receive_one(&reader), [0]);
    writer
        .register_wake(send_wait, reentrant_wake_token(&probe))
        .unwrap();
    assert_eq!(probe.count.load(Ordering::SeqCst), 2);
    writer.cancel(send_wait).unwrap();
}

#[test]
fn sealed_readiness_is_owned_by_callback_across_the_dispatch_gap() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let probe = Arc::new(DelayedSealedWakeProbe {
        entered: Barrier::new(2),
        release: Barrier::new(2),
        count: AtomicUsize::new(0),
        signal: Mutex::new(None),
    });

    let waiting = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected reader wait, got {other:?}"),
    };
    let registration = reader
        .register_wake_sealed(waiting, delayed_sealed_wake_token(&probe))
        .unwrap();
    let producer = thread::spawn(move || writer.start(&[0x5a]));

    probe.entered.wait();
    // Readiness detached the callback, but the callback deliberately has not
    // published its move-only signal. Registration exposes cancellation only.
    assert!(probe.signal.lock().unwrap().is_none());
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);
    assert_eq!(stream.depth(), 1);
    assert_eq!(registration.operation(), waiting);
    assert_eq!(reader.resume(waiting), Err(StreamError::SealedWakeRequired));
    assert_eq!(reader.start(), Err(StreamError::Busy));
    assert_eq!(stream.depth(), 1);

    probe.release.wait();
    assert_eq!(producer.join().unwrap(), Ok(StreamSendDispatch::Sent));
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    let signal = probe
        .signal
        .lock()
        .unwrap()
        .take()
        .expect("callback must publish exact readiness");
    let prepared = match reader.resume_after_wake(signal).unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("callback-issued signal must prepare, got {other:?}"),
    };
    drop(registration);
    let mut byte = [0_u8];
    assert_eq!(
        reader.commit(prepared.operation(), &mut byte),
        Ok(StreamReceiveCommit::Received(1))
    );
    assert_eq!(byte, [0x5a]);
}

#[test]
fn sealed_writer_cannot_resume_across_the_callback_dispatch_gap() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let probe = Arc::new(DelayedSealedWakeProbe {
        entered: Barrier::new(2),
        release: Barrier::new(2),
        count: AtomicUsize::new(0),
        signal: Mutex::new(None),
    });

    for byte in 0..STREAM_BUFFER_CHUNKS {
        assert_eq!(writer.start(&[byte as u8]), Ok(StreamSendDispatch::Sent));
    }
    let waiting = match writer.start(&[0xd1]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected writer backpressure, got {other:?}"),
    };
    let registration = writer
        .register_wake_sealed(waiting, delayed_sealed_wake_token(&probe))
        .unwrap();
    let consumer = thread::spawn(move || receive_one(&reader));

    probe.entered.wait();
    assert!(probe.signal.lock().unwrap().is_none());
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);
    assert_eq!(registration.operation(), waiting);
    assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS - 1);
    assert_eq!(
        writer.resume(waiting, &[0xd1]),
        Err(StreamError::SealedWakeRequired)
    );
    assert_eq!(writer.start(&[0xd2]), Err(StreamError::Busy));
    assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS - 1);

    probe.release.wait();
    assert_eq!(consumer.join().unwrap(), [0]);
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    let signal = probe
        .signal
        .lock()
        .unwrap()
        .take()
        .expect("writer callback must publish exact readiness");
    assert_eq!(
        writer.resume_after_wake(signal, &[0xd1]).unwrap(),
        StreamSendDispatch::Sent
    );
    drop(registration);
    assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS);
    assert_eq!(
        writer.resume(waiting, &[0xd1]),
        Err(StreamError::TokenMismatch)
    );
    assert!(probe.signal.lock().unwrap().is_none());
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
}

#[test]
fn sealed_terminal_cannot_resume_across_the_callback_dispatch_gap() {
    let stream = ByteStream::new();
    let supervisor = stream.supervisor();
    let probe = Arc::new(DelayedSealedWakeProbe {
        entered: Barrier::new(2),
        release: Barrier::new(2),
        count: AtomicUsize::new(0),
        signal: Mutex::new(None),
    });

    let waiting = match supervisor.start_terminal().unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("expected terminal wait, got {other:?}"),
    };
    let registration = supervisor
        .register_terminal_wake_sealed(waiting, delayed_sealed_wake_token(&probe))
        .unwrap();
    let finalizer = {
        let supervisor = supervisor.clone();
        thread::spawn(move || supervisor.finalize(StreamCloseReason::BackendFault))
    };

    probe.entered.wait();
    assert!(probe.signal.lock().unwrap().is_none());
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);
    assert_eq!(registration.operation(), waiting);
    assert_eq!(
        supervisor.resume_terminal(waiting),
        Err(StreamError::SealedWakeRequired)
    );
    assert_eq!(supervisor.start_terminal(), Err(StreamError::Busy));
    assert_eq!(stream.final_reason(), Some(StreamCloseReason::BackendFault));

    probe.release.wait();
    assert_eq!(finalizer.join().unwrap(), StreamCloseOutcome::Published);
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    let signal = probe
        .signal
        .lock()
        .unwrap()
        .take()
        .expect("terminal callback must publish exact readiness");
    assert_eq!(
        supervisor.resume_terminal_after_wake(signal).unwrap(),
        StreamTerminalDispatch::Ready(StreamCloseReason::BackendFault)
    );
    drop(registration);
    assert_eq!(
        supervisor.resume_terminal(waiting),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(
        supervisor.start_terminal(),
        Ok(StreamTerminalDispatch::Ready(
            StreamCloseReason::BackendFault
        ))
    );
    assert!(probe.signal.lock().unwrap().is_none());
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
}

#[test]
fn detached_late_reader_wake_cannot_touch_the_restarted_operation() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();
    let probe = Arc::new(DelayedWakeProbe {
        entered: Barrier::new(2),
        release: Barrier::new(2),
        count: AtomicUsize::new(0),
    });

    let stale = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected reader wait, got {other:?}"),
    };
    reader
        .register_wake(stale, delayed_wake_token(&probe))
        .unwrap();

    let producer = thread::spawn(move || writer.start(&[0xa5]));
    probe.entered.wait();
    // Readiness has detached the old callback and released the lock, but the
    // old operation remains current until this exact supervisor revokes it.
    supervisor.cancel_reader_operation_exact(stale).unwrap();
    let restarted = match reader.start().unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("queued byte must prepare after restart, got {other:?}"),
    };
    assert_ne!(stale, restarted.operation());
    assert_eq!(
        supervisor.cancel_reader_operation_exact(stale),
        Err(StreamError::TokenMismatch)
    );

    probe.release.wait();
    assert_eq!(producer.join().unwrap(), Ok(StreamSendDispatch::Sent));
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert_eq!(reader.resume(stale), Err(StreamError::TokenMismatch));

    let mut byte = [0_u8];
    assert_eq!(
        reader.commit(restarted.operation(), &mut byte),
        Ok(StreamReceiveCommit::Received(1))
    );
    assert_eq!(byte, [0xa5]);
}

#[test]
fn detached_late_writer_wake_cannot_touch_the_restarted_operation() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();
    let probe = Arc::new(DelayedWakeProbe {
        entered: Barrier::new(2),
        release: Barrier::new(2),
        count: AtomicUsize::new(0),
    });

    for value in 0..STREAM_BUFFER_CHUNKS {
        assert_eq!(writer.start(&[value as u8]), Ok(StreamSendDispatch::Sent));
    }
    let stale = match writer.start(&[0xb4]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected writer wait, got {other:?}"),
    };
    writer
        .register_wake(stale, delayed_wake_token(&probe))
        .unwrap();

    let consumer = thread::spawn(move || receive_one(&reader));
    probe.entered.wait();
    supervisor.cancel_writer_operation_exact(stale).unwrap();
    assert_eq!(writer.start(&[0xb5]), Ok(StreamSendDispatch::Sent));
    let restarted = match writer.start(&[0xb6]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("refilled ring must restart writer wait, got {other:?}"),
    };
    assert_ne!(stale, restarted);
    assert_eq!(
        supervisor.cancel_writer_operation_exact(stale),
        Err(StreamError::TokenMismatch)
    );

    probe.release.wait();
    assert_eq!(consumer.join().unwrap(), [0]);
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        writer.resume(stale, &[0xb4]),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(writer.start(&[0xb7]), Err(StreamError::Busy));
    supervisor.cancel_writer_operation_exact(restarted).unwrap();
}

#[test]
fn endpoint_identity_check_is_redacted_and_exact() {
    let first = ByteStream::new();
    let first_reader = first.reader();
    let first_writer = first.writer();
    let second = ByteStream::new();
    let second_reader = second.reader();
    let second_writer = second.writer();

    assert!(first_reader.same_stream_as(&first_writer));
    assert!(first_writer.same_stream_as(&first_reader));
    assert!(!first_reader.same_stream_as(&second_writer));
    assert!(!second_reader.same_stream_as(&first_writer));
}

#[test]
fn supervisor_is_a_distinct_invoke_only_cspace_resource() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();
    let other = ByteStream::new();
    assert_eq!(supervisor.kind(), "component-byte-stream-supervisor");
    assert!(supervisor.same_stream_as_reader(&reader));
    assert!(supervisor.same_stream_as_writer(&writer));
    assert!(!supervisor.same_stream_as_reader(&other.reader()));
    assert!(!supervisor.same_stream_as_writer(&other.writer()));

    let mut space = CSpace::new("stream-supervisor");
    let cap = space.mint(supervisor, Rights::INVOKE);
    assert!(space
        .lookup_as::<vibeos_component_host::ByteStreamSupervisor>(cap, Rights::INVOKE)
        .is_ok());
    assert!(space
        .lookup_as::<vibeos_component_host::ByteStreamSupervisor>(cap, Rights::RECV)
        .is_err());
}

#[test]
fn supervisor_exact_cancel_survives_endpoint_cap_revocation() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let supervisor = stream.supervisor();
    let waiting = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected reader wait, got {other:?}"),
    };
    let mut space = CSpace::new("reader-revoke-before-cancel");
    let endpoint_cap = space.mint(reader.clone(), Rights::RECV.union(Rights::REVOKE));
    let supervisor_cap = space.mint(supervisor, Rights::INVOKE);
    let supervisor = space
        .lookup_as::<vibeos_component_host::ByteStreamSupervisor>(supervisor_cap, Rights::INVOKE)
        .unwrap();
    assert_eq!(space.revoke(endpoint_cap), Ok(1));
    drop(reader);
    assert_eq!(supervisor.cancel_reader_operation_exact(waiting), Ok(()));
    assert!(matches!(
        stream.reader().start(),
        Ok(StreamReceiveDispatch::Waiting(operation)) if operation != waiting
    ));

    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();
    for value in 0..STREAM_BUFFER_CHUNKS {
        assert_eq!(writer.start(&[value as u8]), Ok(StreamSendDispatch::Sent));
    }
    let blocked = match writer.start(&[0xc1]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected writer wait, got {other:?}"),
    };
    let mut space = CSpace::new("writer-revoke-before-cancel");
    let endpoint_cap = space.mint(writer.clone(), Rights::SEND.union(Rights::REVOKE));
    let supervisor_cap = space.mint(supervisor, Rights::INVOKE);
    let supervisor = space
        .lookup_as::<vibeos_component_host::ByteStreamSupervisor>(supervisor_cap, Rights::INVOKE)
        .unwrap();
    assert_eq!(space.revoke(endpoint_cap), Ok(1));
    drop(writer);
    assert_eq!(supervisor.cancel_writer_operation_exact(blocked), Ok(()));
    assert_eq!(receive_one(&reader), [0]);
    assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS - 1);
}

#[test]
fn every_spurious_resume_replaces_the_consumed_wait_generation() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();

    let first = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected wait, got {other:?}"),
    };
    let second = match reader.resume(first).unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected replacement wait, got {other:?}"),
    };
    assert_ne!(first, second);
    assert_eq!(reader.resume(first), Err(StreamError::TokenMismatch));

    for byte in 0..STREAM_BUFFER_CHUNKS as u8 {
        assert_eq!(writer.start(&[byte]), Ok(StreamSendDispatch::Sent));
    }
    let first_send = match writer.start(&[88]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected wait, got {other:?}"),
    };
    let second_send = match writer.resume(first_send, &[88]).unwrap() {
        StreamSendDispatch::Waiting(operation) => operation,
        other => panic!("expected replacement send wait, got {other:?}"),
    };
    assert_ne!(first_send, second_send);
    assert_eq!(writer.cancel(first_send), Err(StreamError::TokenMismatch));
    writer.cancel(second_send).unwrap();
    reader.cancel(second).unwrap();
}

#[test]
fn terminal_wait_rotates_tokens_and_normal_is_not_ready_until_finalized() {
    let stream = ByteStream::new();
    let writer = stream.writer();
    let supervisor = stream.supervisor();
    let probe = Arc::new(WakeProbe {
        count: AtomicUsize::new(0),
    });

    let first = match supervisor.start_terminal().unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("expected terminal wait, got {other:?}"),
    };
    assert_eq!(supervisor.start_terminal(), Err(StreamError::Busy));
    supervisor
        .register_terminal_wake(first, wake_token(&probe))
        .unwrap();
    assert_eq!(
        writer.close(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert!(supervisor.is_normal_provisional());
    assert_eq!(supervisor.final_reason(), None);
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);

    let second = match supervisor.resume_terminal(first).unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("provisional close must remain pending, got {other:?}"),
    };
    assert_ne!(first, second);
    assert_eq!(
        supervisor.resume_terminal(first),
        Err(StreamError::TokenMismatch)
    );
    supervisor
        .register_terminal_wake(second, wake_token(&probe))
        .unwrap();
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        supervisor.resume_terminal(second),
        Ok(StreamTerminalDispatch::Ready(StreamCloseReason::Normal))
    );
    assert_eq!(
        supervisor.resume_terminal(second),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(
        supervisor.start_terminal(),
        Ok(StreamTerminalDispatch::Ready(StreamCloseReason::Normal))
    );
}

#[test]
fn terminal_wrong_stale_and_cancelled_tokens_are_inert() {
    let stream = ByteStream::new();
    let supervisor = stream.supervisor();
    let other = ByteStream::new();
    let other_supervisor = other.supervisor();
    let probe = Arc::new(WakeProbe {
        count: AtomicUsize::new(0),
    });

    let first = match supervisor.start_terminal().unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("expected terminal wait, got {other:?}"),
    };
    let foreign = match other_supervisor.start_terminal().unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("expected foreign terminal wait, got {other:?}"),
    };
    assert_eq!(
        supervisor.resume_terminal(foreign),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(
        supervisor.register_terminal_wake(foreign, wake_token(&probe)),
        Err(StreamError::TokenMismatch)
    );
    assert_eq!(
        supervisor.cancel_terminal(foreign),
        Err(StreamError::TokenMismatch)
    );

    let second = match supervisor.resume_terminal(first).unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("expected replacement terminal wait, got {other:?}"),
    };
    assert_ne!(first, second);
    assert_eq!(
        supervisor.cancel_terminal(first),
        Err(StreamError::TokenMismatch)
    );
    supervisor
        .register_terminal_wake(second, wake_token(&probe))
        .unwrap();
    assert_eq!(
        supervisor.register_terminal_wake(second, wake_token(&probe)),
        Err(StreamError::WakeAlreadyRegistered)
    );
    supervisor.cancel_terminal(second).unwrap();
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);
    assert_eq!(
        supervisor.cancel_terminal(second),
        Err(StreamError::TokenMismatch)
    );

    let replacement = match supervisor.start_terminal().unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("expected replacement after cancel, got {other:?}"),
    };
    assert_ne!(second, replacement);
    supervisor.cancel_terminal(replacement).unwrap();
    other_supervisor.cancel_terminal(foreign).unwrap();
}

#[test]
fn terminal_wait_is_independent_from_a_prepared_reader() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();
    let probe = Arc::new(WakeProbe {
        count: AtomicUsize::new(0),
    });

    assert_eq!(writer.start(&[1, 2, 3]), Ok(StreamSendDispatch::Sent));
    let prepared = match reader.start().unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("expected prepared receive, got {other:?}"),
    };
    let terminal = match supervisor.start_terminal().unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("prepared receive must not occupy terminal slot: {other:?}"),
    };
    supervisor
        .register_terminal_wake(terminal, wake_token(&probe))
        .unwrap();
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        supervisor.resume_terminal(terminal),
        Ok(StreamTerminalDispatch::Ready(StreamCloseReason::Normal))
    );

    let mut bytes = [0_u8; 3];
    assert_eq!(
        reader.commit(prepared.operation(), &mut bytes),
        Ok(StreamReceiveCommit::Received(3))
    );
    assert_eq!(bytes, [1, 2, 3]);
}

#[test]
fn every_non_normal_close_reason_completes_the_exact_terminal_wait() {
    for reason in [
        StreamCloseReason::Failure,
        StreamCloseReason::Cancelled,
        StreamCloseReason::Denied,
        StreamCloseReason::Unavailable,
        StreamCloseReason::Exhausted,
        StreamCloseReason::Invalid,
        StreamCloseReason::BackendFault,
    ] {
        let stream = ByteStream::new();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        let probe = Arc::new(WakeProbe {
            count: AtomicUsize::new(0),
        });
        let terminal = match supervisor.start_terminal().unwrap() {
            StreamTerminalDispatch::Waiting(operation) => operation,
            other => panic!("expected terminal wait, got {other:?}"),
        };
        supervisor
            .register_terminal_wake(terminal, wake_token(&probe))
            .unwrap();

        assert_eq!(writer.close(reason), StreamCloseOutcome::Published);
        assert_eq!(probe.count.load(Ordering::SeqCst), 1);
        assert_eq!(
            supervisor.resume_terminal(terminal),
            Ok(StreamTerminalDispatch::Ready(reason))
        );
        assert_eq!(supervisor.final_reason(), Some(reason));
    }
}

#[test]
fn late_terminal_listener_is_woken_once_and_may_reenter_stream_state() {
    let stream = ByteStream::new();
    let supervisor = stream.supervisor();
    let probe = Arc::new(ReentrantWakeProbe {
        stream: stream.clone(),
        count: AtomicUsize::new(0),
    });
    let terminal = match supervisor.start_terminal().unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("expected terminal wait, got {other:?}"),
    };

    assert_eq!(
        supervisor.finalize(StreamCloseReason::BackendFault),
        StreamCloseOutcome::Published
    );
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);
    supervisor
        .register_terminal_wake(terminal, reentrant_wake_token(&probe))
        .unwrap();
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        supervisor.resume_terminal(terminal),
        Ok(StreamTerminalDispatch::Ready(
            StreamCloseReason::BackendFault
        ))
    );
}

#[test]
fn terminal_wait_is_woken_once_and_cleaned_by_conflict_fail_stop() {
    let stream = ByteStream::new();
    let supervisor = stream.supervisor();
    let probe = Arc::new(WakeProbe {
        count: AtomicUsize::new(0),
    });
    let terminal = match supervisor.start_terminal().unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("expected terminal wait, got {other:?}"),
    };
    supervisor
        .register_terminal_wake(terminal, wake_token(&probe))
        .unwrap();

    assert_eq!(
        supervisor.finalize(StreamCloseReason::Failure),
        StreamCloseOutcome::Published
    );
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Cancelled),
        StreamCloseOutcome::Conflict
    );
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert!(supervisor.is_fail_stopped());
    assert_eq!(supervisor.final_reason(), Some(StreamCloseReason::Failure));
    assert_eq!(
        supervisor.resume_terminal(terminal),
        Err(StreamError::FailStopped)
    );
    assert_eq!(
        supervisor.cancel_terminal(terminal),
        Err(StreamError::FailStopped)
    );
    assert_eq!(supervisor.start_terminal(), Err(StreamError::FailStopped));
}

#[test]
fn normal_is_provisional_until_supervisor_finalization_and_drains_before_eof() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();
    let probe = Arc::new(WakeProbe {
        count: AtomicUsize::new(0),
    });

    let wait = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected wait, got {other:?}"),
    };
    reader.register_wake(wait, wake_token(&probe)).unwrap();
    assert_eq!(
        writer.close(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert!(stream.is_normal_provisional());
    assert!(supervisor.is_normal_provisional());
    assert_eq!(stream.final_reason(), None);
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    let replacement = match reader.resume(wait).unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected provisional wait replacement, got {other:?}"),
    };
    assert_ne!(wait, replacement);
    reader
        .register_wake(replacement, wake_token(&probe))
        .unwrap();
    assert_eq!(probe.count.load(Ordering::SeqCst), 2);
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert_eq!(probe.count.load(Ordering::SeqCst), 2);
    assert_eq!(
        reader.resume(replacement),
        Ok(StreamReceiveDispatch::Closed(StreamCloseReason::Normal))
    );
}

#[test]
fn finalized_normal_drains_all_chunks_then_exposes_one_stable_eof() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();

    assert_eq!(writer.start(&[1, 2]), Ok(StreamSendDispatch::Sent));
    assert_eq!(writer.start(&[3]), Ok(StreamSendDispatch::Sent));
    assert_eq!(
        writer.close(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert_eq!(receive_one(&reader), [1, 2]);
    assert_eq!(receive_one(&reader), [3]);
    assert_eq!(
        reader.start(),
        Ok(StreamReceiveDispatch::Closed(StreamCloseReason::Normal))
    );
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Normal),
        StreamCloseOutcome::AlreadyPublished
    );
}

#[test]
fn non_normal_finalize_preserves_exact_prepared_receive_until_cancel() {
    for reason in [
        StreamCloseReason::Failure,
        StreamCloseReason::Cancelled,
        StreamCloseReason::Invalid,
    ] {
        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        let other = ByteStream::new();
        let other_reader = other.reader();
        let other_writer = other.writer();

        writer.start(&[5, 6, 7]).unwrap();
        let prepared = match reader.start().unwrap() {
            StreamReceiveDispatch::Prepared(prepared) => prepared,
            other => panic!("expected prepared, got {other:?}"),
        };
        other_writer.start(&[8, 9, 10]).unwrap();
        let cross_stream = match other_reader.start().unwrap() {
            StreamReceiveDispatch::Prepared(prepared) => prepared,
            other => panic!("expected cross-stream prepared, got {other:?}"),
        };
        assert_eq!(stream.depth(), 1);
        assert_eq!(supervisor.finalize(reason), StreamCloseOutcome::Published);
        assert_eq!(stream.depth(), 0);

        let mut output = [0_u8; 3];
        assert_eq!(
            reader.commit(prepared.operation(), &mut output),
            Ok(StreamReceiveCommit::Closed(reason))
        );
        // A terminal result did not publish the prepared receive. Repeating
        // the exact observation and probing with foreign tokens are inert;
        // only exact cancellation consumes the reservation.
        assert_eq!(
            reader.commit(prepared.operation(), &mut output),
            Ok(StreamReceiveCommit::Closed(reason))
        );
        assert_eq!(
            reader.commit(cross_stream.operation(), &mut output),
            Err(StreamError::TokenMismatch)
        );
        assert_eq!(
            reader.cancel(cross_stream.operation()),
            Err(StreamError::TokenMismatch)
        );
        assert_eq!(
            other_reader.cancel(prepared.operation()),
            Err(StreamError::TokenMismatch)
        );
        assert_eq!(output, [0, 0, 0]);
        assert!(!stream.is_fail_stopped());
        assert!(!other.is_fail_stopped());

        assert_eq!(reader.cancel(prepared.operation()), Ok(()));
        assert_eq!(
            reader.cancel(prepared.operation()),
            Err(StreamError::TokenMismatch)
        );
        assert_eq!(
            reader.commit(prepared.operation(), &mut output),
            Err(StreamError::TokenMismatch)
        );
        assert!(!stream.is_fail_stopped());
        other_reader.cancel(cross_stream.operation()).unwrap();
    }
}

#[test]
fn consumer_close_discards_fifo_stops_writer_and_waits_for_normal_final() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();

    writer.start(&[1, 2, 3]).unwrap();
    let prepared = match reader.start().unwrap() {
        StreamReceiveDispatch::Prepared(prepared) => prepared,
        other => panic!("expected prepared, got {other:?}"),
    };
    assert_eq!(
        reader.close(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert_eq!(stream.depth(), 0);
    assert_eq!(stream.final_reason(), None);
    assert_eq!(
        writer.start(&[4]),
        Ok(StreamSendDispatch::Closed(StreamCloseReason::Normal))
    );
    let mut output = [0_u8; 3];
    assert_eq!(
        reader.commit(prepared.operation(), &mut output),
        Err(StreamError::EndpointClosed)
    );
    assert_eq!(reader.cancel(prepared.operation()), Ok(()));
    assert_eq!(
        reader.cancel(prepared.operation()),
        Err(StreamError::TokenMismatch)
    );
    assert!(!stream.is_fail_stopped());
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert_eq!(stream.final_reason(), Some(StreamCloseReason::Normal));
    assert_eq!(
        reader.start(),
        Ok(StreamReceiveDispatch::Closed(StreamCloseReason::Normal))
    );
}

#[test]
fn first_final_is_immutable_and_conflict_fail_stops() {
    let stream = ByteStream::new();
    let writer = stream.writer();
    let supervisor = stream.supervisor();

    assert_eq!(
        writer.close(StreamCloseReason::Failure),
        StreamCloseOutcome::Published
    );
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Failure),
        StreamCloseOutcome::AlreadyPublished
    );
    assert_eq!(stream.final_reason(), Some(StreamCloseReason::Failure));
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Cancelled),
        StreamCloseOutcome::Conflict
    );
    assert_eq!(stream.final_reason(), Some(StreamCloseReason::Failure));
    assert!(stream.is_fail_stopped());
    assert_eq!(writer.start(&[1]), Err(StreamError::FailStopped));
}

#[test]
fn late_producer_done_preserves_an_existing_failure_terminal() {
    for reason in [
        StreamCloseReason::Failure,
        StreamCloseReason::Cancelled,
        StreamCloseReason::BackendFault,
    ] {
        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let supervisor = stream.supervisor();

        assert_eq!(supervisor.finalize(reason), StreamCloseOutcome::Published);
        assert_eq!(
            writer.close(StreamCloseReason::Normal),
            StreamCloseOutcome::AlreadyPublished
        );
        assert_eq!(
            reader.close(StreamCloseReason::Normal),
            StreamCloseOutcome::AlreadyPublished
        );
        assert_eq!(stream.final_reason(), Some(reason));
        assert!(!stream.is_fail_stopped());

        let stream = ByteStream::new();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        assert_eq!(
            writer.close(StreamCloseReason::Normal),
            StreamCloseOutcome::Published
        );
        assert_eq!(supervisor.finalize(reason), StreamCloseOutcome::Published);
        assert_eq!(stream.final_reason(), Some(reason));
        assert!(!stream.is_fail_stopped());
    }
}

#[test]
fn observed_close_reports_provisional_and_final_normal_in_the_publication_lock() {
    let stream = ByteStream::new();
    let writer = stream.writer();
    let supervisor = stream.supervisor();

    let provisional = writer.close_observed(StreamCloseReason::Normal);
    assert_eq!(provisional.outcome(), StreamCloseOutcome::Published);
    assert_eq!(
        provisional.effective_reason(),
        Some(StreamCloseReason::Normal)
    );
    assert!(supervisor.is_normal_provisional());
    assert_eq!(supervisor.final_reason(), None);

    let repeated = writer.close_observed(StreamCloseReason::Normal);
    assert_eq!(repeated.outcome(), StreamCloseOutcome::AlreadyPublished);
    assert_eq!(repeated.effective_reason(), Some(StreamCloseReason::Normal));

    let finalized = supervisor.finalize_observed(StreamCloseReason::Normal);
    assert_eq!(finalized.outcome(), StreamCloseOutcome::Published);
    assert_eq!(
        finalized.effective_reason(),
        Some(StreamCloseReason::Normal)
    );
    let same_final = supervisor.finalize_observed(StreamCloseReason::Normal);
    assert_eq!(same_final.outcome(), StreamCloseOutcome::AlreadyPublished);
    assert_eq!(
        same_final.effective_reason(),
        Some(StreamCloseReason::Normal)
    );
}

#[test]
fn observed_late_normal_exposes_the_failure_that_already_won() {
    let stream = ByteStream::new();
    let writer = stream.writer();
    let supervisor = stream.supervisor();

    let failure = supervisor.finalize_observed(StreamCloseReason::Failure);
    assert_eq!(failure.outcome(), StreamCloseOutcome::Published);
    assert_eq!(failure.effective_reason(), Some(StreamCloseReason::Failure));

    let requested = StreamCloseReason::Normal;
    let late = writer.close_observed(requested);
    assert_eq!(late.outcome(), StreamCloseOutcome::AlreadyPublished);
    assert_eq!(late.effective_reason(), Some(StreamCloseReason::Failure));
    assert_ne!(late.effective_reason(), Some(requested));
    assert!(!stream.is_fail_stopped());
}

#[test]
fn observed_conflict_preserves_the_established_reason_and_fail_stops() {
    let stream = ByteStream::new();
    let writer = stream.writer();
    let supervisor = stream.supervisor();

    assert_eq!(
        supervisor
            .finalize_observed(StreamCloseReason::Failure)
            .effective_reason(),
        Some(StreamCloseReason::Failure)
    );
    let conflict = supervisor.finalize_observed(StreamCloseReason::Cancelled);
    assert_eq!(conflict.outcome(), StreamCloseOutcome::Conflict);
    assert_eq!(
        conflict.effective_reason(),
        Some(StreamCloseReason::Failure)
    );
    assert!(stream.is_fail_stopped());

    let repeated = writer.close_observed(StreamCloseReason::Normal);
    assert_eq!(repeated.outcome(), StreamCloseOutcome::Conflict);
    assert_eq!(
        repeated.effective_reason(),
        Some(StreamCloseReason::Failure)
    );
}

#[test]
fn exact_cancel_preserves_fault_close_first_winner_and_restart_incarnation() {
    for reason in [
        StreamCloseReason::Failure,
        StreamCloseReason::Cancelled,
        StreamCloseReason::BackendFault,
    ] {
        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        let probe = Arc::new(WakeProbe {
            count: AtomicUsize::new(0),
        });
        let waiting = match reader.start().unwrap() {
            StreamReceiveDispatch::Waiting(operation) => operation,
            other => panic!("expected reader wait, got {other:?}"),
        };
        reader.register_wake(waiting, wake_token(&probe)).unwrap();
        let first = supervisor.finalize_preserving_first_observed(reason);
        assert_eq!(first.outcome(), StreamCloseOutcome::Published);
        assert_eq!(first.effective_reason(), Some(reason));
        assert_eq!(probe.count.load(Ordering::SeqCst), 1);

        // Finalization detaches the wake but deliberately leaves the endpoint
        // operation for exact lifecycle cleanup after its cap is revoked.
        supervisor.cancel_reader_operation_exact(waiting).unwrap();
        assert_eq!(probe.count.load(Ordering::SeqCst), 1);
        let late_normal = writer.close_observed(StreamCloseReason::Normal);
        assert_eq!(late_normal.outcome(), StreamCloseOutcome::AlreadyPublished);
        assert_eq!(late_normal.effective_reason(), Some(reason));
        assert_eq!(supervisor.final_reason(), Some(reason));
        assert!(!supervisor.is_fail_stopped());
        assert_eq!(reader.start(), Ok(StreamReceiveDispatch::Closed(reason)));

        // A restarted stream is a different supervisor-bound incarnation.
        // Neither side accepts the other's otherwise well-formed token.
        let restarted_stream = ByteStream::new();
        let restarted_reader = restarted_stream.reader();
        let restarted_supervisor = restarted_stream.supervisor();
        let restarted = match restarted_reader.start().unwrap() {
            StreamReceiveDispatch::Waiting(operation) => operation,
            other => panic!("expected restarted stream wait, got {other:?}"),
        };
        assert_eq!(
            supervisor.cancel_reader_operation_exact(restarted),
            Err(StreamError::TokenMismatch)
        );
        assert_eq!(
            restarted_supervisor.cancel_reader_operation_exact(waiting),
            Err(StreamError::TokenMismatch)
        );
        assert_eq!(restarted_reader.start(), Err(StreamError::Busy));
        restarted_supervisor
            .cancel_reader_operation_exact(restarted)
            .unwrap();

        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        let probe = Arc::new(WakeProbe {
            count: AtomicUsize::new(0),
        });
        for value in 0..STREAM_BUFFER_CHUNKS {
            assert_eq!(writer.start(&[value as u8]), Ok(StreamSendDispatch::Sent));
        }
        let blocked = match writer.start(&[0x91]).unwrap() {
            StreamSendDispatch::Waiting(operation) => operation,
            other => panic!("expected writer wait, got {other:?}"),
        };
        writer.register_wake(blocked, wake_token(&probe)).unwrap();
        assert_eq!(
            supervisor
                .finalize_preserving_first_observed(reason)
                .outcome(),
            StreamCloseOutcome::Published
        );
        assert_eq!(stream.depth(), 0);
        assert_eq!(probe.count.load(Ordering::SeqCst), 1);
        supervisor.cancel_writer_operation_exact(blocked).unwrap();
        assert_eq!(
            writer.resume(blocked, &[0x91]),
            Err(StreamError::TokenMismatch)
        );
        assert_eq!(supervisor.final_reason(), Some(reason));
        assert!(!stream.is_fail_stopped());
        assert_eq!(reader.start(), Ok(StreamReceiveDispatch::Closed(reason)));
    }

    let stream = ByteStream::new();
    let reader = stream.reader();
    let supervisor = stream.supervisor();
    let waiting = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected reader wait, got {other:?}"),
    };
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Failure),
        StreamCloseOutcome::Published
    );
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Cancelled),
        StreamCloseOutcome::Conflict
    );
    assert_eq!(
        supervisor.cancel_reader_operation_exact(waiting),
        Err(StreamError::FailStopped)
    );
    assert_eq!(supervisor.final_reason(), Some(StreamCloseReason::Failure));
}

#[test]
fn lifecycle_finalizer_failure_cancelled_race_preserves_exactly_one_winner() {
    for _ in 0..128 {
        let stream = ByteStream::new();
        let failure_supervisor = stream.supervisor();
        let cancelled_supervisor = failure_supervisor.clone();
        let barrier = Arc::new(Barrier::new(3));

        let failure_barrier = barrier.clone();
        let failure = thread::spawn(move || {
            failure_barrier.wait();
            failure_supervisor.finalize_preserving_first_observed(StreamCloseReason::Failure)
        });
        let cancelled_barrier = barrier.clone();
        let cancelled = thread::spawn(move || {
            cancelled_barrier.wait();
            cancelled_supervisor.finalize_preserving_first_observed(StreamCloseReason::Cancelled)
        });

        barrier.wait();
        let failure = failure.join().unwrap();
        let cancelled = cancelled.join().unwrap();
        let published = usize::from(failure.outcome() == StreamCloseOutcome::Published)
            + usize::from(cancelled.outcome() == StreamCloseOutcome::Published);
        assert_eq!(published, 1);
        assert_eq!(
            [failure.outcome(), cancelled.outcome()]
                .into_iter()
                .filter(|outcome| *outcome == StreamCloseOutcome::AlreadyPublished)
                .count(),
            1
        );
        assert_eq!(failure.effective_reason(), cancelled.effective_reason());
        assert!(matches!(
            stream.final_reason(),
            Some(StreamCloseReason::Failure | StreamCloseReason::Cancelled)
        ));
        assert_eq!(failure.effective_reason(), stream.final_reason());
        assert!(!stream.is_fail_stopped());
    }
}

#[test]
fn observed_close_wakes_after_unlock_and_allows_reentrant_state_queries() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let probe = Arc::new(ReentrantWakeProbe {
        stream: stream.clone(),
        count: AtomicUsize::new(0),
    });
    let waiting = match reader.start().unwrap() {
        StreamReceiveDispatch::Waiting(operation) => operation,
        other => panic!("expected empty wait, got {other:?}"),
    };
    reader
        .register_wake(waiting, reentrant_wake_token(&probe))
        .unwrap();

    let observed = writer.close_observed(StreamCloseReason::Failure);
    assert_eq!(observed.outcome(), StreamCloseOutcome::Published);
    assert_eq!(
        observed.effective_reason(),
        Some(StreamCloseReason::Failure)
    );
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        reader.resume(waiting),
        Ok(StreamReceiveDispatch::Closed(StreamCloseReason::Failure))
    );
}

#[test]
fn drained_normal_promotion_is_atomic_idempotent_and_does_not_publish_from_open() {
    let stream = ByteStream::new();
    let writer = stream.writer();
    let supervisor = stream.supervisor();

    assert_eq!(supervisor.promote_normal_if_drained_observed(), None);
    assert_eq!(
        writer.close(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );

    let promoted = supervisor
        .promote_normal_if_drained_observed()
        .expect("drained provisional Normal must promote");
    assert_eq!(promoted.outcome(), StreamCloseOutcome::Published);
    assert_eq!(promoted.effective_reason(), Some(StreamCloseReason::Normal));
    assert_eq!(supervisor.final_reason(), Some(StreamCloseReason::Normal));

    let repeated = supervisor
        .promote_normal_if_drained_observed()
        .expect("an existing final reason must remain observable");
    assert_eq!(repeated.outcome(), StreamCloseOutcome::AlreadyPublished);
    assert_eq!(repeated.effective_reason(), Some(StreamCloseReason::Normal));
    assert!(!stream.is_fail_stopped());
}

#[test]
fn normal_promotion_waits_for_the_exact_buffer_to_drain() {
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();

    assert_eq!(writer.start(&[4, 5, 6]), Ok(StreamSendDispatch::Sent));
    assert_eq!(
        writer.close(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert_eq!(supervisor.promote_normal_if_drained_observed(), None);
    assert_eq!(supervisor.final_reason(), None);
    assert_eq!(receive_one(&reader), [4, 5, 6]);

    let promoted = supervisor
        .promote_normal_if_drained_observed()
        .expect("the drained provisional close must promote");
    assert_eq!(promoted.outcome(), StreamCloseOutcome::Published);
    assert_eq!(promoted.effective_reason(), Some(StreamCloseReason::Normal));
}

#[test]
fn normal_promotion_only_observes_an_established_failure_or_fail_stop() {
    let stream = ByteStream::new();
    let supervisor = stream.supervisor();

    assert_eq!(
        supervisor.finalize(StreamCloseReason::Failure),
        StreamCloseOutcome::Published
    );
    let failure = supervisor
        .promote_normal_if_drained_observed()
        .expect("an established failure must be observed");
    assert_eq!(failure.outcome(), StreamCloseOutcome::AlreadyPublished);
    assert_eq!(failure.effective_reason(), Some(StreamCloseReason::Failure));
    assert!(!stream.is_fail_stopped());

    assert_eq!(
        supervisor.finalize(StreamCloseReason::Cancelled),
        StreamCloseOutcome::Conflict
    );
    let failed = supervisor
        .promote_normal_if_drained_observed()
        .expect("fail-stop remains observable");
    assert_eq!(failed.outcome(), StreamCloseOutcome::Conflict);
    assert_eq!(failed.effective_reason(), Some(StreamCloseReason::Failure));
    assert!(stream.is_fail_stopped());
}

#[test]
fn normal_promotion_wakes_terminal_wait_after_unlock_and_allows_reentry() {
    let stream = ByteStream::new();
    let writer = stream.writer();
    let supervisor = stream.supervisor();
    let probe = Arc::new(ReentrantWakeProbe {
        stream: stream.clone(),
        count: AtomicUsize::new(0),
    });
    let terminal = match supervisor.start_terminal().unwrap() {
        StreamTerminalDispatch::Waiting(operation) => operation,
        other => panic!("expected terminal wait, got {other:?}"),
    };
    supervisor
        .register_terminal_wake(terminal, reentrant_wake_token(&probe))
        .unwrap();

    assert_eq!(
        writer.close(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert_eq!(probe.count.load(Ordering::SeqCst), 0);
    let promoted = supervisor
        .promote_normal_if_drained_observed()
        .expect("drained provisional Normal must promote");
    assert_eq!(promoted.outcome(), StreamCloseOutcome::Published);
    assert_eq!(probe.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        supervisor.resume_terminal(terminal),
        Ok(StreamTerminalDispatch::Ready(StreamCloseReason::Normal))
    );
}

#[test]
fn normal_promotion_and_failure_publication_are_linearizable_across_harts() {
    for _ in 0..128 {
        let stream = ByteStream::new();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        assert_eq!(
            writer.close(StreamCloseReason::Normal),
            StreamCloseOutcome::Published
        );

        let barrier = Arc::new(Barrier::new(3));
        let promotion_supervisor = supervisor.clone();
        let promotion_barrier = barrier.clone();
        let promotion = thread::spawn(move || {
            promotion_barrier.wait();
            promotion_supervisor
                .promote_normal_if_drained_observed()
                .expect("provisional or final lifecycle must be observable")
        });
        let failure_supervisor = supervisor.clone();
        let failure_barrier = barrier.clone();
        let failure = thread::spawn(move || {
            failure_barrier.wait();
            failure_supervisor.finalize_observed(StreamCloseReason::Failure)
        });

        barrier.wait();
        let promotion = promotion.join().unwrap();
        let failure = failure.join().unwrap();
        match (promotion.outcome(), failure.outcome()) {
            (StreamCloseOutcome::Published, StreamCloseOutcome::Conflict) => {
                assert_eq!(
                    promotion.effective_reason(),
                    Some(StreamCloseReason::Normal)
                );
                assert_eq!(failure.effective_reason(), Some(StreamCloseReason::Normal));
                assert_eq!(supervisor.final_reason(), Some(StreamCloseReason::Normal));
                assert!(stream.is_fail_stopped());
            }
            (StreamCloseOutcome::AlreadyPublished, StreamCloseOutcome::Published) => {
                assert_eq!(
                    promotion.effective_reason(),
                    Some(StreamCloseReason::Failure)
                );
                assert_eq!(failure.effective_reason(), Some(StreamCloseReason::Failure));
                assert_eq!(supervisor.final_reason(), Some(StreamCloseReason::Failure));
                assert!(!stream.is_fail_stopped());
            }
            pair => panic!("non-linearizable promotion/failure outcomes: {pair:?}"),
        }
    }
}

#[test]
fn observed_producer_done_and_failure_are_linearizable_across_harts() {
    for _ in 0..128 {
        let stream = ByteStream::new();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        let barrier = Arc::new(Barrier::new(3));
        let writer_barrier = barrier.clone();
        let producer_done = thread::spawn(move || {
            writer_barrier.wait();
            writer.close_observed(StreamCloseReason::Normal)
        });
        let supervisor_barrier = barrier.clone();
        let finalize = thread::spawn(move || {
            supervisor_barrier.wait();
            supervisor.finalize_observed(StreamCloseReason::Failure)
        });

        barrier.wait();
        let producer_done = producer_done.join().unwrap();
        assert!(
            (producer_done.outcome() == StreamCloseOutcome::Published
                && producer_done.effective_reason() == Some(StreamCloseReason::Normal))
                || (producer_done.outcome() == StreamCloseOutcome::AlreadyPublished
                    && producer_done.effective_reason() == Some(StreamCloseReason::Failure))
        );
        let finalize = finalize.join().unwrap();
        assert_eq!(finalize.outcome(), StreamCloseOutcome::Published);
        assert_eq!(
            finalize.effective_reason(),
            Some(StreamCloseReason::Failure)
        );
        assert_eq!(stream.final_reason(), Some(StreamCloseReason::Failure));
        assert!(!stream.is_fail_stopped());
    }
}

#[test]
fn exact_cancel_model_exhausts_both_linearization_orders_for_both_directions() {
    for cancel_first in [true, false] {
        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        assert_eq!(writer.start(&[0x51]), Ok(StreamSendDispatch::Sent));
        let prepared = match reader.start().unwrap() {
            StreamReceiveDispatch::Prepared(prepared) => prepared,
            other => panic!("expected prepared reader operation, got {other:?}"),
        };
        let mut byte = [0_u8];

        if cancel_first {
            assert_eq!(
                supervisor.cancel_reader_operation_exact(prepared.operation()),
                Ok(())
            );
            assert_eq!(
                reader.commit(prepared.operation(), &mut byte),
                Err(StreamError::TokenMismatch)
            );
            assert_eq!(stream.depth(), 1);
            assert_eq!(receive_one(&reader), [0x51]);
        } else {
            assert_eq!(
                reader.commit(prepared.operation(), &mut byte),
                Ok(StreamReceiveCommit::Received(1))
            );
            assert_eq!(byte, [0x51]);
            assert_eq!(
                supervisor.cancel_reader_operation_exact(prepared.operation()),
                Err(StreamError::TokenMismatch)
            );
            assert_eq!(stream.depth(), 0);
        }

        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        for value in 0..STREAM_BUFFER_CHUNKS {
            assert_eq!(writer.start(&[value as u8]), Ok(StreamSendDispatch::Sent));
        }
        let blocked = match writer.start(&[0x61]).unwrap() {
            StreamSendDispatch::Waiting(operation) => operation,
            other => panic!("expected blocked writer operation, got {other:?}"),
        };
        assert_eq!(receive_one(&reader), [0]);

        if cancel_first {
            assert_eq!(supervisor.cancel_writer_operation_exact(blocked), Ok(()));
            assert_eq!(
                writer.resume(blocked, &[0x61]),
                Err(StreamError::TokenMismatch)
            );
            assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS - 1);
        } else {
            assert_eq!(
                writer.resume(blocked, &[0x61]),
                Ok(StreamSendDispatch::Sent)
            );
            assert_eq!(
                supervisor.cancel_writer_operation_exact(blocked),
                Err(StreamError::TokenMismatch)
            );
            assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS);
        }
        assert!(!stream.is_fail_stopped());
    }
}

#[test]
fn exact_cancel_and_backend_linearization_are_atomic_across_harts() {
    for _ in 0..128 {
        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        assert_eq!(writer.start(&[0x71]), Ok(StreamSendDispatch::Sent));
        let prepared = match reader.start().unwrap() {
            StreamReceiveDispatch::Prepared(prepared) => prepared,
            other => panic!("expected prepared reader operation, got {other:?}"),
        };
        let barrier = Arc::new(Barrier::new(3));
        let cancel_barrier = barrier.clone();
        let cancel = thread::spawn(move || {
            cancel_barrier.wait();
            supervisor.cancel_reader_operation_exact(prepared.operation())
        });
        let commit_barrier = barrier.clone();
        let commit = thread::spawn(move || {
            let mut byte = [0_u8];
            commit_barrier.wait();
            (reader.commit(prepared.operation(), &mut byte), byte)
        });
        barrier.wait();
        let cancel = cancel.join().unwrap();
        let (commit, byte) = commit.join().unwrap();
        match (cancel, commit) {
            (Ok(()), Err(StreamError::TokenMismatch)) => {
                assert_eq!(byte, [0]);
                assert_eq!(stream.depth(), 1);
                let replacement = stream.reader();
                assert_eq!(receive_one(&replacement), [0x71]);
            }
            (Err(StreamError::TokenMismatch), Ok(StreamReceiveCommit::Received(1))) => {
                assert_eq!(byte, [0x71]);
                assert_eq!(stream.depth(), 0);
            }
            other => panic!("non-linearizable reader cancellation outcome: {other:?}"),
        }
        assert!(!stream.is_fail_stopped());

        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        for value in 0..STREAM_BUFFER_CHUNKS {
            assert_eq!(writer.start(&[value as u8]), Ok(StreamSendDispatch::Sent));
        }
        let blocked = match writer.start(&[0x72]).unwrap() {
            StreamSendDispatch::Waiting(operation) => operation,
            other => panic!("expected blocked writer operation, got {other:?}"),
        };
        assert_eq!(receive_one(&reader), [0]);
        let barrier = Arc::new(Barrier::new(3));
        let cancel_barrier = barrier.clone();
        let cancel = thread::spawn(move || {
            cancel_barrier.wait();
            supervisor.cancel_writer_operation_exact(blocked)
        });
        let resume_barrier = barrier.clone();
        let resume = thread::spawn(move || {
            resume_barrier.wait();
            writer.resume(blocked, &[0x72])
        });
        barrier.wait();
        let cancel = cancel.join().unwrap();
        let resume = resume.join().unwrap();
        match (cancel, resume) {
            (Ok(()), Err(StreamError::TokenMismatch)) => {
                assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS - 1)
            }
            (Err(StreamError::TokenMismatch), Ok(StreamSendDispatch::Sent)) => {
                assert_eq!(stream.depth(), STREAM_BUFFER_CHUNKS)
            }
            other => panic!("non-linearizable writer cancellation outcome: {other:?}"),
        }
        assert!(!stream.is_fail_stopped());
    }
}

#[test]
fn invalid_chunks_never_consume_queue_or_create_waiters() {
    let stream = ByteStream::new();
    let writer = stream.writer();
    assert_eq!(writer.start(&[]), Err(StreamError::InvalidChunk));
    assert_eq!(
        writer.start(&vec![0; MAX_STREAM_CHUNK_BYTES + 1]),
        Err(StreamError::InvalidChunk)
    );
    assert_eq!(stream.depth(), 0);
    assert_eq!(writer.start(&[1]), Ok(StreamSendDispatch::Sent));
}

#[test]
fn concurrent_producer_consumer_preserve_order_under_repeated_backpressure() {
    const COUNT: usize = 400;
    let stream = ByteStream::new();
    let reader = stream.reader();
    let writer = stream.writer();
    let supervisor = stream.supervisor();

    let producer = thread::spawn(move || {
        for sequence in 0..COUNT {
            let bytes = (sequence as u32).to_le_bytes();
            let mut pending = None;
            loop {
                let dispatch = match pending {
                    Some(operation) => writer.resume(operation, &bytes).unwrap(),
                    None => writer.start(&bytes).unwrap(),
                };
                match dispatch {
                    StreamSendDispatch::Sent => break,
                    StreamSendDispatch::Waiting(operation) => {
                        pending = Some(operation);
                        thread::yield_now();
                    }
                    StreamSendDispatch::Closed(reason) => {
                        panic!("producer closed early: {reason:?}")
                    }
                }
            }
        }
        assert_eq!(
            writer.close(StreamCloseReason::Normal),
            StreamCloseOutcome::Published
        );
    });

    let consumer = thread::spawn(move || {
        let mut observed = Vec::with_capacity(COUNT);
        let mut waiting = None;
        while observed.len() != COUNT {
            let dispatch = match waiting {
                Some(operation) => reader.resume(operation).unwrap(),
                None => reader.start().unwrap(),
            };
            match dispatch {
                StreamReceiveDispatch::Waiting(operation) => {
                    waiting = Some(operation);
                    thread::yield_now();
                }
                StreamReceiveDispatch::Prepared(prepared) => {
                    waiting = None;
                    assert_eq!(prepared.length(), 4);
                    let mut bytes = [0_u8; 4];
                    assert_eq!(
                        reader.commit(prepared.operation(), &mut bytes),
                        Ok(StreamReceiveCommit::Received(4))
                    );
                    observed.push(u32::from_le_bytes(bytes) as usize);
                }
                StreamReceiveDispatch::Closed(reason) => {
                    panic!("consumer closed early: {reason:?}")
                }
            }
        }
        observed
    });

    producer.join().unwrap();
    let observed = consumer.join().unwrap();
    assert_eq!(observed, (0..COUNT).collect::<Vec<_>>());
    assert_eq!(
        supervisor.finalize(StreamCloseReason::Normal),
        StreamCloseOutcome::Published
    );
    assert!(stream.peak_depth() <= STREAM_BUFFER_CHUNKS);
}

#[test]
fn commit_and_failure_finalize_are_linearizable_across_harts() {
    for _ in 0..128 {
        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        writer.start(&[0xaa]).unwrap();
        let prepared = match reader.start().unwrap() {
            StreamReceiveDispatch::Prepared(prepared) => prepared,
            other => panic!("expected prepared, got {other:?}"),
        };
        let barrier = Arc::new(Barrier::new(3));
        let commit_barrier = barrier.clone();
        let commit = thread::spawn(move || {
            let mut byte = [0_u8];
            commit_barrier.wait();
            (reader.commit(prepared.operation(), &mut byte), byte)
        });
        let finalize_barrier = barrier.clone();
        let finalize = thread::spawn(move || {
            finalize_barrier.wait();
            supervisor.finalize(StreamCloseReason::BackendFault)
        });
        barrier.wait();
        let (commit, byte) = commit.join().unwrap();
        assert_eq!(finalize.join().unwrap(), StreamCloseOutcome::Published);
        match commit {
            Ok(StreamReceiveCommit::Received(1)) => assert_eq!(byte, [0xaa]),
            Ok(StreamReceiveCommit::Closed(StreamCloseReason::BackendFault)) => {
                assert_eq!(byte, [0])
            }
            other => panic!("non-linearizable commit result: {other:?}"),
        }
        assert_eq!(stream.depth(), 0);
        assert!(!stream.is_fail_stopped());
    }
}
