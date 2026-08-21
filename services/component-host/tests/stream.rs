use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use vibeos_component_host::{
    ByteStream, StreamCloseOutcome, StreamCloseReason, StreamError, StreamReceiveCommit,
    StreamReceiveDispatch, StreamSendDispatch, MAX_STREAM_CHUNK_BYTES, STREAM_BUFFER_CHUNKS,
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
fn producer_done_and_failure_finalize_are_linearizable_across_harts() {
    for _ in 0..128 {
        let stream = ByteStream::new();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        let barrier = Arc::new(Barrier::new(3));
        let writer_barrier = barrier.clone();
        let producer_done = thread::spawn(move || {
            writer_barrier.wait();
            writer.close(StreamCloseReason::Normal)
        });
        let supervisor_barrier = barrier.clone();
        let finalize = thread::spawn(move || {
            supervisor_barrier.wait();
            supervisor.finalize(StreamCloseReason::Failure)
        });

        barrier.wait();
        assert!(matches!(
            producer_done.join().unwrap(),
            StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
        ));
        assert_eq!(finalize.join().unwrap(), StreamCloseOutcome::Published);
        assert_eq!(stream.final_reason(), Some(StreamCloseReason::Failure));
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
