#![cfg(feature = "receive-buffer-exchange")]
use std::{num::NonZeroU64, sync::Arc};
use vibeos_core::{
    heap::{AllocationDomain, ArenaId, OwnerId},
    sync::TaskRecoveryKey,
};
use vibeos_net_api::{
    receive_ownership::{Owner, Ticket},
    receive_storage::Storage,
    TcpFrontendError, TcpIoResult, TcpListener, TcpListenerId, TcpStreamState,
};

fn owner(task: u64) -> Owner {
    Owner {
        domain: AllocationDomain::new(OwnerId::new(task), ArenaId::new(task)),
        task: TaskRecoveryKey::new(task).unwrap(),
    }
}
fn fixture(capacity: usize) -> (&'static Storage<3>, Arc<TcpListener>) {
    let pool = Storage::new_static(16, 64).unwrap();
    let listener = TcpListener::new_with_receive_storage(
        "exchange",
        TcpListenerId::new(90).unwrap(),
        9000,
        capacity,
        16,
        pool,
    )
    .unwrap();
    listener
        .network_update_state(TcpStreamState::Established)
        .unwrap();
    (pool, listener)
}
fn pending(pool: &Storage<3>, connection: NonZeroU64, bytes: &[u8]) -> Ticket {
    let ticket = pool.reserve(owner(1)).unwrap();
    let (pointer, capacity) = pool.writer_address(ticket, owner(1)).unwrap();
    // Wrap every transfer to exercise both physical fragments through the frontend.
    let offset = capacity - 2;
    unsafe {
        let buffer = std::slice::from_raw_parts_mut(pointer.as_ptr(), capacity);
        for (i, byte) in bytes.iter().enumerate() {
            buffer[(offset + i) % capacity] = *byte;
        }
    }
    // No mutable payload reference remains when preparing this transfer.
    unsafe {
        pool.prepare(ticket, owner(1), connection, offset, bytes.len())
            .unwrap();
    }
    ticket
}

#[test]
fn mixed_stream_preserves_order_wrap_and_exact_capacity() {
    let (pool, listener) = fixture(16);
    let peer = listener.try_accept().unwrap();
    let generation = listener.network_exchange_generation().unwrap();
    let mut observed = Vec::new();
    for _ in 0..100 {
        assert_eq!(listener.network_receive(b"abc"), 3);
        let first = pending(pool, generation, b"defgh");
        assert_eq!(
            listener.network_publish_exchange(first, owner(1), generation),
            Ok(5)
        );
        assert_eq!(listener.network_receive(b"ijk"), 3);
        let last = pending(pool, generation, b"lmnop");
        assert_eq!(
            listener.network_publish_exchange(last, owner(1), generation),
            Ok(5)
        );
        assert_eq!(listener.network_receive(b"overflow"), 0);
        assert_eq!(listener.snapshot().readable_bytes, 16);
        assert_eq!(listener.network_receive_capacity(), 0);
        let mut scratch = [0; 4];
        let mut count = 0;
        while count < 16 {
            let TcpIoResult::Progress(n) =
                listener.try_recv_for(peer, owner(2), &mut scratch).unwrap()
            else {
                panic!("queued bytes disappeared");
            };
            assert!(n > 0);
            observed.extend_from_slice(&scratch[..n]);
            count += n;
            assert_eq!(listener.snapshot().readable_bytes, 16 - count);
        }
        assert_eq!(pool.queued_bytes(), 0);
        assert_eq!(listener.network_receive_capacity(), 16);
        assert_eq!(
            listener.try_recv_for(peer, owner(2), &mut scratch),
            Ok(TcpIoResult::WouldBlock)
        );
    }
    assert_eq!(observed, b"abcdefghijklmnop".repeat(100));
}

#[test]
fn rejected_publications_preserve_pending_transfer_and_stream() {
    let (pool, listener) = fixture(8);
    let peer = listener.try_accept().unwrap();
    let generation = listener.network_exchange_generation().unwrap();
    let ticket = pending(pool, generation, b"defghi");
    assert_eq!(listener.network_receive(b"abc"), 3);
    // Byte capacity, not just available pool slots, constrains admission.
    assert!(listener
        .network_publish_exchange(ticket, owner(1), generation)
        .is_err());
    assert_eq!(pool.pending_length(ticket, owner(1), generation), Ok(6));
    assert!(listener
        .network_publish_exchange(ticket, owner(2), generation)
        .is_err());
    let foreign = Storage::<3>::new_static(16, 64).unwrap();
    let wrong_pool = pending(foreign, generation, b"xx");
    assert!(listener
        .network_publish_exchange(wrong_pool, owner(1), generation)
        .is_err());
    let wrong_connection = pending(pool, NonZeroU64::new(generation.get() + 1).unwrap(), b"xx");
    assert!(listener
        .network_publish_exchange(wrong_connection, owner(1), generation)
        .is_err());
    let mut buffer = [0; 8];
    assert_eq!(
        listener.try_recv_for(peer, owner(2), &mut buffer),
        Ok(TcpIoResult::Progress(3))
    );
    assert_eq!(&buffer[..3], b"abc");
    assert_eq!(
        listener.network_publish_exchange(ticket, owner(1), generation),
        Ok(6)
    );
    assert!(listener
        .network_publish_exchange(ticket, owner(1), generation)
        .is_err());
    assert_eq!(
        listener.try_recv_for(peer, owner(2), &mut buffer),
        Ok(TcpIoResult::Progress(6))
    );
    assert_eq!(&buffer[..6], b"defghi");
    assert_eq!(listener.snapshot().readable_bytes, 0);
    // Pending transfers not admitted by this listener remain producer-owned.
    assert_eq!(unsafe { pool.retire_stopped_owner(owner(1)) }, 1);
    assert_eq!(unsafe { foreign.retire_stopped_owner(owner(1)) }, 1);
}

#[test]
fn reset_discards_published_bytes_and_rejects_old_generation() {
    let (pool, listener) = fixture(32);
    let old = listener.try_accept().unwrap();
    let generation = listener.network_exchange_generation().unwrap();
    listener.network_receive(b"copy");
    let published = pending(pool, generation, b"old-exchange");
    listener
        .network_publish_exchange(published, owner(1), generation)
        .unwrap();
    let delayed = pending(pool, generation, b"late");
    listener
        .network_update_state(TcpStreamState::Reset)
        .unwrap();
    assert_eq!(listener.snapshot().readable_bytes, 0);
    assert_eq!(pool.queued_bytes(), 4); // Only the producer's unadmitted transfer.
    assert_eq!(listener.network_exchange_generation(), None);
    listener
        .network_update_state(TcpStreamState::Listening)
        .unwrap();
    listener
        .network_update_state(TcpStreamState::Established)
        .unwrap();
    let fresh = listener.try_accept().unwrap();
    let next = listener.network_exchange_generation().unwrap();
    assert_ne!(generation, next);
    assert_eq!(
        listener.network_publish_exchange(delayed, owner(1), generation),
        Err(TcpFrontendError::StaleConnection)
    );
    assert!(listener
        .network_publish_exchange(delayed, owner(1), next)
        .is_err());
    assert_eq!(
        listener.try_recv_for(old, owner(2), &mut [0; 8]),
        Err(TcpFrontendError::StaleConnection)
    );
    assert_eq!(pool.pending_length(delayed, owner(1), generation), Ok(4));
    let new = pending(pool, next, b"fresh");
    listener
        .network_publish_exchange(new, owner(1), next)
        .unwrap();
    let mut output = [0; 8];
    assert_eq!(
        listener.try_recv_for(fresh, owner(2), &mut output),
        Ok(TcpIoResult::Progress(5))
    );
    assert_eq!(&output[..5], b"fresh");
    assert_eq!(unsafe { pool.retire_stopped_owner(owner(1)) }, 1);
}

#[cfg(feature = "activity-events")]
#[test]
fn publication_wakes_reader_after_releasing_both_locks() {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Wake, Waker},
    };
    struct Reader {
        listener: Arc<TcpListener>,
        peer: vibeos_net_api::TcpConnectionToken,
    }
    impl Wake for Reader {
        fn wake(self: Arc<Self>) {
            let mut output = [0; 8];
            assert_eq!(
                self.listener.try_recv_for(self.peer, owner(2), &mut output),
                Ok(TcpIoResult::Progress(4))
            );
            assert_eq!(&output[..4], b"wake");
        }
    }
    let (pool, listener) = fixture(16);
    let peer = listener.try_accept().unwrap();
    let generation = listener.network_exchange_generation().unwrap();
    let event = listener.network_event();
    let waker = Waker::from(Arc::new(Reader {
        listener: listener.clone(),
        peer,
    }));
    let mut cx = Context::from_waker(&waker);
    let mut wait = pin!(event.wait());
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    let ticket = pending(pool, generation, b"wake");
    assert_eq!(
        listener.network_publish_exchange(ticket, owner(1), generation),
        Ok(4)
    );
    assert!(wait.as_mut().poll(&mut cx).is_ready());
    assert_eq!(listener.snapshot().readable_bytes, 0);
    assert_eq!(pool.queued_bytes(), 0);
}

#[test]
fn exchanged_reads_require_current_task_provenance() {
    let (pool, listener) = fixture(16);
    let peer = listener.try_accept().unwrap();
    let generation = listener.network_exchange_generation().unwrap();
    let ticket = pending(pool, generation, b"data");
    listener
        .network_publish_exchange(ticket, owner(1), generation)
        .unwrap();
    // Host test is outside an executor task: no fabricated retirement identity.
    assert_eq!(
        listener.try_recv(peer, &mut [0; 8]),
        Err(TcpFrontendError::InvalidIdentity)
    );
    assert_eq!(listener.snapshot().readable_bytes, 4);
    assert_eq!(
        listener.try_recv_for(peer, owner(2), &mut [0; 8]),
        Ok(TcpIoResult::Progress(4))
    );
}

#[test]
fn rejected_pending_transfer_can_be_discarded_without_releasing_published_data() {
    let (pool, listener) = fixture(8);
    let generation = listener.network_exchange_generation().unwrap();
    let peer = listener.try_accept().unwrap();
    let live = pool.reserve(owner(1)).unwrap();
    let rejected = pending(pool, generation, b"rejected");
    assert!(pool.discard_pending(rejected, owner(2)).is_err());
    assert!(pool.discard_pending(live, owner(1)).is_err());
    assert_eq!(pool.pending_length(rejected, owner(1), generation), Ok(8));
    pool.discard_pending(rejected, owner(1)).unwrap();
    assert!(pool.discard_pending(rejected, owner(1)).is_err());
    assert_eq!(pool.queued_bytes(), 0);
    let published = pending(pool, generation, b"keep");
    listener
        .network_publish_exchange(published, owner(1), generation)
        .unwrap();
    assert!(pool.discard_pending(published, owner(1)).is_err());
    let mut bytes = [0; 8];
    assert_eq!(
        listener.try_recv_for(peer, owner(2), &mut bytes),
        Ok(TcpIoResult::Progress(4))
    );
    assert_eq!(&bytes[..4], b"keep");
    assert!(pool.writer_address(live, owner(1)).is_ok());
    unsafe {
        pool.release_writer(live, owner(1)).unwrap();
    }
}

#[test]
fn bounded_publication_admits_the_current_range_and_preserves_rejected_bytes() {
    let (pool, listener) = fixture(16);
    let generation = listener.network_exchange_generation().unwrap();
    let ticket = pending(pool, generation, b"old");
    assert_eq!(pool.pending_length(ticket, owner(1), generation), Ok(3));
    pool.cancel_pending(ticket, owner(1)).unwrap();
    let (pointer, _) = pool.writer_address(ticket, owner(1)).unwrap();
    unsafe {
        core::ptr::copy_nonoverlapping(b"new-range".as_ptr(), pointer.as_ptr(), 9);
        pool.prepare(ticket, owner(1), generation, 0, 9).unwrap();
    }
    // A caller's earlier size observation cannot admit a larger replacement.
    assert!(pool
        .publish_bounded(ticket, owner(1), generation, 3)
        .is_err());
    assert_eq!(pool.pending_length(ticket, owner(1), generation), Ok(9));
    assert_eq!(pool.publish_bounded(ticket, owner(1), generation, 9), Ok(9));
    assert!(pool
        .publish_bounded(ticket, owner(1), generation, 9)
        .is_err());
    let mut bytes = [0; 16];
    assert_eq!(pool.read(ticket, generation, owner(2), &mut bytes), Ok(9));
    assert_eq!(&bytes[..9], b"new-range");
    assert_eq!(pool.queued_bytes(), 0);
}

#[test]
fn dropping_frontend_releases_unread_ranges_but_not_unadmitted_transfers() {
    let (pool, listener) = fixture(32);
    let generation = listener.network_exchange_generation().unwrap();
    listener.network_receive(b"copied");
    let first = pending(pool, generation, b"first");
    listener
        .network_publish_exchange(first, owner(1), generation)
        .unwrap();
    listener.network_receive(b"between");
    let last = pending(pool, generation, b"last");
    listener
        .network_publish_exchange(last, owner(1), generation)
        .unwrap();
    let unadmitted = pending(pool, generation, b"pending");
    drop(listener);
    assert_eq!(pool.queued_bytes(), 7);
    assert_eq!(pool.pending_length(unadmitted, owner(1), generation), Ok(7));
    let a = pool.reserve(owner(2)).unwrap();
    let b = pool.reserve(owner(2)).unwrap();
    assert!(pool.reserve(owner(2)).is_err());
    unsafe {
        pool.release_writer(a, owner(2)).unwrap();
        pool.release_writer(b, owner(2)).unwrap();
    }
    pool.discard_pending(unadmitted, owner(1)).unwrap();
}

#[test]
fn stale_frontend_chunk_does_not_leak_following_ranges_or_free_reused_slot() {
    let (pool, listener) = fixture(32);
    let generation = listener.network_exchange_generation().unwrap();
    let first = pending(pool, generation, b"first");
    listener
        .network_publish_exchange(first, owner(1), generation)
        .unwrap();
    let last = pending(pool, generation, b"last");
    listener
        .network_publish_exchange(last, owner(1), generation)
        .unwrap();
    // Simulate an independently retired queue entry: destruction must validate
    // generations and still process subsequent valid entries.
    pool.discard_published(first, generation).unwrap();
    let a = pool.reserve(owner(2)).unwrap();
    let b = pool.reserve(owner(2)).unwrap();
    drop(listener);
    assert_eq!(pool.queued_bytes(), 0);
    assert!(pool.writer_address(a, owner(2)).is_ok());
    assert!(pool.writer_address(b, owner(2)).is_ok());
    let c = pool.reserve(owner(2)).unwrap();
    unsafe {
        pool.release_writer(a, owner(2)).unwrap();
        pool.release_writer(b, owner(2)).unwrap();
        pool.release_writer(c, owner(2)).unwrap();
    }
}
