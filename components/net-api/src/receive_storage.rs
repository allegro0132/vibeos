//! Permanent backing storage for receive-buffer exchange experiments.
//!
//! Construct once per listener at runtime assembly, never per socket restart.
//! Socket mapping and stopped-owner retirement are unsafe integration boundaries;
//! the metadata-only state machine cannot establish scheduler quiescence.
use super::receive_ownership::{Error, Owner, Ownership, ReadTicket, Ticket};
use alloc::{boxed::Box, vec};
use core::{num::NonZeroU64, ptr::NonNull};
use vibeos_core::{
    heap::{self, OwnerId},
    sync::SpinLock,
};

pub const MAX_BUFFER_BYTES: usize = 256 * 1024;

pub struct Storage<const N: usize> {
    ownership: SpinLock<super::receive_metadata::Metadata<N>>,
    pointers: [NonNull<u8>; N],
    buffer_bytes: usize,
}
// All safe access is serialized by ownership. The unsafe socket-mapping API
// requires exclusive access until prepare/retirement ends its ownership.
unsafe impl<const N: usize> Sync for Storage<N> {}

struct ReadGuard<'a, const N: usize> {
    storage: &'a Storage<N>,
    lease: Option<ReadTicket>,
}
impl<const N: usize> ReadGuard<'_, N> {
    fn finish(mut self, length: usize) -> Result<(), Error> {
        let result = self
            .storage
            .ownership
            .lock()
            .update(|state| state.finish_read(self.lease.unwrap(), length));
        if result.is_ok() {
            self.lease = None;
        }
        result
    }
}
impl<const N: usize> Drop for ReadGuard<'_, N> {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            // Normal unwinding returns the unchanged range to the frontend.
            // A hard fault instead requires exact-reader supervisor retirement.
            let _ = self
                .storage
                .ownership
                .lock()
                .update(|state| state.finish_read(lease, 0));
        }
    }
}

impl<const N: usize> Storage<N> {
    pub fn new_static(buffer_bytes: usize, byte_budget: usize) -> Result<&'static Self, Error> {
        if buffer_bytes == 0 || buffer_bytes > MAX_BUFFER_BYTES {
            return Err(Error::Capacity);
        }
        let ownership = Ownership::new(buffer_bytes, byte_budget)?;
        let _system = heap::enter_owner(OwnerId::SYSTEM);
        let pointers = core::array::from_fn(|_| {
            let bytes = Box::leak(vec![0; buffer_bytes].into_boxed_slice());
            NonNull::new(bytes.as_mut_ptr()).expect("nonempty backing store")
        });
        Ok(Box::leak(Box::new(Self {
            ownership: SpinLock::new_recoverable(super::receive_metadata::Metadata::new(ownership)),
            pointers,
            buffer_bytes,
        })))
    }

    pub fn reserve(&self, owner: Owner) -> Result<Ticket, Error> {
        self.ownership.lock().update(|state| state.reserve(owner))
    }

    /// # Safety
    /// Every socket reference and all possible future access through cached
    /// addresses for this writer must have ended before releasing the slot.
    pub unsafe fn release_writer(&self, ticket: Ticket, owner: Owner) -> Result<(), Error> {
        self.ownership
            .lock()
            .update(|state| state.release_writer(ticket, owner))
    }

    pub fn available_bytes(&self) -> usize {
        self.ownership.lock().available_bytes()
    }

    /// Obtain the socket's backing storage address, without constructing a Rust
    /// reference. Dereferencing it is the integrator's unsafe operation: only
    /// this exact task may write it, and all references must end before prepare
    /// or stopped-owner retirement. Repeated address queries grant no new lease.
    pub fn writer_address(
        &self,
        ticket: Ticket,
        owner: Owner,
    ) -> Result<(NonNull<u8>, usize), Error> {
        let metadata = self.ownership.lock();
        metadata.validate_writer(ticket, owner)?;
        // No payload reference is constructed while the socket may hold &mut.
        Ok((self.pointers[ticket.index()], self.buffer_bytes))
    }

    /// Freeze received data for frontend publication.
    ///
    /// # Safety
    /// All socket references into this slot must have ended, and the range must
    /// consist entirely of received stream bytes for this connection. Neither
    /// the producer nor another CPU may mutate it until cancel_pending restores
    /// socket ownership or the slot is retired and reserved again.
    pub unsafe fn prepare(
        &self,
        ticket: Ticket,
        owner: Owner,
        connection: NonZeroU64,
        offset: usize,
        length: usize,
    ) -> Result<(), Error> {
        self.ownership
            .lock()
            .update(|state| state.prepare(ticket, owner, connection, offset, length))
    }

    pub fn cancel_pending(&self, ticket: Ticket, owner: Owner) -> Result<(), Error> {
        self.ownership
            .lock()
            .update(|state| state.cancel_pending(ticket, owner))
    }

    /// Discard a transfer rejected before frontend publication. Unlike owner
    /// retirement this touches no live writer or published reader range.
    pub fn discard_pending(&self, ticket: Ticket, owner: Owner) -> Result<(), Error> {
        self.ownership
            .lock()
            .update(|state| state.discard_pending(ticket, owner))
    }

    pub fn pending_length(
        &self,
        ticket: Ticket,
        owner: Owner,
        connection: NonZeroU64,
    ) -> Result<usize, Error> {
        self.ownership
            .lock()
            .pending_range(ticket, owner, connection)
            .map(|range| range.length)
    }

    /// The frontend must serialize queue publication with this transition and
    /// its connection-generation check. No application can read pending data.
    pub fn publish(
        &self,
        ticket: Ticket,
        owner: Owner,
        connection: NonZeroU64,
    ) -> Result<(), Error> {
        self.ownership
            .lock()
            .update(|state| state.publish(ticket, owner, connection))
    }

    /// Validate size and publish in one metadata critical section. The returned
    /// length belongs to exactly the range whose state was committed, even if
    /// a producer cancelled/reprepared the ticket before this lock was taken.
    pub fn publish_bounded(
        &self,
        ticket: Ticket,
        owner: Owner,
        connection: NonZeroU64,
        maximum: usize,
    ) -> Result<usize, Error> {
        self.ownership.lock().update(|metadata| {
            let length = metadata.pending_range(ticket, owner, connection)?.length;
            if length > maximum {
                return Err(Error::Budget);
            }
            metadata.publish(ticket, owner, connection)?;
            Ok(length)
        })
    }

    /// Copy directly from the exchanged buffer to application output. No
    /// intermediate byte queue or borrowed pointer escapes this operation. A
    /// read lease pins the data without holding the metadata lock during copy.
    /// `consumer` must be supplied by the trusted executor adapter, not client
    /// data; it identifies the task whose quiescence permits read recovery.
    pub fn read(
        &self,
        ticket: Ticket,
        connection: NonZeroU64,
        consumer: Owner,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let (lease, range) = self
            .ownership
            .lock()
            .update(|state| state.begin_read(ticket, connection, consumer))?;
        let guard = ReadGuard {
            storage: self,
            lease: Some(lease),
        };
        let length = output
            .len()
            .min(super::MAX_TCP_IO_BYTES_PER_CALL)
            .min(range.length);
        let first = length.min(self.buffer_bytes - range.offset);
        // prepare ended the mutable socket borrow; the Reading lease pins the
        // immutable range even though the metadata lock is no longer held.
        let bytes = unsafe {
            core::slice::from_raw_parts(self.pointers[ticket.index()].as_ptr(), self.buffer_bytes)
        };
        output[..first].copy_from_slice(&bytes[range.offset..range.offset + first]);
        output[first..length].copy_from_slice(&bytes[..length - first]);
        guard.finish(length)?;
        Ok(length)
    }

    /// Discard a frontend-owned chunk after connection teardown. The lock
    /// serializes against read; no borrowed payload escapes either operation.
    pub fn discard_published(&self, ticket: Ticket, connection: NonZeroU64) -> Result<(), Error> {
        self.ownership.lock().update(|metadata| {
            let length = metadata.readable(ticket, connection)?.length;
            metadata.consume(ticket, connection, length)
        })
    }

    /// # Safety
    /// The trusted scheduler must have stopped this exact task incarnation
    /// permanently, with every socket or read pointer/reference dead. Revocation alone
    /// is insufficient. This does not recover an abandoned metadata lock; an
    /// adapter must not use it as a hard-fault lock-recovery implementation.
    pub unsafe fn retire_stopped_owner(&self, owner: Owner) -> usize {
        self.ownership
            .lock()
            .update(|state| state.retire_stopped_owner(owner))
    }

    /// Release only a metadata guard abandoned by this exact task. The double
    /// bank keeps its last complete commit; it does not repair frontend queues.
    /// False is not proof of safety: the lock may be free or owned by another task.
    ///
    /// # Safety
    /// This task incarnation must be permanently stopped, with no possibility
    /// of resuming or dropping its guard. For another hart, observe its Release
    /// quiescence acknowledgement with Acquire first. `owner.domain` must be
    /// the allocation domain at lock acquisition, not a guessed service domain.
    /// This authorizes neither payload retirement nor frontend publication.
    pub unsafe fn recover_metadata_lock(&self, owner: Owner) -> bool {
        unsafe {
            self.ownership
                .recover_after_task_fault(owner.domain, owner.task)
        }
    }

    pub fn queued_bytes(&self) -> usize {
        self.ownership.lock().queued_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_core::{
        heap::{AllocationDomain, ArenaId},
        sync::TaskRecoveryKey,
    };
    fn owner(task: u64) -> Owner {
        Owner {
            domain: AllocationDomain::new(OwnerId::new(7), ArenaId::new(task)),
            task: TaskRecoveryKey::new(task).unwrap(),
        }
    }
    fn connection(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).unwrap()
    }

    #[test]
    fn published_wrapped_bytes_survive_producer_retirement() {
        let pool = Storage::<2>::new_static(16, 16).unwrap();
        let a = owner(1);
        let ticket = pool.reserve(a).unwrap();
        let (pointer, capacity) = pool.writer_address(ticket, a).unwrap();
        unsafe {
            let bytes = core::slice::from_raw_parts_mut(pointer.as_ptr(), capacity);
            bytes[14..].copy_from_slice(b"ab");
            bytes[..4].copy_from_slice(b"cdef");
        }
        unsafe {
            pool.prepare(ticket, a, connection(1), 14, 6).unwrap();
        }
        assert_eq!(
            pool.read(ticket, connection(1), owner(9), &mut [0; 8]),
            Err(Error::WrongState)
        );
        pool.publish(ticket, a, connection(1)).unwrap();
        assert!(pool.writer_address(ticket, a).is_err());
        assert_eq!(unsafe { pool.retire_stopped_owner(a) }, 0);
        let second = pool.reserve(owner(2)).unwrap();
        assert_ne!(ticket.index(), second.index());
        let mut out = [0; 4];
        assert_eq!(
            pool.read(ticket, connection(2), owner(9), &mut out),
            Err(Error::Connection)
        );
        assert_eq!(pool.read(ticket, connection(1), owner(9), &mut out), Ok(4));
        assert_eq!(&out, b"abcd");
        assert_eq!(pool.read(ticket, connection(1), owner(9), &mut out), Ok(2));
        assert_eq!(&out[..2], b"ef");
        assert_eq!(pool.queued_bytes(), 0);
        let replacement = pool.reserve(owner(3)).unwrap();
        assert_eq!(replacement.index(), ticket.index());
        assert_eq!(
            pool.read(ticket, connection(1), owner(9), &mut out),
            Err(Error::Stale)
        );
    }

    #[test]
    fn discard_releases_only_the_matching_published_generation() {
        let pool = Storage::<1>::new_static(16, 16).unwrap();
        let a = owner(1);
        let ticket = pool.reserve(a).unwrap();
        // The pool's initial zero bytes form this test's received payload.
        unsafe {
            pool.prepare(ticket, a, connection(1), 0, 1).unwrap();
        }
        pool.publish(ticket, a, connection(1)).unwrap();
        assert_eq!(
            pool.discard_published(ticket, connection(2)),
            Err(Error::Connection)
        );
        pool.discard_published(ticket, connection(1)).unwrap();
        let next = pool.reserve(owner(2)).unwrap();
        assert_ne!(next, ticket);
        assert_eq!(
            pool.discard_published(ticket, connection(1)),
            Err(Error::Stale)
        );
        assert!(pool.writer_address(next, owner(2)).is_ok());
    }

    #[test]
    fn unpublished_transfer_recovery_and_retry_preserve_exclusivity() {
        let pool = Storage::<1>::new_static(16, 16).unwrap();
        let a = owner(1);
        let ticket = pool.reserve(a).unwrap();
        let (pointer, size) = pool.writer_address(ticket, a).unwrap();
        unsafe {
            core::slice::from_raw_parts_mut(pointer.as_ptr(), size)[..3].copy_from_slice(b"old");
        }
        unsafe {
            pool.prepare(ticket, a, connection(1), 0, 3).unwrap();
        }
        pool.cancel_pending(ticket, a).unwrap();
        assert_eq!(pool.writer_address(ticket, a).unwrap().0, pointer);
        unsafe {
            pool.prepare(ticket, a, connection(1), 0, 3).unwrap();
        }
        assert_eq!(unsafe { pool.retire_stopped_owner(owner(2)) }, 0);
        assert_eq!(unsafe { pool.retire_stopped_owner(a) }, 1);
        let next = pool.reserve(owner(2)).unwrap();
        assert_ne!(ticket, next);
        assert_eq!(pool.publish(ticket, a, connection(1)), Err(Error::Stale));
    }
    #[test]
    fn forgotten_read_can_be_retired_without_reclaiming_published_bytes() {
        let pool = Storage::<2>::new_static(16, 16).unwrap();
        let producer = owner(1);
        let consumer = owner(2);
        let ticket = pool.reserve(producer).unwrap();
        let (pointer, _) = pool.writer_address(ticket, producer).unwrap();
        unsafe {
            core::slice::from_raw_parts_mut(pointer.as_ptr(), 4).copy_from_slice(b"data");
        }
        unsafe {
            pool.prepare(ticket, producer, connection(1), 0, 4).unwrap();
        }
        pool.publish(ticket, producer, connection(1)).unwrap();
        let (lease, _) = pool
            .ownership
            .lock()
            .update(|state| state.begin_read(ticket, connection(1), consumer))
            .unwrap();
        let guard = ReadGuard {
            storage: pool,
            lease: Some(lease),
        };
        // A live read does not retain the metadata lock: another slot remains
        // usable, while this slot cannot be discarded or read a second time.
        let other = pool.reserve(owner(3)).unwrap();
        assert_ne!(other.index(), ticket.index());
        assert_eq!(
            pool.discard_published(ticket, connection(1)),
            Err(Error::WrongState)
        );
        core::mem::forget(guard);
        // Model a stopped task that skipped Drop, with no outstanding payload
        // references. This is not a real trap/quiescence-barrier test.
        assert_eq!(unsafe { pool.retire_stopped_owner(consumer) }, 1);
        assert_eq!(
            pool.ownership
                .lock()
                .update(|state| state.finish_read(lease, 4)),
            Err(Error::WrongState)
        );
        let mut out = [0; 4];
        assert_eq!(pool.read(ticket, connection(1), owner(4), &mut out), Ok(4));
        assert_eq!(&out, b"data");
    }

    #[test]
    fn ordinary_unwind_cancels_read_without_consuming_data() {
        extern crate std;
        let pool = Storage::<1>::new_static(16, 16).unwrap();
        let producer = owner(1);
        let ticket = pool.reserve(producer).unwrap();
        unsafe {
            pool.prepare(ticket, producer, connection(1), 0, 4).unwrap();
        }
        pool.publish(ticket, producer, connection(1)).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (lease, _) = pool
                .ownership
                .lock()
                .update(|state| state.begin_read(ticket, connection(1), owner(2)))
                .unwrap();
            let _guard = ReadGuard {
                storage: pool,
                lease: Some(lease),
            };
            panic!("simulated application unwind");
        }));
        assert!(result.is_err());
        assert_eq!(pool.queued_bytes(), 4);
        assert_eq!(
            pool.read(ticket, connection(1), owner(3), &mut [0; 4]),
            Ok(4)
        );
    }
    #[test]
    fn exact_task_recovers_abandoned_metadata_without_exposing_incomplete_bank() {
        let pool = Storage::<3>::new_static(16, 32).unwrap();
        let producer = owner(151);
        let published = pool.reserve(producer).unwrap();
        let (pointer, _) = pool.writer_address(published, producer).unwrap();
        unsafe {
            core::ptr::copy_nonoverlapping(b"keep".as_ptr(), pointer.as_ptr(), 4);
            pool.prepare(published, producer, connection(1), 0, 4)
                .unwrap();
        }
        pool.publish(published, producer, connection(1)).unwrap();
        let writer = pool.reserve(producer).unwrap();
        {
            let _domain = unsafe { vibeos_core::heap::enter_domain(producer.domain) };
            let _task = vibeos_core::sync::enter_task_recovery_context(producer.task);
            let mut guard = pool.ownership.lock();
            guard.interrupt_inactive_write_for_test();
            core::mem::forget(guard);
        }
        // There are no remaining references to the forgotten guard or socket
        // payload in this host fixture. This models skipped Drop, not a trap.
        let wrong_task = Owner {
            task: TaskRecoveryKey::new(152).unwrap(),
            ..producer
        };
        let wrong_domain = Owner {
            domain: owner(152).domain,
            ..producer
        };
        assert!(!unsafe { pool.recover_metadata_lock(wrong_task) });
        assert!(!unsafe { pool.recover_metadata_lock(wrong_domain) });
        assert!(unsafe { pool.recover_metadata_lock(producer) });
        assert!(!unsafe { pool.recover_metadata_lock(producer) });
        assert!(pool.writer_address(writer, producer).is_ok());
        let mut output = [0; 4];
        assert_eq!(
            pool.read(published, connection(1), owner(153), &mut output),
            Ok(4)
        );
        assert_eq!(&output, b"keep");
        unsafe {
            pool.release_writer(writer, producer).unwrap();
        }
    }
}
