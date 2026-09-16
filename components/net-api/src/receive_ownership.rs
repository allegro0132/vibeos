//! Ownership metadata for a future stable TCP receive-storage pool.
//!
//! This module owns no payload and grants no memory access. The storage adapter
//! must serialize this table with frontend publication, preserve backing memory,
//! and end every socket borrow before preparing a transfer. A ticket is an
//! identifier, not capability authority. Published storage is immutable until
//! consumption; it must not be reclaimed merely because its producer stopped.
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};
use vibeos_core::{heap::AllocationDomain, sync::TaskRecoveryKey};

static NEXT_POOL: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub domain: AllocationDomain,
    pub task: TaskRecoveryKey,
}

impl Owner {
    /// Producer setup must run in an actual tracked task poll. Resolve the
    /// scheduler's domain, not a temporary allocation-owner scope.
    pub fn current_producer() -> Option<Self> {
        let (task, domain) = vibeos_core::exec::current_task_allocation_identity()?;
        if !domain.arena.is_tracked() { return None; }
        Some(Self { domain, task: TaskRecoveryKey::new(task.0)? })
    }

    /// Lightweight synchronous read provenance; this does not authorize reads
    /// or prove quiescence. The frontend capability/connection does admission.
    pub fn current_reader() -> Option<Self> {
        let task = vibeos_core::exec::current_task_scope_id()?;
        let domain = vibeos_core::heap::current_domain();
        if !domain.arena.is_tracked() { return None; }
        Some(Self { domain, task: TaskRecoveryKey::new(task.0)? })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    pool: u64,
    index: usize,
    generation: u64,
}
impl Ticket {
    pub fn index(self) -> usize {
        self.index
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadTicket {
    ticket: Ticket,
    generation: u64,
    consumer: Owner,
    connection: NonZeroU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub offset: usize,
    pub length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Capacity,
    UntrackedOwner,
    Exhausted,
    Full,
    Stale,
    WrongOwner,
    WrongState,
    Budget,
    Range,
    Connection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Free,
    Socket(Owner),
    Pending {
        owner: Owner,
        connection: NonZeroU64,
        range: Range,
    },
    Published {
        connection: NonZeroU64,
        range: Range,
    },
    Reading {
        consumer: Owner,
        connection: NonZeroU64,
        range: Range,
    },
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    read_generation: u64,
    state: State,
}

/// Fixed metadata for one listener's pool. No operation allocates or touches
/// payload bytes. `byte_budget` includes pending and published transfers.
pub struct Ownership<const N: usize> {
    id: u64,
    buffer_bytes: usize,
    byte_budget: usize,
    cursor: usize,
    slots: [Slot; N],
}
impl<const N: usize> Ownership<N> {
    pub(crate) fn snapshot(&self) -> Self {
        Self { id: self.id, buffer_bytes: self.buffer_bytes, byte_budget: self.byte_budget,
            cursor: self.cursor, slots: self.slots }
    }

    pub fn new(buffer_bytes: usize, byte_budget: usize) -> Result<Self, Error> {
        if N == 0
            || N > 32
            || buffer_bytes == 0
            || byte_budget == 0
            || byte_budget > super::MAX_TCP_FRONTEND_BUFFER_BYTES
        {
            return Err(Error::Capacity);
        }
        let id = NEXT_POOL
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Exhausted)?;
        Ok(Self {
            id,
            buffer_bytes,
            byte_budget,
            cursor: 0,
            slots: [Slot {
                generation: 0,
                read_generation: 0,
                state: State::Free,
            }; N],
        })
    }

    pub fn reserve(&mut self, owner: Owner) -> Result<Ticket, Error> {
        if !owner.domain.arena.is_tracked() {
            return Err(Error::UntrackedOwner);
        }
        let mut exhausted = false;
        for delta in 0..N {
            let index = (self.cursor + delta) % N;
            let slot = &mut self.slots[index];
            if slot.state != State::Free {
                continue;
            }
            let Some(generation) = slot.generation.checked_add(1) else {
                exhausted = true;
                continue;
            };
            slot.generation = generation;
            slot.state = State::Socket(owner);
            self.cursor = (index + 1) % N;
            return Ok(Ticket {
                pool: self.id,
                index,
                generation,
            });
        }
        Err(if exhausted {
            Error::Exhausted
        } else {
            Error::Full
        })
    }

    fn slot(&self, ticket: Ticket) -> Result<&Slot, Error> {
        if ticket.pool != self.id {
            return Err(Error::Stale);
        }
        let slot = self.slots.get(ticket.index).ok_or(Error::Stale)?;
        if slot.state == State::Free || slot.generation != ticket.generation {
            return Err(Error::Stale);
        }
        Ok(slot)
    }

    pub fn validate_writer(&self, ticket: Ticket, owner: Owner) -> Result<(), Error> {
        match self.slot(ticket)?.state {
            State::Socket(actual) if actual == owner => Ok(()),
            State::Socket(_) => Err(Error::WrongOwner),
            _ => Err(Error::WrongState),
        }
    }

    /// Return an unused writer after its final socket reference has ended.
    pub fn release_writer(&mut self, ticket: Ticket, owner: Owner) -> Result<(), Error> {
        self.validate_writer(ticket, owner)?;
        self.slots[ticket.index].state = State::Free;
        Ok(())
    }

    pub fn available_bytes(&self) -> usize {
        self.byte_budget.saturating_sub(self.queued_bytes())
    }

    /// Storage adapter precondition: all mutable socket references to this
    /// buffer have ended. Failed preparation leaves the socket ownership intact.
    pub fn prepare(
        &mut self,
        ticket: Ticket,
        owner: Owner,
        connection: NonZeroU64,
        offset: usize,
        length: usize,
    ) -> Result<(), Error> {
        self.validate_writer(ticket, owner)?;
        if offset >= self.buffer_bytes || length == 0 || length > self.buffer_bytes {
            return Err(Error::Range);
        }
        if length > super::MAX_TCP_IO_BYTES_PER_CALL
            || length > self.byte_budget.saturating_sub(self.queued_bytes())
        {
            return Err(Error::Budget);
        }
        self.slots[ticket.index].state = State::Pending {
            owner,
            connection,
            range: Range { offset, length },
        };
        Ok(())
    }

    pub fn pending_range(&self, ticket: Ticket, owner: Owner, connection: NonZeroU64) -> Result<Range, Error> {
        match self.slot(ticket)?.state {
            State::Pending { owner: actual, connection: current, range } if actual == owner && current == connection => Ok(range),
            State::Pending { .. } => Err(Error::Connection),
            _ => Err(Error::WrongState),
        }
    }

    /// Complete the frontend's ownership transfer under its publication lock.
    /// Queue insertion and this transition must be one serialized operation;
    /// a pending ticket is never readable by an application.
    pub fn publish(
        &mut self,
        ticket: Ticket,
        owner: Owner,
        connection: NonZeroU64,
    ) -> Result<(), Error> {
        match self.slot(ticket)?.state {
            State::Pending {
                owner: actual,
                connection: current,
                range,
            } => {
                if actual != owner {
                    return Err(Error::WrongOwner);
                }
                if current != connection {
                    return Err(Error::Connection);
                }
                self.slots[ticket.index].state = State::Published { connection, range };
                Ok(())
            }
            _ => Err(Error::WrongState),
        }
    }

    pub fn readable(&self, ticket: Ticket, connection: NonZeroU64) -> Result<Range, Error> {
        match self.slot(ticket)?.state {
            State::Published {
                connection: current,
                range,
            } if current == connection => Ok(range),
            State::Published { .. } => Err(Error::Connection),
            _ => Err(Error::WrongState),
        }
    }

    /// Pin a published range while payload copying occurs outside the metadata
    /// lock. A separate read generation rejects completions from earlier leases
    /// even when the buffer slot itself has not been reused.
    pub fn begin_read(
        &mut self,
        ticket: Ticket,
        connection: NonZeroU64,
        consumer: Owner,
    ) -> Result<(ReadTicket, Range), Error> {
        if !consumer.domain.arena.is_tracked() {
            return Err(Error::UntrackedOwner);
        }
        let range = self.readable(ticket, connection)?;
        let slot = &mut self.slots[ticket.index];
        let generation = slot
            .read_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        slot.read_generation = generation;
        slot.state = State::Reading {
            consumer,
            connection,
            range,
        };
        Ok((
            ReadTicket {
                ticket,
                generation,
                consumer,
                connection,
            },
            range,
        ))
    }

    /// Commit a completed read, or cancel it with length zero after all payload
    /// references have ended. Never accept a stale read lease's completion.
    pub fn finish_read(&mut self, read: ReadTicket, length: usize) -> Result<(), Error> {
        let slot = self.slot(read.ticket)?;
        if slot.read_generation != read.generation {
            return Err(Error::Stale);
        }
        let range = match slot.state {
            State::Reading {
                consumer,
                connection,
                range,
            } if consumer == read.consumer && connection == read.connection => range,
            _ => return Err(Error::WrongState),
        };
        if length > range.length {
            return Err(Error::Range);
        }
        self.slots[read.ticket.index].state = State::Published {
            connection: read.connection,
            range,
        };
        self.consume(read.ticket, read.connection, length)
    }

    /// Advance only after the corresponding application read has finished.
    pub fn consume(
        &mut self,
        ticket: Ticket,
        connection: NonZeroU64,
        length: usize,
    ) -> Result<(), Error> {
        let range = self.readable(ticket, connection)?;
        if length > range.length {
            return Err(Error::Range);
        }
        self.slots[ticket.index].state = if length == range.length {
            State::Free
        } else {
            // Avoid offset + length overflow even for arbitrary buffer sizes.
            let tail = self.buffer_bytes - range.offset;
            let offset = if length >= tail {
                length - tail
            } else {
                range.offset + length
            };
            State::Published {
                connection,
                range: Range {
                    offset,
                    length: range.length - length,
                },
            }
        };
        Ok(())
    }

    /// Roll back a transfer not yet published. Retains the exclusive socket
    /// lease, allowing retry without issuing a second writer for this slot.
    pub fn cancel_pending(&mut self, ticket: Ticket, owner: Owner) -> Result<(), Error> {
        match self.slot(ticket)?.state {
            State::Pending { owner: actual, .. } if actual == owner => {
                self.slots[ticket.index].state = State::Socket(owner);
                Ok(())
            }
            State::Pending { .. } => Err(Error::WrongOwner),
            _ => Err(Error::WrongState),
        }
    }

    /// Release only an unpublished transfer. Pending storage has no socket or
    /// reader references; published data is deliberately refused.
    pub fn discard_pending(&mut self, ticket: Ticket, owner: Owner) -> Result<(), Error> {
        match self.slot(ticket)?.state {
            State::Pending { owner: actual, .. } if actual == owner => {
                self.slots[ticket.index].state = State::Free;
                Ok(())
            }
            State::Pending { .. } => Err(Error::WrongOwner),
            _ => Err(Error::WrongState),
        }
    }

    /// Apply a trusted supervisor's quiescence decision, never revocation alone.
    /// The payload adapter must ensure this exact task can never resume or use
    /// socket references. Published frontend data deliberately survives.
    pub fn retire_stopped_owner(&mut self, owner: Owner) -> usize {
        let mut retired = 0;
        for slot in &mut self.slots {
            let matches = match slot.state {
                State::Socket(actual) | State::Pending { owner: actual, .. } => actual == owner,
                _ => false,
            };
            if matches {
                slot.state = State::Free;
                retired += 1;
            } else if let State::Reading {
                consumer,
                connection,
                range,
            } = slot.state
            {
                if consumer == owner {
                    // The exact stopped reader can never touch the bytes again.
                    // Its uncommitted read consumes nothing and leaves the
                    // frontend's published data intact.
                    slot.state = State::Published { connection, range };
                    retired += 1;
                }
            }
        }
        retired
    }

    pub fn queued_bytes(&self) -> usize {
        self.slots
            .iter()
            .map(|s| match s.state {
                State::Pending { range, .. }
                | State::Published { range, .. }
                | State::Reading { range, .. } => range.length,
                _ => 0,
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_core::heap::{ArenaId, OwnerId};
    fn owner(arena: u64, task: u64) -> Owner {
        Owner {
            domain: AllocationDomain::new(OwnerId::new(7), ArenaId::new(arena)),
            task: TaskRecoveryKey::new(task).unwrap(),
        }
    }
    fn connection(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).unwrap()
    }

    #[test]
    fn published_data_survives_producer_retirement_and_wraps() {
        let mut pool = Ownership::<2>::new(16, 16).unwrap();
        let producer = owner(1, 1);
        let ticket = pool.reserve(producer).unwrap();
        pool.prepare(ticket, producer, connection(1), 14, 8)
            .unwrap();
        assert_eq!(pool.readable(ticket, connection(1)), Err(Error::WrongState));
        pool.publish(ticket, producer, connection(1)).unwrap();
        assert_eq!(
            pool.validate_writer(ticket, producer),
            Err(Error::WrongState)
        );
        assert_eq!(pool.retire_stopped_owner(producer), 0);
        assert_eq!(
            pool.consume(ticket, connection(2), 1),
            Err(Error::Connection)
        );
        assert_eq!(pool.consume(ticket, connection(1), 9), Err(Error::Range));
        pool.consume(ticket, connection(1), 3).unwrap();
        assert_eq!(
            pool.readable(ticket, connection(1)),
            Ok(Range {
                offset: 1,
                length: 5
            })
        );
        assert_eq!(pool.queued_bytes(), 5);
        pool.consume(ticket, connection(1), 5).unwrap();
        assert_eq!(pool.readable(ticket, connection(1)), Err(Error::Stale));
        assert_eq!(pool.queued_bytes(), 0);
    }

    #[test]
    fn exact_task_recovery_retires_unpublished_transfers_only() {
        let mut pool = Ownership::<3>::new(16, 16).unwrap();
        let a = owner(1, 1);
        let same_arena_other_task = owner(1, 2);
        let next_arena = owner(2, 1);
        let first = pool.reserve(a).unwrap();
        let other = pool.reserve(same_arena_other_task).unwrap();
        pool.prepare(first, a, connection(1), 0, 8).unwrap();
        assert_eq!(pool.retire_stopped_owner(next_arena), 0);
        assert_eq!(pool.retire_stopped_owner(a), 1);
        assert_eq!(pool.publish(first, a, connection(1)), Err(Error::Stale));
        assert_eq!(pool.validate_writer(other, same_arena_other_task), Ok(()));
        assert_eq!(pool.queued_bytes(), 0);
    }

    #[test]
    fn stale_pool_slot_generation_and_owner_cannot_change_state() {
        let a = owner(1, 1);
        let b = owner(1, 2);
        let mut pool = Ownership::<1>::new(16, 16).unwrap();
        let mut foreign = Ownership::<1>::new(16, 16).unwrap();
        let old = pool.reserve(a).unwrap();
        let wrong_pool = foreign.reserve(a).unwrap();
        assert_eq!(pool.validate_writer(wrong_pool, a), Err(Error::Stale));
        assert_eq!(
            pool.prepare(old, b, connection(1), 0, 1),
            Err(Error::WrongOwner)
        );
        pool.retire_stopped_owner(a);
        let new = pool.reserve(b).unwrap();
        assert_ne!(old, new);
        assert_eq!(pool.prepare(old, a, connection(1), 0, 1), Err(Error::Stale));
        pool.prepare(new, b, connection(2), 0, 1).unwrap();
        assert_eq!(pool.publish(new, a, connection(2)), Err(Error::WrongOwner));
        assert_eq!(pool.publish(new, b, connection(1)), Err(Error::Connection));
        pool.publish(new, b, connection(2)).unwrap();
        assert_eq!(pool.cancel_pending(new, b), Err(Error::WrongState));
        assert_eq!(pool.publish(new, b, connection(2)), Err(Error::WrongState));
    }

    #[test]
    fn pending_bytes_reserve_budget_and_rollback_restores_writer() {
        let mut pool = Ownership::<3>::new(16, 10).unwrap();
        let a = owner(1, 1);
        let first = pool.reserve(a).unwrap();
        let second = pool.reserve(a).unwrap();
        pool.prepare(first, a, connection(1), 0, 8).unwrap();
        assert_eq!(
            pool.prepare(second, a, connection(1), 0, 3),
            Err(Error::Budget)
        );
        assert_eq!(pool.validate_writer(second, a), Ok(()));
        pool.cancel_pending(first, a).unwrap();
        assert_eq!(pool.validate_writer(first, a), Ok(()));
        assert_eq!(pool.queued_bytes(), 0);
        pool.prepare(second, a, connection(1), 0, 3).unwrap();
        pool.publish(second, a, connection(1)).unwrap();
        assert_eq!(
            pool.prepare(first, a, connection(1), 0, 8),
            Err(Error::Budget)
        );
        pool.consume(second, connection(1), 1).unwrap();
        pool.prepare(first, a, connection(1), 0, 8).unwrap();
        assert_eq!(pool.queued_bytes(), 10);
    }

    #[test]
    fn ranges_per_call_limit_and_exhaustion_fail_closed() {
        let a = owner(1, 1);
        let mut pool = Ownership::<2>::new(65536, 65536).unwrap();
        pool.slots[0].generation = u64::MAX;
        let ticket = pool.reserve(a).unwrap();
        assert_eq!(ticket.index(), 1);
        for (offset, length, error) in [
            (65536, 1, Error::Range),
            (0, 0, Error::Range),
            (0, 65537, Error::Range),
            (0, 32769, Error::Budget),
        ] {
            assert_eq!(
                pool.prepare(ticket, a, connection(1), offset, length),
                Err(error)
            );
            assert_eq!(pool.validate_writer(ticket, a), Ok(()));
        }
        pool.retire_stopped_owner(a);
        pool.slots[1].generation = u64::MAX;
        assert_eq!(pool.reserve(a), Err(Error::Exhausted));
        let mut huge = Ownership::<1>::new(usize::MAX, 16).unwrap();
        let ticket = huge.reserve(a).unwrap();
        huge.prepare(ticket, a, connection(1), usize::MAX - 1, 4)
            .unwrap();
        huge.publish(ticket, a, connection(1)).unwrap();
        huge.consume(ticket, connection(1), 2).unwrap();
        assert_eq!(
            huge.readable(ticket, connection(1)),
            Ok(Range {
                offset: 1,
                length: 2
            })
        );
    }

    #[test]
    fn full_pool_and_untracked_owner_do_not_issue_writers() {
        let mut pool = Ownership::<1>::new(16, 16).unwrap();
        assert_eq!(pool.reserve(owner(0, 1)), Err(Error::UntrackedOwner));
        let a = owner(1, 1);
        let ticket = pool.reserve(a).unwrap();
        assert_eq!(pool.reserve(a), Err(Error::Full));
        pool.prepare(ticket, a, connection(1), 0, 1).unwrap();
        pool.publish(ticket, a, connection(1)).unwrap();
        assert_eq!(pool.reserve(a), Err(Error::Full));
        pool.consume(ticket, connection(1), 1).unwrap();
        assert!(pool.reserve(a).is_ok());
    }
    #[test]
    fn read_lease_pins_bytes_and_rejects_delayed_completion() {
        let mut pool = Ownership::<1>::new(16, 16).unwrap();
        let producer = owner(1, 1);
        let consumer = owner(2, 2);
        let ticket = pool.reserve(producer).unwrap();
        pool.prepare(ticket, producer, connection(1), 14, 6)
            .unwrap();
        pool.publish(ticket, producer, connection(1)).unwrap();
        let (old, range) = pool.begin_read(ticket, connection(1), consumer).unwrap();
        assert_eq!(
            range,
            Range {
                offset: 14,
                length: 6
            }
        );
        assert_eq!(
            pool.consume(ticket, connection(1), 6),
            Err(Error::WrongState)
        );
        assert_eq!(pool.reserve(producer), Err(Error::Full));
        assert_eq!(
            pool.begin_read(ticket, connection(1), consumer),
            Err(Error::WrongState)
        );
        assert_eq!(pool.queued_bytes(), 6);
        assert_eq!(pool.retire_stopped_owner(producer), 0);
        assert_eq!(pool.retire_stopped_owner(owner(2, 3)), 0);
        assert_eq!(pool.retire_stopped_owner(owner(3, 2)), 0);
        assert_eq!(pool.retire_stopped_owner(consumer), 1);
        let (new, _) = pool.begin_read(ticket, connection(1), owner(4, 4)).unwrap();
        assert_ne!(old, new);
        assert_eq!(pool.finish_read(old, 6), Err(Error::Stale));
        assert_eq!(pool.finish_read(new, 7), Err(Error::Range));
        pool.finish_read(new, 3).unwrap();
        assert_eq!(
            pool.readable(ticket, connection(1)),
            Ok(Range {
                offset: 1,
                length: 3
            })
        );
    }

    #[test]
    fn read_generation_exhaustion_never_reissues_a_lease() {
        let mut pool = Ownership::<1>::new(16, 16).unwrap();
        let a = owner(1, 1);
        let ticket = pool.reserve(a).unwrap();
        pool.prepare(ticket, a, connection(1), 0, 1).unwrap();
        pool.publish(ticket, a, connection(1)).unwrap();
        assert_eq!(
            pool.begin_read(ticket, connection(1), owner(0, 1)),
            Err(Error::UntrackedOwner)
        );
        pool.slots[0].read_generation = u64::MAX;
        assert_eq!(
            pool.begin_read(ticket, connection(1), a),
            Err(Error::Exhausted)
        );
        assert_eq!(
            pool.readable(ticket, connection(1)),
            Ok(Range {
                offset: 0,
                length: 1
            })
        );
    }
    #[test]
    fn releasing_unused_writer_checks_owner_state_and_generation() {
        let mut pool = Ownership::<1>::new(16, 16).unwrap();
        let a = owner(1, 1);
        let first = pool.reserve(a).unwrap();
        assert_eq!(
            pool.release_writer(first, owner(1, 2)),
            Err(Error::WrongOwner)
        );
        pool.release_writer(first, a).unwrap();
        let next = pool.reserve(a).unwrap();
        assert_eq!(pool.release_writer(first, a), Err(Error::Stale));
        pool.prepare(next, a, connection(1), 0, 4).unwrap();
        assert_eq!(pool.release_writer(next, a), Err(Error::WrongState));
        pool.publish(next, a, connection(1)).unwrap();
        assert_eq!(pool.release_writer(next, a), Err(Error::WrongState));
        assert_eq!(pool.available_bytes(), 12);
    }
}
