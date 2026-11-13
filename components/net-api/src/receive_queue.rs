//! Ordered copied/exchanged receive stream. Serialized by the listener lock.
use super::{
    receive_ownership::{Error, Owner, Ticket},
    receive_storage::Storage,
};
use alloc::collections::VecDeque;
use core::num::NonZeroU64;

enum Chunk {
    Copied(usize),
    Exchanged {
        ticket: Ticket,
        connection: NonZeroU64,
        length: usize,
    },
}
pub(crate) struct Queue<const N: usize> {
    pool: &'static Storage<N>,
    copied: VecDeque<u8>,
    chunks: VecDeque<Chunk>,
    length: usize,
    capacity: usize,
}
impl<const N: usize> Queue<N> {
    pub fn new(pool: &'static Storage<N>, capacity: usize, copied: VecDeque<u8>) -> Self {
        assert!(copied.is_empty() && copied.capacity() >= capacity);
        Self {
            pool,
            copied,
            chunks: VecDeque::with_capacity(2 * N + 1),
            length: 0,
            capacity,
        }
    }
    pub fn pool(&self) -> &'static Storage<N> {
        self.pool
    }
    pub fn len(&self) -> usize {
        self.length
    }
    pub fn push_copy(&mut self, input: &[u8]) -> usize {
        let length = input
            .len()
            .min(self.capacity - self.length)
            .min(super::MAX_TCP_IO_BYTES_PER_CALL);
        if length == 0 {
            return 0;
        }
        if let Some(Chunk::Copied(count)) = self.chunks.back_mut() {
            *count += length;
        } else {
            // At most N exchange chunks, with copied runs between/around them.
            if self.chunks.len() == self.chunks.capacity() {
                return 0;
            }
            self.chunks.push_back(Chunk::Copied(length));
        }
        self.copied.extend(&input[..length]);
        self.length += length;
        length
    }
    pub fn publish(
        &mut self,
        ticket: Ticket,
        owner: Owner,
        connection: NonZeroU64,
    ) -> Result<usize, Error> {
        if self.chunks.len() == self.chunks.capacity() {
            return Err(Error::Budget);
        }
        // Admission and the committed range length must refer to the same
        // metadata state, rather than two independently locked observations.
        let length =
            self.pool
                .publish_bounded(ticket, owner, connection, self.capacity - self.length)?;
        // Capacity was reserved at construction; insertion allocates nothing.
        // Hard-fault recovery between these two publications is not yet wired.
        self.chunks.push_back(Chunk::Exchanged {
            ticket,
            connection,
            length,
        });
        self.length += length;
        Ok(length)
    }
    pub fn read(&mut self, consumer: Owner, output: &mut [u8]) -> Result<usize, Error> {
        let Some(front) = self.chunks.front_mut() else {
            return Ok(0);
        };
        let (read, remaining) = match front {
            Chunk::Copied(remaining) => {
                let length = (*remaining)
                    .min(output.len())
                    .min(super::MAX_TCP_IO_BYTES_PER_CALL);
                let (first, second) = self.copied.as_slices();
                let prefix = length.min(first.len());
                output[..prefix].copy_from_slice(&first[..prefix]);
                output[prefix..length].copy_from_slice(&second[..length - prefix]);
                self.copied.drain(..length);
                *remaining -= length;
                (length, *remaining)
            }
            Chunk::Exchanged {
                ticket,
                connection,
                length,
            } => {
                let maximum = output.len().min(*length);
                let count =
                    self.pool
                        .read(*ticket, *connection, consumer, &mut output[..maximum])?;
                *length -= count;
                (count, *length)
            }
        };
        self.length -= read;
        if remaining == 0 {
            self.chunks.pop_front();
        }
        Ok(read)
    }
    pub fn clear(&mut self) -> Result<(), Error> {
        while let Some(front) = self.chunks.front() {
            match front {
                Chunk::Copied(count) => {
                    self.copied.drain(..*count);
                    self.length -= count;
                }
                Chunk::Exchanged {
                    ticket,
                    connection,
                    length,
                } => {
                    self.pool.discard_published(*ticket, *connection)?;
                    self.length -= length;
                }
            }
            self.chunks.pop_front();
        }
        Ok(())
    }
}

impl<const N: usize> Drop for Queue<N> {
    fn drop(&mut self) {
        // Normal destruction only: the listener's last reference is gone.
        // Validate every ticket independently so one stale/pinned chunk cannot
        // prevent releasing other published ranges. Never retire whole owners.
        for chunk in self.chunks.drain(..) {
            if let Chunk::Exchanged {
                ticket, connection, ..
            } = chunk
            {
                // Reading or invalid metadata is not permission to free a slot.
                // Skipped Drop/abandoned locks still require supervisor recovery.
                let _ = self.pool.discard_published(ticket, connection);
            }
        }
    }
}
