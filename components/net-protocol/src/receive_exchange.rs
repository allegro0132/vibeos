//! Experimental socket-buffer/persistent-pool binding. Not enabled by firmware.
//! The supervisor must retain pool ownership independently of the task arena.
//! No automatic Drop releases writers: a socket may still hold their references.
use core::num::NonZeroU64;
use smoltcp::socket::tcp;
use vibeos_net_api::{
    receive_ownership::{Error, Owner, Ticket},
    receive_storage::Storage,
};

#[derive(Debug)]
pub struct Transfer {
    pub ticket: Ticket,
    pub length: usize,
}

pub struct Binding<const N: usize> {
    pool: &'static Storage<N>,
    owner: Owner,
    current: Ticket,
}
impl<const N: usize> Binding<N> {
    /// Create one exclusive writer for a new socket. The returned buffer must
    /// be installed in that socket before exchanging. Lost bindings retain
    /// their slot until the supervisor proves exact-task quiescence.
    pub fn new(
        pool: &'static Storage<N>,
        owner: Owner,
    ) -> Result<(Self, tcp::SocketBuffer<'static>), Error> {
        let (current, buffer) = Self::reserve_buffer(pool, owner)?;
        Ok((
            Self {
                pool,
                owner,
                current,
            },
            buffer,
        ))
    }

    fn reserve_buffer(
        pool: &'static Storage<N>,
        owner: Owner,
    ) -> Result<(Ticket, tcp::SocketBuffer<'static>), Error> {
        let ticket = pool.reserve(owner)?;
        let (pointer, length) = pool.writer_address(ticket, owner)?;
        // This fresh slot has one writer. Permanent backing outlives the
        // socket; prepare/release require all such references to have ended.
        let bytes = unsafe { core::slice::from_raw_parts_mut(pointer.as_ptr(), length) };
        Ok((ticket, tcp::SocketBuffer::new(bytes)))
    }

    /// Drop bytes rejected by frontend publication, without touching the
    /// replacement buffer now owned by the socket or any published range.
    pub fn discard_unpublished(&self, transfer: Transfer) -> Result<(), Error> {
        self.pool.discard_pending(transfer.ticket, self.owner)
    }

    /// # Safety
    /// The matching socket/buffer and all its references must have been dropped.
    pub unsafe fn release_writer(self) -> Result<(), Error> {
        unsafe { self.pool.release_writer(self.current, self.owner) }
    }

    /// Try exchanging the entire readable ring. None leaves its bytes in the
    /// socket for ordinary copied receive, without retaining an unused spare.
    /// Success returns an unpublished transfer; publication remains subject to
    /// the frontend connection check and queue transaction.
    ///
    /// # Safety
    /// `socket` must own this binding's current receive buffer exclusively.
    /// The calling task must match owner and remain live throughout the call.
    /// Serialize producers/publication for this listener, so the byte budget
    /// cannot be spent by another producer between admission and preparation.
    /// If an error is returned after exchange, abort the stream and retire its
    /// task-owned slots after quiescence; do not silently retry copied receive.
    pub unsafe fn exchange(
        &mut self,
        socket: &mut tcp::Socket<'static>,
        connection: NonZeroU64,
        max_bytes: usize,
    ) -> Result<Option<Transfer>, Error> {
        let length = socket.recv_queue();
        let limit = max_bytes
            .min(vibeos_net_api::MAX_TCP_IO_BYTES_PER_CALL)
            .min(self.pool.available_bytes());
        if length == 0 || length > limit {
            return Ok(None);
        }
        let (old_pointer, capacity) = self.pool.writer_address(self.current, self.owner)?;
        let (next, replacement) = match Self::reserve_buffer(self.pool, self.owner) {
            Ok(value) => value,
            Err(Error::Full) => return Ok(None),
            Err(error) => return Err(error),
        };
        let received = match socket.exchange_receive_buffer(replacement, limit) {
            Ok(buffer) => buffer,
            Err(unused) => {
                // The failed exchange never installed this spare in the socket.
                drop(unused);
                unsafe {
                    self.pool.release_writer(next, self.owner)?;
                }
                return Ok(None);
            }
        };
        let old = self.current;
        self.current = next;
        let offset = (received.get_allocated(0, length).as_ptr() as usize)
            .checked_sub(old_pointer.as_ptr() as usize)
            .filter(|offset| *offset < capacity);
        let actual_length = received.len();
        // End the outgoing ring's mutable borrow before freezing its bytes.
        drop(received);
        let offset = offset.ok_or(Error::Range)?;
        if actual_length != length {
            return Err(Error::Range);
        }
        unsafe {
            self.pool
                .prepare(old, self.owner, connection, offset, length)?;
        }
        Ok(Some(Transfer {
            ticket: old,
            length,
        }))
    }
}
