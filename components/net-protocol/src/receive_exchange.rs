//! Experimental socket-buffer/persistent-pool binding. Not enabled by firmware.
//! The supervisor must retain pool ownership independently of the task arena.
//! No automatic Drop releases writers: a socket may still hold their references.
use core::num::NonZeroU64;
use smoltcp::socket::tcp;
use vibeos_net_api::{
    receive_ownership::{Error, Owner, Ticket},
    receive_storage::Storage,
};

// Diagnostic-only first-refusal counters. The selected reason is exclusive;
// later conditions may also have refused the same attempt. Counts and pending
// bytes are separate so short/control traffic does not dominate interpretation.
#[cfg(feature = "receive-exchange-profile")]
static ATTEMPTS: [core::sync::atomic::AtomicU64; 16] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 16];

#[cfg(feature = "receive-exchange-profile")]
pub fn attempt_stats() -> [u64; 16] {
    core::array::from_fn(|i| ATTEMPTS[i].load(core::sync::atomic::Ordering::Relaxed))
}

#[inline]
fn record(reason: usize, bytes: usize) {
    #[cfg(feature = "receive-exchange-profile")]
    {
        ATTEMPTS[reason * 2].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        ATTEMPTS[reason * 2 + 1].fetch_add(bytes as u64, core::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(not(feature = "receive-exchange-profile"))]
    let _ = (reason, bytes);
}

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
        if length == 0 { record(0, length); return Ok(None); }
        if length > max_bytes { record(1, length); return Ok(None); }
        if length > vibeos_net_api::MAX_TCP_RECEIVE_TRANSFER_BYTES {
            record(2, length); return Ok(None);
        }
        let limit = max_bytes
            .min(vibeos_net_api::MAX_TCP_RECEIVE_TRANSFER_BYTES)
            .min(self.pool.available_bytes());
        if length > limit { record(3, length); return Ok(None); }
        let (old_pointer, capacity) = self.pool.writer_address(self.current, self.owner)?;
        let (next, replacement) = match Self::reserve_buffer(self.pool, self.owner) {
            Ok(value) => value,
            Err(Error::Full) => { record(4, length); return Ok(None); }
            Err(error) => { record(7, length); return Err(error); }
        };
        let received = match socket.exchange_receive_buffer(replacement, limit) {
            Ok(buffer) => buffer,
            Err(unused) => {
                // The failed exchange never installed this spare in the socket.
                drop(unused);
                unsafe {
                    self.pool.release_writer(next, self.owner)?;
                }
                record(5, length);
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
        record(6, length);
        Ok(Some(Transfer {
            ticket: old,
            length,
        }))
    }
}
