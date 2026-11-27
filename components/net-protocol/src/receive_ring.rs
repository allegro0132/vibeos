//! Share a detached TCP receive ring until its last consumer releases it.
use crate::wipe::bytes as wipe;
use alloc::{sync::Arc, vec};
use smoltcp::socket::tcp;
use vibeos_core::sync::SpinLock;

type Ring = tcp::SocketBuffer<'static>;
type Pool = Arc<SpinLock<Option<Ring>>>;

struct Received {
    ring: Option<Ring>,
    pool: Pool,
}
impl Drop for Received {
    fn drop(&mut self) {
        let mut ring = self.ring.take().unwrap();
        while !ring.is_empty() {
            wipe(ring.dequeue_many(ring.len()));
        }
        ring.clear();
        *self.pool.lock() = Some(ring);
    }
}
#[derive(Clone)]
pub struct Span {
    source: Arc<Received>,
    offset: usize,
    len: usize,
}
impl Span {
    pub fn bytes(&self) -> &[u8] {
        self.source
            .ring
            .as_ref()
            .unwrap()
            .get_allocated(self.offset, self.len)
    }
}

impl Span {
    pub fn prefix(&self, bytes: &[u8]) -> Option<Self> {
        let offered = self.bytes();
        (core::ptr::eq(offered.as_ptr(), bytes.as_ptr()) && bytes.len() <= offered.len()).then(
            || Self {
                source: self.source.clone(),
                offset: self.offset,
                len: bytes.len(),
            },
        )
    }

    pub fn consume(&mut self, n: usize) {
        assert!(n <= self.len);
        self.offset += n;
        self.len -= n;
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub struct ReceivePool(Pool);
impl ReceivePool {
    pub fn new(capacity: usize) -> Self {
        Self(Arc::new(SpinLock::new(Some(Ring::new(vec![0; capacity])))))
    }
    pub fn exchange(&self, socket: &mut tcp::Socket<'static>) -> Option<Span> {
        let mut spare = self.0.lock();
        let empty = spare.take()?;
        match socket.exchange_receive_buffer(empty, socket.recv_capacity()) {
            Ok(ring) => {
                let len = ring.len();
                Some(Span {
                    source: Arc::new(Received {
                        ring: Some(ring),
                        pool: self.0.clone(),
                    }),
                    offset: 0,
                    len,
                })
            }
            Err(empty) => {
                *spare = Some(empty);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_matches_only_the_offered_prefix_and_pins_the_ring_through_cancellation() {
        let pool = Arc::new(SpinLock::new(None));
        let mut ring = Ring::new(vec![0; 32]);
        assert_eq!(ring.enqueue_slice(b"0123456789abcdefgh"), 18);
        let span = Span {
            source: Arc::new(Received {
                ring: Some(ring),
                pool: pool.clone(),
            }),
            offset: 10,
            len: 8,
        };

        assert!(span.prefix(b"abcd").is_none());
        assert!(span.prefix(&span.bytes()[1..]).is_none());
        let job = span.prefix(&span.bytes()[..4]).unwrap();
        drop(span);
        assert!(pool.lock().is_none());
        assert_eq!(job.bytes(), b"abcd");
        drop(job);
        let mut reused = pool.lock().take().unwrap();
        assert!(reused.is_empty());
        reused.enqueue_unallocated(18);
        assert_eq!(reused.get_allocated(0, 18), &[0; 18]);
    }
}
