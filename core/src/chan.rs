//! Typed asynchronous channels — the only IPC primitive in VibeOS.
//!
//! There is no `read(fd, buf, n)` and no ioctl. Components exchange *typed
//! messages*; the compiler checks the protocol, and the capability's rights
//! decide which end of the channel you are.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

use crate::cap::Resource;
use crate::exec::WaitQueue;
use crate::heap::{self, OwnerId};
use crate::sync::SpinLock;

struct Inner<T> {
    queue: VecDeque<T>,
    sent: u64,
    received: u64,
}

/// A bounded, typed, multi-producer/multi-consumer endpoint.
///
/// One object serves both directions: hold it with `SEND` and you can push,
/// hold it with `RECV` and you can pull. Attenuating a cap to `SEND` alone is
/// how you hand out a write-only pipe.
pub struct Endpoint<T: Send + 'static> {
    name: String,
    bound: usize,
    inner: SpinLock<Inner<T>>,
    on_message: Arc<WaitQueue>,
    on_space: WaitQueue,
}

impl<T: Send + 'static> Endpoint<T> {
    pub fn new(name: &str, bound: usize) -> Arc<Self> {
        // The endpoint and its bounded queue are shared runtime metadata, not
        // memory that becomes invalid with whichever component created it.
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let endpoint = Arc::new(Self {
            name: String::from(name),
            bound,
            // A bounded channel never needs to grow while its queue lock is
            // held.  Besides making the bound a physical reservation, this
            // keeps an allocation failure from abandoning the shared lock via
            // the task fault landing pad.
            inner: SpinLock::new(Inner {
                queue: VecDeque::with_capacity(bound),
                sent: 0,
                received: 0,
            }),
            on_message: Arc::new(WaitQueue::new()),
            on_space: WaitQueue::new(),
        });
        system.restore();
        endpoint
    }

    /// Notification only; this handle cannot read messages or bypass authority.
    /// Signals empty-to-nonempty transitions, not individual messages.
    /// Construct its listener before checking has_message under live authority.
    pub fn message_event(&self) -> MessageEvent { MessageEvent(self.on_message.clone()) }
    /// Producer-side hint that external input may be ready. Consumers must
    /// still check their capability and queue; this does not publish a message.
    pub(crate) fn notify_input(&self) { self.on_message.wake_all(); }
    pub fn has_message(&self) -> bool { !self.inner.lock().queue.is_empty() }

    pub fn try_send(&self, msg: T) -> Result<(), T> {
        let mut i = self.inner.lock();
        if i.queue.len() >= self.bound {
            crate::net_profile::queue(&self.name, i.queue.len(), true);
            return Err(msg);
        }
        let was_empty = i.queue.is_empty();
        i.queue.push_back(msg);
        crate::net_profile::queue(&self.name, i.queue.len(), false);
        i.sent += 1;
        drop(i);
        // Waiters may park only after observing empty. Wake all on that
        // transition; additional queued messages need no additional signal.
        if was_empty { self.on_message.wake_all(); }
        Ok(())
    }

    /// Move at most `limit` occupied slots, preserving order and all unsent
    /// ownership. Bounded metadata only: no callback or allocation under lock.
    #[cfg(feature = "rx-publish-batch")]
    pub fn try_send_batch(&self, messages: &mut [Option<T>], limit: usize) -> usize {
        assert!(messages.len() <= 32, "bounded batch required");
        if limit == 0 || messages.is_empty() { return 0; }
        let mut inner = self.inner.lock();
        let was_empty = inner.queue.is_empty();
        let mut sent = 0;
        for message in messages {
            if message.is_none() { continue; }
            if sent == limit { break; }
            if inner.queue.len() == self.bound {
                crate::net_profile::queue(&self.name, inner.queue.len(), true);
                break;
            }
            inner.queue.push_back(message.take().unwrap());
            inner.sent += 1;
            sent += 1;
        }
        crate::net_profile::queue(&self.name, inner.queue.len(), false);
        drop(inner);
        if was_empty && sent != 0 { self.on_message.wake_all(); }
        sent
    }

    /// Backpressure is a first-class await, not an `EAGAIN` the caller may ignore.
    pub async fn send(&self, msg: T) {
        let mut pending = msg;
        loop {
            // Prepare the listener before checking queue capacity. If a
            // receiver creates space between these two operations, the
            // listener's epoch records that wake and the await completes.
            let space = self.on_space.wait();
            match self.try_send(pending) {
                Ok(()) => return,
                Err(m) => {
                    pending = m;
                    space.await;
                }
            }
        }
    }

    pub fn try_recv(&self) -> Option<T> {
        let mut i = self.inner.lock();
        let was_full = i.queue.len() == self.bound;
        let msg = i.queue.pop_front()?;
        i.received += 1;
        drop(i);
        // A blocked sender observed full. Its listener predates that check,
        // so a single full-to-space signal also covers not-yet-polled waiters.
        if was_full { self.on_space.wake_all(); }
        Some(msg)
    }

    /// Keep identifiers queued until durable DMA ownership has been recorded.
    /// Callback must not allocate, await, reenter a queue, or reverse lock order.
    /// After a callback task fault, recover the lock only once its domain is
    /// permanently quiescent; uncommitted identifiers remain in the queue.
    #[cfg(feature = "rx-admission-batch")]
    pub(crate) unsafe fn admit_prefix<R>(&self, limit: usize,
        admit: impl FnOnce(&[Option<T>; 8], usize) -> R) -> Option<R> where T: Copy {
        let mut inner = self.inner.lock();
        let count = inner.queue.len().min(limit).min(8);
        if count == 0 { return None; }
        let was_full = inner.queue.len() == self.bound;
        let prefix = core::array::from_fn(|i| if i < count { inner.queue.get(i).copied() } else { None });
        let result = admit(&prefix, count);
        for _ in 0..count { inner.queue.pop_front(); }
        inner.received += count as u64;
        drop(inner);
        if was_full { self.on_space.wake_all(); }
        Some(result)
    }

    #[cfg(feature = "rx-admission-batch")]
    pub(crate) unsafe fn recover_admission(&self, domain: heap::AllocationDomain) {
        let _ = self.inner.recover_after_fault(domain);
    }

    pub async fn recv(&self) -> T {
        loop {
            // See send: listener-before-check closes the IRQ/producer race.
            let message = self.on_message.wait();
            if let Some(m) = self.try_recv() {
                return m;
            }
            message.await;
        }
    }

    pub fn stats(&self) -> (u64, u64, usize) {
        let i = self.inner.lock();
        (i.sent, i.received, i.queue.len())
    }
}

impl<T: Send + 'static> Resource for Endpoint<T> {
    fn kind(&self) -> &'static str {
        "endpoint"
    }
    fn describe(&self) -> String {
        let (sent, recv, depth) = self.stats();
        format!(
            "{} [{}/{} sent={} recv={}]",
            self.name, depth, self.bound, sent, recv
        )
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Owned notification lifetime for selecting queue input alongside an IRQ.
/// A wake is only a hint: revalidate authority and retry the queue operation.
pub struct MessageEvent(Arc<WaitQueue>);
impl MessageEvent {
    /// Wrap a notification queue; this handle grants no access to resource data.
    pub fn from_queue(queue: Arc<WaitQueue>) -> Self { Self(queue) }
    pub fn wait(&self) -> crate::exec::WaitFuture<'_> { self.0.wait() }
}
