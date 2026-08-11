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
    on_message: WaitQueue,
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
            on_message: WaitQueue::new(),
            on_space: WaitQueue::new(),
        });
        system.restore();
        endpoint
    }

    pub fn try_send(&self, msg: T) -> Result<(), T> {
        let mut i = self.inner.lock();
        if i.queue.len() >= self.bound {
            return Err(msg);
        }
        i.queue.push_back(msg);
        i.sent += 1;
        drop(i);
        self.on_message.wake_all();
        Ok(())
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
        let msg = i.queue.pop_front()?;
        i.received += 1;
        drop(i);
        self.on_space.wake_all();
        Some(msg)
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
