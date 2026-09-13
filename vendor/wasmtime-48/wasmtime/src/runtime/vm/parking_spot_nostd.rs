//! Wait/notify for shared memories without `std`.
//!
//! Waiters are recorded in a fixed table of copy-only scalars; nothing owned
//! by the embedder is stored here. A waiting guest thread suspends its async
//! fiber; `notify` marks the waiter and asks the embedder to wake its token.

#![deny(missing_docs)]

use crate::prelude::*;
use crate::runtime::vm::WaitResult;
use crate::runtime::vm::threads::ThreadHooks;
use crate::sync::RwLock;
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::SeqCst};
use core::task::Poll;
use core::time::Duration;

/// Maximum number of simultaneously suspended waiters per shared memory.
pub const MAX_WAITERS: usize = 16;

#[derive(Clone, Copy, Debug)]
struct Waiter {
    key: u64,
    token: [usize; 2],
    notified: bool,
    seq: u64,
}

#[derive(Debug)]
struct Table {
    slots: [Option<Waiter>; MAX_WAITERS],
    next_seq: u64,
}

/// The per-memory waiter table.
#[derive(Debug)]
pub struct ParkingSpot {
    inner: RwLock<Table>,
}

impl Default for ParkingSpot {
    fn default() -> Self {
        Self {
            inner: RwLock::new(Table {
                slots: [None; MAX_WAITERS],
                next_seq: 0,
            }),
        }
    }
}

struct Registration<'a> {
    spot: &'a ParkingSpot,
    seq: u64,
    armed: bool,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.spot.remove(self.seq);
        }
    }
}

impl ParkingSpot {
    /// Atomically validates `atomic == expected` and, if so, suspends the
    /// current guest thread until notified or until `timeout` elapses.
    pub async fn wait32(
        &self,
        atomic: &AtomicU32,
        expected: u32,
        timeout: Option<Duration>,
        hooks: &dyn ThreadHooks,
    ) -> Result<WaitResult> {
        self.wait(
            atomic.as_ptr() as u64,
            || atomic.load(SeqCst) == expected,
            timeout,
            hooks,
        )
        .await
    }

    /// Same as `wait32`, but for 64-bit values.
    pub async fn wait64(
        &self,
        atomic: &AtomicU64,
        expected: u64,
        timeout: Option<Duration>,
        hooks: &dyn ThreadHooks,
    ) -> Result<WaitResult> {
        self.wait(
            atomic.as_ptr() as u64,
            || atomic.load(SeqCst) == expected,
            timeout,
            hooks,
        )
        .await
    }

    async fn wait(
        &self,
        key: u64,
        validate: impl FnOnce() -> bool,
        timeout: Option<Duration>,
        hooks: &dyn ThreadHooks,
    ) -> Result<WaitResult> {
        let seq = {
            let mut table = self.inner.write();
            // The validation happens under the table lock, so a concurrent
            // `notify` either sees this waiter or happens before the load.
            if !validate() {
                return Ok(WaitResult::Mismatch);
            }
            let Some(slot) = table.slots.iter().position(Option::is_none) else {
                bail!("atomic wait table exhausted ({MAX_WAITERS} waiters)");
            };
            let seq = table.next_seq;
            table.next_seq += 1;
            table.slots[slot] = Some(Waiter {
                key,
                token: hooks.current(),
                notified: false,
                seq,
            });
            seq
        };
        let mut registration = Registration {
            spot: self,
            seq,
            armed: true,
        };
        let timeout_ns = timeout.map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        let mut timer: Option<Pin<Box<dyn Future<Output = ()> + Send>>> = None;
        let result = poll_fn(|cx| {
            if self.take_notified(seq) {
                return Poll::Ready(WaitResult::Ok);
            }
            if let Some(ns) = timeout_ns {
                let timer = timer.get_or_insert_with(|| hooks.sleep(ns));
                if timer.as_mut().poll(cx).is_ready() {
                    // Notify may have raced the timer; prefer the notification
                    // so a notified count is never lost.
                    return Poll::Ready(if self.take_notified(seq) {
                        WaitResult::Ok
                    } else {
                        self.remove(seq);
                        WaitResult::TimedOut
                    });
                }
            }
            Poll::Pending
        })
        .await;
        registration.armed = false;
        Ok(result)
    }

    fn take_notified(&self, seq: u64) -> bool {
        let mut table = self.inner.write();
        match table.slots.iter().position(|w| w.is_some_and(|w| w.seq == seq)) {
            Some(index) if table.slots[index].unwrap().notified => {
                table.slots[index] = None;
                true
            }
            _ => false,
        }
    }

    fn remove(&self, seq: u64) {
        let mut table = self.inner.write();
        if let Some(index) = table.slots.iter().position(|w| w.is_some_and(|w| w.seq == seq)) {
            table.slots[index] = None;
        }
    }

    /// Notify at most `n` threads waiting on `addr`, in arrival order.
    ///
    /// Returns the number of threads notified.
    pub fn notify<T>(&self, addr: &T, n: u32, hooks: Option<&dyn ThreadHooks>) -> u32 {
        if n == 0 {
            return 0;
        }
        let key = addr as *const _ as u64;
        let mut tokens = [None; MAX_WAITERS];
        let mut count = 0u32;
        {
            let mut table = self.inner.write();
            loop {
                let next = table
                    .slots
                    .iter()
                    .enumerate()
                    .filter(|(_, w)| w.is_some_and(|w| w.key == key && !w.notified))
                    .min_by_key(|(_, w)| w.unwrap().seq)
                    .map(|(i, _)| i);
                let Some(index) = next else { break };
                let waiter = table.slots[index].as_mut().unwrap();
                waiter.notified = true;
                tokens[count as usize] = Some(waiter.token);
                count += 1;
                if count == n {
                    break;
                }
            }
        }
        // Wake outside the table lock: the embedder may take scheduler locks.
        if let Some(hooks) = hooks {
            for token in tokens.iter().flatten() {
                hooks.wake(*token);
            }
        }
        count
    }
}
