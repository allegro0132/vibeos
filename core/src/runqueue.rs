//! Allocation-controlled per-hart ready queues.
//!
//! M5.1 keeps execution on physical hart 0, but makes ready ownership a real
//! four-hart scheduler property. The queue layer is deliberately independent
//! from futures and lifecycle state so its steal/capacity rules can be tested
//! exhaustively on the host. M5.2 can use the returned owner hart to decide
//! whether a cross-hart enqueue needs an IPI.

extern crate alloc;

use alloc::collections::{TryReserveError, VecDeque};

pub const MAX_HARTS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HartId(u8);

impl HartId {
    pub const BOOT: Self = Self(0);

    pub const fn new(index: usize) -> Option<Self> {
        if index < MAX_HARTS {
            Some(Self(index as u8))
        } else {
            None
        }
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HartRunQueueStats {
    pub queued: usize,
    pub dispatches: u64,
    pub steals: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunQueueDispatch<T> {
    pub task: T,
    pub source: HartId,
    pub executor: HartId,
    pub stolen: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueError {
    Duplicate,
    CapacityExhausted,
}

/// Four ready queues protected by the executor's scheduler lock.
///
/// `reserve_live_bound` is the allocation boundary. Once it succeeds, every
/// live task may be enqueued on any one hart without growing a queue, including
/// from an IRQ wake path or after ownership migrates through stealing.
pub struct RunQueues<T> {
    queues: [VecDeque<ReadyEntry<T>>; MAX_HARTS],
    dispatches: [u64; MAX_HARTS],
    steals: [u64; MAX_HARTS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReadyEntry<T> {
    task: T,
    stealable: bool,
}

impl<T> RunQueues<T> {
    pub const fn new() -> Self {
        Self {
            queues: [const { VecDeque::new() }; MAX_HARTS],
            dispatches: [0; MAX_HARTS],
            steals: [0; MAX_HARTS],
        }
    }

    pub fn reserve_live_bound(&mut self, live_bound: usize) -> Result<(), TryReserveError> {
        for queue in &mut self.queues {
            if queue.capacity() < live_bound {
                queue.try_reserve(live_bound.saturating_sub(queue.len()))?;
            }
        }
        Ok(())
    }

    pub fn capacity(&self, hart: HartId) -> usize {
        self.queues[hart.index()].capacity()
    }

    pub fn min_capacity(&self) -> usize {
        self.queues
            .iter()
            .map(VecDeque::capacity)
            .min()
            .unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.queues.iter().map(VecDeque::len).sum()
    }

    pub fn queued_on(&self, hart: HartId) -> usize {
        self.queues[hart.index()].len()
    }

    /// A hart is idle only when it has no local work and cannot steal any
    /// remote work. This is the predicate an M5.2 IPI gate can sample.
    pub fn hart_idle(&self, hart: HartId) -> bool {
        let local = hart.index();
        self.queues[local].is_empty()
            && self
                .queues
                .iter()
                .enumerate()
                .all(|(index, queue)| index == local || queue.iter().all(|entry| !entry.stealable))
    }

    pub fn stats(&self) -> [HartRunQueueStats; MAX_HARTS] {
        let mut stats = [HartRunQueueStats::default(); MAX_HARTS];
        for (index, stat) in stats.iter_mut().enumerate() {
            *stat = HartRunQueueStats {
                queued: self.queues[index].len(),
                dispatches: self.dispatches[index],
                steals: self.steals[index],
            };
        }
        stats
    }
}

impl<T: Copy + Eq> RunQueues<T> {
    pub fn entries(&self) -> impl Iterator<Item = (HartId, T, bool)> + '_ {
        self.queues.iter().enumerate().flat_map(|(index, queue)| {
            let hart = HartId::new(index).expect("queue index is a valid hart");
            queue
                .iter()
                .map(move |entry| (hart, entry.task, entry.stealable))
        })
    }

    pub fn contains(&self, task: T) -> bool {
        self.queues
            .iter()
            .any(|queue| queue.iter().any(|entry| entry.task == task))
    }

    pub fn owner(&self, task: T) -> Option<HartId> {
        self.queues.iter().enumerate().find_map(|(index, queue)| {
            queue
                .iter()
                .any(|entry| entry.task == task)
                .then(|| HartId::new(index).expect("queue index is a valid hart"))
        })
    }

    /// Enqueue without allocation. Callers must have reserved the global live
    /// bound before an IRQ-visible task is published.
    pub fn enqueue(&mut self, owner: HartId, task: T, stealable: bool) -> Result<(), EnqueueError> {
        if self.contains(task) {
            return Err(EnqueueError::Duplicate);
        }
        let queue = &mut self.queues[owner.index()];
        if queue.len() >= queue.capacity() {
            return Err(EnqueueError::CapacityExhausted);
        }
        queue.push_back(ReadyEntry { task, stealable });
        Ok(())
    }

    pub fn remove(&mut self, owner: HartId, task: T) -> bool {
        let queue = &mut self.queues[owner.index()];
        let Some(index) = queue.iter().position(|candidate| candidate.task == task) else {
            return false;
        };
        queue.remove(index);
        true
    }

    /// Prefer local FIFO work, then steal from the back of remote queues in a
    /// deterministic cyclic order. Stealing from the back minimizes contention
    /// with a future owner hart consuming its own front.
    pub fn dispatch(&mut self, executor: HartId) -> Option<RunQueueDispatch<T>> {
        let executor_index = executor.index();
        if let Some(entry) = self.queues[executor_index].pop_front() {
            self.dispatches[executor_index] = self.dispatches[executor_index].saturating_add(1);
            return Some(RunQueueDispatch {
                task: entry.task,
                source: executor,
                executor,
                stolen: false,
            });
        }

        for offset in 1..MAX_HARTS {
            let source_index = (executor_index + offset) % MAX_HARTS;
            let candidate = self.queues[source_index]
                .iter()
                .rposition(|entry| entry.stealable);
            if let Some(entry) = candidate.and_then(|index| self.queues[source_index].remove(index))
            {
                self.dispatches[executor_index] = self.dispatches[executor_index].saturating_add(1);
                self.steals[executor_index] = self.steals[executor_index].saturating_add(1);
                return Some(RunQueueDispatch {
                    task: entry.task,
                    source: HartId::new(source_index).expect("queue index is a valid hart"),
                    executor,
                    stolen: true,
                });
            }
        }
        None
    }
}

impl<T> Default for RunQueues<T> {
    fn default() -> Self {
        Self::new()
    }
}
