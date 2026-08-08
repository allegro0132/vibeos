//! Interrupt-safe spinlock. VibeOS runs one hart in v0.1, so the real job of
//! this lock is to keep trap handlers from re-entering data the task side owns.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::{irq_restore, irq_save};
use crate::heap::{self, AllocationDomain, ArenaId, OwnerId};

pub struct SpinLock<T> {
    locked: AtomicBool,
    owner: AtomicU64,
    arena: AtomicU64,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            owner: AtomicU64::new(OwnerId::SYSTEM.get()),
            arena: AtomicU64::new(ArenaId::UNTRACKED.get()),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> SpinGuard<'_, T> {
        let irq = irq_save();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let domain = heap::current_domain();
        self.owner.store(domain.owner.get(), Ordering::Relaxed);
        self.arena.store(domain.arena.get(), Ordering::Relaxed);
        SpinGuard { lock: self, irq }
    }

    /// Recover a lock only when its guard was acquired by `expected_domain` and
    /// then abandoned by that fault domain's `longjmp`.
    ///
    /// A guard held by SYSTEM or by another component is left untouched. This
    /// domain check is what prevents fault teardown from manufacturing a second
    /// mutable reference to externally guarded data.
    ///
    /// # Safety
    ///
    /// If this returns `true`, the caller must prove that every task in
    /// `expected_domain` is terminal and can never resume, so the abandoned
    /// guard can never later run `Drop`. This is only valid at the single-hart
    /// fault-domain teardown boundary.
    pub unsafe fn recover_after_fault(&self, expected_domain: AllocationDomain) -> bool {
        let irq = irq_save();
        let matches = self.locked.load(Ordering::Acquire)
            && self.owner.load(Ordering::Relaxed) == expected_domain.owner.get()
            && self.arena.load(Ordering::Relaxed) == expected_domain.arena.get();
        if matches {
            self.owner
                .store(OwnerId::SYSTEM.get(), Ordering::Relaxed);
            self.arena
                .store(ArenaId::UNTRACKED.get(), Ordering::Relaxed);
            self.locked.store(false, Ordering::Release);
        }
        irq_restore(irq);
        matches
    }
}

pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
    irq: bool,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.lock
            .owner
            .store(OwnerId::SYSTEM.get(), Ordering::Relaxed);
        self.lock
            .arena
            .store(ArenaId::UNTRACKED.get(), Ordering::Relaxed);
        self.lock.locked.store(false, Ordering::Release);
        irq_restore(self.irq);
    }
}
