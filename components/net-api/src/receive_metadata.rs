//! Two metadata banks; only the atomically selected bank is observable.
//! Caller serializes access and proves quiescence before abandoned-lock recovery.
use super::receive_ownership::Ownership;
use core::{
    mem::MaybeUninit,
    ops::Deref,
    sync::atomic::{AtomicUsize, Ordering},
};

pub(crate) struct Metadata<const N: usize> {
    // An interrupted write may leave the inactive bank with invalid enum bytes.
    // MaybeUninit prevents reading or dropping that bank as a typed Ownership.
    banks: [MaybeUninit<Ownership<N>>; 2],
    active: AtomicUsize,
}
impl<const N: usize> Metadata<N> {
    pub fn new(initial: Ownership<N>) -> Self {
        Self {
            banks: [MaybeUninit::new(initial), MaybeUninit::uninit()],
            active: AtomicUsize::new(0),
        }
    }
    #[cfg(test)]
    pub(crate) fn interrupt_inactive_write_for_test(&mut self) {
        let inactive = 1 - self.active.load(Ordering::Relaxed);
        unsafe {
            core::ptr::write_bytes(
                self.banks[inactive].as_mut_ptr().cast::<u8>(),
                0xff,
                core::mem::size_of::<Ownership<N>>(),
            );
        }
    }

    pub fn update<R>(&mut self, operation: impl FnOnce(&mut Ownership<N>) -> R) -> R {
        let mut next = self.deref().snapshot();
        let result = operation(&mut next);
        let index = 1 - self.active.load(Ordering::Relaxed);
        self.banks[index].write(next);
        // This is the only commit point. A stopped task's partial inactive
        // write is ignored; a committed bank is complete before it is selected.
        self.active.store(index, Ordering::Release);
        result
    }
}
impl<const N: usize> Deref for Metadata<N> {
    type Target = Ownership<N>;
    fn deref(&self) -> &Self::Target {
        let index = self.active.load(Ordering::Acquire);
        // Construction initializes bank zero; update selects a bank only after
        // fully initializing it. No reference to the inactive bank is exposed.
        unsafe { self.banks[index].assume_init_ref() }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::receive_ownership::Owner;
    use vibeos_core::{
        heap::{AllocationDomain, ArenaId, OwnerId},
        sync::TaskRecoveryKey,
    };
    #[test]
    fn uncommitted_updates_and_invalid_inactive_bank_preserve_last_commit() {
        let owner = Owner {
            domain: AllocationDomain::new(OwnerId::new(141), ArenaId::new(141)),
            task: TaskRecoveryKey::new(141).unwrap(),
        };
        let mut metadata = Metadata::<3>::new(Ownership::new(16, 32).unwrap());
        let first = metadata.update(|state| state.reserve(owner)).unwrap();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            metadata.update(|state| {
                state.reserve(owner).unwrap();
                panic!("interrupted before bank publication");
            });
        }));
        assert!(failed.is_err());
        assert!(metadata.validate_writer(first, owner).is_ok());
        let inactive = 1 - metadata.active.load(Ordering::Relaxed);
        // Model an arbitrary interrupted bank write without creating an invalid
        // Rust Ownership value. No consumer may interpret these bytes.
        unsafe {
            core::ptr::write_bytes(
                metadata.banks[inactive].as_mut_ptr().cast::<u8>(),
                0xff,
                core::mem::size_of::<Ownership<3>>(),
            );
        }
        assert!(metadata.validate_writer(first, owner).is_ok());
        let second = metadata.update(|state| state.reserve(owner)).unwrap();
        let third = metadata.update(|state| state.reserve(owner)).unwrap();
        assert!(metadata.update(|state| state.reserve(owner)).is_err());
        for ticket in [first, second, third] {
            assert!(metadata.validate_writer(ticket, owner).is_ok());
        }
    }
}
