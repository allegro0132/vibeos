//! Scoped parallel calls with owner fallback when a helper is busy.
use core::{
    cell::UnsafeCell,
    hint::spin_loop,
    marker::PhantomData,
    mem::MaybeUninit,
    sync::atomic::{
        AtomicU64, AtomicU8,
        Ordering::{AcqRel, Acquire, Relaxed, Release},
    },
};

const FREE: u8 = 0;
const RESERVED: u8 = 1;
const POSTED: u8 = 2;
const RUNNING: u8 = 3;
const DONE: u8 = 4;

#[derive(Clone, Copy)]
struct Call {
    data: *mut (),
    invoke: unsafe fn(*mut ()),
}
#[repr(align(64))]
struct Slot {
    state: AtomicU8,
    call: UnsafeCell<MaybeUninit<Call>>,
    remote: AtomicU64,
    local: AtomicU64,
}
// The reserving owner writes the call before POSTED. Only the hart changing
// POSTED to RUNNING reads it. The join guard prevents stack storage or the
// slot from being reused until that hart publishes DONE.
unsafe impl Sync for Slot {}
impl Slot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(FREE),
            call: UnsafeCell::new(MaybeUninit::uninit()),
            remote: AtomicU64::new(0),
            local: AtomicU64::new(0),
        }
    }
}

pub struct WorkSlots<const N: usize> {
    slots: [Slot; N],
}
impl<const N: usize> WorkSlots<N> {
    pub const fn new() -> Self {
        Self {
            slots: [const { Slot::new() }; N],
        }
    }
}

impl Slot {
    fn execute(&self) -> bool {
        if self.state.load(Acquire) != POSTED
            || self
                .state
                .compare_exchange(POSTED, RUNNING, AcqRel, Relaxed)
                .is_err()
        {
            return false;
        }
        struct Finished<'a>(&'a AtomicU8);
        impl Drop for Finished<'_> {
            fn drop(&mut self) {
                self.0.store(DONE, Release);
            }
        }
        let _finished = Finished(&self.state);
        let call = unsafe { (*self.call.get()).assume_init_read() };
        unsafe {
            (call.invoke)(call.data);
        }
        true
    }
}

impl<const N: usize> WorkSlots<N> {
    pub fn service(&self, hart: usize) -> bool {
        let Some(slot) = self.slots.get(hart) else {
            return false;
        };
        if !slot.execute() {
            return false;
        }
        slot.remote.fetch_add(1, Relaxed);
        true
    }
}

struct Join<'a, F> {
    slot: &'a Slot,
    _task: PhantomData<&'a mut Option<F>>,
}
impl<'a, F: FnOnce() + Send> Join<'a, F> {
    fn post(slot: &'a Slot, task: &'a mut Option<F>) -> Self {
        unsafe fn invoke<F: FnOnce()>(data: *mut ()) {
            // Only the winning executor calls this function. Its exclusive
            // borrow ends before DONE releases the owner from the scope.
            unsafe { (&mut *data.cast::<Option<F>>()).take().unwrap()() }
        }
        let call = Call {
            data: core::ptr::from_mut(task).cast(),
            invoke: invoke::<F>,
        };
        unsafe {
            (*slot.call.get()).write(call);
        }
        slot.state.store(POSTED, Release);
        Self {
            slot,
            _task: PhantomData,
        }
    }
}
impl<F> Drop for Join<'_, F> {
    fn drop(&mut self) {
        if self.slot.execute() {
            self.slot.local.fetch_add(1, Relaxed);
        }
        while self.slot.state.load(Acquire) != DONE {
            spin_loop();
        }
        self.slot.state.store(FREE, Release);
    }
}

impl<const N: usize> WorkSlots<N> {
    pub fn run(&self, partner: Option<usize>, local: impl FnOnce(), remote: impl FnOnce() + Send) {
        let slot = partner.and_then(|h| self.slots.get(h)).filter(|s| {
            s.state
                .compare_exchange(FREE, RESERVED, AcqRel, Relaxed)
                .is_ok()
        });
        if let Some(slot) = slot {
            let mut task = Some(remote);
            let _join = Join::post(slot, &mut task);
            local();
        } else {
            local();
            remote();
        }
    }

    pub fn snapshot(&self) -> [[u64; 2]; N] {
        self.slots
            .each_ref()
            .map(|s| [s.remote.load(Relaxed), s.local.load(Relaxed)])
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::AtomicBool;
    use std::thread;

    #[test]
    fn borrowed_work_finishes_on_the_helper_and_can_be_stolen_if_idle() {
        let slots = WorkSlots::<4>::new();
        let mut remote_sum = 0;
        let mut local_sum = 0;
        let running = AtomicBool::new(false);
        thread::scope(|scope| {
            let seen = &running;
            let slots = &slots;
            scope.spawn(move || {
                while !slots.service(3) {
                    thread::yield_now();
                }
            });
            slots.run(
                Some(3),
                || {
                    while !seen.load(Acquire) {
                        thread::yield_now();
                    }
                    local_sum += 11;
                },
                || {
                    remote_sum += 7;
                    seen.store(true, Release);
                },
            );
        });
        slots.run(Some(3), || local_sum += 11, || remote_sum += 7);
        assert_eq!((local_sum, remote_sum), (22, 14));
        assert_eq!(slots.snapshot()[3], [1, 1]);
    }
}
