//! Stable TLS snapshots for calls in tracked task arenas. Never follow a TLS
//! pointer after an executor fault; restore the pre-call values before reuse.
use core::sync::atomic::{AtomicUsize, Ordering};
use vibeos_core::{exec::TaskId, heap::AllocationDomain};
#[derive(Clone, Copy)]
struct Frame { task: TaskId, domain: AllocationDomain, tls: [usize; 2], fcsr: usize }
const DEPTH: usize = 16;
static FRAMES: crate::sync::SpinLock<[[Option<Frame>; DEPTH]; crate::exec::MAX_HARTS]> =
    crate::sync::SpinLock::new([[None; DEPTH]; crate::exec::MAX_HARTS]);
pub(super) static RECOVERED: AtomicUsize = AtomicUsize::new(0);

pub(super) fn enter() -> Option<usize> {
    let domain = vibeos_core::heap::current_domain();
    if !domain.arena.is_tracked() { return None; }
    let task = crate::exec::current_task_scope_id().expect("tracked native call needs guarded task scope");
    let hart = super::hart();
    let tls = core::array::from_fn(|i| super::TLS[hart][i].load(Ordering::Relaxed).addr());
    let mut frames = FRAMES.lock();
    let Some(index) = frames[hart].iter().position(Option::is_none) else {
        drop(frames);
        panic!("native recovery nesting limit");
    };
    frames[hart][index] = Some(Frame { task, domain, tls, fcsr: super::async_call::fcsr() });
    Some(index)
}
pub(super) fn leave(index: Option<usize>) {
    let Some(index) = index else { return };
    let mut frames = FRAMES.lock();
    let stack = &mut frames[super::hart()];
    let valid = stack[index + 1..].iter().all(Option::is_none) && stack[index].is_some();
    if valid { stack[index] = None; }
    drop(frames);
    assert!(valid, "native recovery guards must leave in stack order");
}
/// Called after permanent exact-task detach, before the hart can poll again
/// and before raw arena reclamation. All calls are synchronous poll boundaries;
/// async suspension removes its frame when poll returns Pending.
pub(crate) unsafe fn recover_task(task: TaskId, domain: AllocationDomain) {
    let hart = super::hart();
    let mut frames = FRAMES.lock();
    for (index, stack) in frames.iter_mut().enumerate() {
        let Some(first) = stack.iter().flatten().find(|f| f.task == task && f.domain == domain).copied() else { continue };
        // An active call cannot migrate or survive a return from poll.
        assert_eq!(index, hart, "active native call abandoned on another hart");
        assert!(stack.iter().flatten().all(|f| f.task == task && f.domain == domain));
        for (slot, value) in super::TLS[index].iter().zip(first.tls) {
            slot.store(value as *mut u8, Ordering::Relaxed);
        }
        super::async_call::set_fcsr(first.fcsr);
        *stack = [None; DEPTH];
        RECOVERED.fetch_add(1, Ordering::Relaxed);
    }
}
