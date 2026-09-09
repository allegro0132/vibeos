//! Bounded RW/NX fiber aliases with an unmapped page below each stack.
use alloc::{alloc::{alloc_zeroed, dealloc}, boxed::Box, sync::Arc};
use core::{alloc::Layout, ops::Range};
use vibeos_core::heap::{self, AllocationDomain};
use vibeos_wasmtime_runtime::wasmtime::{self, Config, StackCreator, StackMemory};
const PAGE: usize = 4096;
#[derive(Clone, Copy)]
struct Record { domain: AllocationDomain, physical: usize, size: usize }
static SLOTS: crate::sync::SpinLock<[Option<Record>; crate::mmu::NATIVE_FIBER_SLOTS]> =
    crate::sync::SpinLock::new([None; crate::mmu::NATIVE_FIBER_SLOTS]);
struct Creator;
struct Stack { slot: usize, physical: usize, layout: Layout }
pub(super) fn configure(config: &mut Config) {
    config.with_host_stack(Arc::new(Creator));
}
fn base(slot: usize) -> usize { crate::mmu::NATIVE_FIBER_BASE + slot * crate::mmu::NATIVE_FIBER_STRIDE + PAGE }
unsafe impl StackCreator for Creator {
    fn new_stack(&self, size: usize, _zeroed: bool) -> wasmtime::Result<Box<dyn StackMemory>> {
        if size == 0 || size > 256 * 1024 || size % PAGE != 0 {
            wasmtime::bail!("unsupported native fiber stack size");
        }
        let domain = heap::current_domain();
        let slot = {
            let mut slots = SLOTS.lock();
            let index = slots.iter().position(Option::is_none);
            if let Some(index) = index { slots[index] = Some(Record { domain, physical: 0, size: 0 }); }
            index
        };
        let Some(slot) = slot else { wasmtime::bail!("native fiber stack slots exhausted"); };
        let layout = Layout::from_size_align(size, PAGE).unwrap();
        let physical = unsafe { alloc_zeroed(layout) } as usize;
        if physical == 0 {
            SLOTS.lock()[slot] = None;
            wasmtime::bail!("native fiber stack allocation failed");
        }
        {
            let mut slots = SLOTS.lock();
            unsafe { crate::mmu::replace_native_fiber(slot, 0, 0, physical, size); }
            slots[slot] = Some(Record { domain, physical, size });
        }
        Ok(Box::new(Stack { slot, physical, layout }))
    }
}
unsafe impl StackMemory for Stack {
    fn top(&self) -> *mut u8 { (base(self.slot) + self.layout.size()) as *mut u8 }
    fn range(&self) -> Range<usize> { base(self.slot)..base(self.slot) + self.layout.size() }
    fn guard_range(&self) -> Range<*mut u8> { (base(self.slot) - PAGE) as *mut u8..base(self.slot) as *mut u8 }
}
impl Drop for Stack {
    fn drop(&mut self) {
        {
            let mut slots = SLOTS.lock();
            let record = slots[self.slot].unwrap();
            assert_eq!((record.physical, record.size), (self.physical, self.layout.size()));
            unsafe { crate::mmu::replace_native_fiber(self.slot, record.physical, record.size, 0, 0); }
            slots[self.slot] = None;
        }
        unsafe { dealloc(self.physical as *mut u8, self.layout); }
    }
}
/// Exact-domain executor quiescence is required. Unmap before arena bytes are
/// freed; do not follow or destroy an interrupted StackMemory object.
pub(super) unsafe fn recover(domain: AllocationDomain) {
    assert!(domain.arena.is_tracked());
    let mut slots = SLOTS.lock();
    for (index, slot) in slots.iter_mut().enumerate() {
        if let Some(record) = *slot {
            if record.domain != domain { continue; }
            unsafe { crate::mmu::replace_native_fiber(index, record.physical, record.size, 0, 0); }
            *slot = None;
        }
    }
}
pub(super) fn assert_idle() {
    let idle = SLOTS.lock().iter().all(Option::is_none);
    assert!(idle);
    for offset in (0..crate::mmu::NATIVE_FIBER_SLOTS * crate::mmu::NATIVE_FIBER_STRIDE).step_by(PAGE) {
        assert!(crate::mmu::mapping(crate::mmu::NATIVE_FIBER_BASE + offset).is_none());
    }
    crate::println!("  WASMTIME FIBER STACK PASS slots=4 limit=262144 guard=4096 idle=1");
}


pub(super) fn assert_current() {
    let sp: usize;
    unsafe { core::arch::asm!("mv {}, sp", out(reg) sp, options(nomem, nostack)); }
    let active = {
        let slots = SLOTS.lock();
        slots.iter().enumerate().find_map(|(index, slot)| {
            slot.filter(|r| sp >= base(index) && sp < base(index) + r.size).map(|r| (index, r))
        })
    };
    let (index, record) = active.expect("host callback must execute on its native fiber stack");
    assert_eq!(record.domain, heap::current_domain());
    assert!(crate::mmu::mapping(base(index) - 1).is_none());
    assert!(crate::mmu::mapping(base(index) + record.size).is_none());
    let mapping = crate::mmu::mapping(sp).unwrap();
    use vibeos_core::mmu::PagePermissions as P;
    assert!(mapping.permissions.contains(P::READ) && mapping.permissions.contains(P::WRITE));
    assert!(!mapping.permissions.contains(P::EXECUTE));
}
