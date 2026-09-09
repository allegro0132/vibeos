use crate::Engine;
use crate::prelude::*;
#[cfg(not(has_custom_threads))]
use crate::runtime::vm::parking_spot::Waiter;
use crate::runtime::vm::memory::{LocalMemory, validate_atomic_addr};
use crate::runtime::vm::parking_spot::ParkingSpot;
#[cfg(has_custom_threads)]
use crate::runtime::vm::threads::ThreadHooks;
use crate::runtime::vm::{self, Memory, VMMemoryDefinition, WaitResult};
use crate::sync::RwLock;
use alloc::sync::Arc;
use core::ops::Range;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
#[cfg(not(has_custom_threads))]
use std::cell::RefCell;
#[cfg(not(has_custom_threads))]
use std::time::Instant;
use wasmtime_environ::Trap;

/// For shared memory (and only for shared memory), this lock-version restricts
/// access when growing the memory or checking its size. This is to conform with
/// the [thread proposal]: "When `IsSharedArrayBuffer(...)` is true, the return
/// value should be the result of an atomic read-modify-write of the new size to
/// the internal `length` slot."
///
/// [thread proposal]:
///     https://github.com/WebAssembly/threads/blob/master/proposals/threads/Overview.md#webassemblymemoryprototypegrow
#[derive(Clone)]
pub struct SharedMemory(Arc<SharedMemoryInner>);

struct SharedMemoryInner {
    memory: RwLock<LocalMemory>,
    spot: ParkingSpot,
    ty: wasmtime_environ::Memory,
    def: LongTermVMMemoryDefinition,
}

impl SharedMemory {
    /// Construct a new [`SharedMemory`].
    ///
    /// The backing store comes from the engine's configured host memory
    /// creator when one is installed; otherwise the default mmap-backed
    /// allocation is used.
    pub fn new(engine: &Engine, ty: &wasmtime_environ::Memory) -> Result<Self> {
        let tunables = engine.tunables();
        let memory_tunables = wasmtime_environ::MemoryTunables::new(
            tunables,
            wasmtime_environ::MemoryKind::LinearMemory,
        );
        // Note that without a limiter being passed to `limit_new` this
        // `assert_ready` should never panic.
        let (minimum_bytes, maximum_bytes) = vm::assert_ready(Memory::limit_new(ty, None))?;
        let boxed: Box<dyn crate::runtime::vm::RuntimeLinearMemory> =
            match &engine.config().mem_creator {
                Some(creator) => {
                    creator.new_memory(ty, &memory_tunables, minimum_bytes, maximum_bytes)?
                }
                None => {
                    #[cfg(has_virtual_memory)]
                    {
                        let mmap_memory = crate::runtime::vm::memory::MmapMemory::new(
                            ty,
                            &memory_tunables,
                            minimum_bytes,
                            maximum_bytes,
                        )?;
                        try_new::<Box<_>>(mmap_memory)?
                    }
                    #[cfg(not(has_virtual_memory))]
                    {
                        bail!("shared memory requires a host memory creator on this platform")
                    }
                }
            };
        Self::wrap(
            engine,
            ty,
            LocalMemory::new(ty, &memory_tunables, boxed, None)?,
        )
    }

    /// Wrap an existing [Memory] with the locking provided by a [SharedMemory].
    pub fn wrap(
        engine: &Engine,
        ty: &wasmtime_environ::Memory,
        memory: LocalMemory,
    ) -> Result<Self> {
        if !engine.config().shared_memory {
            bail!(
                "shared memory support is disabled for this engine -- see `Config::shared_memory`"
            );
        }
        if !ty.shared {
            bail!("shared memory must have a `shared` memory type");
        }
        Ok(Self(try_new::<Arc<_>>(SharedMemoryInner {
            ty: *ty,
            spot: ParkingSpot::default(),
            def: LongTermVMMemoryDefinition(memory.vmmemory()),
            memory: RwLock::new(memory),
        })?))
    }

    /// Return the memory type for this [`SharedMemory`].
    pub fn ty(&self) -> &wasmtime_environ::Memory {
        &self.0.ty
    }

    /// Convert this shared memory into a [`Memory`].
    pub fn as_memory(self) -> Memory {
        Memory::Shared(self)
    }

    /// Return a pointer to the shared memory's [VMMemoryDefinition].
    pub fn vmmemory_ptr(&self) -> NonNull<VMMemoryDefinition> {
        NonNull::from(&self.0.def.0)
    }

    /// Same as `RuntimeLinearMemory::grow`, except with `&self`.
    pub fn grow(&self, delta_pages: u64) -> Result<Option<(usize, usize)>, Error> {
        let mut memory = self.0.memory.write();
        // Without a limiter being passed in this shouldn't have an await point,
        // so it should be safe to assert that it's ready.
        let result = vm::assert_ready(memory.grow(delta_pages, None))?;
        if let Some((_old_size_in_bytes, new_size_in_bytes)) = result {
            // Store the new size to the `VMMemoryDefinition` for JIT-generated
            // code (and runtime functions) to access. No other code can be
            // growing this memory due to the write lock, but code in other
            // threads could have access to this shared memory and we want them
            // to see the most consistent version of the `current_length`; a
            // weaker consistency is possible if we accept them seeing an older,
            // smaller memory size (assumption: memory only grows) but presently
            // we are aiming for accuracy.
            //
            // Note that it could be possible to access a memory address that is
            // now-valid due to changes to the page flags in `grow` above but
            // beyond the `memory.size` that we are about to assign to. In these
            // and similar cases, discussion in the thread proposal concluded
            // that: "multiple accesses in one thread racing with another
            // thread's `memory.grow` that are in-bounds only after the grow
            // commits may independently succeed or trap" (see
            // https://github.com/WebAssembly/threads/issues/26#issuecomment-433930711).
            // In other words, some non-determinism is acceptable when using
            // `memory.size` on work being done by `memory.grow`.
            self.0
                .def
                .0
                .current_length
                .store(new_size_in_bytes, Ordering::SeqCst);
        }
        Ok(result)
    }

    /// Implementation of `memory.atomic.notify` for this shared memory.
    #[cfg(not(has_custom_threads))]
    pub fn atomic_notify(&self, addr_index: u64, count: u32) -> Result<u32, Trap> {
        let ptr = validate_atomic_addr(&self.0.def.0, addr_index, 4, 4)?;
        log::trace!("memory.atomic.notify(addr={addr_index:#x}, count={count})");
        let ptr = unsafe { &*ptr };
        Ok(self.0.spot.notify(ptr, count))
    }

    /// Implementation of `memory.atomic.notify` for this shared memory.
    ///
    /// Waiters are woken through `hooks`; without hooks the waiters are still
    /// marked notified and complete at their next poll.
    #[cfg(has_custom_threads)]
    pub fn atomic_notify(
        &self,
        addr_index: u64,
        count: u32,
        hooks: Option<&dyn ThreadHooks>,
    ) -> Result<u32, Trap> {
        let ptr = validate_atomic_addr(&self.0.def.0, addr_index, 4, 4)?;
        log::trace!("memory.atomic.notify(addr={addr_index:#x}, count={count})");
        let ptr = unsafe { &*ptr };
        Ok(self.0.spot.notify(ptr, count, hooks))
    }

    /// Implementation of `memory.atomic.wait32` for this shared memory.
    #[cfg(not(has_custom_threads))]
    pub fn atomic_wait32(
        &self,
        addr_index: u64,
        expected: u32,
        timeout: Option<Duration>,
    ) -> Result<WaitResult, Trap> {
        let addr = validate_atomic_addr(&self.0.def.0, addr_index, 4, 4)?;
        log::trace!(
            "memory.atomic.wait32(addr={addr_index:#x}, expected={expected}, timeout={timeout:?})"
        );

        // SAFETY: `addr_index` was validated by `validate_atomic_addr` above.
        assert!(core::mem::size_of::<AtomicU32>() == 4);
        assert!(core::mem::align_of::<AtomicU32>() <= 4);
        let atomic = unsafe { AtomicU32::from_ptr(addr.cast()) };
        // Wasm linear memory is always little-endian, but `AtomicU32` uses the
        // host's native endianness.
        let expected = expected.to_le();

        // Note that `checked_add` is used such that when `timeout` is too large
        // it'll cause there to be no timeout at all if we can't represent the
        // deadline. That effectively maps to the requested timeout since if we
        // can't represent the deadline we'll be here awhile.
        let deadline = timeout.and_then(|d| Instant::now().checked_add(d));

        WAITER.with(|waiter| {
            let mut waiter = waiter.borrow_mut();
            Ok(self.0.spot.wait32(atomic, expected, deadline, &mut waiter))
        })
    }

    /// Implementation of `memory.atomic.wait64` for this shared memory.
    #[cfg(not(has_custom_threads))]
    pub fn atomic_wait64(
        &self,
        addr_index: u64,
        expected: u64,
        timeout: Option<Duration>,
    ) -> Result<WaitResult, Trap> {
        let addr = validate_atomic_addr(&self.0.def.0, addr_index, 8, 8)?;
        log::trace!(
            "memory.atomic.wait64(addr={addr_index:#x}, expected={expected}, timeout={timeout:?})"
        );

        // SAFETY: `addr_index` was validated by `validate_atomic_addr` above.
        assert!(core::mem::size_of::<AtomicU64>() == 8);
        assert!(core::mem::align_of::<AtomicU64>() <= 8);
        let atomic = unsafe { AtomicU64::from_ptr(addr.cast()) };
        // Wasm linear memory is always little-endian, but `AtomicU64` uses the
        // host's native endianness.
        let expected = expected.to_le();

        // See `atomic_wait32` for why this is using `checked_add`.
        let deadline = timeout.and_then(|d| Instant::now().checked_add(d));

        WAITER.with(|waiter| {
            let mut waiter = waiter.borrow_mut();
            Ok(self.0.spot.wait64(atomic, expected, deadline, &mut waiter))
        })
    }

    /// Implementation of `memory.atomic.wait32` that suspends the calling
    /// guest thread's async fiber instead of an OS thread.
    #[cfg(has_custom_threads)]
    pub async fn atomic_wait32_async(
        &self,
        addr_index: u64,
        expected: u32,
        timeout: Option<Duration>,
        hooks: &dyn ThreadHooks,
    ) -> Result<WaitResult> {
        let addr = validate_atomic_addr(&self.0.def.0, addr_index, 4, 4)?;
        log::trace!(
            "memory.atomic.wait32(addr={addr_index:#x}, expected={expected}, timeout={timeout:?})"
        );
        // SAFETY: `addr_index` was validated by `validate_atomic_addr` above,
        // and the base pointer of a shared memory never changes.
        assert!(core::mem::size_of::<AtomicU32>() == 4);
        assert!(core::mem::align_of::<AtomicU32>() <= 4);
        let atomic = unsafe { AtomicU32::from_ptr(addr.cast()) };
        let expected = expected.to_le();
        self.0.spot.wait32(atomic, expected, timeout, hooks).await
    }

    /// Implementation of `memory.atomic.wait64` that suspends the calling
    /// guest thread's async fiber instead of an OS thread.
    #[cfg(has_custom_threads)]
    pub async fn atomic_wait64_async(
        &self,
        addr_index: u64,
        expected: u64,
        timeout: Option<Duration>,
        hooks: &dyn ThreadHooks,
    ) -> Result<WaitResult> {
        let addr = validate_atomic_addr(&self.0.def.0, addr_index, 8, 8)?;
        log::trace!(
            "memory.atomic.wait64(addr={addr_index:#x}, expected={expected}, timeout={timeout:?})"
        );
        // SAFETY: see `atomic_wait32_async`.
        assert!(core::mem::size_of::<AtomicU64>() == 8);
        assert!(core::mem::align_of::<AtomicU64>() <= 8);
        let atomic = unsafe { AtomicU64::from_ptr(addr.cast()) };
        let expected = expected.to_le();
        self.0.spot.wait64(atomic, expected, timeout, hooks).await
    }

    pub(crate) fn byte_size(&self) -> usize {
        self.0.memory.read().byte_size()
    }

    pub(crate) fn needs_init(&self) -> bool {
        self.0.memory.read().needs_init()
    }

    pub(crate) fn wasm_accessible(&self) -> Range<usize> {
        self.0.memory.read().wasm_accessible()
    }
}

#[cfg(not(has_custom_threads))]
thread_local! {
    /// Structure used in conjunction with `ParkingSpot` to block the current
    /// thread if necessary. Note that this is lazily initialized.
    static WAITER: RefCell<Waiter> = const { RefCell::new(Waiter::new()) };
}

/// Shared memory needs some representation of a `VMMemoryDefinition` for
/// JIT-generated code to access. This structure owns the base pointer and
/// length to the actual memory and we share this definition across threads by:
/// - never changing the base pointer; according to the specification, shared
///   memory must be created with a known maximum size so it can be allocated
///   once and never moved
/// - carefully changing the length, using atomic accesses in both the runtime
///   and JIT-generated code.
struct LongTermVMMemoryDefinition(VMMemoryDefinition);
unsafe impl Send for LongTermVMMemoryDefinition {}
unsafe impl Sync for LongTermVMMemoryDefinition {}
