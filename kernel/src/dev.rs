//! Devices as capability-guarded resources.
//!
//! Note what is *absent*: there is no `/dev/console`, so there is nothing to
//! open by name and no permission bits to get wrong. Writing to the console
//! requires holding a cap on this object with `WRITE`.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::cap::{InvocationLease, Resource, Rights};
use crate::sync::SpinLock;
use crate::uart;

pub struct ConsoleDev {
    bytes: AtomicU64,
}

impl ConsoleDev {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { bytes: AtomicU64::new(0) })
    }

    pub fn write(&self, s: &str) {
        self.bytes.fetch_add(s.len() as u64, Ordering::Relaxed);
        uart::_print(format_args!("{}", s));
    }

    /// Routine status output. Counts against the device the same way, but the
    /// console may drop it when the operator asks for quiet.
    pub fn write_bg(&self, s: &str) {
        self.bytes.fetch_add(s.len() as u64, Ordering::Relaxed);
        uart::_print_bg(format_args!("{}", s));
    }
}

impl Resource for ConsoleDev {
    fn kind(&self) -> &'static str {
        "console"
    }
    fn describe(&self) -> String {
        format!("ns16550a @ {:#x} [{} bytes out]", uart::UART_BASE, self.bytes.load(Ordering::Relaxed))
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}


/// A fixed slice of memory a component may be granted.
///
/// This is how a compiled program gets storage: not by asking an allocator, but
/// by being handed a capability on a bounded region. A program with no region
/// capability has no memory beyond its own frame, and one with a small region
/// cannot quietly grow — the bound is the capability.
pub struct MemoryRegion {
    name: &'static str,
    words: SpinLock<alloc::vec::Vec<u64>>,
    len: usize,
    claimed: AtomicBool,
}

impl MemoryRegion {
    pub fn new(name: &'static str, elements: usize) -> Arc<Self> {
        Arc::new(Self {
            name,
            words: SpinLock::new(alloc::vec![0u64; elements]),
            len: elements,
            claimed: AtomicBool::new(false),
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn invocation_claimed(&self) -> bool {
        self.claimed.load(Ordering::Acquire)
    }
}

/// Exclusive raw-memory access for one generated-code invocation.
///
/// The non-`Clone` capability lease remains in this object for as long as the
/// raw extent is live. Dropping it releases the region claim on both normal and
/// non-local program returns.
pub struct MemoryInvocation {
    lease: InvocationLease<MemoryRegion>,
    base: usize,
    len: usize,
}

impl MemoryInvocation {
    pub fn claim(lease: InvocationLease<MemoryRegion>) -> Result<Self, ()> {
        if !lease.authorizes(Rights::READ.union(Rights::WRITE)) {
            return Err(());
        }
        let claimed = lease.with(|region| {
            region
                .claimed
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        });
        if !claimed {
            return Err(());
        }

        let (base, len) = lease.with(|region| {
            let mut words = region.words.lock();
            words.iter_mut().for_each(|word| *word = 0);
            (words.as_mut_ptr() as usize, region.len)
        });
        Ok(Self { lease, base, len })
    }

    /// Base address and element count for the generated program's register
    /// contract. This is intentionally unavailable from `MemoryRegion`.
    pub(crate) fn extent(&self) -> (usize, usize) {
        (self.base, self.len)
    }
}

impl Drop for MemoryInvocation {
    fn drop(&mut self) {
        self.lease
            .with(|region| region.claimed.store(false, Ordering::Release));
    }
}

impl Resource for MemoryRegion {
    fn kind(&self) -> &'static str {
        "memory"
    }
    fn describe(&self) -> String {
        format!("{} [{} x i64]", self.name, self.len)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
