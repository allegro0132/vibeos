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
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::Resource;
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
}

impl MemoryRegion {
    pub fn new(name: &'static str, elements: usize) -> Arc<Self> {
        Arc::new(Self {
            name,
            words: SpinLock::new(alloc::vec![0u64; elements]),
            len: elements,
        })
    }

    /// Base address and length in elements, for the program's register contract.
    pub fn extent(&self) -> (usize, usize) {
        (self.words.lock().as_ptr() as usize, self.len)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Zero the region between runs, so one program cannot read what another
    /// left behind.
    pub fn clear(&self) {
        self.words.lock().iter_mut().for_each(|w| *w = 0);
    }
}

impl Resource for MemoryRegion {
    fn kind(&self) -> &'static str {
        "memory"
    }
    fn describe(&self) -> String {
        let (base, len) = self.extent();
        format!("{} [{} x i64 @ {:#x}]", self.name, len, base)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
