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
