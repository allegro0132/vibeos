//! Kernel composition adapter for the board-independent PCI driver crate.
//!
//! The driver owns ECAM enumeration and BAR assignment. The kernel supplies
//! the selected BSP description and serializes the single host bridge.

extern crate alloc;

use alloc::vec::Vec;
use crate::sync::SpinLock;

pub use vibeos_driver_pci::{Bar, Function};

static PCI: SpinLock<vibeos_driver_pci::Pci> =
    SpinLock::new(vibeos_driver_pci::Pci::new(crate::platform::PCI));

pub fn init() -> Result<usize, vibeos_driver_pci::Error> {
    PCI.lock().init()
}

pub fn functions() -> Vec<Function> {
    PCI.lock().functions()
}

pub fn find_xhci() -> Option<Function> {
    PCI.lock().find_xhci()
}
