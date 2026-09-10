//! Kernel composition adapter for the board-independent PCI driver crate.
//!
//! The driver owns ECAM enumeration and BAR assignment. The kernel supplies
//! the selected BSP description and serializes the single host bridge.

extern crate alloc;

use crate::sync::SpinLock;
use alloc::vec::Vec;

pub use vibeos_driver_pci::{Bar, Function};

static PCI: SpinLock<Option<vibeos_driver_pci::Pci>> = SpinLock::new(None);

pub fn init() -> Result<usize, vibeos_driver_pci::Error> {
    PCI.lock().get_or_insert_with(|| vibeos_driver_pci::Pci::new(crate::platform::pci())).init()
}

pub fn functions() -> Vec<Function> {
    PCI.lock().as_ref().map(|p| p.functions()).unwrap_or_default()
}

pub fn find_xhci() -> Option<Function> {
    PCI.lock().as_ref().and_then(|p| p.find_xhci())
}
