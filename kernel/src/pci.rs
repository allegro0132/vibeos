//! Kernel serialization and inventory view for the firmware PCI host.
extern crate alloc;
use crate::sync::SpinLock;
use alloc::vec::Vec;
use vibeos_hal::pci::{host, Error};
pub use vibeos_hal::pci::{Bar, Function};
static PCI: SpinLock<()> = SpinLock::new(());
pub fn init() -> Result<usize, Error> {
    let _lock = PCI.lock();
    unsafe { (host().init)() }
}
pub fn functions() -> Vec<Function> {
    let _lock = PCI.lock();
    let mut functions = Vec::new();
    unsafe {
        (host().functions)(&mut |function| functions.push(function));
    }
    functions
}
pub fn find_xhci() -> Option<Function> {
    let _lock = PCI.lock();
    let mut found = None;
    unsafe {
        (host().functions)(&mut |function| {
            if found.is_none() && function.is_xhci() {
                found = Some(function);
            }
        });
    }
    found
}
pub fn enable_bus_mastering(function: Function) -> Result<(), Error> {
    let _lock = PCI.lock();
    unsafe { (host().enable_bus_mastering)(function) }
}
