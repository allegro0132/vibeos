//! Firmware-owned ECAM host and resource allocator. The kernel serializes calls.
use super::Board;
use core::cell::UnsafeCell;
use vibeos_driver_pci::Pci;
use vibeos_hal::{pci::Host, Board as _};
struct HostState(UnsafeCell<Pci>);
// SAFETY: the kernel's PCI lock covers all mutable/shared host operations.
unsafe impl Sync for HostState {}
static PCI: HostState = HostState(UnsafeCell::new(Pci::new(Board::INFO.pci.unwrap())));
#[no_mangle]
pub static VIBEOS_PCI_HOST: Host = Host {
    init: || unsafe { (&mut *PCI.0.get()).init() },
    functions: |visit| unsafe { (&*PCI.0.get()).visit_functions(visit) },
    enable_bus_mastering: |function| unsafe { (&mut *PCI.0.get()).enable_bus_mastering(function) },
};
