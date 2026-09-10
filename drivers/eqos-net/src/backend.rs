//! Bind the concrete register engine to an independently admitted DMA pool.
use crate::{
    controller::{Controller, Io},
    ring::{self, Direction, Layout},
};

/// # Safety
/// Successful admission proves the complete layout belongs to this exclusive,
/// permanent pool with 64-byte independent synchronization. Operations must obey
/// ring::Backend's volatile access, cache, ordering and slice-lifetime rules.
/// The pool remains allocated and unavailable to others even after a dropped
/// backend or a failed controller stop/reset. Cache operations are visibility
/// operations; descriptor ownership is transferred by the OWN protocol.
pub unsafe trait Memory: 'static {
    fn admit(&self, layout: Layout) -> bool;
    fn read_word(&mut self, address: u64, word: usize) -> u32;
    fn write_word(&mut self, address: u64, word: usize, value: u32);
    fn copy_tx(&mut self, address: u64, packet: &[u8]);
    fn copy_rx(&mut self, address: u64, output: &mut [u8]);
    fn for_device(&mut self, address: u64, bytes: usize, direction: Direction);
    fn for_cpu(&mut self, address: u64, bytes: usize, direction: Direction);
    fn barrier(&mut self);
}

pub struct Backend<R: Io, M: Memory> {
    controller: Controller<R>,
    memory: &'static mut M,
    failed: bool,
}
impl<R: Io + 'static, M: Memory> ring::Ring<Backend<R, M>> {
    /// Update software configuration while retaining the ring's ownership even
    /// if the caller faults mid-operation. No DMA may be running at this point.
    pub fn set_link(
        &mut self,
        speed: crate::controller::Speed,
        full_duplex: bool,
    ) -> Result<(), crate::controller::Error> {
        self.stopped_backend()
            .ok_or(crate::controller::Error::NotReady)?
            .set_link(speed, full_duplex)
    }
}
impl<R: Io, M: Memory> Backend<R, M> {
    pub fn set_link(
        &mut self,
        speed: crate::controller::Speed,
        full_duplex: bool,
    ) -> Result<(), crate::controller::Error> {
        self.controller.set_link(speed, full_duplex)
    }
    pub fn new(controller: Controller<R>, memory: &'static mut M) -> Self {
        Self {
            controller,
            memory,
            failed: false,
        }
    }
}
// Safety: the Memory contract supplies permanent exclusive storage and complete
// pool admission. Controller config never starts DMA, and reset/stop only succeed
// after the bounded SWR and disabled-enable readback checks.
unsafe impl<R: Io, M: Memory> ring::Backend for Backend<R, M> {
    fn reset(&mut self) -> bool {
        self.failed = self.controller.reset().is_err();
        !self.failed
    }
    fn configure(&mut self, layout: Layout) -> bool {
        if self.failed || !self.memory.admit(layout) {
            self.failed = true;
            return false;
        }
        self.failed = self.controller.configure(layout).is_err();
        !self.failed
    }
    fn start(&mut self) -> bool {
        if self.failed {
            return false;
        }
        self.failed = self.controller.start().is_err();
        !self.failed
    }
    fn stop(&mut self) -> bool {
        self.failed = self.controller.stop().is_err();
        !self.failed
    }
    fn read_word(&mut self, a: u64, w: usize) -> u32 {
        self.memory.read_word(a, w)
    }
    fn write_word(&mut self, a: u64, w: usize, v: u32) {
        self.memory.write_word(a, w, v)
    }
    fn copy_tx(&mut self, a: u64, p: &[u8]) {
        self.memory.copy_tx(a, p)
    }
    fn copy_rx(&mut self, a: u64, p: &mut [u8]) {
        self.memory.copy_rx(a, p)
    }
    fn for_device(&mut self, a: u64, n: usize, d: Direction) {
        self.memory.for_device(a, n, d)
    }
    fn for_cpu(&mut self, a: u64, n: usize, d: Direction) {
        self.memory.for_cpu(a, n, d)
    }
    fn barrier(&mut self) {
        self.memory.barrier()
    }
    fn tail(&mut self, rx: bool, a: u64) {
        self.memory.barrier();
        if self.controller.tail(rx, a).is_err() {
            self.failed = true;
        }
    }
}
