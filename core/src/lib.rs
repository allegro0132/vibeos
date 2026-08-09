//! VibeOS core: the parts of the kernel with no hardware in them.
//!
//! Split out from the kernel binary so `cargo test` can exercise the
//! capability system, the scheduler, the channels, and the allocator on the
//! host — no QEMU, no boot, millisecond iteration.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod arch;
pub mod bench;
pub mod cap;
pub mod chan;
pub mod durable;
pub mod exec;
pub mod heap;
pub mod interrupt;
pub mod sync;
pub mod virtio;
