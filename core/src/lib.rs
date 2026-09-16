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
pub mod exec;
#[cfg(feature = "idle-profile")]
mod idle_profile;
pub mod heap;
pub mod instance;
pub mod interrupt;
pub mod ipi;
pub mod mmu;
pub mod net;
pub mod net_profile;
#[cfg(feature = "copy-profile")]
pub mod copy_profile;
#[cfg(feature = "pc-sample")]
pub mod pc_sample;
pub mod net_tx_audit;
pub mod poll_budget;
pub mod runqueue;
pub mod sync;

pub mod net_segmentation;

#[cfg(feature = "network-tso-probe")]
pub mod net_tso_probe;

pub mod net_tx_coalesce;

pub mod net_segment_pool;

pub mod net_transmit;
pub mod net_receive;

#[cfg(feature = "tx-lease-profile")]
pub mod tx_lease_profile;
