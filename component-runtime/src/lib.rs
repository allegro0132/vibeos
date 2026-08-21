//! Bounded Component Model validation and Canonical ABI runtime primitives.

#![no_std]

extern crate alloc;

pub mod abi_value;
pub mod async_abi;
pub mod async_state;
pub mod canonical;
pub mod decode;
mod execution;
pub mod host;
pub mod memory;
mod native_async;
mod predecode;
pub mod resource;
pub mod sync;
pub mod types;
pub mod value;
pub mod world;

pub use execution::{HostCoreExportInfo, HostImportInfo};
