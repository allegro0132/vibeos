//! Bounded synchronous Component Model and Canonical ABI runtime.

#![no_std]

extern crate alloc;

pub mod abi_value;
pub mod canonical;
pub mod decode;
mod execution;
pub mod memory;
mod predecode;
pub mod resource;
pub mod sync;
pub mod types;
pub mod value;
pub mod world;
