//! Independently versioned C8.12 validation facade over the audited Wasmi
//! soft-float source. C8.12 configures floats off and Reference Types on.
//!
//! The facade supplies package identity only. The candidate inspection layer
//! narrows Wasmi's parser support to nullable Core-internal `funcref`.

#![no_std]

pub use wasmi_reference_base::*;
