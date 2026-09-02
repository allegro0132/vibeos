//! Independently versioned C8.11 executable facade over the qualified C8.10
//! deterministic fixed-SIMD implementation.
//!
//! The new package identity prevents code-7 artifacts from selecting the
//! code-8 engine. Semantics remain supplied by the exact audited `simd1.1`
//! closure and are requalified under C8.11 before release.

#![no_std]

pub use wasmi_simd_base::*;
