#![no_std]
#![cfg_attr(
    not(feature = "c88-f5-acceptance"),
    doc = r#"
The C8.8-F5 target qualification runner is structurally absent by default:

```compile_fail
use vibeos_wasm_float_target::{qualify, QualificationReport};
```
"#
)]

//! Shared C8.8-F5 host and target scalar-float qualification.
//!
//! The same `no_std` routine runs in host tests and in the isolated fixed-QEMU
//! image. It consumes the exact F4 image pin and exercises the F2/F3/F4
//! candidate stack. It does not publish a command, bind a current engine,
//! create a durable object, or allocate an executable successor profile.

#[cfg(feature = "c88-f5-acceptance")]
extern crate alloc;

#[cfg(feature = "c88-f5-acceptance")]
mod acceptance {
    use alloc::{boxed::Box, vec, vec::Vec};
    use sha2::{Digest, Sha256};
    use vibeos_component_format::{
        current_validation_engine_identity, ProfileIdentity, ProfileStage, TrapCode,
        PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS, PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
    };
    use vibeos_component_image_adapter::project_float_candidate;
    use vibeos_component_runtime::{
        abi_value::float_candidate::{
            lift_flat_values, lift_parameters, lift_results, lift_value, lower_flat_values,
            lower_parameters, lower_results, lower_value, CandidateFlatValue,
            CandidateLoweredParameters, CandidateLoweredResults, CodecError, PayloadAllocator,
            RejectResources,
        },
        float_candidate::{
            FloatCandidateLifecycle, FloatCandidateLifecycleMetrics, FloatCandidateLifecyclePoll,
            FloatCandidateState,
        },
        memory::{GuestMemory, VecMemory},
        value::{CanonicalF32, CanonicalF64, CanonicalValue, ValuePosition, ValueType},
    };
    use vibeos_image_policy::C88_F4_FLOAT_CANDIDATE;
    use vibeos_wasm_float_candidate::{
        CandidateIdentity, CandidateInstance, CandidateModule, CandidatePoll, CandidateValue,
        CANDIDATE_IDENTITY,
    };
    use vibeos_wasm_runtime::{
        profile_2_candidate_required_compile_bytes, OwnerAllocationReservation,
    };

    include!(concat!(env!("OUT_DIR"), "/scalar_target_identity.rs"));

    pub const PLATFORM: &str = "qemu-virt-rv64-tcg-icount-v1";
    pub const PLATFORM_CLASS: &str = "emulator";
    pub const PHYSICAL_PROVENANCE: &str = "not-claimed";
    pub const CANDIDATE_SHA256: &str =
        "5fdb9dc9a48a9c54e899a5dc724445083c055dbf0d664927ba55d9780cc9996a";
    pub const CANDIDATE_SHA256_BYTES: [u8; 32] = [
        0x5f, 0xdb, 0x9d, 0xc9, 0xa4, 0x8a, 0x9c, 0x54, 0xe8, 0x99, 0xa5, 0xdc, 0x72, 0x44, 0x45,
        0x08, 0x3c, 0x05, 0x5d, 0xbf, 0x0d, 0x66, 0x49, 0x27, 0xba, 0x55, 0xd9, 0x78, 0x0c, 0xc9,
        0x99, 0x6a,
    ];
    pub const WIT_SHA256: &str = "4c2b4d994caee3755671b89a0dfe92136fd3d130f001d5ac660aa988371f31ac";
    pub const WIT_SHA256_BYTES: [u8; 32] = [
        0x4c, 0x2b, 0x4d, 0x99, 0x4c, 0xae, 0xe3, 0x75, 0x56, 0x71, 0xb8, 0x9a, 0x0d, 0xfe, 0x92,
        0x13, 0x6f, 0xd3, 0xd1, 0x30, 0xf0, 0x01, 0xd5, 0xac, 0x66, 0x0a, 0xa9, 0x88, 0x37, 0x1f,
        0x31, 0xac,
    ];
    pub const CANDIDATE_COMPONENT_BYTES: usize = C88_F4_FLOAT_CANDIDATE.artifact_bytes().len();
    pub const WORLD: &str = "vibe:float-acceptance/lifecycle@1.0.0";
    pub const TOTAL_FUEL: u64 = 100_000;
    pub const POLL_QUANTUM: u64 = 100;
    pub const MAX_FUEL_TRACE_POLLS: u32 = 2_000;
    pub const CORE_MEMORY_BYTES: usize = 65_536;
    pub const CORE_PATH_CASES: usize = SCALAR_TARGET_RUNTIME_OP_COUNT as usize * 2;
    pub const CORE_CASES: usize = CORE_PATH_CASES + 2;

    pub const fn candidate_identity() -> CandidateIdentity {
        CANDIDATE_IDENTITY
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CorePath {
        Runtime,
        Fold,
        Spin,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CoreOutcome {
        Value(u64),
        Trap(TrapCode),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CoreVector {
        pub id: &'static str,
        pub input0: u64,
        pub input1: u64,
        pub expected: CoreOutcome,
    }

    macro_rules! value_vector {
        ($id:literal, $input0:expr, $input1:expr, $expected:expr) => {
            CoreVector {
                id: $id,
                input0: $input0,
                input1: $input1,
                expected: CoreOutcome::Value($expected),
            }
        };
    }

    macro_rules! trap_vector {
        ($id:literal, $input0:expr, $input1:expr, $expected:expr) => {
            CoreVector {
                id: $id,
                input0: $input0,
                input1: $input1,
                expected: CoreOutcome::Trap($expected),
            }
        };
    }

    /// Closed F2 scalar-op matrix. Inputs cross the engine boundary only as
    /// integer bits; the paired `fold` call executes literal operands inside
    /// the same module so both runtime and translation-time paths are covered.
    pub const CORE_VECTORS: [CoreVector; SCALAR_TARGET_RUNTIME_OP_COUNT as usize] = [
        value_vector!(
            "f32-add",
            0x0000_0000_3fc0_0000,
            0x0000_0000_3f00_0000,
            0x0000_0000_4000_0000
        ),
        value_vector!(
            "f32-sub",
            0x0000_0000_3fc0_0000,
            0x0000_0000_3f00_0000,
            0x0000_0000_3f80_0000
        ),
        value_vector!(
            "f32-mul",
            0x0000_0000_3fc0_0000,
            0x0000_0000_3f00_0000,
            0x0000_0000_3f40_0000
        ),
        value_vector!(
            "f32-div",
            0x0000_0000_3fc0_0000,
            0x0000_0000_3f00_0000,
            0x0000_0000_4040_0000
        ),
        value_vector!(
            "f32-min",
            0x0000_0000_3fc0_0000,
            0x0000_0000_3f00_0000,
            0x0000_0000_3f00_0000
        ),
        value_vector!(
            "f32-max",
            0x0000_0000_3fc0_0000,
            0x0000_0000_3f00_0000,
            0x0000_0000_3fc0_0000
        ),
        value_vector!(
            "f32-copysign",
            0x0000_0000_3fc0_0000,
            0x0000_0000_bf00_0000,
            0x0000_0000_bfc0_0000
        ),
        value_vector!(
            "f64-add",
            0x3ff8_0000_0000_0000,
            0x3fe0_0000_0000_0000,
            0x4000_0000_0000_0000
        ),
        value_vector!(
            "f64-sub",
            0x3ff8_0000_0000_0000,
            0x3fe0_0000_0000_0000,
            0x3ff0_0000_0000_0000
        ),
        value_vector!(
            "f64-mul",
            0x3ff8_0000_0000_0000,
            0x3fe0_0000_0000_0000,
            0x3fe8_0000_0000_0000
        ),
        value_vector!(
            "f64-div",
            0x3ff8_0000_0000_0000,
            0x3fe0_0000_0000_0000,
            0x4008_0000_0000_0000
        ),
        value_vector!(
            "f64-min",
            0x3ff8_0000_0000_0000,
            0x3fe0_0000_0000_0000,
            0x3fe0_0000_0000_0000
        ),
        value_vector!(
            "f64-max",
            0x3ff8_0000_0000_0000,
            0x3fe0_0000_0000_0000,
            0x3ff8_0000_0000_0000
        ),
        value_vector!(
            "f64-copysign",
            0x3ff8_0000_0000_0000,
            0xbfe0_0000_0000_0000,
            0xbff8_0000_0000_0000
        ),
        value_vector!("f32-abs", 0x0000_0000_bfc0_0000, 0, 0x0000_0000_3fc0_0000),
        value_vector!("f32-neg", 0x0000_0000_3fc0_0000, 0, 0x0000_0000_bfc0_0000),
        value_vector!("f32-ceil", 0x0000_0000_3fa0_0000, 0, 0x0000_0000_4000_0000),
        value_vector!("f32-floor", 0x0000_0000_3fe0_0000, 0, 0x0000_0000_3f80_0000),
        value_vector!("f32-trunc", 0x0000_0000_bfe0_0000, 0, 0x0000_0000_bf80_0000),
        value_vector!(
            "f32-nearest",
            0x0000_0000_4020_0000,
            0,
            0x0000_0000_4000_0000
        ),
        value_vector!("f32-sqrt", 0x0000_0000_4080_0000, 0, 0x0000_0000_4000_0000),
        value_vector!("f64-abs", 0xbff8_0000_0000_0000, 0, 0x3ff8_0000_0000_0000),
        value_vector!("f64-neg", 0x3ff8_0000_0000_0000, 0, 0xbff8_0000_0000_0000),
        value_vector!("f64-ceil", 0x3ff4_0000_0000_0000, 0, 0x4000_0000_0000_0000),
        value_vector!("f64-floor", 0x3ffc_0000_0000_0000, 0, 0x3ff0_0000_0000_0000),
        value_vector!("f64-trunc", 0xbffc_0000_0000_0000, 0, 0xbff0_0000_0000_0000),
        value_vector!(
            "f64-nearest",
            0x4004_0000_0000_0000,
            0,
            0x4000_0000_0000_0000
        ),
        value_vector!("f64-sqrt", 0x4010_0000_0000_0000, 0, 0x4000_0000_0000_0000),
        value_vector!("f32-eq", 0x0000_0000_3fc0_0000, 0x0000_0000_3fc0_0000, 1),
        value_vector!("f32-ne", 0x0000_0000_3fc0_0000, 0x0000_0000_3f00_0000, 1),
        value_vector!("f32-lt", 0x0000_0000_3f00_0000, 0x0000_0000_3fc0_0000, 1),
        value_vector!("f32-gt", 0x0000_0000_3fc0_0000, 0x0000_0000_3f00_0000, 1),
        value_vector!("f32-le", 0x0000_0000_3fc0_0000, 0x0000_0000_3fc0_0000, 1),
        value_vector!("f32-ge", 0x0000_0000_3fc0_0000, 0x0000_0000_3fc0_0000, 1),
        value_vector!("f64-eq", 0x3ff8_0000_0000_0000, 0x3ff8_0000_0000_0000, 1),
        value_vector!("f64-ne", 0x3ff8_0000_0000_0000, 0x3fe0_0000_0000_0000, 1),
        value_vector!("f64-lt", 0x3fe0_0000_0000_0000, 0x3ff8_0000_0000_0000, 1),
        value_vector!("f64-gt", 0x3ff8_0000_0000_0000, 0x3fe0_0000_0000_0000, 1),
        value_vector!("f64-le", 0x3ff8_0000_0000_0000, 0x3ff8_0000_0000_0000, 1),
        value_vector!("f64-ge", 0x3ff8_0000_0000_0000, 0x3ff8_0000_0000_0000, 1),
        value_vector!(
            "i32-trunc-f32-s",
            0x0000_0000_c0f8_0000,
            0,
            0xffff_ffff_ffff_fff9
        ),
        value_vector!("i32-trunc-f32-u", 0x0000_0000_40f8_0000, 0, 7),
        value_vector!(
            "i64-trunc-f32-s",
            0x0000_0000_c0f8_0000,
            0,
            0xffff_ffff_ffff_fff9
        ),
        value_vector!("i64-trunc-f32-u", 0x0000_0000_40f8_0000, 0, 7),
        value_vector!(
            "i32-trunc-f64-s",
            0xc01f_0000_0000_0000,
            0,
            0xffff_ffff_ffff_fff9
        ),
        value_vector!("i32-trunc-f64-u", 0x401f_0000_0000_0000, 0, 7),
        value_vector!(
            "i64-trunc-f64-s",
            0xc01f_0000_0000_0000,
            0,
            0xffff_ffff_ffff_fff9
        ),
        value_vector!("i64-trunc-f64-u", 0x401f_0000_0000_0000, 0, 7),
        value_vector!(
            "f32-convert-i32-s",
            0x0000_0000_ffff_fff9,
            0,
            0x0000_0000_c0e0_0000
        ),
        value_vector!(
            "f32-convert-i32-u",
            0x0000_0000_ffff_ffff,
            0,
            0x0000_0000_4f80_0000
        ),
        value_vector!(
            "f32-convert-i64-s",
            0xffff_ffff_ffff_fff9,
            0,
            0x0000_0000_c0e0_0000
        ),
        value_vector!(
            "f32-convert-i64-u",
            0xffff_ffff_ffff_ffff,
            0,
            0x0000_0000_5f80_0000
        ),
        value_vector!(
            "f64-convert-i32-s",
            0x0000_0000_ffff_fff9,
            0,
            0xc01c_0000_0000_0000
        ),
        value_vector!(
            "f64-convert-i32-u",
            0x0000_0000_ffff_ffff,
            0,
            0x41ef_ffff_ffe0_0000
        ),
        value_vector!(
            "f64-convert-i64-s",
            0xffff_ffff_ffff_fff9,
            0,
            0xc01c_0000_0000_0000
        ),
        value_vector!(
            "f64-convert-i64-u",
            0xffff_ffff_ffff_ffff,
            0,
            0x43f0_0000_0000_0000
        ),
        value_vector!(
            "f64-promote-f32",
            0x0000_0000_3fc0_0000,
            0,
            0x3ff8_0000_0000_0000
        ),
        value_vector!(
            "f32-demote-f64",
            0x3ff8_0000_0000_0000,
            0,
            0x0000_0000_3fc0_0000
        ),
        value_vector!("f32-local", 0x0000_0000_3fc0_0000, 0, 0x0000_0000_3fc0_0000),
        value_vector!("f64-local", 0x3ff8_0000_0000_0000, 0, 0x3ff8_0000_0000_0000),
        value_vector!(
            "f32-global",
            0x0000_0000_3fc0_0000,
            0,
            0x0000_0000_3fc0_0000
        ),
        value_vector!(
            "f64-global",
            0x3ff8_0000_0000_0000,
            0,
            0x3ff8_0000_0000_0000
        ),
        value_vector!(
            "f32-memory",
            0x0000_0000_3fc0_0000,
            0,
            0x0000_0000_3fc0_0000
        ),
        value_vector!(
            "f64-memory",
            0x3ff8_0000_0000_0000,
            0,
            0x3ff8_0000_0000_0000
        ),
        value_vector!(
            "f32-select",
            0x0000_0000_3fc0_0000,
            0,
            0x0000_0000_3fc0_0000
        ),
        value_vector!(
            "f64-select",
            0x3ff8_0000_0000_0000,
            0,
            0x3ff8_0000_0000_0000
        ),
        value_vector!("f32-call", 0x0000_0000_3fc0_0000, 0, 0x0000_0000_3fc0_0000),
        value_vector!("f64-call", 0x3ff8_0000_0000_0000, 0, 0x3ff8_0000_0000_0000),
        value_vector!(
            "f32-reinterpret",
            0x0000_0000_3fc0_0000,
            0,
            0x0000_0000_3fc0_0000
        ),
        value_vector!(
            "f64-reinterpret",
            0x3ff8_0000_0000_0000,
            0,
            0x3ff8_0000_0000_0000
        ),
        trap_vector!(
            "invalid-conversion",
            0x0000_0000_7f80_0001,
            0,
            TrapCode::InvalidConversionToInteger
        ),
        trap_vector!(
            "integer-overflow",
            0x7ff0_0000_0000_0000,
            0,
            TrapCode::IntegerOverflow
        ),
    ];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CoreObservation {
        pub id: &'static str,
        pub path: CorePath,
        pub op_index: u32,
        pub input0: u64,
        pub input1: u64,
        pub expected: CoreOutcome,
        pub actual: CoreOutcome,
        pub consumed_fuel: u64,
        pub remaining_fuel: u64,
        pub poll_calls: u32,
        pub pending_polls: u32,
        pub trace_digest: u64,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct CoreQualificationReport {
        pub wasm_bytes: u32,
        pub wasm_sha256: &'static str,
        pub wasm_sha256_bytes: [u8; 32],
        pub compile_reservation_bytes: usize,
        pub observations: Vec<CoreObservation>,
        pub runtime_digest: u64,
        pub fold_digest: u64,
        pub spin_trace_digest: u64,
        pub spin_consumed_fuel: u64,
        pub spin_remaining_fuel: u64,
        pub spin_poll_calls: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct QualificationVector {
        pub id: &'static str,
        pub left_bits: u32,
        pub right_bits: u64,
        pub expected_bits: u64,
    }

    pub const F4_VECTORS: [QualificationVector; 12] = [
        QualificationVector {
            id: "positive-zero",
            left_bits: 0x0000_0000,
            right_bits: 0x0000_0000_0000_0000,
            expected_bits: 0x0000_0000_0000_0000,
        },
        QualificationVector {
            id: "negative-zero",
            left_bits: 0x8000_0000,
            right_bits: 0x8000_0000_0000_0000,
            expected_bits: 0x8000_0000_0000_0000,
        },
        QualificationVector {
            id: "opposite-zero",
            left_bits: 0x8000_0000,
            right_bits: 0x0000_0000_0000_0000,
            expected_bits: 0x0000_0000_0000_0000,
        },
        QualificationVector {
            id: "finite",
            left_bits: 0x3fc0_0000,
            right_bits: 0x4002_0000_0000_0000,
            expected_bits: 0x400e_0000_0000_0000,
        },
        QualificationVector {
            id: "finite-cancellation",
            left_bits: 0xbf80_0000,
            right_bits: 0x3ff0_0000_0000_0000,
            expected_bits: 0x0000_0000_0000_0000,
        },
        QualificationVector {
            id: "f32-subnormal-promote",
            left_bits: 0x0000_0001,
            right_bits: 0x0000_0000_0000_0000,
            expected_bits: 0x36a0_0000_0000_0000,
        },
        QualificationVector {
            id: "f64-subnormal",
            left_bits: 0x0000_0000,
            right_bits: 0x0000_0000_0000_0001,
            expected_bits: 0x0000_0000_0000_0001,
        },
        QualificationVector {
            id: "round-tie-even",
            left_bits: 0x3f80_0000,
            right_bits: 0x3ca0_0000_0000_0000,
            expected_bits: 0x3ff0_0000_0000_0000,
        },
        QualificationVector {
            id: "round-up-two-ulp",
            left_bits: 0x3f80_0000,
            right_bits: 0x3cb8_0000_0000_0000,
            expected_bits: 0x3ff0_0000_0000_0002,
        },
        QualificationVector {
            id: "opposite-infinities",
            left_bits: 0xff80_0000,
            right_bits: 0x7ff0_0000_0000_0000,
            expected_bits: PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
        },
        QualificationVector {
            id: "f32-signaling-nan-boundary",
            left_bits: 0xff80_0001,
            right_bits: 0x0000_0000_0000_0000,
            expected_bits: PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
        },
        QualificationVector {
            id: "f64-signaling-nan-boundary",
            left_bits: 0x0000_0000,
            right_bits: 0xfff0_0000_0000_0001,
            expected_bits: PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
        },
    ];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CodecVector {
        pub id: &'static str,
        pub raw_f32: u32,
        pub raw_f64: u64,
        pub expected_f32: u32,
        pub expected_f64: u64,
    }

    pub const F3_VECTORS: [CodecVector; 12] = [
        CodecVector {
            id: "positive-zero",
            raw_f32: 0x0000_0000,
            raw_f64: 0x0000_0000_0000_0000,
            expected_f32: 0x0000_0000,
            expected_f64: 0x0000_0000_0000_0000,
        },
        CodecVector {
            id: "negative-zero",
            raw_f32: 0x8000_0000,
            raw_f64: 0x8000_0000_0000_0000,
            expected_f32: 0x8000_0000,
            expected_f64: 0x8000_0000_0000_0000,
        },
        CodecVector {
            id: "minimum-subnormal",
            raw_f32: 0x0000_0001,
            raw_f64: 0x0000_0000_0000_0001,
            expected_f32: 0x0000_0001,
            expected_f64: 0x0000_0000_0000_0001,
        },
        CodecVector {
            id: "maximum-subnormal",
            raw_f32: 0x007f_ffff,
            raw_f64: 0x000f_ffff_ffff_ffff,
            expected_f32: 0x007f_ffff,
            expected_f64: 0x000f_ffff_ffff_ffff,
        },
        CodecVector {
            id: "minimum-normal",
            raw_f32: 0x0080_0000,
            raw_f64: 0x0010_0000_0000_0000,
            expected_f32: 0x0080_0000,
            expected_f64: 0x0010_0000_0000_0000,
        },
        CodecVector {
            id: "maximum-finite",
            raw_f32: 0x7f7f_ffff,
            raw_f64: 0x7fef_ffff_ffff_ffff,
            expected_f32: 0x7f7f_ffff,
            expected_f64: 0x7fef_ffff_ffff_ffff,
        },
        CodecVector {
            id: "positive-infinity",
            raw_f32: 0x7f80_0000,
            raw_f64: 0x7ff0_0000_0000_0000,
            expected_f32: 0x7f80_0000,
            expected_f64: 0x7ff0_0000_0000_0000,
        },
        CodecVector {
            id: "negative-infinity",
            raw_f32: 0xff80_0000,
            raw_f64: 0xfff0_0000_0000_0000,
            expected_f32: 0xff80_0000,
            expected_f64: 0xfff0_0000_0000_0000,
        },
        CodecVector {
            id: "canonical-nan",
            raw_f32: 0x7fc0_0000,
            raw_f64: 0x7ff8_0000_0000_0000,
            expected_f32: PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS,
            expected_f64: PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
        },
        CodecVector {
            id: "positive-signaling-nan",
            raw_f32: 0x7f80_0001,
            raw_f64: 0x7ff0_0000_0000_0001,
            expected_f32: PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS,
            expected_f64: PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
        },
        CodecVector {
            id: "negative-signaling-nan",
            raw_f32: 0xff80_0001,
            raw_f64: 0xfff0_0000_0000_0001,
            expected_f32: PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS,
            expected_f64: PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
        },
        CodecVector {
            id: "maximum-payload-nan",
            raw_f32: 0xffff_ffff,
            raw_f64: 0xffff_ffff_ffff_ffff,
            expected_f32: PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS,
            expected_f64: PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
        },
    ];

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct VectorObservation {
        pub output_bits: u64,
        pub consumed_fuel: u64,
        pub remaining_fuel: u64,
        pub poll_calls: u32,
        pub pending_polls: u32,
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct CodecObservation {
        pub actual_f32: u32,
        pub actual_f64: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CodecQualificationReport {
        pub vectors: [CodecObservation; F3_VECTORS.len()],
        pub scalar_cases: u32,
        pub flat_cases: u32,
        pub memory_cases: u32,
        pub indirect_cases: u32,
        pub variant_cases: u32,
        pub nested_cases: u32,
        pub hostile_rejections: u32,
        pub allocations: u32,
        pub allocated_bytes: u32,
        pub digest: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FuelOutcome {
        Pending,
        FuelExhausted,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FuelObservation {
        pub poll_index: u32,
        pub outcome: FuelOutcome,
        pub consumed_fuel: u64,
        pub remaining_fuel: u64,
        pub delta: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct LifecycleSnapshot {
        pub id: &'static str,
        pub state: FloatCandidateState,
        pub live_instances: u8,
        pub metrics: FloatCandidateLifecycleMetrics,
        pub last_consumed_fuel: u64,
        pub last_remaining_fuel: u64,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct LifecycleQualificationReport {
        pub component_sha256_bytes: [u8; 32],
        pub wit_sha256_bytes: [u8; 32],
        pub vectors: [VectorObservation; F4_VECTORS.len()],
        pub vector_digest: u64,
        pub vector_fuel_total: u64,
        pub exhaustion_pending_polls: u32,
        pub exhaustion_trace_digest: u64,
        pub exhaustion_consumed_fuel: u64,
        pub exhaustion_remaining_fuel: u64,
        pub exhaustion_trace: Vec<FuelObservation>,
        pub recovery_output_bits: u64,
        pub recovery_consumed_fuel: u64,
        pub lifecycle_metrics: FloatCandidateLifecycleMetrics,
        pub snapshots: [LifecycleSnapshot; 5],
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct QualificationReport {
        pub core: CoreQualificationReport,
        pub codec: CodecQualificationReport,
        pub lifecycle: LifecycleQualificationReport,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u16)]
    pub enum QualificationError {
        Identity = 1,
        Projection = 2,
        Limits = 3,
        Activation = 4,
        VectorStart = 5,
        VectorPoll = 6,
        VectorBits = 7,
        VectorFuel = 8,
        FuelStart = 9,
        FuelTrace = 10,
        FuelTerminal = 11,
        Recovery = 12,
        RecoveryVector = 13,
        FinalState = 14,
        CodecMemory = 15,
        CodecFlat = 16,
        CodecNested = 17,
        CodecHostile = 18,
        Cancellation = 19,
        GuestTrap = 20,
        EvidenceAllocation = 21,
        FuelTerminalInvariant = 22,
        FuelUnexpectedOutcome = 23,
        FuelTimeout = 24,
        FuelTerminalMetrics = 25,
        FuelTerminalSum = 26,
        FuelTerminalRemainder = 27,
        FuelTerminalState = 28,
        CoreIdentity = 29,
        CoreReservation = 30,
        CoreCompile = 31,
        CoreInstantiate = 32,
        CoreStart = 33,
        CorePoll = 34,
        CoreFuel = 35,
        CoreOutcome = 36,
        CoreTimeout = 37,
        CoreRepeatability = 38,
    }

    impl QualificationError {
        pub const fn code(self) -> u16 {
            self as u16
        }
    }

    fn mix(mut state: u64, value: u64) -> u64 {
        state ^= value;
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
        state.rotate_left(17)
    }

    fn fuel_balances(consumed_fuel: u64, remaining_fuel: u64) -> bool {
        consumed_fuel.checked_add(remaining_fuel) == Some(TOTAL_FUEL)
    }

    fn core_outcome_word(outcome: CoreOutcome) -> u64 {
        match outcome {
            CoreOutcome::Value(bits) => mix(0x7661_6c75_6500_0000, bits),
            CoreOutcome::Trap(trap) => 0x7472_6170_0000_0000 | trap.code() as u64,
        }
    }

    fn run_core_call(
        instance: &mut CandidateInstance,
        id: &'static str,
        path: CorePath,
        op_index: u32,
        input0: u64,
        input1: u64,
        expected: CoreOutcome,
        export: &str,
        inputs: &[CandidateValue],
    ) -> Result<CoreObservation, QualificationError> {
        instance
            .start_call(export, inputs, TOTAL_FUEL, POLL_QUANTUM)
            .map_err(|_| QualificationError::CoreStart)?;
        let mut poll_calls = 0_u32;
        let mut pending_polls = 0_u32;
        let mut previous_consumed = 0_u64;
        let mut trace_digest = 0xcbf2_9ce4_8422_2325_u64;
        loop {
            poll_calls = poll_calls
                .checked_add(1)
                .ok_or(QualificationError::CorePoll)?;
            if poll_calls > MAX_FUEL_TRACE_POLLS + 1 {
                return Err(QualificationError::CoreTimeout);
            }
            let terminal = match instance.poll_call() {
                CandidatePoll::Pending(metrics) => {
                    pending_polls = pending_polls
                        .checked_add(1)
                        .ok_or(QualificationError::CorePoll)?;
                    let delta = metrics
                        .consumed_fuel
                        .checked_sub(previous_consumed)
                        .ok_or(QualificationError::CoreFuel)?;
                    if delta == 0
                        || delta > POLL_QUANTUM
                        || !fuel_balances(metrics.consumed_fuel, metrics.remaining_fuel)
                    {
                        return Err(QualificationError::CoreFuel);
                    }
                    previous_consumed = metrics.consumed_fuel;
                    trace_digest = mix(trace_digest, poll_calls as u64);
                    trace_digest = mix(trace_digest, 0);
                    trace_digest = mix(trace_digest, metrics.consumed_fuel);
                    trace_digest = mix(trace_digest, metrics.remaining_fuel);
                    continue;
                }
                CandidatePoll::Ready(values) => {
                    let actual = match values.as_slice() {
                        [CandidateValue::I64(value)] => CoreOutcome::Value(*value as u64),
                        _ => return Err(QualificationError::CoreOutcome),
                    };
                    (actual, instance.call_metrics())
                }
                CandidatePoll::Trapped(trap) => (CoreOutcome::Trap(trap), instance.call_metrics()),
            };
            let metrics = terminal.1.ok_or(QualificationError::CoreFuel)?;
            if metrics.consumed_fuel == 0
                || metrics.consumed_fuel < previous_consumed
                || metrics.consumed_fuel > TOTAL_FUEL
                || !fuel_balances(metrics.consumed_fuel, metrics.remaining_fuel)
                || terminal.0 != expected
            {
                return Err(if terminal.0 == expected {
                    QualificationError::CoreFuel
                } else {
                    QualificationError::CoreOutcome
                });
            }
            trace_digest = mix(trace_digest, poll_calls as u64);
            trace_digest = mix(trace_digest, core_outcome_word(terminal.0));
            trace_digest = mix(trace_digest, metrics.consumed_fuel);
            trace_digest = mix(trace_digest, metrics.remaining_fuel);
            return Ok(CoreObservation {
                id,
                path,
                op_index,
                input0,
                input1,
                expected,
                actual: terminal.0,
                consumed_fuel: metrics.consumed_fuel,
                remaining_fuel: metrics.remaining_fuel,
                poll_calls,
                pending_polls,
                trace_digest,
            });
        }
    }

    fn mix_core_observation(mut digest: u64, observation: CoreObservation) -> u64 {
        digest = mix(digest, observation.op_index as u64);
        digest = mix(digest, observation.input0);
        digest = mix(digest, observation.input1);
        digest = mix(digest, core_outcome_word(observation.expected));
        digest = mix(digest, core_outcome_word(observation.actual));
        digest = mix(digest, observation.consumed_fuel);
        digest = mix(digest, observation.remaining_fuel);
        digest = mix(digest, observation.poll_calls as u64);
        mix(digest, observation.trace_digest)
    }

    fn qualify_core() -> Result<CoreQualificationReport, QualificationError> {
        if CANDIDATE_IDENTITY.production_ready
            || CANDIDATE_IDENTITY.acceptance_feature != "c88-f2-acceptance"
            || CANDIDATE_IDENTITY.package != "vibeos-wasmi-softfloat"
            || SCALAR_TARGET_RUNTIME_OP_COUNT as usize != CORE_VECTORS.len()
            || SCALAR_TARGET_WASM_BYTES.len() > u32::MAX as usize
        {
            return Err(QualificationError::CoreIdentity);
        }
        let compile_reservation_bytes =
            profile_2_candidate_required_compile_bytes(SCALAR_TARGET_WASM_BYTES)
                .map_err(|_| QualificationError::CoreReservation)?;
        let module = CandidateModule::compile(
            SCALAR_TARGET_WASM_BYTES,
            OwnerAllocationReservation::new(compile_reservation_bytes),
        )
        .map_err(|_| QualificationError::CoreCompile)?;
        let summary = module.summary();
        if module.reserved_compile_bytes() != compile_reservation_bytes
            || summary.bytes as usize != SCALAR_TARGET_WASM_BYTES.len()
            || summary.imports != 0
            || summary.exports != 3
            || summary.memories != 1
            || summary.tables != 0
        {
            return Err(QualificationError::CoreReservation);
        }
        let mut instance = module
            .instantiate_with_memory_limit(CORE_MEMORY_BYTES)
            .map_err(|_| QualificationError::CoreInstantiate)?;
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(CORE_CASES)
            .map_err(|_| QualificationError::EvidenceAllocation)?;
        let mut runtime_digest = 0x7275_6e74_696d_6500_u64;
        let mut fold_digest = 0x666f_6c64_0000_0000_u64;
        for (op_index, vector) in CORE_VECTORS.iter().copied().enumerate() {
            let runtime_inputs = [
                CandidateValue::I32(op_index as i32),
                CandidateValue::I64(vector.input0 as i64),
                CandidateValue::I64(vector.input1 as i64),
            ];
            let runtime = run_core_call(
                &mut instance,
                vector.id,
                CorePath::Runtime,
                op_index as u32,
                vector.input0,
                vector.input1,
                vector.expected,
                "runtime",
                &runtime_inputs,
            )?;
            runtime_digest = mix_core_observation(runtime_digest, runtime);
            observations.push(runtime);

            let fold_inputs = [CandidateValue::I32(op_index as i32)];
            let fold = run_core_call(
                &mut instance,
                vector.id,
                CorePath::Fold,
                op_index as u32,
                0,
                0,
                vector.expected,
                "fold",
                &fold_inputs,
            )?;
            fold_digest = mix_core_observation(fold_digest, fold);
            observations.push(fold);
        }

        let spin_expected = CoreOutcome::Trap(TrapCode::FuelExhausted);
        let first_spin = run_core_call(
            &mut instance,
            "spin-a",
            CorePath::Spin,
            SCALAR_TARGET_RUNTIME_OP_COUNT,
            0,
            0,
            spin_expected,
            "spin",
            &[],
        )?;
        let second_spin = run_core_call(
            &mut instance,
            "spin-b",
            CorePath::Spin,
            SCALAR_TARGET_RUNTIME_OP_COUNT,
            0,
            0,
            spin_expected,
            "spin",
            &[],
        )?;
        if first_spin.actual != second_spin.actual
            || first_spin.consumed_fuel != second_spin.consumed_fuel
            || first_spin.remaining_fuel != second_spin.remaining_fuel
            || first_spin.poll_calls != second_spin.poll_calls
            || first_spin.pending_polls != second_spin.pending_polls
            || first_spin.trace_digest != second_spin.trace_digest
        {
            return Err(QualificationError::CoreRepeatability);
        }
        observations.push(first_spin);
        observations.push(second_spin);
        if observations.len() != CORE_CASES {
            return Err(QualificationError::CoreIdentity);
        }

        Ok(CoreQualificationReport {
            wasm_bytes: SCALAR_TARGET_WASM_BYTES.len() as u32,
            wasm_sha256: SCALAR_TARGET_WASM_SHA256_HEX,
            wasm_sha256_bytes: SCALAR_TARGET_WASM_SHA256,
            compile_reservation_bytes,
            observations,
            runtime_digest,
            fold_digest,
            spin_trace_digest: first_spin.trace_digest,
            spin_consumed_fuel: first_spin.consumed_fuel,
            spin_remaining_fuel: first_spin.remaining_fuel,
            spin_poll_calls: first_spin.poll_calls,
        })
    }

    fn output_bits(value: CanonicalValue) -> Result<u64, QualificationError> {
        match value {
            CanonicalValue::F64(value) => Ok(value.to_bits()),
            _ => Err(QualificationError::VectorBits),
        }
    }

    fn run_vector(
        lifecycle: &mut FloatCandidateLifecycle,
        vector: QualificationVector,
    ) -> Result<VectorObservation, QualificationError> {
        lifecycle
            .start_call(
                0,
                CanonicalF32::from_bits(vector.left_bits),
                CanonicalF64::from_bits(vector.right_bits),
            )
            .map_err(|_| QualificationError::VectorStart)?;
        let mut poll_calls = 0_u32;
        let mut pending_polls = 0_u32;
        let mut previous_consumed = 0_u64;
        loop {
            poll_calls = poll_calls
                .checked_add(1)
                .ok_or(QualificationError::VectorPoll)?;
            if poll_calls > 1_002 {
                return Err(QualificationError::VectorPoll);
            }
            match lifecycle
                .poll_call()
                .map_err(|_| QualificationError::VectorPoll)?
            {
                FloatCandidateLifecyclePoll::Pending(metrics) => {
                    pending_polls = pending_polls
                        .checked_add(1)
                        .ok_or(QualificationError::VectorPoll)?;
                    if metrics.consumed_fuel <= previous_consumed
                        || metrics.consumed_fuel - previous_consumed > POLL_QUANTUM
                        || !fuel_balances(metrics.consumed_fuel, metrics.remaining_fuel)
                    {
                        return Err(QualificationError::VectorFuel);
                    }
                    previous_consumed = metrics.consumed_fuel;
                }
                FloatCandidateLifecyclePoll::Ready(value) => {
                    let output_bits = output_bits(value)?;
                    if output_bits != vector.expected_bits {
                        return Err(QualificationError::VectorBits);
                    }
                    let metrics = lifecycle
                        .last_call_metrics()
                        .ok_or(QualificationError::VectorFuel)?;
                    if metrics.consumed_fuel == 0
                        || metrics.consumed_fuel < previous_consumed
                        || metrics.consumed_fuel > TOTAL_FUEL
                        || !fuel_balances(metrics.consumed_fuel, metrics.remaining_fuel)
                    {
                        return Err(QualificationError::VectorFuel);
                    }
                    return Ok(VectorObservation {
                        output_bits,
                        consumed_fuel: metrics.consumed_fuel,
                        remaining_fuel: metrics.remaining_fuel,
                        poll_calls,
                        pending_polls,
                    });
                }
                FloatCandidateLifecyclePoll::Faulted(_) => {
                    return Err(QualificationError::VectorPoll)
                }
            }
        }
    }

    fn run_exhaustion(
        lifecycle: &mut FloatCandidateLifecycle,
    ) -> Result<(u32, u64, u64, u64, Vec<FuelObservation>), QualificationError> {
        lifecycle
            .start_call(2, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0))
            .map_err(|_| QualificationError::FuelStart)?;
        let mut pending_polls = 0_u32;
        let mut expected_consumed = 0_u64;
        let mut trace_digest = 0xcbf2_9ce4_8422_2325_u64;
        let mut trace = Vec::new();
        trace
            .try_reserve_exact(MAX_FUEL_TRACE_POLLS as usize + 1)
            .map_err(|_| QualificationError::EvidenceAllocation)?;
        for _ in 0..=MAX_FUEL_TRACE_POLLS {
            match lifecycle
                .poll_call()
                .map_err(|_| QualificationError::FuelTrace)?
            {
                FloatCandidateLifecyclePoll::Pending(metrics) => {
                    pending_polls = pending_polls
                        .checked_add(1)
                        .ok_or(QualificationError::FuelTrace)?;
                    let delta = metrics
                        .consumed_fuel
                        .checked_sub(expected_consumed)
                        .ok_or(QualificationError::FuelTrace)?;
                    if delta == 0
                        || delta > POLL_QUANTUM
                        || !fuel_balances(metrics.consumed_fuel, metrics.remaining_fuel)
                    {
                        return Err(QualificationError::FuelTrace);
                    }
                    expected_consumed = metrics.consumed_fuel;
                    trace_digest = mix(trace_digest, pending_polls as u64);
                    trace_digest = mix(trace_digest, metrics.consumed_fuel);
                    trace_digest = mix(trace_digest, metrics.remaining_fuel);
                    trace.push(FuelObservation {
                        poll_index: pending_polls - 1,
                        outcome: FuelOutcome::Pending,
                        consumed_fuel: metrics.consumed_fuel,
                        remaining_fuel: metrics.remaining_fuel,
                        delta,
                    });
                }
                FloatCandidateLifecyclePoll::Faulted(TrapCode::FuelExhausted) => {
                    let metrics = lifecycle
                        .last_call_metrics()
                        .ok_or(QualificationError::FuelTerminal)?;
                    if pending_polls == 0 || pending_polls > MAX_FUEL_TRACE_POLLS {
                        return Err(QualificationError::FuelTerminalInvariant);
                    }
                    let terminal_delta = metrics
                        .consumed_fuel
                        .checked_sub(expected_consumed)
                        .ok_or(QualificationError::FuelTerminalMetrics)?;
                    if terminal_delta == 0 || terminal_delta > POLL_QUANTUM {
                        return Err(QualificationError::FuelTerminalMetrics);
                    }
                    if !fuel_balances(metrics.consumed_fuel, metrics.remaining_fuel) {
                        return Err(QualificationError::FuelTerminalSum);
                    }
                    if metrics.remaining_fuel >= POLL_QUANTUM {
                        return Err(QualificationError::FuelTerminalRemainder);
                    }
                    if lifecycle.state() != FloatCandidateState::Faulted(TrapCode::FuelExhausted)
                        || lifecycle.live_instances() != 0
                    {
                        return Err(QualificationError::FuelTerminalState);
                    }
                    trace.push(FuelObservation {
                        poll_index: pending_polls,
                        outcome: FuelOutcome::FuelExhausted,
                        consumed_fuel: metrics.consumed_fuel,
                        remaining_fuel: metrics.remaining_fuel,
                        delta: terminal_delta,
                    });
                    trace_digest = mix(trace_digest, pending_polls as u64);
                    trace_digest = mix(trace_digest, metrics.consumed_fuel);
                    trace_digest = mix(trace_digest, metrics.remaining_fuel);
                    trace_digest = mix(trace_digest, TrapCode::FuelExhausted.code() as u64);
                    return Ok((
                        pending_polls,
                        trace_digest,
                        metrics.consumed_fuel,
                        metrics.remaining_fuel,
                        trace,
                    ));
                }
                _ => return Err(QualificationError::FuelUnexpectedOutcome),
            }
        }
        Err(QualificationError::FuelTimeout)
    }

    fn lifecycle_snapshot(
        id: &'static str,
        lifecycle: &FloatCandidateLifecycle,
    ) -> Result<LifecycleSnapshot, QualificationError> {
        let last = lifecycle
            .last_call_metrics()
            .ok_or(QualificationError::FinalState)?;
        Ok(LifecycleSnapshot {
            id,
            state: lifecycle.state(),
            live_instances: lifecycle.live_instances(),
            metrics: lifecycle.metrics(),
            last_consumed_fuel: last.consumed_fuel,
            last_remaining_fuel: last.remaining_fuel,
        })
    }

    fn qualify_lifecycle() -> Result<LifecycleQualificationReport, QualificationError> {
        let profile = ProfileIdentity::PROFILE_2_SYNC_FLOAT;
        if profile.stage != ProfileStage::ValidationOnly
            || profile.execution_enabled()
            || current_validation_engine_identity(profile).is_some()
        {
            return Err(QualificationError::Identity);
        }
        let pin = C88_F4_FLOAT_CANDIDATE;
        let component_sha256_bytes: [u8; 32] = Sha256::digest(pin.artifact_bytes()).into();
        let wit_sha256_bytes: [u8; 32] = Sha256::digest(pin.wit_source().as_bytes()).into();
        if component_sha256_bytes != pin.expected_sha256()
            || component_sha256_bytes != CANDIDATE_SHA256_BYTES
            || wit_sha256_bytes != WIT_SHA256_BYTES
            || pin.profile() != profile
            || pin.world() != WORLD
            || pin.export_name() != "run"
            || pin.activation_label() != "c88-f4-float-candidate"
            || pin.limits().memory_bytes != 2 * 65_536
            || pin.limits().total_fuel != TOTAL_FUEL
            || pin.limits().poll_quantum != POLL_QUANTUM
            || pin.limits().resources != 0
        {
            return Err(QualificationError::Limits);
        }
        let projection =
            project_float_candidate(pin).map_err(|_| QualificationError::Projection)?;
        if projection.profile() != profile
            || projection.activation_label() != "c88-f4-float-candidate"
            || projection.validated_plan().is_err()
        {
            return Err(QualificationError::Projection);
        }
        let mut lifecycle = projection
            .activate_candidate()
            .map_err(|_| QualificationError::Activation)?;
        if lifecycle.state() != FloatCandidateState::Idle
            || lifecycle.live_instances() != 1
            || lifecycle.limits().total_fuel != TOTAL_FUEL
            || lifecycle.limits().poll_quantum != POLL_QUANTUM
        {
            return Err(QualificationError::Activation);
        }

        let mut observations = [VectorObservation::default(); F4_VECTORS.len()];
        let mut vector_digest = 0xcbf2_9ce4_8422_2325_u64;
        let mut vector_fuel_total = 0_u64;
        for (index, vector) in F4_VECTORS.iter().copied().enumerate() {
            let observation = run_vector(&mut lifecycle, vector)?;
            observations[index] = observation;
            vector_fuel_total = vector_fuel_total
                .checked_add(observation.consumed_fuel)
                .ok_or(QualificationError::VectorFuel)?;
            vector_digest = mix(vector_digest, index as u64);
            vector_digest = mix(vector_digest, vector.left_bits as u64);
            vector_digest = mix(vector_digest, vector.right_bits);
            vector_digest = mix(vector_digest, observation.output_bits);
            vector_digest = mix(vector_digest, observation.consumed_fuel);
            vector_digest = mix(vector_digest, observation.poll_calls as u64);
        }

        lifecycle
            .start_call(2, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0))
            .map_err(|_| QualificationError::Cancellation)?;
        let cancellation_metrics = match lifecycle
            .poll_call()
            .map_err(|_| QualificationError::Cancellation)?
        {
            FloatCandidateLifecyclePoll::Pending(metrics)
                if metrics.consumed_fuel > 0
                    && metrics.consumed_fuel <= POLL_QUANTUM
                    && fuel_balances(metrics.consumed_fuel, metrics.remaining_fuel) =>
            {
                metrics
            }
            _ => return Err(QualificationError::Cancellation),
        };
        lifecycle
            .cancel()
            .map_err(|_| QualificationError::Cancellation)?;
        if lifecycle.state() != FloatCandidateState::Cancelled
            || lifecycle.live_instances() != 0
            || lifecycle.metrics().cancellations != 1
            || lifecycle.metrics().reclaimed_instances != 1
        {
            return Err(QualificationError::Cancellation);
        }
        let cancelled = lifecycle_snapshot("cancelled", &lifecycle)?;
        if cancelled.last_consumed_fuel != cancellation_metrics.consumed_fuel
            || cancelled.last_remaining_fuel != cancellation_metrics.remaining_fuel
            || (cancelled.last_consumed_fuel, cancelled.last_remaining_fuel) != (99, 99_901)
        {
            return Err(QualificationError::Cancellation);
        }

        lifecycle
            .recover()
            .map_err(|_| QualificationError::Recovery)?;
        lifecycle
            .start_call(1, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0))
            .map_err(|_| QualificationError::GuestTrap)?;
        let mut trapped = false;
        for _ in 0..=TOTAL_FUEL / POLL_QUANTUM {
            match lifecycle
                .poll_call()
                .map_err(|_| QualificationError::GuestTrap)?
            {
                FloatCandidateLifecyclePoll::Pending(metrics)
                    if metrics.consumed_fuel <= TOTAL_FUEL
                        && fuel_balances(metrics.consumed_fuel, metrics.remaining_fuel) => {}
                FloatCandidateLifecyclePoll::Faulted(TrapCode::Unreachable) => {
                    trapped = true;
                    break;
                }
                _ => return Err(QualificationError::GuestTrap),
            }
        }
        if !trapped
            || lifecycle.state() != FloatCandidateState::Faulted(TrapCode::Unreachable)
            || lifecycle.live_instances() != 0
            || lifecycle.metrics().faults != 1
            || lifecycle.metrics().reclaimed_instances != 2
        {
            return Err(QualificationError::GuestTrap);
        }
        let unreachable_fault = lifecycle_snapshot("unreachable-fault", &lifecycle)?;
        if (
            unreachable_fault.last_consumed_fuel,
            unreachable_fault.last_remaining_fuel,
        ) != (5, 99_995)
        {
            return Err(QualificationError::GuestTrap);
        }

        lifecycle
            .recover()
            .map_err(|_| QualificationError::Recovery)?;

        let (
            exhaustion_pending_polls,
            exhaustion_trace_digest,
            exhaustion_consumed_fuel,
            exhaustion_remaining_fuel,
            exhaustion_trace,
        ) = run_exhaustion(&mut lifecycle)?;
        let before_recovery = lifecycle.metrics();
        if before_recovery.calls_started != F4_VECTORS.len() as u64 + 3
            || before_recovery.calls_completed != F4_VECTORS.len() as u64
            || before_recovery.cancellations != 1
            || before_recovery.faults != 2
            || before_recovery.reclaimed_instances != 3
        {
            return Err(QualificationError::FinalState);
        }
        let fuel_fault = lifecycle_snapshot("fuel-fault", &lifecycle)?;
        if (
            fuel_fault.last_consumed_fuel,
            fuel_fault.last_remaining_fuel,
        ) != (exhaustion_consumed_fuel, exhaustion_remaining_fuel)
        {
            return Err(QualificationError::FinalState);
        }

        lifecycle
            .recover()
            .map_err(|_| QualificationError::Recovery)?;
        let recovery = run_vector(
            &mut lifecycle,
            QualificationVector {
                id: "cold-recovery",
                left_bits: 0x3f80_0000,
                right_bits: 0,
                expected_bits: 0x3ff0_0000_0000_0000,
            },
        )
        .map_err(|_| QualificationError::RecoveryVector)?;
        let recovered = lifecycle_snapshot("recovered", &lifecycle)?;
        if (recovered.last_consumed_fuel, recovered.last_remaining_fuel)
            != (recovery.consumed_fuel, recovery.remaining_fuel)
        {
            return Err(QualificationError::RecoveryVector);
        }
        lifecycle.revoke();
        let lifecycle_metrics = lifecycle.metrics();
        if recovery.output_bits != 0x3ff0_0000_0000_0000
            || lifecycle.state() != FloatCandidateState::Revoked
            || lifecycle.live_instances() != 0
            || lifecycle_metrics.activations != 4
            || lifecycle_metrics.calls_started != F4_VECTORS.len() as u64 + 4
            || lifecycle_metrics.calls_completed != F4_VECTORS.len() as u64 + 1
            || lifecycle_metrics.cancellations != 1
            || lifecycle_metrics.faults != 2
            || lifecycle_metrics.revocations != 1
            || lifecycle_metrics.reclaimed_instances != 4
            || lifecycle_metrics.peak_live_instances != 1
            || current_validation_engine_identity(profile).is_some()
        {
            return Err(QualificationError::FinalState);
        }
        let revoked = lifecycle_snapshot("revoked", &lifecycle)?;
        if (revoked.last_consumed_fuel, revoked.last_remaining_fuel)
            != (recovery.consumed_fuel, recovery.remaining_fuel)
        {
            return Err(QualificationError::FinalState);
        }

        Ok(LifecycleQualificationReport {
            component_sha256_bytes,
            wit_sha256_bytes,
            vectors: observations,
            vector_digest,
            vector_fuel_total,
            exhaustion_pending_polls,
            exhaustion_trace_digest,
            exhaustion_consumed_fuel,
            exhaustion_remaining_fuel,
            exhaustion_trace,
            recovery_output_bits: recovery.output_bits,
            recovery_consumed_fuel: recovery.consumed_fuel,
            lifecycle_metrics,
            snapshots: [cancelled, unreachable_fault, fuel_fault, recovered, revoked],
        })
    }

    #[derive(Default)]
    struct BumpAllocator {
        next: u32,
        allocations: u32,
        allocated_bytes: u32,
    }

    impl BumpAllocator {
        const fn at(next: u32) -> Self {
            Self {
                next,
                allocations: 0,
                allocated_bytes: 0,
            }
        }
    }

    impl PayloadAllocator<VecMemory> for BumpAllocator {
        fn allocate(
            &mut self,
            memory: &mut VecMemory,
            size: u32,
            alignment: u32,
        ) -> Result<u32, CodecError> {
            let mask = alignment.checked_sub(1).ok_or(CodecError::Misaligned)?;
            let pointer = self.next.checked_add(mask).ok_or(CodecError::Overflow)? & !mask;
            let end = pointer.checked_add(size).ok_or(CodecError::Overflow)?;
            memory.grow_to(end as usize).map_err(CodecError::from)?;
            self.next = end.max(pointer.saturating_add(1));
            self.allocations = self
                .allocations
                .checked_add(1)
                .ok_or(CodecError::AllocationLimit)?;
            self.allocated_bytes = self
                .allocated_bytes
                .checked_add(size)
                .ok_or(CodecError::AllocationLimit)?;
            Ok(pointer)
        }
    }

    fn canonical_f32(bits: u32) -> u32 {
        CanonicalF32::from_bits(bits).to_bits()
    }

    fn canonical_f64(bits: u64) -> u64 {
        CanonicalF64::from_bits(bits).to_bits()
    }

    fn qualify_codec() -> Result<CodecQualificationReport, QualificationError> {
        let mut digest = 0xcbf2_9ce4_8422_2325_u64;
        let mut scalar_cases = 0_u32;
        let mut flat_cases = 0_u32;
        let mut memory_cases = 0_u32;
        let mut observations = [CodecObservation::default(); F3_VECTORS.len()];
        let mut memory =
            VecMemory::new(1024, 128 * 1024).map_err(|_| QualificationError::CodecMemory)?;
        let mut allocator = BumpAllocator::at(4096);

        for (index, vector) in F3_VECTORS.iter().copied().enumerate() {
            let actual_f32 = canonical_f32(vector.raw_f32);
            let actual_f64 = canonical_f64(vector.raw_f64);
            if actual_f32 != vector.expected_f32 || actual_f64 != vector.expected_f64 {
                return Err(QualificationError::CodecFlat);
            }
            observations[index] = CodecObservation {
                actual_f32,
                actual_f64,
            };

            let f32_types = [ValueType::F32];
            let f32_values = [CanonicalValue::F32(CanonicalF32::from_bits(vector.raw_f32))];
            let (f32_flat, _) =
                lower_flat_values(&mut memory, &mut allocator, &f32_types, &f32_values)
                    .map_err(|_| QualificationError::CodecFlat)?;
            if f32_flat.as_slice() != [CandidateFlatValue::F32Bits(actual_f32)] {
                return Err(QualificationError::CodecFlat);
            }
            let (f32_lifted, _) = lift_flat_values(
                &memory,
                &RejectResources,
                &f32_types,
                &[CandidateFlatValue::F32Bits(vector.raw_f32)],
                ValuePosition::Parameter,
            )
            .map_err(|_| QualificationError::CodecFlat)?;
            if f32_lifted.as_slice() != f32_values {
                return Err(QualificationError::CodecFlat);
            }

            let f64_types = [ValueType::F64];
            let f64_values = [CanonicalValue::F64(CanonicalF64::from_bits(vector.raw_f64))];
            let (f64_flat, _) =
                lower_flat_values(&mut memory, &mut allocator, &f64_types, &f64_values)
                    .map_err(|_| QualificationError::CodecFlat)?;
            if f64_flat.as_slice() != [CandidateFlatValue::F64Bits(actual_f64)] {
                return Err(QualificationError::CodecFlat);
            }
            let (f64_lifted, _) = lift_flat_values(
                &memory,
                &RejectResources,
                &f64_types,
                &[CandidateFlatValue::F64Bits(vector.raw_f64)],
                ValuePosition::Parameter,
            )
            .map_err(|_| QualificationError::CodecFlat)?;
            if f64_lifted.as_slice() != f64_values {
                return Err(QualificationError::CodecFlat);
            }

            let f32_source = 64 + (index as u32) * 8;
            let f32_target = f32_source + 4;
            memory
                .write_exact(f32_source, &vector.raw_f32.to_le_bytes())
                .map_err(|_| QualificationError::CodecMemory)?;
            let (f32_memory_value, _) = lift_value(
                &memory,
                &RejectResources,
                &ValueType::F32,
                f32_source,
                ValuePosition::Parameter,
            )
            .map_err(|_| QualificationError::CodecMemory)?;
            lower_value(
                &mut memory,
                &mut allocator,
                &ValueType::F32,
                &f32_memory_value,
                f32_target,
                ValuePosition::Result,
            )
            .map_err(|_| QualificationError::CodecMemory)?;
            let mut lowered_f32 = [0_u8; 4];
            memory
                .read_exact(f32_target, &mut lowered_f32)
                .map_err(|_| QualificationError::CodecMemory)?;
            if u32::from_le_bytes(lowered_f32) != actual_f32 {
                return Err(QualificationError::CodecMemory);
            }

            let f64_source = 256 + (index as u32) * 16;
            let f64_target = f64_source + 8;
            memory
                .write_exact(f64_source, &vector.raw_f64.to_le_bytes())
                .map_err(|_| QualificationError::CodecMemory)?;
            let (f64_memory_value, _) = lift_value(
                &memory,
                &RejectResources,
                &ValueType::F64,
                f64_source,
                ValuePosition::Parameter,
            )
            .map_err(|_| QualificationError::CodecMemory)?;
            lower_value(
                &mut memory,
                &mut allocator,
                &ValueType::F64,
                &f64_memory_value,
                f64_target,
                ValuePosition::Result,
            )
            .map_err(|_| QualificationError::CodecMemory)?;
            let mut lowered_f64 = [0_u8; 8];
            memory
                .read_exact(f64_target, &mut lowered_f64)
                .map_err(|_| QualificationError::CodecMemory)?;
            if u64::from_le_bytes(lowered_f64) != actual_f64 {
                return Err(QualificationError::CodecMemory);
            }

            digest = mix(digest, index as u64);
            digest = mix(digest, vector.raw_f32 as u64);
            digest = mix(digest, vector.raw_f64);
            digest = mix(digest, actual_f32 as u64);
            digest = mix(digest, actual_f64);
            scalar_cases += 2;
            flat_cases += 4;
            memory_cases += 2;
        }

        let mut sixteen_types = Vec::new();
        let mut sixteen_values = Vec::new();
        sixteen_types
            .try_reserve_exact(16)
            .map_err(|_| QualificationError::EvidenceAllocation)?;
        sixteen_values
            .try_reserve_exact(16)
            .map_err(|_| QualificationError::EvidenceAllocation)?;
        for index in 0..16_u32 {
            sixteen_types.push(ValueType::F32);
            sixteen_values.push(CanonicalValue::F32(CanonicalF32::from_bits(index)));
        }
        match lower_parameters(&mut memory, &mut allocator, &sixteen_types, &sixteen_values)
            .map_err(|_| QualificationError::CodecNested)?
        {
            CandidateLoweredParameters::Flat { values, .. } if values.len() == 16 => {}
            _ => return Err(QualificationError::CodecNested),
        }

        let mut seventeen_types = Vec::new();
        let mut seventeen_values = Vec::new();
        seventeen_types
            .try_reserve_exact(17)
            .map_err(|_| QualificationError::EvidenceAllocation)?;
        seventeen_values
            .try_reserve_exact(17)
            .map_err(|_| QualificationError::EvidenceAllocation)?;
        for index in 0..17_u32 {
            seventeen_types.push(ValueType::F32);
            seventeen_values.push(CanonicalValue::F32(CanonicalF32::from_bits(index)));
        }
        let indirect_arguments = match lower_parameters(
            &mut memory,
            &mut allocator,
            &seventeen_types,
            &seventeen_values,
        )
        .map_err(|_| QualificationError::CodecNested)?
        {
            CandidateLoweredParameters::Indirect { arguments, .. } => arguments,
            _ => return Err(QualificationError::CodecNested),
        };
        let (seventeen_lifted, _) = lift_parameters(
            &memory,
            &RejectResources,
            &seventeen_types,
            &indirect_arguments,
        )
        .map_err(|_| QualificationError::CodecNested)?;
        if seventeen_lifted != seventeen_values {
            return Err(QualificationError::CodecNested);
        }

        let result_types = [ValueType::F32, ValueType::F64];
        let result_values = [
            CanonicalValue::F32(CanonicalF32::from_bits(0x8000_0000)),
            CanonicalValue::F64(CanonicalF64::from_bits(0xfff0_0000_0000_0001)),
        ];
        let result_pointer =
            match lower_results(&mut memory, &mut allocator, &result_types, &result_values)
                .map_err(|_| QualificationError::CodecNested)?
            {
                CandidateLoweredResults::Retptr { pointer, .. } => pointer,
                _ => return Err(QualificationError::CodecNested),
            };
        let (result_lifted, _) = lift_results(
            &memory,
            &RejectResources,
            &result_types,
            &[CandidateFlatValue::I32(result_pointer as i32)],
        )
        .map_err(|_| QualificationError::CodecNested)?;
        if result_lifted != result_values {
            return Err(QualificationError::CodecNested);
        }
        digest = mix(digest, indirect_arguments[0].kind() as u64);
        digest = mix(digest, result_pointer as u64);

        let variant_type =
            ValueType::Variant(vec![Some(ValueType::F32), Some(ValueType::F64), None]);
        let variant_value = CanonicalValue::Variant {
            case: 0,
            payload: Some(Box::new(CanonicalValue::F32(CanonicalF32::from_bits(
                0xff80_0001,
            )))),
        };
        let variant_arguments = match lower_parameters(
            &mut memory,
            &mut allocator,
            core::slice::from_ref(&variant_type),
            core::slice::from_ref(&variant_value),
        )
        .map_err(|_| QualificationError::CodecNested)?
        {
            CandidateLoweredParameters::Flat { values, .. } => values,
            _ => return Err(QualificationError::CodecNested),
        };
        if variant_arguments.as_slice()
            != [
                CandidateFlatValue::I32(0),
                CandidateFlatValue::I64(PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS as i64),
            ]
        {
            return Err(QualificationError::CodecNested);
        }
        let (variant_lifted, _) = lift_parameters(
            &memory,
            &RejectResources,
            core::slice::from_ref(&variant_type),
            &variant_arguments,
        )
        .map_err(|_| QualificationError::CodecNested)?;
        if variant_lifted.as_slice() != core::slice::from_ref(&variant_value) {
            return Err(QualificationError::CodecNested);
        }
        digest = mix(digest, PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS as u64);

        let nested_type = ValueType::Record(vec![
            ValueType::F32,
            ValueType::List(Box::new(ValueType::F64)),
            ValueType::Result {
                ok: Some(Box::new(ValueType::List(Box::new(ValueType::F32)))),
                error: Some(Box::new(ValueType::F64)),
            },
        ]);
        let nested_value = CanonicalValue::Record(vec![
            CanonicalValue::F32(CanonicalF32::from_bits(0xff80_0001)),
            CanonicalValue::List(vec![
                CanonicalValue::F64(CanonicalF64::from_bits(1)),
                CanonicalValue::F64(CanonicalF64::from_bits(0xfff0_0000_0000_0001)),
            ]),
            CanonicalValue::Result(Ok(Some(Box::new(CanonicalValue::List(vec![
                CanonicalValue::F32(CanonicalF32::from_bits(0x8000_0000)),
                CanonicalValue::F32(CanonicalF32::from_bits(0x7f80_0001)),
            ]))))),
        ]);
        lower_value(
            &mut memory,
            &mut allocator,
            &nested_type,
            &nested_value,
            512,
            ValuePosition::Parameter,
        )
        .map_err(|_| QualificationError::CodecNested)?;
        let (nested_lifted, _) = lift_value(
            &memory,
            &RejectResources,
            &nested_type,
            512,
            ValuePosition::Parameter,
        )
        .map_err(|_| QualificationError::CodecNested)?;
        if nested_lifted != nested_value {
            return Err(QualificationError::CodecNested);
        }
        digest = mix(digest, allocator.allocations as u64);
        digest = mix(digest, allocator.allocated_bytes as u64);

        let mut hostile = VecMemory::new(256, 256).map_err(|_| QualificationError::CodecHostile)?;
        hostile
            .write_exact(0, &240_u32.to_le_bytes())
            .map_err(|_| QualificationError::CodecHostile)?;
        hostile
            .write_exact(4, &5_u32.to_le_bytes())
            .map_err(|_| QualificationError::CodecHostile)?;
        let list_type = ValueType::List(Box::new(ValueType::F32));
        if lift_value(
            &hostile,
            &RejectResources,
            &list_type,
            0,
            ValuePosition::Parameter,
        ) != Err(CodecError::OutOfBounds)
            || lift_value(
                &hostile,
                &RejectResources,
                &ValueType::F32,
                2,
                ValuePosition::Parameter,
            ) != Err(CodecError::Misaligned)
        {
            return Err(QualificationError::CodecHostile);
        }
        hostile
            .write_exact(0, &0xffff_fffc_u32.to_le_bytes())
            .map_err(|_| QualificationError::CodecHostile)?;
        hostile
            .write_exact(4, &2_u32.to_le_bytes())
            .map_err(|_| QualificationError::CodecHostile)?;
        if lift_value(
            &hostile,
            &RejectResources,
            &list_type,
            0,
            ValuePosition::Parameter,
        ) != Err(CodecError::OutOfBounds)
        {
            return Err(QualificationError::CodecHostile);
        }

        Ok(CodecQualificationReport {
            vectors: observations,
            scalar_cases,
            flat_cases,
            memory_cases,
            indirect_cases: 3,
            variant_cases: 1,
            nested_cases: 1,
            hostile_rejections: 3,
            allocations: allocator.allocations,
            allocated_bytes: allocator.allocated_bytes,
            digest,
        })
    }

    /// Run the closed F5 target replay of selected F2/F3/F4 gates on both
    /// host and target. The broader host-only differential, fuzz, hostile,
    /// and cleanup corpora remain the independently completed F2/F3/F4 gates.
    pub fn qualify() -> Result<QualificationReport, QualificationError> {
        Ok(QualificationReport {
            core: qualify_core()?,
            codec: qualify_codec()?,
            lifecycle: qualify_lifecycle()?,
        })
    }
}

#[cfg(feature = "c88-f5-acceptance")]
pub use acceptance::*;

#[cfg(all(test, feature = "c88-f5-acceptance"))]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn shared_host_core_codec_and_lifecycle_qualification_passes() {
        let report = qualify().unwrap();
        assert_eq!(report.core.wasm_bytes, 4_179);
        assert_eq!(
            report.core.wasm_sha256,
            "6e1cb23543bdfbbb9397c3dd5ad69b2f023d23cf292f652029da838d098121ba"
        );
        assert_eq!(report.core.observations.len(), CORE_CASES);
        assert_eq!(report.core.compile_reservation_bytes, 135_720);
        assert_eq!(report.core.runtime_digest, 0x3fb9_3000_b758_09b0);
        assert_eq!(report.core.fold_digest, 0x2972_8126_8f51_6746);
        assert_eq!(report.core.spin_trace_digest, 0xaf2d_de39_8571_6198);
        assert_eq!(report.core.spin_consumed_fuel, 99_998);
        assert_eq!(report.core.spin_remaining_fuel, 2);
        assert_eq!(report.core.spin_poll_calls, 1_011);
        assert_eq!(report.codec.scalar_cases, 24);
        assert_eq!(report.codec.flat_cases, 48);
        assert_eq!(report.codec.memory_cases, 24);
        assert_eq!(report.codec.indirect_cases, 3);
        assert_eq!(report.codec.variant_cases, 1);
        assert_eq!(report.codec.nested_cases, 1);
        assert_eq!(report.codec.hostile_rejections, 3);
        assert_eq!(report.codec.allocations, 4);
        assert_eq!(report.codec.allocated_bytes, 108);
        assert_eq!(report.codec.digest, 0x6a86_6785_1156_a05c);
        assert_eq!(report.lifecycle.vectors.len(), F4_VECTORS.len());
        assert_eq!(report.lifecycle.vector_digest, 0x14ec_9b26_b290_191c);
        assert_eq!(report.lifecycle.vector_fuel_total, 84);
        assert_eq!(report.lifecycle.exhaustion_pending_polls, 999);
        assert_eq!(
            report.lifecycle.exhaustion_trace_digest,
            0x1377_4615_3ac6_133c
        );
        assert_eq!(
            report
                .lifecycle
                .exhaustion_consumed_fuel
                .checked_add(report.lifecycle.exhaustion_remaining_fuel),
            Some(TOTAL_FUEL)
        );
        assert_eq!(report.lifecycle.exhaustion_consumed_fuel, 99_999);
        assert_eq!(report.lifecycle.exhaustion_remaining_fuel, 1);
        assert_eq!(report.lifecycle.recovery_output_bits, 0x3ff0_0000_0000_0000);
    }
}
