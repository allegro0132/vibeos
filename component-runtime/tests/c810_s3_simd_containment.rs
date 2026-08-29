#![cfg(feature = "c810-s3-acceptance")]

//! C8.10-S3 acceptance-only Component containment and fixed SIMD corpora.

use std::panic::{catch_unwind, AssertUnwindSafe};

use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity, PROFILE_2_SYNC_FLOAT_PROFILE_CODE,
    PROFILE_4_SYNC_SIMD_VALIDATION_PROFILE_CODE,
};
use vibeos_component_runtime::decode::{
    inspect_component_for_profile, inspect_component_for_profile_4_candidate, DecodeError,
};
use vibeos_wasm_simd_candidate::{execute, CandidateValue};

const CASES: usize = 512;
const EXPECTED_DIFFERENTIAL_FNV64: u64 = 0xfcb8_de30_59c1_3007;
const EXPECTED_MUTATION_FNV64: u64 = 0x8af2_9a0e_a0a0_b294;

#[derive(Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}

#[derive(Clone, Copy)]
struct Fnv64(u64);

impl Fnv64 {
    const fn new(domain: &[u8]) -> Self {
        let mut hash = Self(0xcbf2_9ce4_8422_2325);
        let mut index = 0;
        while index < domain.len() {
            hash.0 ^= domain[index] as u64;
            hash.0 = hash.0.wrapping_mul(0x0000_0100_0000_01b3);
            index += 1;
        }
        hash
    }

    fn byte(&mut self, value: u8) {
        self.0 ^= u64::from(value);
        self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
    }

    fn u128(&mut self, value: u128) {
        for byte in value.to_le_bytes() {
            self.byte(byte);
        }
    }

    const fn finish(self) -> u64 {
        self.0
    }
}

fn core_fixture() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (func (export "i32-add") (param v128 v128) (result v128)
              local.get 0 local.get 1 i32x4.add)
            (func (export "f32-add") (param v128 v128) (result v128)
              local.get 0 local.get 1 f32x4.add))"#,
    )
    .unwrap()
}

fn component_fixture() -> Vec<u8> {
    wat::parse_str(
        r#"(component
            (core module
              (func (export "run") (param v128 v128) (result v128)
                local.get 0 local.get 1 i32x4.add)))"#,
    )
    .unwrap()
}

fn lane_i32_add(lhs: u128, rhs: u128) -> u128 {
    let mut result = 0_u128;
    for lane in 0..4 {
        let shift = lane * 32;
        let a = (lhs >> shift) as u32;
        let b = (rhs >> shift) as u32;
        result |= u128::from(a.wrapping_add(b)) << shift;
    }
    result
}

fn canonical_f32(bits: u32) -> u32 {
    if bits & 0x7f80_0000 == 0x7f80_0000 && bits & 0x007f_ffff != 0 {
        0x7fc0_0000
    } else {
        bits
    }
}

fn lane_f32_add(lhs: u128, rhs: u128) -> u128 {
    let mut result = 0_u128;
    for lane in 0..4 {
        let shift = lane * 32;
        let a = f32::from_bits((lhs >> shift) as u32);
        let b = f32::from_bits((rhs >> shift) as u32);
        result |= u128::from(canonical_f32((a + b).to_bits())) << shift;
    }
    result
}

fn only_v128(values: Vec<CandidateValue>) -> u128 {
    let [CandidateValue::V128Bits(bits)] = values.as_slice() else {
        panic!("expected one v128 result")
    };
    *bits
}

#[test]
fn v128_is_accepted_only_inside_core_and_code_7_stays_non_current() {
    let bytes = component_fixture();
    let plan = inspect_component_for_profile_4_candidate(&bytes).unwrap();
    assert_eq!(plan.summary().embedded_modules, 1);
    assert!(matches!(
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION),
        Err(DecodeError::Unsupported)
    ));
    assert!(
        current_validation_engine_identity(ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION)
            .is_none()
    );
    assert_eq!(PROFILE_4_SYNC_SIMD_VALIDATION_PROFILE_CODE, 7);
    assert_eq!(PROFILE_2_SYNC_FLOAT_PROFILE_CODE, 5);
    assert!(current_validation_engine_identity(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none());
    assert!(matches!(
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_SYNC),
        Err(DecodeError::InvalidEmbeddedCore | DecodeError::Unsupported)
    ));

    assert!(wat::parse_str(r#"(component (type (func (param "forbidden" v128))))"#).is_err());

    let relaxed = wat::parse_str(
        r#"(component
            (core module
              (func (param v128 v128 v128) (result v128)
                local.get 0 local.get 1 local.get 2 f32x4.relaxed_madd)))"#,
    )
    .unwrap();
    assert!(matches!(
        inspect_component_for_profile_4_candidate(&relaxed),
        Err(DecodeError::InvalidEmbeddedCore)
    ));
}

#[test]
fn fixed_seed_integer_and_float_lane_differential_corpus_matches_oracles() {
    let module = core_fixture();
    let mut rng = XorShift64(0x243f_6a88_85a3_08d3);
    let mut hash = Fnv64::new(b"vibeos-c810-s3-simd-differential-v1");
    for _ in 0..CASES {
        let lhs = u128::from(rng.next()) | (u128::from(rng.next()) << 64);
        let rhs = u128::from(rng.next()) | (u128::from(rng.next()) << 64);
        let arguments = [CandidateValue::V128Bits(lhs), CandidateValue::V128Bits(rhs)];
        let integer = only_v128(execute(&module, "i32-add", &arguments, 10_000).unwrap().0);
        let float = only_v128(execute(&module, "f32-add", &arguments, 10_000).unwrap().0);
        assert_eq!(integer, lane_i32_add(lhs, rhs));
        assert_eq!(float, lane_f32_add(lhs, rhs));
        hash.u128(lhs);
        hash.u128(rhs);
        hash.u128(integer);
        hash.u128(float);
    }
    assert_eq!(hash.finish(), EXPECTED_DIFFERENTIAL_FNV64);
}

#[test]
fn fixed_seed_component_mutations_are_bounded_panic_free_and_stable() {
    let fixture = component_fixture();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut rng = XorShift64(0x1319_8a2e_0370_7344);
        let mut hash = Fnv64::new(b"vibeos-c810-s3-component-mutations-v1");
        for index in 0..CASES {
            let mut bytes = fixture.clone();
            match index & 3 {
                0 => bytes.truncate((rng.next() as usize) % bytes.len()),
                1 => {
                    let offset = (rng.next() as usize) % bytes.len();
                    bytes[offset] ^= 1 << (rng.next() & 7);
                }
                2 => bytes.extend_from_slice(&(rng.next() as u32).to_le_bytes()),
                3 => {
                    let offset = (rng.next() as usize) % bytes.len();
                    bytes.insert(offset, rng.next() as u8);
                }
                _ => unreachable!(),
            }
            hash.byte((index & 3) as u8);
            match inspect_component_for_profile_4_candidate(&bytes) {
                Ok(plan) => {
                    hash.byte(0);
                    hash.byte(plan.summary().embedded_modules as u8);
                }
                Err(error) => {
                    hash.byte(1);
                    hash.byte(match error {
                        DecodeError::Malformed => 1,
                        DecodeError::Unsupported => 2,
                        DecodeError::Limit => 3,
                        DecodeError::InvalidEmbeddedCore => 4,
                        _ => 5,
                    });
                }
            }
        }
        hash.finish()
    }));
    assert!(
        outcome.is_ok(),
        "the fixed mutation corpus must never panic"
    );
    assert_eq!(outcome.unwrap(), EXPECTED_MUTATION_FNV64);
}
