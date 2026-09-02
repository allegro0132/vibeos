#![cfg(feature = "c88-f2-acceptance")]

use std::{vec, vec::Vec};
use vibeos_component_format::{current_validation_engine_identity, ProfileIdentity, TrapCode};
use vibeos_wasm_float_candidate::{
    CandidateInstance, CandidateModule, CandidatePoll, CandidateValue,
};
use vibeos_wasm_runtime::OwnerAllocationReservation;

const EXECUTION_CASES: usize = 4_096;
const MALFORMED_CASES: usize = 4_096;

fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn mix(digest: &mut u64, value: u64) {
    *digest ^= value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    *digest = digest.rotate_left(27).wrapping_mul(0x94d0_49bb_1331_11eb);
}

fn compile(source: &str) -> CandidateModule {
    let bytes = wat::parse_str(source).expect("valid fuzz harness WAT");
    CandidateModule::compile(&bytes, OwnerAllocationReservation::profile_default())
        .expect("fuzz harness must compile")
}

fn run(
    instance: &mut CandidateInstance,
    export: &str,
    inputs: &[CandidateValue],
) -> Result<Vec<CandidateValue>, TrapCode> {
    instance
        .start_call(export, inputs, 100_000, 10_000)
        .expect("fuzz call shape and budget must be valid");
    match instance.poll_call() {
        CandidatePoll::Ready(values) => Ok(values),
        CandidatePoll::Trapped(trap) => Err(trap),
        CandidatePoll::Pending(_) => panic!("single-operation fuzz call exceeded one quantum"),
    }
}

fn value_bits(value: CandidateValue) -> u64 {
    match value {
        CandidateValue::I32(value) => u64::from(value as u32),
        CandidateValue::I64(value) => value as u64,
        CandidateValue::F32Bits(bits) => u64::from(bits),
        CandidateValue::F64Bits(bits) => bits,
    }
}

fn expect_value(
    instance: &mut CandidateInstance,
    export: &str,
    inputs: &[CandidateValue],
    expected: CandidateValue,
    digest: &mut u64,
) {
    let values = run(instance, export, inputs).unwrap_or_else(|trap| {
        panic!("{export} unexpectedly trapped with {trap:?} for {inputs:?}")
    });
    assert_eq!(values, vec![expected], "{export} for {inputs:?}");
    mix(digest, value_bits(values[0]));
}

fn expected_trunc<T>(result: Result<T, softfloat_core::TrapCode>) -> Result<T, TrapCode> {
    match result {
        Ok(value) => Ok(value),
        Err(softfloat_core::TrapCode::BadConversionToInteger) => {
            Err(TrapCode::InvalidConversionToInteger)
        }
        Err(softfloat_core::TrapCode::IntegerOverflow) => Err(TrapCode::IntegerOverflow),
        Err(other) => panic!("unexpected backend truncation trap {other:?}"),
    }
}

#[test]
fn fixed_seed_end_to_end_fuzz_routes_dynamic_float_ops_through_candidate_wasmi() {
    let module = compile(
        r#"(module
            (func (export "add32") (param f32 f32) (result f32) local.get 0 local.get 1 f32.add)
            (func (export "div32") (param f32 f32) (result f32) local.get 0 local.get 1 f32.div)
            (func (export "sqrt32") (param f32) (result f32) local.get 0 f32.sqrt)
            (func (export "nearest32") (param f32) (result f32) local.get 0 f32.nearest)
            (func (export "min32") (param f32 f32) (result f32) local.get 0 local.get 1 f32.min)
            (func (export "lt32") (param f32 f32) (result i32) local.get 0 local.get 1 f32.lt)
            (func (export "add64") (param f64 f64) (result f64) local.get 0 local.get 1 f64.add)
            (func (export "div64") (param f64 f64) (result f64) local.get 0 local.get 1 f64.div)
            (func (export "sqrt64") (param f64) (result f64) local.get 0 f64.sqrt)
            (func (export "nearest64") (param f64) (result f64) local.get 0 f64.nearest)
            (func (export "max64") (param f64 f64) (result f64) local.get 0 local.get 1 f64.max)
            (func (export "le64") (param f64 f64) (result i32) local.get 0 local.get 1 f64.le)
            (func (export "demote") (param f64) (result f32) local.get 0 f32.demote_f64)
            (func (export "promote") (param f32) (result f64) local.get 0 f64.promote_f32)
            (func (export "trunc32s") (param f32) (result i32) local.get 0 i32.trunc_f32_s)
            (func (export "trunc64u") (param f64) (result i64) local.get 0 i64.trunc_f64_u)
        )"#,
    );
    let mut instance = module.instantiate().expect("fuzz harness must instantiate");
    let mut state = 0xc88f_2e2e_d15c_a11e;
    let mut digest = 0xcbf2_9ce4_8422_2325;

    for index in 0..EXECUTION_CASES {
        let a32 = next(&mut state) as u32;
        let b32 = next(&mut state) as u32;
        let a64 = next(&mut state);
        let b64 = next(&mut state);
        let f32_inputs = [CandidateValue::F32Bits(a32), CandidateValue::F32Bits(b32)];
        let f64_inputs = [CandidateValue::F64Bits(a64), CandidateValue::F64Bits(b64)];
        for bits in [a32, b32] {
            mix(&mut digest, u64::from(bits));
        }
        for bits in [a64, b64] {
            mix(&mut digest, bits);
        }

        expect_value(
            &mut instance,
            "add32",
            &f32_inputs,
            CandidateValue::F32Bits(softfloat_core::softfloat::f32_add_bits(a32, b32)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "div32",
            &f32_inputs,
            CandidateValue::F32Bits(softfloat_core::softfloat::f32_div_bits(a32, b32)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "sqrt32",
            &f32_inputs[..1],
            CandidateValue::F32Bits(softfloat_core::softfloat::f32_sqrt_bits(a32)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "nearest32",
            &f32_inputs[..1],
            CandidateValue::F32Bits(softfloat_core::softfloat::f32_nearest_bits(a32)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "min32",
            &f32_inputs,
            CandidateValue::F32Bits(softfloat_core::softfloat::f32_min_bits(a32, b32)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "lt32",
            &f32_inputs,
            CandidateValue::I32(i32::from(softfloat_core::softfloat::f32_lt_bits(a32, b32))),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "add64",
            &f64_inputs,
            CandidateValue::F64Bits(softfloat_core::softfloat::f64_add_bits(a64, b64)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "div64",
            &f64_inputs,
            CandidateValue::F64Bits(softfloat_core::softfloat::f64_div_bits(a64, b64)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "sqrt64",
            &f64_inputs[..1],
            CandidateValue::F64Bits(softfloat_core::softfloat::f64_sqrt_bits(a64)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "nearest64",
            &f64_inputs[..1],
            CandidateValue::F64Bits(softfloat_core::softfloat::f64_nearest_bits(a64)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "max64",
            &f64_inputs,
            CandidateValue::F64Bits(softfloat_core::softfloat::f64_max_bits(a64, b64)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "le64",
            &f64_inputs,
            CandidateValue::I32(i32::from(softfloat_core::softfloat::f64_le_bits(a64, b64))),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "demote",
            &f64_inputs[..1],
            CandidateValue::F32Bits(softfloat_core::softfloat::f32_demote_f64_bits(a64)),
            &mut digest,
        );
        expect_value(
            &mut instance,
            "promote",
            &f32_inputs[..1],
            CandidateValue::F64Bits(softfloat_core::softfloat::f64_promote_f32_bits(a32)),
            &mut digest,
        );

        let backend32 = softfloat_core::softfloat::i32_trunc_f32_s_bits(a32);
        let expected32 = expected_trunc(backend32);
        let actual32 = run(&mut instance, "trunc32s", &f32_inputs[..1]).map(|values| {
            assert_eq!(values.len(), 1);
            values[0]
        });
        assert_eq!(
            actual32,
            expected32.map(CandidateValue::I32),
            "trunc32s case {index}: {a32:08x}"
        );
        mix(
            &mut digest,
            actual32
                .map(value_bits)
                .unwrap_or_else(|trap| u64::from(trap as u16) << 48),
        );

        let backend64 = softfloat_core::softfloat::i64_trunc_f64_u_bits(a64);
        let expected64 = expected_trunc(backend64);
        let actual64 = run(&mut instance, "trunc64u", &f64_inputs[..1]).map(|values| {
            assert_eq!(values.len(), 1);
            values[0]
        });
        assert_eq!(
            actual64,
            expected64.map(|value| CandidateValue::I64(value as i64)),
            "trunc64u case {index}: {a64:016x}"
        );
        mix(
            &mut digest,
            actual64
                .map(value_bits)
                .unwrap_or_else(|trap| u64::from(trap as u16) << 48),
        );
    }

    assert_eq!(
        digest, 0xee61_7316_87e8_c81d,
        "fixed end-to-end fuzz digest changed"
    );
}

fn exercise_bytes(bytes: &[u8], digest: &mut u64) {
    mix(digest, bytes.len() as u64);
    for chunk in bytes.chunks(8) {
        let mut word = [0_u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        mix(digest, u64::from_le_bytes(word));
    }
    match CandidateModule::compile(bytes, OwnerAllocationReservation::profile_default()) {
        Ok(module) => {
            assert_eq!(module.summary().imports, 0);
            mix(digest, 1);
            mix(digest, u64::from(module.summary().functions));
            mix(digest, u64::from(module.summary().globals));
        }
        Err(error) => {
            mix(digest, u64::from(error.trap as u16) << 32);
        }
    }
}

#[test]
fn fixed_seed_malformed_and_mutated_core_fuzz_is_bounded_and_code_5_stays_inert() {
    let seed = wat::parse_str(
        "(module (func (export \"f\") (param f32 f64) (result f64) local.get 0 f64.promote_f32 local.get 1 f64.add))",
    )
    .unwrap();
    let mut digest = 0xcbf2_9ce4_8422_2325;

    for end in 0..seed.len() {
        exercise_bytes(&seed[..end], &mut digest);
    }
    for byte in 0..seed.len() {
        for bit in 0..8 {
            let mut mutated = seed.clone();
            mutated[byte] ^= 1 << bit;
            exercise_bytes(&mutated, &mut digest);
        }
    }
    for suffix in [0_u8, 1, 0x7f, 0x80, 0xff] {
        let mut appended = seed.clone();
        appended.push(suffix);
        exercise_bytes(&appended, &mut digest);
    }

    let mut state = 0xc88f_2bad_5eed_a11e;
    for _ in 0..MALFORMED_CASES {
        let len = (next(&mut state) as usize) & 0xff;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(next(&mut state) as u8);
        }
        exercise_bytes(&bytes, &mut digest);
    }

    assert_eq!(
        digest, 0xb8ec_a640_2ca6_a5df,
        "fixed malformed-corpus digest changed"
    );
    assert!(
        current_validation_engine_identity(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none(),
        "fuzzing must not activate profile code 5"
    );
}
