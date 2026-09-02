#![cfg(feature = "c88-f2-acceptance")]

use std::{format, string::String, vec, vec::Vec};
use vibeos_component_format::{
    current_validation_engine_identity, profile_2_sync_float_validation_contract, ProfileIdentity,
    TrapCode,
};
use vibeos_wasm_float_candidate::{
    CandidateInstance, CandidateModule, CandidatePoll, CandidateValue, CANDIDATE_IDENTITY,
};
use vibeos_wasm_runtime::OwnerAllocationReservation;

const F32_NAN: u32 = 0x7fc0_0000;
const F64_NAN: u64 = 0x7ff8_0000_0000_0000;

type F32BinaryOp = (&'static str, fn(u32, u32) -> u32);
type F64BinaryOp = (&'static str, fn(u64, u64) -> u64);
type F32UnaryOp = (&'static str, fn(u32) -> u32);
type F64UnaryOp = (&'static str, fn(u64) -> u64);
type F32ComparisonOp = (&'static str, fn(u32, u32) -> bool);
type F64ComparisonOp = (&'static str, fn(u64, u64) -> bool);

fn compile(wat_source: &str) -> CandidateModule {
    let bytes = wat::parse_str(wat_source).expect("valid WAT fixture");
    CandidateModule::compile(&bytes, OwnerAllocationReservation::profile_default())
        .expect("candidate module must compile")
}

fn run(
    instance: &mut CandidateInstance,
    export: &str,
    inputs: &[CandidateValue],
) -> Result<Vec<CandidateValue>, TrapCode> {
    instance
        .start_call(export, inputs, 1_000_000, 10_000)
        .expect("call shape and budget must be valid");
    for _ in 0..10_000 {
        match instance.poll_call() {
            CandidatePoll::Pending(_) => {}
            CandidatePoll::Ready(values) => return Ok(values),
            CandidatePoll::Trapped(trap) => return Err(trap),
        }
    }
    panic!("candidate call did not terminate");
}

fn f32_value(bits: u32) -> CandidateValue {
    CandidateValue::F32Bits(bits)
}

fn f64_value(bits: u64) -> CandidateValue {
    CandidateValue::F64Bits(bits)
}

fn expected_truncation(name: &str, bits: u64) -> Result<Vec<CandidateValue>, TrapCode> {
    use softfloat_core::softfloat as sf;
    let result = match name {
        "i32_trunc_f32_s" => sf::i32_trunc_f32_s_bits(bits as u32).map(CandidateValue::I32),
        "i32_trunc_f32_u" => {
            sf::i32_trunc_f32_u_bits(bits as u32).map(|value| CandidateValue::I32(value as i32))
        }
        "i64_trunc_f32_s" => sf::i64_trunc_f32_s_bits(bits as u32).map(CandidateValue::I64),
        "i64_trunc_f32_u" => {
            sf::i64_trunc_f32_u_bits(bits as u32).map(|value| CandidateValue::I64(value as i64))
        }
        "i32_trunc_f64_s" => sf::i32_trunc_f64_s_bits(bits).map(CandidateValue::I32),
        "i32_trunc_f64_u" => {
            sf::i32_trunc_f64_u_bits(bits).map(|value| CandidateValue::I32(value as i32))
        }
        "i64_trunc_f64_s" => sf::i64_trunc_f64_s_bits(bits).map(CandidateValue::I64),
        "i64_trunc_f64_u" => {
            sf::i64_trunc_f64_u_bits(bits).map(|value| CandidateValue::I64(value as i64))
        }
        _ => panic!("unknown truncation operation {name}"),
    };
    result.map(|value| vec![value]).map_err(|trap| match trap {
        softfloat_core::TrapCode::BadConversionToInteger => TrapCode::InvalidConversionToInteger,
        softfloat_core::TrapCode::IntegerOverflow => TrapCode::IntegerOverflow,
        other => panic!("unexpected backend truncation trap {other:?}"),
    })
}

#[test]
fn candidate_identity_is_acceptance_only_and_code_5_stays_inert() {
    assert_eq!(CANDIDATE_IDENTITY.package, "vibeos-wasmi-softfloat");
    assert_eq!(CANDIDATE_IDENTITY.version, "1.1.0-vibeos-f2.1");
    assert_eq!(
        CANDIDATE_IDENTITY.patched_manifest_sha256,
        "2d94218e4fa5eea30b8e516e055fae8f72465dbc1ef75f8b1df3495cbcd0432f"
    );
    assert_eq!(
        CANDIDATE_IDENTITY.patch_delta_sha256,
        "3d2aec1d7e510fc3b3edb87dcacb2d4ed34eb448356704a027841b047938ec64"
    );
    const {
        assert!(!CANDIDATE_IDENTITY.production_ready);
    }
    assert_eq!(CANDIDATE_IDENTITY.acceptance_feature, "c88-f2-acceptance");
    let contract = profile_2_sync_float_validation_contract();
    assert!(!contract.runtime_ready());
    assert!(current_validation_engine_identity(contract.profile()).is_none());
    assert!(current_validation_engine_identity(ProfileIdentity::PROFILE_1_SYNC).is_some());
}

#[test]
fn every_scalar_arithmetic_comparison_and_rounding_op_matches_backend_in_runtime_and_folded_paths()
{
    let binary = ["add", "sub", "mul", "div", "min", "max", "copysign"];
    let unary = ["abs", "neg", "ceil", "floor", "trunc", "nearest", "sqrt"];
    let comparisons = ["eq", "ne", "lt", "gt", "le", "ge"];
    let build_source = |width: &str| {
        let mut source = String::from("(module\n");
        let (lhs, rhs) = if width == "f32" {
            ("0x3fa00000", "0xc0200000")
        } else {
            ("0x3ff4000000000000", "0xc004000000000000")
        };
        let int_width = if width == "f32" { "i32" } else { "i64" };
        for op in binary {
            source.push_str(&format!(
                "(func (export \"{width}_{op}_runtime\") (param {width} {width}) (result {width}) local.get 0 local.get 1 {width}.{op})\n"
            ));
            source.push_str(&format!(
                "(func (export \"{width}_{op}_folded\") (result {width}) ({width}.{op} ({width}.reinterpret_{int_width} ({int_width}.const {lhs})) ({width}.reinterpret_{int_width} ({int_width}.const {rhs}))))\n"
            ));
        }
        for op in unary {
            source.push_str(&format!(
                "(func (export \"{width}_{op}_runtime\") (param {width}) (result {width}) local.get 0 {width}.{op})\n"
            ));
            source.push_str(&format!(
                "(func (export \"{width}_{op}_folded\") (result {width}) ({width}.{op} ({width}.reinterpret_{int_width} ({int_width}.const {lhs}))))\n"
            ));
        }
        for op in comparisons {
            source.push_str(&format!(
                "(func (export \"{width}_{op}_runtime\") (param {width} {width}) (result i32) local.get 0 local.get 1 {width}.{op})\n"
            ));
            source.push_str(&format!(
                "(func (export \"{width}_{op}_folded\") (result i32) ({width}.{op} ({width}.reinterpret_{int_width} ({int_width}.const {lhs})) ({width}.reinterpret_{int_width} ({int_width}.const {rhs}))))\n"
            ));
        }
        source.push(')');
        source
    };
    let f32_module = compile(&build_source("f32"));
    let f64_module = compile(&build_source("f64"));
    let mut f32_instance = f32_module
        .instantiate()
        .expect("instantiate f32 operation matrix");
    let mut f64_instance = f64_module
        .instantiate()
        .expect("instantiate f64 operation matrix");

    let f32_lhs = 0x3fa0_0000;
    let f32_rhs = 0xc020_0000;
    let f64_lhs = 0x3ff4_0000_0000_0000;
    let f64_rhs = 0xc004_0000_0000_0000;
    let f32_binary: [F32BinaryOp; 7] = [
        ("add", softfloat_core::softfloat::f32_add_bits),
        ("sub", softfloat_core::softfloat::f32_sub_bits),
        ("mul", softfloat_core::softfloat::f32_mul_bits),
        ("div", softfloat_core::softfloat::f32_div_bits),
        ("min", softfloat_core::softfloat::f32_min_bits),
        ("max", softfloat_core::softfloat::f32_max_bits),
        ("copysign", softfloat_core::softfloat::f32_copysign_bits),
    ];
    let f64_binary: [F64BinaryOp; 7] = [
        ("add", softfloat_core::softfloat::f64_add_bits),
        ("sub", softfloat_core::softfloat::f64_sub_bits),
        ("mul", softfloat_core::softfloat::f64_mul_bits),
        ("div", softfloat_core::softfloat::f64_div_bits),
        ("min", softfloat_core::softfloat::f64_min_bits),
        ("max", softfloat_core::softfloat::f64_max_bits),
        ("copysign", softfloat_core::softfloat::f64_copysign_bits),
    ];
    for (op, backend) in f32_binary {
        let expected = vec![f32_value(backend(f32_lhs, f32_rhs))];
        assert_eq!(
            run(
                &mut f32_instance,
                &format!("f32_{op}_runtime"),
                &[f32_value(f32_lhs), f32_value(f32_rhs)]
            ),
            Ok(expected.clone()),
            "f32.{op} runtime"
        );
        assert_eq!(
            run(&mut f32_instance, &format!("f32_{op}_folded"), &[]),
            Ok(expected),
            "f32.{op} folded"
        );
    }
    for (op, backend) in f64_binary {
        let expected = vec![f64_value(backend(f64_lhs, f64_rhs))];
        assert_eq!(
            run(
                &mut f64_instance,
                &format!("f64_{op}_runtime"),
                &[f64_value(f64_lhs), f64_value(f64_rhs)]
            ),
            Ok(expected.clone()),
            "f64.{op} runtime"
        );
        assert_eq!(
            run(&mut f64_instance, &format!("f64_{op}_folded"), &[]),
            Ok(expected),
            "f64.{op} folded"
        );
    }

    let f32_unary: [F32UnaryOp; 7] = [
        ("abs", softfloat_core::softfloat::f32_abs_bits),
        ("neg", softfloat_core::softfloat::f32_neg_bits),
        ("ceil", softfloat_core::softfloat::f32_ceil_bits),
        ("floor", softfloat_core::softfloat::f32_floor_bits),
        ("trunc", softfloat_core::softfloat::f32_trunc_bits),
        ("nearest", softfloat_core::softfloat::f32_nearest_bits),
        ("sqrt", softfloat_core::softfloat::f32_sqrt_bits),
    ];
    let f64_unary: [F64UnaryOp; 7] = [
        ("abs", softfloat_core::softfloat::f64_abs_bits),
        ("neg", softfloat_core::softfloat::f64_neg_bits),
        ("ceil", softfloat_core::softfloat::f64_ceil_bits),
        ("floor", softfloat_core::softfloat::f64_floor_bits),
        ("trunc", softfloat_core::softfloat::f64_trunc_bits),
        ("nearest", softfloat_core::softfloat::f64_nearest_bits),
        ("sqrt", softfloat_core::softfloat::f64_sqrt_bits),
    ];
    for (op, backend) in f32_unary {
        let expected = vec![f32_value(backend(f32_lhs))];
        assert_eq!(
            run(
                &mut f32_instance,
                &format!("f32_{op}_runtime"),
                &[f32_value(f32_lhs)]
            ),
            Ok(expected.clone()),
            "f32.{op} runtime"
        );
        assert_eq!(
            run(&mut f32_instance, &format!("f32_{op}_folded"), &[]),
            Ok(expected),
            "f32.{op} folded"
        );
    }
    for (op, backend) in f64_unary {
        let expected = vec![f64_value(backend(f64_lhs))];
        assert_eq!(
            run(
                &mut f64_instance,
                &format!("f64_{op}_runtime"),
                &[f64_value(f64_lhs)]
            ),
            Ok(expected.clone()),
            "f64.{op} runtime"
        );
        assert_eq!(
            run(&mut f64_instance, &format!("f64_{op}_folded"), &[]),
            Ok(expected),
            "f64.{op} folded"
        );
    }

    let f32_cmp: [F32ComparisonOp; 6] = [
        ("eq", softfloat_core::softfloat::f32_eq_bits),
        ("ne", softfloat_core::softfloat::f32_ne_bits),
        ("lt", softfloat_core::softfloat::f32_lt_bits),
        ("gt", softfloat_core::softfloat::f32_gt_bits),
        ("le", softfloat_core::softfloat::f32_le_bits),
        ("ge", softfloat_core::softfloat::f32_ge_bits),
    ];
    let f64_cmp: [F64ComparisonOp; 6] = [
        ("eq", softfloat_core::softfloat::f64_eq_bits),
        ("ne", softfloat_core::softfloat::f64_ne_bits),
        ("lt", softfloat_core::softfloat::f64_lt_bits),
        ("gt", softfloat_core::softfloat::f64_gt_bits),
        ("le", softfloat_core::softfloat::f64_le_bits),
        ("ge", softfloat_core::softfloat::f64_ge_bits),
    ];
    for (op, backend) in f32_cmp {
        let expected = vec![CandidateValue::I32(i32::from(backend(f32_lhs, f32_rhs)))];
        assert_eq!(
            run(
                &mut f32_instance,
                &format!("f32_{op}_runtime"),
                &[f32_value(f32_lhs), f32_value(f32_rhs)]
            ),
            Ok(expected.clone()),
            "f32.{op} runtime"
        );
        assert_eq!(
            run(&mut f32_instance, &format!("f32_{op}_folded"), &[]),
            Ok(expected)
        );
    }
    for (op, backend) in f64_cmp {
        let expected = vec![CandidateValue::I32(i32::from(backend(f64_lhs, f64_rhs)))];
        assert_eq!(
            run(
                &mut f64_instance,
                &format!("f64_{op}_runtime"),
                &[f64_value(f64_lhs), f64_value(f64_rhs)]
            ),
            Ok(expected.clone()),
            "f64.{op} runtime"
        );
        assert_eq!(
            run(&mut f64_instance, &format!("f64_{op}_folded"), &[]),
            Ok(expected)
        );
    }
}

#[test]
fn conversions_reinterpret_and_transport_are_exact() {
    let module = compile(
        r#"(module
            (memory (export "memory") 1 1)
            (global $g32 f32 (f32.const nan:0x12345))
            (global $g64 f64 (f64.const -nan:0x123456789abcd))
            (func (export "id32") (param f32) (result f32) local.get 0)
            (func (export "id64") (param f64) (result f64) local.get 0)
            (func (export "local32") (param f32) (result f32) (local f32)
                local.get 0 local.set 1 local.get 1)
            (func (export "global32") (result f32) global.get $g32)
            (func (export "global64") (result f64) global.get $g64)
            (func (export "call32") (param f32) (result f32) local.get 0 call 0)
            (func (export "store_load32") (param f32) (result f32)
                i32.const 0 local.get 0 f32.store i32.const 0 f32.load)
            (func (export "store_load64") (param f64) (result f64)
                i32.const 8 local.get 0 f64.store i32.const 8 f64.load)
            (func (export "select32") (param f32 f32 i32) (result f32)
                local.get 0 local.get 1 local.get 2 select)
            (func (export "reinterpret32") (param f32) (result f32)
                local.get 0 i32.reinterpret_f32 f32.reinterpret_i32)
            (func (export "reinterpret64") (param f64) (result f64)
                local.get 0 i64.reinterpret_f64 f64.reinterpret_i64)
            (func (export "demote") (param f64) (result f32) local.get 0 f32.demote_f64)
            (func (export "promote") (param f32) (result f64) local.get 0 f64.promote_f32)
            (func (export "fold_demote") (result f32)
                (f32.demote_f64 (f64.reinterpret_i64 (i64.const 0x3ff0000020000000))))
            (func (export "fold_promote") (result f64)
                (f64.promote_f32 (f32.reinterpret_i32 (i32.const 0x3f800001))))
            (func (export "i32sf32") (param i32) (result f32) local.get 0 f32.convert_i32_s)
            (func (export "i32uf32") (param i32) (result f32) local.get 0 f32.convert_i32_u)
            (func (export "i64sf32") (param i64) (result f32) local.get 0 f32.convert_i64_s)
            (func (export "i64uf32") (param i64) (result f32) local.get 0 f32.convert_i64_u)
            (func (export "i32sf64") (param i32) (result f64) local.get 0 f64.convert_i32_s)
            (func (export "i32uf64") (param i32) (result f64) local.get 0 f64.convert_i32_u)
            (func (export "i64sf64") (param i64) (result f64) local.get 0 f64.convert_i64_s)
            (func (export "i64uf64") (param i64) (result f64) local.get 0 f64.convert_i64_u)
            (func (export "fold_i32sf32") (result f32) (f32.convert_i32_s (i32.const -123)))
            (func (export "fold_i32uf32") (result f32) (f32.convert_i32_u (i32.const -1)))
            (func (export "fold_i64sf32") (result f32) (f32.convert_i64_s (i64.const 16777217)))
            (func (export "fold_i64uf32") (result f32) (f32.convert_i64_u (i64.const -1)))
            (func (export "fold_i32sf64") (result f64) (f64.convert_i32_s (i32.const -123)))
            (func (export "fold_i32uf64") (result f64) (f64.convert_i32_u (i32.const -1)))
            (func (export "fold_i64sf64") (result f64) (f64.convert_i64_s (i64.const 16777217)))
            (func (export "fold_i64uf64") (result f64) (f64.convert_i64_u (i64.const -1)))
            (func (export "fold_reinterpret32") (result f32)
                (f32.reinterpret_i32 (i32.const 0xff812345)))
            (func (export "fold_reinterpret64") (result f64)
                (f64.reinterpret_i64 (i64.const 0xfff0000000012345)))
        )"#,
    );
    let mut instance = module.instantiate().unwrap();
    let n32 = 0xff81_2345;
    let n64 = 0xfff0_0000_0001_2345;
    for export in ["id32", "local32", "call32", "store_load32", "reinterpret32"] {
        assert_eq!(
            run(&mut instance, export, &[f32_value(n32)]),
            Ok(vec![f32_value(n32)])
        );
    }
    assert_eq!(
        run(
            &mut instance,
            "select32",
            &[
                f32_value(n32),
                f32_value(0x7f80_0001),
                CandidateValue::I32(1)
            ]
        ),
        Ok(vec![f32_value(n32)])
    );
    for export in ["id64", "store_load64", "reinterpret64"] {
        assert_eq!(
            run(&mut instance, export, &[f64_value(n64)]),
            Ok(vec![f64_value(n64)])
        );
    }
    assert_eq!(
        run(&mut instance, "global32", &[]),
        Ok(vec![f32_value(0x7f81_2345)])
    );
    assert_eq!(
        run(&mut instance, "global64", &[]),
        Ok(vec![f64_value(0xfff1_2345_6789_abcd)])
    );
    assert_eq!(
        run(&mut instance, "demote", &[f64_value(n64)]),
        Ok(vec![f32_value(F32_NAN)])
    );
    assert_eq!(
        run(&mut instance, "promote", &[f32_value(n32)]),
        Ok(vec![f64_value(F64_NAN)])
    );
    assert_eq!(
        run(&mut instance, "fold_demote", &[]),
        Ok(vec![f32_value(
            softfloat_core::softfloat::f32_demote_f64_bits(0x3ff0_0000_2000_0000)
        )])
    );
    assert_eq!(
        run(&mut instance, "fold_promote", &[]),
        Ok(vec![f64_value(
            softfloat_core::softfloat::f64_promote_f32_bits(0x3f80_0001)
        )])
    );
    assert_eq!(
        run(&mut instance, "fold_reinterpret32", &[]),
        Ok(vec![f32_value(n32)])
    );
    assert_eq!(
        run(&mut instance, "fold_reinterpret64", &[]),
        Ok(vec![f64_value(n64)])
    );

    let integer = 16_777_217_i64;
    let conversions = [
        (
            "i32sf32",
            CandidateValue::I32(-123),
            f32_value(softfloat_core::softfloat::f32_convert_i32_s_bits(-123)),
        ),
        (
            "i32uf32",
            CandidateValue::I32(-1),
            f32_value(softfloat_core::softfloat::f32_convert_i32_u_bits(u32::MAX)),
        ),
        (
            "i64sf32",
            CandidateValue::I64(integer),
            f32_value(softfloat_core::softfloat::f32_convert_i64_s_bits(integer)),
        ),
        (
            "i64uf32",
            CandidateValue::I64(-1),
            f32_value(softfloat_core::softfloat::f32_convert_i64_u_bits(u64::MAX)),
        ),
        (
            "i32sf64",
            CandidateValue::I32(-123),
            f64_value(softfloat_core::softfloat::f64_convert_i32_s_bits(-123)),
        ),
        (
            "i32uf64",
            CandidateValue::I32(-1),
            f64_value(softfloat_core::softfloat::f64_convert_i32_u_bits(u32::MAX)),
        ),
        (
            "i64sf64",
            CandidateValue::I64(integer),
            f64_value(softfloat_core::softfloat::f64_convert_i64_s_bits(integer)),
        ),
        (
            "i64uf64",
            CandidateValue::I64(-1),
            f64_value(softfloat_core::softfloat::f64_convert_i64_u_bits(u64::MAX)),
        ),
    ];
    for (export, input, expected) in conversions {
        assert_eq!(
            run(&mut instance, export, &[input]),
            Ok(vec![expected]),
            "{export}"
        );
        assert_eq!(
            run(&mut instance, &format!("fold_{export}"), &[]),
            Ok(vec![expected]),
            "folded {export}"
        );
    }
}

#[test]
fn strict_nan_policy_covers_generated_propagated_and_sign_only_operations() {
    let module = compile(
        r#"(module
            (func (export "add32") (param f32 f32) (result f32) local.get 0 local.get 1 f32.add)
            (func (export "div32") (param f32 f32) (result f32) local.get 0 local.get 1 f32.div)
            (func (export "sqrt64") (param f64) (result f64) local.get 0 f64.sqrt)
            (func (export "min64") (param f64 f64) (result f64) local.get 0 local.get 1 f64.min)
            (func (export "abs32") (param f32) (result f32) local.get 0 f32.abs)
            (func (export "neg64") (param f64) (result f64) local.get 0 f64.neg)
            (func (export "copysign32") (param f32 f32) (result f32) local.get 0 local.get 1 f32.copysign)
            (func (export "fold_add32") (result f32)
                (f32.add (f32.reinterpret_i32 (i32.const 0xff812345)) (f32.const 1)))
            (func (export "fold_sqrt64") (result f64)
                (f64.sqrt (f64.reinterpret_i64 (i64.const 0xbff0000000000000))))
        )"#,
    );
    let mut instance = module.instantiate().unwrap();
    assert_eq!(
        run(
            &mut instance,
            "add32",
            &[f32_value(0xff81_2345), f32_value(0x3f80_0000)]
        ),
        Ok(vec![f32_value(F32_NAN)])
    );
    assert_eq!(
        run(&mut instance, "div32", &[f32_value(0), f32_value(0)]),
        Ok(vec![f32_value(F32_NAN)])
    );
    assert_eq!(
        run(&mut instance, "sqrt64", &[f64_value(0xbff0_0000_0000_0000)]),
        Ok(vec![f64_value(F64_NAN)])
    );
    assert_eq!(
        run(
            &mut instance,
            "min64",
            &[f64_value(0x7ff0_0000_0000_0001), f64_value(0)]
        ),
        Ok(vec![f64_value(F64_NAN)])
    );
    assert_eq!(
        run(&mut instance, "fold_add32", &[]),
        Ok(vec![f32_value(F32_NAN)])
    );
    assert_eq!(
        run(&mut instance, "fold_sqrt64", &[]),
        Ok(vec![f64_value(F64_NAN)])
    );
    assert_eq!(
        run(&mut instance, "abs32", &[f32_value(0xff81_2345)]),
        Ok(vec![f32_value(0x7f81_2345)])
    );
    assert_eq!(
        run(&mut instance, "neg64", &[f64_value(0xfff0_0000_0001_2345)]),
        Ok(vec![f64_value(0x7ff0_0000_0001_2345)])
    );
    assert_eq!(
        run(
            &mut instance,
            "copysign32",
            &[f32_value(0x7f81_2345), f32_value(0x8000_0000)]
        ),
        Ok(vec![f32_value(0xff81_2345)])
    );
}

#[test]
fn all_eight_truncations_have_stable_nan_and_overflow_traps_in_runtime_and_folded_paths() {
    let operations = [
        (
            "i32_trunc_f32_s",
            "i32",
            "f32",
            "i32.trunc_f32_s",
            "0x4f000000",
            "0xcf000001",
            "0xcf000000",
            "0x4effffff",
        ),
        (
            "i32_trunc_f32_u",
            "i32",
            "f32",
            "i32.trunc_f32_u",
            "0x4f800000",
            "0xbf800000",
            "0xbf7fffff",
            "0x4f7fffff",
        ),
        (
            "i64_trunc_f32_s",
            "i64",
            "f32",
            "i64.trunc_f32_s",
            "0x5f000000",
            "0xdf000001",
            "0xdf000000",
            "0x5effffff",
        ),
        (
            "i64_trunc_f32_u",
            "i64",
            "f32",
            "i64.trunc_f32_u",
            "0x5f800000",
            "0xbf800000",
            "0xbf7fffff",
            "0x5f7fffff",
        ),
        (
            "i32_trunc_f64_s",
            "i32",
            "f64",
            "i32.trunc_f64_s",
            "0x41e0000000000000",
            "0xc1e0000000200000",
            "0xc1e0000000000000",
            "0x41dfffffffc00000",
        ),
        (
            "i32_trunc_f64_u",
            "i32",
            "f64",
            "i32.trunc_f64_u",
            "0x41f0000000000000",
            "0xbff0000000000000",
            "0xbfefffffffffffff",
            "0x41efffffffe00000",
        ),
        (
            "i64_trunc_f64_s",
            "i64",
            "f64",
            "i64.trunc_f64_s",
            "0x43e0000000000000",
            "0xc3e0000000000001",
            "0xc3e0000000000000",
            "0x43dfffffffffffff",
        ),
        (
            "i64_trunc_f64_u",
            "i64",
            "f64",
            "i64.trunc_f64_u",
            "0x43f0000000000000",
            "0xbff0000000000000",
            "0xbfefffffffffffff",
            "0x43efffffffffffff",
        ),
    ];
    for (
        name,
        result,
        float,
        op,
        positive_bits,
        negative_bits,
        lower_valid_bits,
        upper_valid_bits,
    ) in operations
    {
        let int = if float == "f32" { "i32" } else { "i64" };
        let (qnan_bits, snan_bits, negative_nan_bits, positive_inf_bits, negative_inf_bits) =
            if float == "f32" {
                (
                    "0x7fc00001",
                    "0x7f800001",
                    "0xffc00001",
                    "0x7f800000",
                    "0xff800000",
                )
            } else {
                (
                    "0x7ff8000000000001",
                    "0x7ff0000000000001",
                    "0xfff8000000000001",
                    "0x7ff0000000000000",
                    "0xfff0000000000000",
                )
            };
        let wat_source = format!(
            "(module
                (func (export \"runtime\") (param {float}) (result {result}) local.get 0 {op})
                (func (export \"folded_qnan\") (result {result})
                    ({op} ({float}.reinterpret_{int} ({int}.const {qnan_bits}))))
                (func (export \"folded_snan\") (result {result})
                    ({op} ({float}.reinterpret_{int} ({int}.const {snan_bits}))))
                (func (export \"folded_negative_nan\") (result {result})
                    ({op} ({float}.reinterpret_{int} ({int}.const {negative_nan_bits}))))
                (func (export \"folded_valid\") (result {result})
                    ({op} ({float}.const 3.75)))
                (func (export \"folded_positive\") (result {result})
                    ({op} ({float}.reinterpret_{int} ({int}.const {positive_bits}))))
                (func (export \"folded_negative\") (result {result})
                    ({op} ({float}.reinterpret_{int} ({int}.const {negative_bits}))))
                (func (export \"folded_positive_inf\") (result {result})
                    ({op} ({float}.reinterpret_{int} ({int}.const {positive_inf_bits}))))
                (func (export \"folded_negative_inf\") (result {result})
                    ({op} ({float}.reinterpret_{int} ({int}.const {negative_inf_bits}))))
                (func (export \"folded_lower_valid\") (result {result})
                    ({op} ({float}.reinterpret_{int} ({int}.const {lower_valid_bits}))))
                (func (export \"folded_upper_valid\") (result {result})
                    ({op} ({float}.reinterpret_{int} ({int}.const {upper_valid_bits}))))
            )"
        );
        let module = compile(&wat_source);
        let mut instance = module.instantiate().unwrap();
        let parse_bits = |bits: &str| {
            if float == "f32" {
                u64::from(u32::from_str_radix(&bits[2..], 16).unwrap())
            } else {
                u64::from_str_radix(&bits[2..], 16).unwrap()
            }
        };
        let candidate_value = |bits: u64| {
            if float == "f32" {
                f32_value(bits as u32)
            } else {
                f64_value(bits)
            }
        };
        for (class, bits, folded) in [
            ("qNaN", qnan_bits, "folded_qnan"),
            ("sNaN", snan_bits, "folded_snan"),
            ("negative NaN", negative_nan_bits, "folded_negative_nan"),
        ] {
            assert_eq!(
                run(
                    &mut instance,
                    "runtime",
                    &[candidate_value(parse_bits(bits))]
                ),
                Err(TrapCode::InvalidConversionToInteger),
                "{name} {class}"
            );
            assert_eq!(
                run(&mut instance, folded, &[]),
                Err(TrapCode::InvalidConversionToInteger),
                "{name} folded {class}"
            );
        }
        let valid = if result == "i32" {
            CandidateValue::I32(3)
        } else {
            CandidateValue::I64(3)
        };
        assert_eq!(
            run(&mut instance, "folded_valid", &[]),
            Ok(vec![valid]),
            "{name} folded valid"
        );
        assert_eq!(
            run(&mut instance, "folded_positive", &[]),
            Err(TrapCode::IntegerOverflow),
            "{name} folded positive overflow"
        );
        for (class, bits, folded) in [
            ("positive overflow", positive_bits, "folded_positive"),
            ("negative overflow", negative_bits, "folded_negative"),
            (
                "positive infinity",
                positive_inf_bits,
                "folded_positive_inf",
            ),
            (
                "negative infinity",
                negative_inf_bits,
                "folded_negative_inf",
            ),
        ] {
            assert_eq!(
                run(
                    &mut instance,
                    "runtime",
                    &[candidate_value(parse_bits(bits))]
                ),
                Err(TrapCode::IntegerOverflow),
                "{name} {class}"
            );
            assert_eq!(
                run(&mut instance, folded, &[]),
                Err(TrapCode::IntegerOverflow),
                "{name} folded {class}"
            );
        }
        for (class, bits, folded) in [
            (
                "lower valid boundary",
                lower_valid_bits,
                "folded_lower_valid",
            ),
            (
                "upper valid boundary",
                upper_valid_bits,
                "folded_upper_valid",
            ),
        ] {
            let bits = parse_bits(bits);
            let expected = expected_truncation(name, bits);
            assert!(
                expected.is_ok(),
                "{name} {class} backend fixture must be valid"
            );
            if class == "lower valid boundary" && name.ends_with("_u") {
                let zero = if result == "i32" {
                    CandidateValue::I32(0)
                } else {
                    CandidateValue::I64(0)
                };
                assert_eq!(
                    expected,
                    Ok(vec![zero]),
                    "{name} adjacent value above -1.0 must truncate to zero"
                );
            }
            assert_eq!(
                run(&mut instance, "runtime", &[candidate_value(bits)]),
                expected,
                "{name} {class}"
            );
            assert_eq!(
                run(&mut instance, folded, &[]),
                expected,
                "{name} folded {class}"
            );
        }
    }
}

#[test]
fn fused_float_branch_and_select_obey_unordered_and_signed_zero_rules() {
    let module = compile(
        r#"(module
            (func (export "branch32") (param f32 f32) (result i32)
                (if (result i32) (f32.lt (local.get 0) (local.get 1))
                    (then (i32.const 11)) (else (i32.const 22))))
            (func (export "branch64") (param f64 f64) (result i32)
                (if (result i32) (f64.le (local.get 0) (local.get 1))
                    (then (i32.const 11)) (else (i32.const 22))))
            (func (export "select32") (param f32 f32 f32 f32) (result f32)
                local.get 2 local.get 3
                local.get 0 local.get 1 f32.lt
                select)
            (func (export "select64") (param f64 f64 f64 f64) (result f64)
                local.get 2 local.get 3
                local.get 0 local.get 1 f64.eq
                select)
        )"#,
    );
    let mut instance = module.instantiate().unwrap();
    assert_eq!(
        run(
            &mut instance,
            "branch32",
            &[f32_value(0x7f80_0001), f32_value(0)]
        ),
        Ok(vec![CandidateValue::I32(22)])
    );
    assert_eq!(
        run(
            &mut instance,
            "branch64",
            &[f64_value(0x8000_0000_0000_0000), f64_value(0)]
        ),
        Ok(vec![CandidateValue::I32(11)])
    );
    assert_eq!(
        run(
            &mut instance,
            "select32",
            &[
                f32_value(0x7fc0_0001),
                f32_value(0),
                f32_value(0x7f80_0042),
                f32_value(0xff80_0042)
            ]
        ),
        Ok(vec![f32_value(0xff80_0042)])
    );
    assert_eq!(
        run(
            &mut instance,
            "select64",
            &[
                f64_value(0x8000_0000_0000_0000),
                f64_value(0),
                f64_value(0x7ff0_0000_0000_0042),
                f64_value(1)
            ]
        ),
        Ok(vec![f64_value(0x7ff0_0000_0000_0042)])
    );
}

fn collect_trace(
    instance: &mut CandidateInstance,
    export: &str,
) -> (Vec<(u64, u64)>, CandidateValue, u64) {
    instance
        .start_call(export, &[CandidateValue::I32(200)], 20_000, 17)
        .unwrap();
    let mut trace = Vec::new();
    loop {
        match instance.poll_call() {
            CandidatePoll::Pending(metrics) => {
                trace.push((metrics.consumed_fuel, metrics.remaining_fuel))
            }
            CandidatePoll::Ready(values) => {
                let metrics = instance.call_metrics().unwrap();
                return (trace, values[0], metrics.consumed_fuel);
            }
            CandidatePoll::Trapped(trap) => panic!("unexpected trap {trap:?}"),
        }
    }
}

#[test]
fn fuel_quantum_trace_is_repeatable_float_cost_matches_integer_and_traps_recover() {
    let module = compile(
        r#"(module
            (func (export "float_loop") (param i32) (result f32)
                (local i32) (local f32)
                f32.const 1 local.set 2
                block loop
                    local.get 2 f32.const 1.0009765625 f32.mul local.set 2
                    local.get 1 i32.const 1 i32.add local.tee 1
                    local.get 0 i32.lt_s br_if 0
                end end
                local.get 2)
            (func (export "float_add") (param f32 f32) (result f32) local.get 0 local.get 1 f32.add)
            (func (export "int_add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)
            (func (export "bad") (param f32) (result i32) local.get 0 i32.trunc_f32_s)
        )"#,
    );
    let mut first = module.instantiate().unwrap();
    let mut second = module.instantiate().unwrap();
    let trace_a = collect_trace(&mut first, "float_loop");
    let trace_b = collect_trace(&mut second, "float_loop");
    assert_eq!(trace_a, trace_b);
    assert!(!trace_a.0.is_empty());

    let mut costs = module.instantiate().unwrap();
    assert_eq!(
        run(
            &mut costs,
            "float_add",
            &[f32_value(0x3f80_0000), f32_value(0x4000_0000)]
        ),
        Ok(vec![f32_value(0x4040_0000)])
    );
    let float_fuel = costs.call_metrics().unwrap().consumed_fuel;
    assert_eq!(
        run(
            &mut costs,
            "int_add",
            &[CandidateValue::I32(1), CandidateValue::I32(2)]
        ),
        Ok(vec![CandidateValue::I32(3)])
    );
    assert_eq!(costs.call_metrics().unwrap().consumed_fuel, float_fuel);

    assert_eq!(
        run(&mut costs, "bad", &[f32_value(0x7fc0_0001)]),
        Err(TrapCode::InvalidConversionToInteger)
    );
    assert_eq!(
        run(&mut costs, "bad", &[f32_value(0x4040_0000)]),
        Ok(vec![CandidateValue::I32(3)])
    );
}

#[test]
fn candidate_store_limits_and_core_trap_mapping_are_execution_exact_and_reusable() {
    let module = compile(
        r#"(module
            (type $f32_id (func (param f32) (result f32)))
            (type $f64_id (func (param f64) (result f64)))
            (memory 16 16)
            (table 2 2 funcref)
            (func $id32 (type $f32_id) local.get 0)
            (elem (i32.const 0) $id32)
            (func (export "safe") (param f32) (result f32) local.get 0)
            (func (export "grow") (param i32) (result i32) local.get 0 memory.grow)
            (func (export "oob_load") (result i32) i32.const -1 i32.load)
            (func (export "indirect") (param f32 i32) (result f32)
                local.get 0 local.get 1 call_indirect (type $f32_id))
            (func (export "mismatch") (param f64) (result f64)
                local.get 0 i32.const 0 call_indirect (type $f64_id))
            (func (export "div_zero") (result i32) i32.const 1 i32.const 0 i32.div_s)
            (func (export "unreachable") unreachable)
            (func $recurse (param i32) (result i32)
                local.get 0 i32.eqz
                if (result i32)
                    i32.const 0
                else
                    local.get 0 i32.const 1 i32.sub call $recurse
                end)
            (func (export "recurse") (param i32) (result i32) local.get 0 call $recurse)
        )"#,
    );
    let mut instance = module.instantiate().unwrap();
    let safe = |instance: &mut CandidateInstance| {
        assert_eq!(
            run(instance, "safe", &[f32_value(0x7f81_2345)]),
            Ok(vec![f32_value(0x7f81_2345)])
        );
    };

    assert_eq!(
        run(
            &mut instance,
            "indirect",
            &[f32_value(0x3f80_0000), CandidateValue::I32(0)]
        ),
        Ok(vec![f32_value(0x3f80_0000)])
    );
    for (export, inputs, expected) in [
        (
            "indirect",
            vec![f32_value(0x3f80_0000), CandidateValue::I32(1)],
            TrapCode::TableOutOfBounds,
        ),
        (
            "indirect",
            vec![f32_value(0x3f80_0000), CandidateValue::I32(2)],
            TrapCode::TableOutOfBounds,
        ),
        (
            "mismatch",
            vec![f64_value(0x3ff0_0000_0000_0000)],
            TrapCode::IndirectCallTypeMismatch,
        ),
        ("oob_load", vec![], TrapCode::MemoryOutOfBounds),
        ("div_zero", vec![], TrapCode::IntegerDivisionByZero),
        ("unreachable", vec![], TrapCode::Unreachable),
        (
            "recurse",
            vec![CandidateValue::I32(256)],
            TrapCode::CallDepthExceeded,
        ),
    ] {
        assert_eq!(
            run(&mut instance, export, &inputs),
            Err(expected),
            "{export}"
        );
        safe(&mut instance);
    }

    assert_eq!(
        run(&mut instance, "grow", &[CandidateValue::I32(1)]),
        Ok(vec![CandidateValue::I32(-1)])
    );
    safe(&mut instance);
}

#[test]
fn candidate_store_limit_allows_growth_to_ceiling_and_traps_beyond_it() {
    let module = compile(
        r#"(module
            (memory 1 3)
            (func (export "size") (result i32) memory.size)
            (func (export "grow") (param i32) (result i32) local.get 0 memory.grow)
        )"#,
    );
    let mut instance = module.instantiate_with_memory_limit(2 * 65_536).unwrap();
    assert_eq!(
        run(&mut instance, "size", &[]),
        Ok(vec![CandidateValue::I32(1)])
    );
    assert_eq!(
        run(&mut instance, "grow", &[CandidateValue::I32(1)]),
        Ok(vec![CandidateValue::I32(1)])
    );
    assert_eq!(
        run(&mut instance, "size", &[]),
        Ok(vec![CandidateValue::I32(2)])
    );
    assert_eq!(
        run(&mut instance, "grow", &[CandidateValue::I32(1)]),
        Err(TrapCode::LimitExceeded)
    );
    assert_eq!(
        run(&mut instance, "size", &[]),
        Ok(vec![CandidateValue::I32(2)])
    );
}

#[test]
fn imports_are_denied_before_candidate_engine_instantiation() {
    let bytes = wat::parse_str("(module (import \"host\" \"f\" (func (param f32))))").unwrap();
    let error = CandidateModule::compile(&bytes, OwnerAllocationReservation::profile_default())
        .expect_err("all candidate imports remain denied");
    assert_eq!(error.trap, TrapCode::Validation);
}
