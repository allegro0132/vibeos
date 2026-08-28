#![cfg(feature = "c88-f3-acceptance")]

//! Host-only C8.8-F3 differential evidence against pinned Wasmtime 48.
//!
//! Wasmtime is an independent Component Model boundary oracle here: the
//! import-free fixture reinterprets scalar floats to integer bits (and back)
//! without arithmetic.  Wasmtime therefore exposes the raw boundary bits.
//! The candidate codec is compared with those bits after applying this
//! profile's deliberately stricter, integer-only NaN canonicalization oracle.

use vibeos_component_format::{ProfileIdentity, PROFILE_2_SYNC_FLOAT_PROFILE_CODE};
use vibeos_component_runtime::{
    abi_value::float_candidate::{
        lift_flat_values, lower_flat_values, CandidateFlatValue, CodecError, PayloadAllocator,
        RejectResources,
    },
    decode::{inspect_component, inspect_component_for_profile_2_candidate, DecodeError},
    memory::VecMemory,
    value::{CanonicalF32, CanonicalF64, CanonicalValue, ValuePosition, ValueType},
    world::WorldContract,
};
use wasm_encoder::{
    CanonicalOption, ComponentBuilder, ComponentExportKind, ComponentExportSection,
    ComponentInstanceSection, ComponentSection, ComponentValType, ExportKind, ModuleArg,
    PrimitiveValType,
};
use wasmtime::component::{
    Component as ReferenceComponent, Func as ReferenceFunc, Linker as ReferenceLinker, Val,
};
use wasmtime::{Config, Engine, Store};

const REFERENCE_FUEL: u64 = 10_000_000;
const F32_CANONICAL_NAN: u32 = 0x7fc0_0000;
const F64_CANONICAL_NAN: u64 = 0x7ff8_0000_0000_0000;

const WORLD: &str = r#"
    package vibe:float-reference@1.0.0;

    interface float-api {
        record pair {
            left: f32,
            right: f64,
        }

        f32-to-bits: func(value: f32) -> u32;
        f32-from-bits: func(value: u32) -> f32;
        f64-to-bits: func(value: f64) -> u64;
        f64-from-bits: func(value: u64) -> f64;
        nested-right: func(value: pair) -> f64;
    }

    world codec {
        export float-api;
    }
"#;

const EXACT_WORLD: &str = "vibe:float-reference/codec@1.0.0";
const INTERFACE: &str = "vibe:float-reference/float-api@1.0.0";

const F32_CASES: [u32; 14] = [
    0x0000_0000,
    0x8000_0000,
    0x3f80_0000,
    0xc020_0000,
    0x0000_0001,
    0x007f_ffff,
    0x7f7f_ffff,
    0x7f80_0000,
    0xff80_0000,
    0x7fc0_0000,
    0x7fc0_1234,
    0x7f80_0001,
    0xff80_0001,
    0xffff_ffff,
];

const F64_CASES: [u64; 14] = [
    0x0000_0000_0000_0000,
    0x8000_0000_0000_0000,
    0x3ff0_0000_0000_0000,
    0xc004_0000_0000_0000,
    0x0000_0000_0000_0001,
    0x000f_ffff_ffff_ffff,
    0x7fef_ffff_ffff_ffff,
    0x7ff0_0000_0000_0000,
    0xfff0_0000_0000_0000,
    0x7ff8_0000_0000_0000,
    0x7ff8_0000_0000_1234,
    0x7ff0_0000_0000_0001,
    0xfff0_0000_0000_0001,
    0xffff_ffff_ffff_ffff,
];

#[derive(Default)]
struct NoAllocation;

impl PayloadAllocator<VecMemory> for NoAllocation {
    fn allocate(
        &mut self,
        _memory: &mut VecMemory,
        _size: u32,
        _alignment: u32,
    ) -> Result<u32, CodecError> {
        panic!("the scalar and flat-record differential path must not allocate")
    }
}

fn canonicalize_f32(bits: u32) -> u32 {
    if bits & 0x7f80_0000 == 0x7f80_0000 && bits & 0x007f_ffff != 0 {
        F32_CANONICAL_NAN
    } else {
        bits
    }
}

fn canonicalize_f64(bits: u64) -> u64 {
    if bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000 && bits & 0x000f_ffff_ffff_ffff != 0 {
        F64_CANONICAL_NAN
    } else {
        bits
    }
}

fn fixture() -> Vec<u8> {
    let core = wat::parse_str(
        r#"
            (module
              (func (export "f32-to-bits") (param f32) (result i32)
                local.get 0
                i32.reinterpret_f32)
              (func (export "f32-from-bits") (param i32) (result f32)
                local.get 0
                f32.reinterpret_i32)
              (func (export "f64-to-bits") (param f64) (result i64)
                local.get 0
                i64.reinterpret_f64)
              (func (export "f64-from-bits") (param i64) (result f64)
                local.get 0
                f64.reinterpret_i64)
              (func (export "nested-right") (param f32 f64) (result f64)
                local.get 1))
        "#,
    )
    .expect("float reference core module");

    let mut builder = ComponentBuilder::default();
    let module = builder.core_module_raw(Some("float-reference"), &core);
    let instance = builder.core_instantiate(
        Some("float-reference-instance"),
        module,
        core::iter::empty::<(&str, ModuleArg)>(),
    );

    let f32_to_bits_core = builder.core_alias_export(
        Some("f32-to-bits-core"),
        instance,
        "f32-to-bits",
        ExportKind::Func,
    );
    let f32_from_bits_core = builder.core_alias_export(
        Some("f32-from-bits-core"),
        instance,
        "f32-from-bits",
        ExportKind::Func,
    );
    let f64_to_bits_core = builder.core_alias_export(
        Some("f64-to-bits-core"),
        instance,
        "f64-to-bits",
        ExportKind::Func,
    );
    let f64_from_bits_core = builder.core_alias_export(
        Some("f64-from-bits-core"),
        instance,
        "f64-from-bits",
        ExportKind::Func,
    );
    let nested_right_core = builder.core_alias_export(
        Some("nested-right-core"),
        instance,
        "nested-right",
        ExportKind::Func,
    );

    let (f32_to_bits_ty, mut ty) = builder.type_function(Some("f32-to-bits-type"));
    ty.params([("value", PrimitiveValType::F32)])
        .result(Some(PrimitiveValType::U32.into()));
    let (f32_from_bits_ty, mut ty) = builder.type_function(Some("f32-from-bits-type"));
    ty.params([("value", PrimitiveValType::U32)])
        .result(Some(PrimitiveValType::F32.into()));
    let (f64_to_bits_ty, mut ty) = builder.type_function(Some("f64-to-bits-type"));
    ty.params([("value", PrimitiveValType::F64)])
        .result(Some(PrimitiveValType::U64.into()));
    let (f64_from_bits_ty, mut ty) = builder.type_function(Some("f64-from-bits-type"));
    ty.params([("value", PrimitiveValType::U64)])
        .result(Some(PrimitiveValType::F64.into()));

    let (pair_ty, ty) = builder.type_defined(Some("pair"));
    ty.record([
        ("left", ComponentValType::Primitive(PrimitiveValType::F32)),
        ("right", ComponentValType::Primitive(PrimitiveValType::F64)),
    ]);
    let (nested_right_ty, mut ty) = builder.type_function(Some("nested-right-type"));
    ty.params([("value", ComponentValType::Type(pair_ty))])
        .result(Some(PrimitiveValType::F64.into()));

    let no_options = || core::iter::empty::<CanonicalOption>();
    let f32_to_bits = builder.lift_func(
        Some("f32-to-bits"),
        f32_to_bits_core,
        f32_to_bits_ty,
        no_options(),
    );
    let f32_from_bits = builder.lift_func(
        Some("f32-from-bits"),
        f32_from_bits_core,
        f32_from_bits_ty,
        no_options(),
    );
    let f64_to_bits = builder.lift_func(
        Some("f64-to-bits"),
        f64_to_bits_core,
        f64_to_bits_ty,
        no_options(),
    );
    let f64_from_bits = builder.lift_func(
        Some("f64-from-bits"),
        f64_from_bits_core,
        f64_from_bits_ty,
        no_options(),
    );
    let nested_right = builder.lift_func(
        Some("nested-right"),
        nested_right_core,
        nested_right_ty,
        no_options(),
    );

    let mut bytes = builder.finish();
    let mut instances = ComponentInstanceSection::new();
    instances.export_items([
        ("pair", ComponentExportKind::Type, pair_ty),
        ("f32-to-bits", ComponentExportKind::Func, f32_to_bits),
        ("f32-from-bits", ComponentExportKind::Func, f32_from_bits),
        ("f64-to-bits", ComponentExportKind::Func, f64_to_bits),
        ("f64-from-bits", ComponentExportKind::Func, f64_from_bits),
        ("nested-right", ComponentExportKind::Func, nested_right),
    ]);
    instances.append_to_component(&mut bytes);

    let mut exports = ComponentExportSection::new();
    exports.export(INTERFACE, ComponentExportKind::Instance, 0, None);
    exports.append_to_component(&mut bytes);
    bytes
}

fn reference_func(
    component: &ReferenceComponent,
    instance: &wasmtime::component::Instance,
    store: &mut Store<()>,
    name: &str,
) -> ReferenceFunc {
    let interface = component
        .get_export_index(None, INTERFACE)
        .expect("Wasmtime float interface export");
    let index = component
        .get_export_index(Some(&interface), name)
        .unwrap_or_else(|| panic!("Wasmtime export index for {name}"));
    instance
        .get_func(store, index)
        .unwrap_or_else(|| panic!("Wasmtime dynamic function for {name}"))
}

fn reference_call(store: &mut Store<()>, function: &ReferenceFunc, parameter: Val) -> Val {
    store
        .set_fuel(REFERENCE_FUEL)
        .expect("reset bounded Wasmtime fuel");
    let mut results = [Val::Bool(false)];
    function
        .call(&mut *store, &[parameter], &mut results)
        .expect("pinned Wasmtime dynamic call");
    assert!(
        store.get_fuel().expect("observe Wasmtime fuel") < REFERENCE_FUEL,
        "reference call must consume bounded fuel"
    );
    results.into_iter().next().unwrap()
}

fn candidate_f32(bits: u32) -> u32 {
    let mut memory = VecMemory::new(64, 64).unwrap();
    let mut allocator = NoAllocation;
    let (lifted, _) = lift_flat_values(
        &memory,
        &RejectResources,
        &[ValueType::F32],
        &[CandidateFlatValue::F32Bits(bits)],
        ValuePosition::Parameter,
    )
    .unwrap();
    let CanonicalValue::F32(value) = lifted[0] else {
        panic!("candidate f32 lift returned a different type")
    };
    let (lowered, _) = lower_flat_values(
        &mut memory,
        &mut allocator,
        &[ValueType::F32],
        &[CanonicalValue::F32(value)],
    )
    .unwrap();
    let CandidateFlatValue::F32Bits(bits) = lowered[0] else {
        panic!("candidate f32 lower returned a different flat kind")
    };
    bits
}

fn candidate_f64(bits: u64) -> u64 {
    let mut memory = VecMemory::new(64, 64).unwrap();
    let mut allocator = NoAllocation;
    let (lifted, _) = lift_flat_values(
        &memory,
        &RejectResources,
        &[ValueType::F64],
        &[CandidateFlatValue::F64Bits(bits)],
        ValuePosition::Parameter,
    )
    .unwrap();
    let CanonicalValue::F64(value) = lifted[0] else {
        panic!("candidate f64 lift returned a different type")
    };
    let (lowered, _) = lower_flat_values(
        &mut memory,
        &mut allocator,
        &[ValueType::F64],
        &[CanonicalValue::F64(value)],
    )
    .unwrap();
    let CandidateFlatValue::F64Bits(bits) = lowered[0] else {
        panic!("candidate f64 lower returned a different flat kind")
    };
    bits
}

#[test]
fn pinned_wasmtime_raw_bits_match_candidate_integer_nan_oracle() {
    let bytes = fixture();
    let mut config = Config::new();
    config.wasm_component_model(true).consume_fuel(true);
    let engine = Engine::new(&config).expect("pinned Wasmtime 48 engine");
    let component = ReferenceComponent::new(&engine, &bytes).expect("Wasmtime float fixture");

    assert!(matches!(
        inspect_component(&bytes),
        Err(DecodeError::Unsupported)
    ));
    let plan = inspect_component_for_profile_2_candidate(&bytes).unwrap();
    assert_eq!(plan.profile(), ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    assert_eq!(
        plan.profile().artifact_abi,
        PROFILE_2_SYNC_FLOAT_PROFILE_CODE
    );
    assert_eq!(
        plan.profile().runtime_abi,
        PROFILE_2_SYNC_FLOAT_PROFILE_CODE
    );
    assert!(!plan.runtime_ready());
    assert_eq!(plan.summary().embedded_modules, 1);
    assert_eq!(plan.summary().imports, 0);
    assert!(plan.imports().is_empty());
    assert_eq!(plan.host_imports().count(), 0);
    assert_eq!(plan.executable_exports().count(), 0);

    let world = WorldContract::parse_profile_2_sync_float_candidate(WORLD, EXACT_WORLD).unwrap();
    plan.check_world(&world).unwrap();

    assert_eq!(component.component_type().imports(&engine).len(), 0);

    // The empty linker is intentional: the reference fixture receives no
    // ambient host authority.
    let linker = ReferenceLinker::<()>::new(&engine);
    let mut store = Store::new(&engine, ());
    let instance = linker
        .instantiate(&mut store, &component)
        .expect("instantiate import-free reference fixture");
    let f32_to_bits = reference_func(&component, &instance, &mut store, "f32-to-bits");
    let f32_from_bits = reference_func(&component, &instance, &mut store, "f32-from-bits");
    let f64_to_bits = reference_func(&component, &instance, &mut store, "f64-to-bits");
    let f64_from_bits = reference_func(&component, &instance, &mut store, "f64-from-bits");
    let nested_right = reference_func(&component, &instance, &mut store, "nested-right");

    for bits in F32_CASES {
        let raw = reference_call(&mut store, &f32_to_bits, Val::Float32(f32::from_bits(bits)));
        assert_eq!(raw, Val::U32(bits), "Wasmtime f32 lowering {bits:#010x}");
        let raw = reference_call(&mut store, &f32_from_bits, Val::U32(bits));
        let Val::Float32(raw) = raw else {
            panic!("Wasmtime f32 lift returned a different type")
        };
        assert_eq!(raw.to_bits(), bits, "Wasmtime f32 lifting {bits:#010x}");

        let expected = canonicalize_f32(raw.to_bits());
        assert_eq!(CanonicalF32::from_bits(raw.to_bits()).to_bits(), expected);
        assert_eq!(candidate_f32(raw.to_bits()), expected);
    }

    for bits in F64_CASES {
        let raw = reference_call(&mut store, &f64_to_bits, Val::Float64(f64::from_bits(bits)));
        assert_eq!(raw, Val::U64(bits), "Wasmtime f64 lowering {bits:#018x}");
        let raw = reference_call(&mut store, &f64_from_bits, Val::U64(bits));
        let Val::Float64(raw) = raw else {
            panic!("Wasmtime f64 lift returned a different type")
        };
        assert_eq!(raw.to_bits(), bits, "Wasmtime f64 lifting {bits:#018x}");

        let expected = canonicalize_f64(raw.to_bits());
        assert_eq!(CanonicalF64::from_bits(raw.to_bits()).to_bits(), expected);
        assert_eq!(candidate_f64(raw.to_bits()), expected);
    }

    // This executes a nested Component record boundary, proving that the
    // candidate validator accepts more than isolated primitive signatures.
    for (left, right) in [
        (0x8000_0000, 0x0000_0000_0000_0001),
        (0x7f80_0001, 0xfff0_0000_0000_0001),
    ] {
        let raw = reference_call(
            &mut store,
            &nested_right,
            Val::Record(vec![
                ("left".into(), Val::Float32(f32::from_bits(left))),
                ("right".into(), Val::Float64(f64::from_bits(right))),
            ]),
        );
        let Val::Float64(raw) = raw else {
            panic!("Wasmtime nested record returned a different type")
        };
        assert_eq!(raw.to_bits(), right, "Wasmtime nested f64 boundary");

        let record_type = ValueType::Record(vec![ValueType::F32, ValueType::F64]);
        let record_value = CanonicalValue::Record(vec![
            CanonicalValue::F32(CanonicalF32::from_bits(left)),
            CanonicalValue::F64(CanonicalF64::from_bits(right)),
        ]);
        let mut memory = VecMemory::new(64, 64).unwrap();
        let mut allocator = NoAllocation;
        let (flat, _) =
            lower_flat_values(&mut memory, &mut allocator, &[record_type], &[record_value])
                .unwrap();
        assert_eq!(
            flat,
            vec![
                CandidateFlatValue::F32Bits(canonicalize_f32(left)),
                CandidateFlatValue::F64Bits(canonicalize_f64(right)),
            ]
        );
    }
}
