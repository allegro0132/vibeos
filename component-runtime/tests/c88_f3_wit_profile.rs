#![cfg(feature = "c88-f3-acceptance")]

use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity,
    PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS, PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
};
use vibeos_component_runtime::{
    abi_value::{flat_signature as profile_1_flat_signature, CodecError},
    decode::{
        current_component_validation_engine, inspect_component,
        inspect_component_for_profile_2_candidate, DecodeError,
    },
    value::{CanonicalF32, CanonicalF64, ValueType},
    world::{EntityShape, ValueShape, WorldContract, WorldError},
};

const WORLD: &str = r#"
    package vibe:float-candidate@1.0.0;

    interface codec-api {
        record sample {
            left: f32,
            right: f64,
        }

        variant nested {
            scalar(f32),
            values(list<f64>),
        }

        run: func(value: sample, choice: nested) -> result<list<f32>, f64>;
    }

    world codec {
        export codec-api;
    }
"#;

const EXACT_WORLD: &str = "vibe:float-candidate/codec@1.0.0";

const ASYNC_FUNCTION_WORLD: &str = r#"
    package vibe:float-candidate-async@1.0.0;
    world codec {
        export run: async func(value: u32);
    }
"#;

const FUTURE_WORLD: &str = r#"
    package vibe:float-candidate-future@1.0.0;
    world codec {
        export run: func(value: future<u32>);
    }
"#;

const STREAM_WORLD: &str = r#"
    package vibe:float-candidate-stream@1.0.0;
    world codec {
        export run: func(value: stream<u8>);
    }
"#;

const COMPONENT: &str = r#"
    (component
      (core module $guest
        (func (export "run") (param f32) (result f64)
          local.get 0
          f64.promote_f32))
      (core instance $guest-instance (instantiate $guest))
      (alias core export $guest-instance "run" (core func $run-core))
      (type $run-type (func (param "value" f32) (result f64)))
      (func $run (type $run-type) (canon lift (core func $run-core)))
      (export "run" (func $run)))
"#;

const COMPONENT_WORLD: &str = r#"
    package vibe:float-component@1.0.0;
    world codec {
        export run: func(value: f32) -> f64;
    }
"#;

#[test]
fn component_float_wrappers_canonicalize_nan_using_integer_bits_only() {
    for bits in [0x7fc0_0000, 0x7f80_0001, 0xff80_0001, 0xffff_ffff] {
        assert_eq!(
            CanonicalF32::from_bits(bits).to_bits(),
            PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS
        );
    }
    for bits in [
        0x7ff8_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0xfff0_0000_0000_0001,
        0xffff_ffff_ffff_ffff,
    ] {
        assert_eq!(
            CanonicalF64::from_bits(bits).to_bits(),
            PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS
        );
    }
    for bits in [0_u32, 0x8000_0000, 1, 0x7f80_0000, 0xff80_0000] {
        assert_eq!(CanonicalF32::from_bits(bits).to_bits(), bits);
    }
    for bits in [
        0_u64,
        0x8000_0000_0000_0000,
        1,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
    ] {
        assert_eq!(CanonicalF64::from_bits(bits).to_bits(), bits);
    }
}

#[test]
fn candidate_wit_accepts_only_the_two_scalar_float_shapes() {
    assert_eq!(
        WorldContract::parse(WORLD, EXACT_WORLD),
        Err(WorldError::UnsupportedType)
    );
    let world = WorldContract::parse_profile_2_sync_float_candidate(WORLD, EXACT_WORLD).unwrap();
    assert_eq!(world.imports.len(), 0);
    assert_eq!(world.exports.len(), 1);
    let EntityShape::Interface(interface) = &world.exports[0].entity else {
        panic!("expected exported interface")
    };
    let function = interface
        .iter()
        .find_map(|item| match &item.entity {
            EntityShape::Function(function) if item.name == "run" => Some(function),
            _ => None,
        })
        .expect("run function");
    assert_eq!(
        function.parameters[0].value,
        ValueShape::Record(vec![
            vibeos_component_runtime::world::NamedValueShape {
                name: "left".into(),
                value: ValueShape::F32,
            },
            vibeos_component_runtime::world::NamedValueShape {
                name: "right".into(),
                value: ValueShape::F64,
            },
        ])
    );
    assert!(matches!(
        function.parameters[1].value,
        ValueShape::Variant(_)
    ));
    assert!(matches!(function.result, Some(ValueShape::Result { .. })));
}

#[test]
fn sync_float_candidate_rejects_every_adjacent_async_wit_shape() {
    for (source, exact_world) in [
        (
            ASYNC_FUNCTION_WORLD,
            "vibe:float-candidate-async/codec@1.0.0",
        ),
        (FUTURE_WORLD, "vibe:float-candidate-future/codec@1.0.0"),
        (STREAM_WORLD, "vibe:float-candidate-stream/codec@1.0.0"),
    ] {
        assert!(WorldContract::parse(source, exact_world).is_ok());
        assert_eq!(
            WorldContract::parse_profile_2_sync_float_candidate(source, exact_world),
            Err(WorldError::UnsupportedType)
        );
    }
}

#[test]
fn profile_1_codec_stays_integer_only_even_in_an_acceptance_build() {
    assert_eq!(
        profile_1_flat_signature(&[ValueType::F32]),
        Err(CodecError::Unsupported)
    );
    assert_eq!(
        profile_1_flat_signature(&[ValueType::List(Box::new(ValueType::F64))]),
        Err(CodecError::Unsupported)
    );
}

#[test]
fn candidate_component_plan_is_typed_but_permanently_inert() {
    let bytes = wat::parse_str(COMPONENT).unwrap();
    assert!(matches!(
        inspect_component(&bytes),
        Err(DecodeError::Unsupported)
    ));
    let plan = inspect_component_for_profile_2_candidate(&bytes).unwrap();
    assert_eq!(plan.profile(), ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    assert!(!plan.runtime_ready());
    assert_eq!(plan.summary().embedded_modules, 1);
    assert_eq!(plan.imports().len(), 0);
    assert_eq!(plan.host_imports().count(), 0);
    assert_eq!(plan.executable_exports().count(), 0);

    let world = WorldContract::parse_profile_2_sync_float_candidate(
        COMPONENT_WORLD,
        "vibe:float-component/codec@1.0.0",
    )
    .unwrap();
    plan.check_world(&world).unwrap();

    assert!(current_validation_engine_identity(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none());
    assert!(current_component_validation_engine(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none());
}
