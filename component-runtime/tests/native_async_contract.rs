use vibeos_component_format::ProfileIdentity;
use vibeos_component_runtime::{
    decode::{inspect_component_for_profile, DecodeError},
    sync::{SyncError, SynchronousComponent},
    world::{EntityShape, FunctionEffect, ValueShape, WorldContract},
};
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};
use wasmparser::{Validator, WasmFeatures};

const NATIVE_STREAM_WAT: &str = include_str!(
    "../../component-format/tests/corpus/component/native-async-stream-0.255.0.component.wat"
);
const STREAM_WIT: &str = include_str!("../../component-format/tests/corpus/wit/stream.wit");

fn native_stream_component() -> Vec<u8> {
    let bytes = wat::parse_str(NATIVE_STREAM_WAT).expect("0.255 native async stream fixture");
    let mut features = WasmFeatures::empty();
    features.set(WasmFeatures::COMPONENT_MODEL, true);
    features.set(WasmFeatures::CM_ASYNC, true);
    Validator::new_with_features(features)
        .validate_all(&bytes)
        .expect("wasmparser 0.255 native async stream fixture");
    bytes
}

fn assert_close_reason(value: &ValueShape) {
    let ValueShape::Enum(cases) = value else {
        panic!("closed future payload must be close-reason")
    };
    assert_eq!(
        cases,
        &[
            "normal",
            "failure",
            "cancelled",
            "denied",
            "unavailable",
            "exhausted",
            "invalid",
            "backend-fault",
        ]
    );
}

fn assert_byte_stream(value: &ValueShape) {
    let ValueShape::Record(fields) = value else {
        panic!("run value must be byte-stream")
    };
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].name, "bytes");
    assert_eq!(
        fields[0].value,
        ValueShape::Stream(Some(Box::new(ValueShape::U8)))
    );
    assert_eq!(fields[1].name, "closed");
    let ValueShape::Future(Some(reason)) = &fields[1].value else {
        panic!("closed must be future<close-reason>")
    };
    assert_close_reason(reason);
}

#[test]
fn native_byte_stream_contract_is_exact_but_validation_only() {
    let bytes = native_stream_component();
    assert_eq!(
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_SYNC).err(),
        Some(DecodeError::Unsupported)
    );

    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    assert_eq!(plan.profile(), ProfileIdentity::PROFILE_1_ASYNC);
    assert_eq!(plan.imports().len(), 4);
    assert_eq!(plan.exports().len(), 1);
    let run = plan
        .exports()
        .iter()
        .find(|export| export.name == "run")
        .expect("run export");
    let EntityShape::Function(run) = &run.entity else {
        panic!("run must be a function")
    };
    assert_eq!(run.effect, FunctionEffect::Async);
    assert_eq!(run.parameters.len(), 1);
    assert_eq!(run.parameters[0].name, "input");
    assert_byte_stream(&run.parameters[0].value);
    assert_byte_stream(run.result.as_ref().expect("byte-stream result"));

    let summary = plan.summary().async_abi;
    assert_eq!(summary.async_function_types, 1);
    assert_eq!(summary.stream_types, 1);
    assert_eq!(summary.future_types, 1);
    assert_eq!(summary.async_lifts, 1);
    assert_eq!(plan.async_lifts().len(), 1);
    assert_eq!(plan.async_lifts()[0].core_function, 0);
    assert_eq!(plan.async_lifts()[0].callback_core_function, 1);

    let world = WorldContract::parse(STREAM_WIT, "vibe:stream/native-filter@1.0.0").unwrap();
    plan.check_world(&world).unwrap();

    assert!(!plan.runtime_ready());
    assert_eq!(plan.runtime_instance_count(), 0);
    assert_eq!(plan.executable_exports().count(), 0);
    let engine = ProfileEngine::new();
    assert_eq!(
        SynchronousComponent::instantiate(
            &plan,
            &engine,
            OwnerAllocationReservation::new(1_000_000),
        )
        .err(),
        Some(SyncError::AsyncUnavailable)
    );
}

#[test]
fn vibe_callback_revision_rejects_upstream_compatibility_signatures() {
    const CALLBACK: &str = r#"(func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#;
    let replacements = [
        r#"(func (export "callback") (param i32) (result i32)
      i32.const 0)"#,
        r#"(func (export "callback") (param i32 i32 i32))"#,
    ];

    assert!(NATIVE_STREAM_WAT.contains(CALLBACK));
    for replacement in replacements {
        let fixture = NATIVE_STREAM_WAT.replacen(CALLBACK, replacement, 1);
        let bytes = wat::parse_str(&fixture).expect("upstream-compatible callback fixture");
        assert_eq!(
            inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).err(),
            Some(DecodeError::InvalidCallbackSignature),
            "Vibe callback revision accepted {replacement}"
        );
    }
}
