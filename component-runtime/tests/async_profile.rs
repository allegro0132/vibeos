use vibeos_component_format::{ProfileIdentity, PROFILE_1_LIMITS};
use vibeos_component_runtime::{
    decode::{inspect_component_for_profile, ComponentSummary, DecodeError},
    sync::{SyncError, SynchronousComponent},
    world::{EntityShape, FunctionEffect, ValueShape, WorldContract, WorldError},
};
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};
use wasm_encoder::{
    CanonicalFunctionSection, CanonicalOption, Component, ComponentImportSection, ComponentTypeRef,
    ComponentTypeSection, Encode, PrimitiveValType, RawSection,
};

const ASYNC_COMPONENT_WAT: &str =
    include_str!("../../component-format/tests/corpus/component/async-0.255.0.component.wat");
const ASYNC_WORLD_WIT: &str =
    include_str!("../../component-format/tests/corpus/wit/async-world.wit");

fn async_world_component() -> Vec<u8> {
    wat::parse_str(ASYNC_COMPONENT_WAT).unwrap()
}

fn async_intrinsics_component() -> Vec<u8> {
    let mut types = ComponentTypeSection::new();
    types.defined_type().future(None);
    types.defined_type().stream(None);

    let mut canon = CanonicalFunctionSection::new();
    canon.task_return(None, []);
    canon.task_cancel();
    canon.context_get(wasm_encoder::ValType::I32, 0);
    canon.context_set(wasm_encoder::ValType::I32, 0);
    canon.subtask_drop();
    canon.subtask_cancel(false);
    canon.thread_yield(false);
    canon.stream_new(1);
    canon.stream_read(1, [CanonicalOption::Async]);
    canon.stream_write(1, [CanonicalOption::Async]);
    canon.stream_cancel_read(1, false);
    canon.stream_cancel_write(1, false);
    canon.stream_drop_readable(1);
    canon.stream_drop_writable(1);
    canon.future_new(0);
    canon.future_read(0, [CanonicalOption::Async]);
    canon.future_write(0, [CanonicalOption::Async]);
    canon.future_cancel_read(0, false);
    canon.future_cancel_write(0, false);
    canon.future_drop_readable(0);
    canon.future_drop_writable(0);
    canon.waitable_set_new();
    canon.waitable_set_drop();
    canon.waitable_join();
    canon.backpressure_inc();
    canon.backpressure_dec();

    let mut component = Component::new();
    component.section(&types);
    component.section(&canon);
    component.finish()
}

fn async_lower_component() -> Vec<u8> {
    let mut types = ComponentTypeSection::new();
    types
        .function()
        .async_(true)
        .params([] as [(&str, PrimitiveValType); 0])
        .result(None);
    let mut imports = ComponentImportSection::new();
    imports.import("run", ComponentTypeRef::Func(0));
    let mut canon = CanonicalFunctionSection::new();
    canon.lower(0, [CanonicalOption::Async]);
    let mut component = Component::new();
    component.section(&types);
    component.section(&imports);
    component.section(&canon);
    component.finish()
}

fn callback_lift_component() -> Vec<u8> {
    wat::parse_str(
        r#"(component
              (core module $m
                (func (export "run") (result i32) i32.const 0)
                (func (export "callback") (param i32 i32 i32)))
              (core instance $i (instantiate $m))
              (alias core export $i "run" (core func $run))
              (alias core export $i "callback" (core func $callback))
              (type $t (func async))
              (func $lifted (type $t)
                (canon lift (core func $run) async (callback (core func $callback))))
              (export "run" (func $lifted)))"#,
    )
    .unwrap()
}

fn async_memory_intrinsics_component() -> Vec<u8> {
    wat::parse_str(
        r#"(component
              (core module $m
                (memory (export "memory") 1 1)
                (func (export "realloc")
                  (param i32 i32 i32 i32) (result i32)
                  local.get 0))
              (core instance $i (instantiate $m))
              (alias core export $i "memory" (core memory $memory))
              (alias core export $i "realloc" (core func $realloc))
              (type $stream (stream string))
              (type $future (future string))
              (core func $task-return
                (canon task.return (result string) (memory $memory)))
              (core func $stream-read
                (canon stream.read $stream async
                  (memory $memory) (realloc $realloc)))
              (core func $stream-write
                (canon stream.write $stream async (memory $memory)))
              (core func $future-read
                (canon future.read $future async
                  (memory $memory) (realloc $realloc)))
              (core func $future-write
                (canon future.write $future async (memory $memory)))
              (core func $wait
                (canon waitable-set.wait (memory $memory)))
              (core func $poll
                (canon waitable-set.poll cancellable (memory $memory))))"#,
    )
    .unwrap()
}

fn raw_component_with_section(id: u8, body: &[u8]) -> Vec<u8> {
    let mut component = Component::new();
    component.section(&RawSection { id, data: body });
    component.finish()
}

#[test]
fn exact_async_types_and_world_are_preserved_but_inert() {
    let bytes = async_world_component();
    assert_eq!(
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_SYNC).err(),
        Some(DecodeError::Unsupported)
    );

    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    assert_eq!(plan.profile(), ProfileIdentity::PROFILE_1_ASYNC);
    assert!(!plan.runtime_ready());
    assert_eq!(plan.executable_exports().count(), 0);
    assert_eq!(plan.summary().async_abi.async_function_types, 1);
    assert_eq!(plan.summary().async_abi.future_types, 1);
    assert_eq!(plan.summary().async_abi.stream_types, 1);

    for entity in plan.imports().iter().chain(plan.exports()) {
        let EntityShape::Function(function) = &entity.entity else {
            panic!("fixture exposes functions only")
        };
        assert_eq!(function.effect, FunctionEffect::Async);
        assert_eq!(
            function.parameters[0].value,
            ValueShape::Future(Some(Box::new(ValueShape::U32)))
        );
        assert_eq!(
            function.parameters[1].value,
            ValueShape::Stream(Some(Box::new(ValueShape::U8)))
        );
    }

    let world =
        WorldContract::parse(ASYNC_WORLD_WIT, "vibe:async-fixture/async-filter@1.0.0").unwrap();
    plan.check_world(&world).unwrap();

    let sync_world = WorldContract::parse(
        r#"
            package test:async-profile@1.0.0;
            world api {
                import source: func(pending: future<u32>, chunks: stream<u8>);
                export run: func(pending: future<u32>, chunks: stream<u8>);
            }
        "#,
        "test:async-profile/api@1.0.0",
    )
    .unwrap();
    assert_eq!(plan.check_world(&sync_world), Err(WorldError::TypeMismatch));

    let swapped_world = WorldContract::parse(
        r#"
            package test:async-profile@1.0.0;
            world api {
                import source: async func(pending: stream<u32>, chunks: future<u8>);
                export run: async func(pending: stream<u32>, chunks: future<u8>);
            }
        "#,
        "test:async-profile/api@1.0.0",
    )
    .unwrap();
    assert_eq!(
        plan.check_world(&swapped_world),
        Err(WorldError::TypeMismatch)
    );

    let payload_world = WorldContract::parse(
        r#"
            package test:async-profile@1.0.0;
            world api {
                import source: async func(pending: future<u64>, chunks: stream);
                export run: async func(pending: future<u64>, chunks: stream);
            }
        "#,
        "test:async-profile/api@1.0.0",
    )
    .unwrap();
    assert_eq!(
        plan.check_world(&payload_world),
        Err(WorldError::TypeMismatch)
    );

    let second = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    assert_eq!(second.summary(), plan.summary());
    assert_eq!(second.imports(), plan.imports());
    assert_eq!(second.exports(), plan.exports());
}

#[test]
fn selected_base_async_intrinsics_are_validated_and_classified() {
    let bytes = async_intrinsics_component();
    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    let summary = plan.summary().async_abi;
    assert_eq!((summary.future_types, summary.stream_types), (1, 1));
    assert_eq!(summary.task_builtins, 2);
    assert_eq!(summary.context_builtins, 2);
    assert_eq!(summary.subtask_builtins, 2);
    assert_eq!(summary.cooperative_yields, 1);
    assert_eq!(summary.stream_builtins, 7);
    assert_eq!(summary.future_builtins, 7);
    assert_eq!(summary.waitable_builtins, 3);
    assert_eq!(summary.backpressure_builtins, 2);
    assert!(!plan.runtime_ready());
}

#[test]
fn selected_memory_bearing_async_intrinsics_are_validated() {
    let bytes = async_memory_intrinsics_component();
    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    let summary = plan.summary().async_abi;
    assert_eq!((summary.future_types, summary.stream_types), (1, 1));
    assert_eq!(summary.task_builtins, 1);
    assert_eq!(summary.stream_builtins, 2);
    assert_eq!(summary.future_builtins, 2);
    assert_eq!(summary.waitable_builtins, 2);
    assert!(!plan.runtime_ready());
    assert_eq!(plan.runtime_instance_count(), 0);
    assert_eq!(plan.executable_exports().count(), 0);
}

#[test]
fn async_lower_is_selected_but_never_enters_the_sync_execution_plan() {
    let bytes = async_lower_component();
    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    assert_eq!(plan.summary().async_abi.async_function_types, 1);
    assert_eq!(plan.summary().async_abi.async_lowers, 1);
    assert_eq!(plan.async_lifts(), []);
    assert_eq!(plan.async_lowers().len(), 1);
    assert_eq!(plan.async_lowers()[0].canonical_index, 0);
    assert_eq!(plan.async_lowers()[0].component_function, 0);
    assert!(!plan.runtime_ready());
    assert_eq!(plan.runtime_instance_count(), 0);
    assert_eq!(plan.host_imports().count(), 0);
    assert_eq!(plan.executable_exports().count(), 0);
}

#[test]
fn callback_async_lift_is_selected_and_stackless() {
    let bytes = callback_lift_component();
    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    assert_eq!(plan.summary().async_abi.async_function_types, 1);
    assert_eq!(plan.summary().async_abi.async_lifts, 1);
    assert_eq!(plan.async_lowers(), []);
    assert_eq!(plan.async_lifts().len(), 1);
    assert_eq!(plan.async_lifts()[0].canonical_index, 0);
    assert_eq!(plan.async_lifts()[0].core_function, 0);
    assert_eq!(plan.async_lifts()[0].function_type, 0);
    assert_eq!(plan.async_lifts()[0].callback_core_function, 1);
    assert!(!plan.runtime_ready());
    assert_eq!(plan.executable_exports().count(), 0);
}

#[test]
fn every_async_plan_is_rejected_at_the_sync_instantiation_boundary() {
    assert_eq!(SyncError::AsyncUnavailable.code(), 15);
    let engine = ProfileEngine::new();
    for bytes in [
        async_world_component(),
        async_intrinsics_component(),
        async_memory_intrinsics_component(),
        async_lower_component(),
        callback_lift_component(),
    ] {
        let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
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
}

#[test]
fn validation_only_identity_cannot_smuggle_a_sync_payload_into_execution() {
    let bytes = wat::parse_str(include_str!(
        "../../component-format/tests/corpus/component/typed.component.wat"
    ))
    .unwrap();
    let executable =
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_SYNC).unwrap();
    assert!(executable.runtime_ready());
    assert_eq!(executable.executable_exports().count(), 1);

    let validation_only =
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    assert!(validation_only.summary().async_abi.is_empty());
    assert!(!validation_only.runtime_ready());
    assert_eq!(validation_only.runtime_instance_count(), 0);
    assert_eq!(validation_only.host_imports().count(), 0);
    assert_eq!(validation_only.executable_exports().count(), 0);

    let engine = ProfileEngine::new();
    assert_eq!(
        SynchronousComponent::instantiate(
            &validation_only,
            &engine,
            OwnerAllocationReservation::new(1_000_000),
        )
        .err(),
        Some(SyncError::AsyncUnavailable)
    );
}

#[test]
fn adjacent_and_disabled_async_spellings_fail_closed() {
    // Callback-free async lift is the disabled stackful ABI. Indices are
    // intentionally unresolved: profile rejection must precede validation.
    let stackful_lift = raw_component_with_section(8, &[1, 0, 0, 0, 1, 6, 0]);
    assert_eq!(
        inspect_component_for_profile(&stackful_lift, ProfileIdentity::PROFILE_1_ASYNC).err(),
        Some(DecodeError::Unsupported)
    );

    // 0x08 was a neighboring draft's backpressure.set opcode.
    let removed_opcode = raw_component_with_section(8, &[1, 8]);
    assert_eq!(
        inspect_component_for_profile(&removed_opcode, ProfileIdentity::PROFILE_1_ASYNC).err(),
        Some(DecodeError::Unsupported)
    );

    let mut more_async = CanonicalFunctionSection::new();
    more_async.subtask_cancel(true);
    let mut component = Component::new();
    component.section(&more_async);
    assert_eq!(
        inspect_component_for_profile(&component.finish(), ProfileIdentity::PROFILE_1_ASYNC,).err(),
        Some(DecodeError::Unsupported)
    );

    let mut threading = CanonicalFunctionSection::new();
    threading.thread_available_parallelism();
    let mut component = Component::new();
    component.section(&threading);
    assert_eq!(
        inspect_component_for_profile(&component.finish(), ProfileIdentity::PROFILE_1_ASYNC,).err(),
        Some(DecodeError::Unsupported)
    );
}

#[test]
fn exact_header_and_disabled_feature_vector_fail_closed() {
    let valid = async_world_component();
    for (offset, value) in [(4, 0x0c), (4, 0x0e), (6, 0x00), (6, 0x02)] {
        let mut bytes = valid.clone();
        bytes[offset] = value;
        assert!(inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).is_err());
    }

    let raw_canonicals: &[&[u8]] = &[
        // callback without async
        &[1, 0, 0, 0, 1, 7, 0, 0],
        // async lower with callback
        &[1, 1, 0, 0, 2, 6, 7, 0],
        // UTF-16, core-type, and GC canonical options
        &[1, 0, 0, 0, 1, 1, 0],
        &[1, 0, 0, 0, 1, 8, 0, 0],
        &[1, 0, 0, 0, 1, 9, 0],
        // CM64 context and CM_THREADING context slot
        &[1, 0x0a, 0x7e, 0],
        &[1, 0x0a, 0x7f, 1],
        // unknown future canonical opcode
        &[1, 0x2e],
    ];
    for body in raw_canonicals {
        let bytes = raw_component_with_section(8, body);
        assert_eq!(
            inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).err(),
            Some(DecodeError::Unsupported),
            "{body:02x?}"
        );
    }

    let mut error_context = CanonicalFunctionSection::new();
    error_context.error_context_drop();
    let mut component = Component::new();
    component.section(&error_context);
    assert_eq!(
        inspect_component_for_profile(&component.finish(), ProfileIdentity::PROFILE_1_ASYNC,).err(),
        Some(DecodeError::Unsupported)
    );
}

#[test]
fn function_effect_and_canonical_call_style_cannot_be_erased() {
    let async_type_sync_lift = wat::parse_str(
        r#"(component
              (core module $m (func (export "run")))
              (core instance $i (instantiate $m))
              (alias core export $i "run" (core func $run))
              (type $t (func async))
              (func $lifted (type $t) (canon lift (core func $run))))"#,
    )
    .unwrap();
    assert!(
        inspect_component_for_profile(&async_type_sync_lift, ProfileIdentity::PROFILE_1_ASYNC,)
            .is_err()
    );

    let sync_type_async_lift = wat::parse_str(
        r#"(component
              (core module $m
                (func (export "run") (result i32) i32.const 0)
                (func (export "callback") (param i32)))
              (core instance $i (instantiate $m))
              (alias core export $i "run" (core func $run))
              (alias core export $i "callback" (core func $callback))
              (type $t (func))
              (func $lifted (type $t)
                (canon lift (core func $run) async (callback (core func $callback)))))"#,
    )
    .unwrap();
    assert!(
        inspect_component_for_profile(&sync_type_async_lift, ProfileIdentity::PROFILE_1_ASYNC,)
            .is_err()
    );

    let async_import_sync_lower = wat::parse_str(
        r#"(component
              (type $t (func async))
              (import "run" (func $run (type $t)))
              (core func $lowered (canon lower (func $run))))"#,
    )
    .unwrap();
    assert_eq!(
        inspect_component_for_profile(&async_import_sync_lower, ProfileIdentity::PROFILE_1_ASYNC,)
            .err(),
        Some(DecodeError::Unsupported)
    );

    let sync_import_async_lower = wat::parse_str(
        r#"(component
              (type $t (func))
              (import "run" (func $run (type $t)))
              (core func $lowered (canon lower (func $run) async)))"#,
    )
    .unwrap();
    assert!(inspect_component_for_profile(
        &sync_import_async_lower,
        ProfileIdentity::PROFILE_1_ASYNC,
    )
    .is_err());
}

#[test]
fn canonical_option_limit_precedes_a_missing_option_body() {
    let count = PROFILE_1_LIMITS.max_canonical_options_per_function + 1;
    let mut body = vec![1, 0, 0, 0];
    count.encode(&mut body);
    let bytes = raw_component_with_section(8, &body);
    assert_eq!(
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).err(),
        Some(DecodeError::Limit)
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Accepted(ComponentSummary),
    Rejected(DecodeError),
}

fn outcome(bytes: &[u8]) -> Outcome {
    match inspect_component_for_profile(bytes, ProfileIdentity::PROFILE_1_ASYNC) {
        Ok(plan) => {
            assert_eq!(plan.profile(), ProfileIdentity::PROFILE_1_ASYNC);
            if !plan.summary().async_abi.is_empty() {
                assert!(!plan.runtime_ready());
                assert_eq!(plan.executable_exports().count(), 0);
            }
            Outcome::Accepted(plan.summary())
        }
        Err(error) => Outcome::Rejected(error),
    }
}

#[test]
fn structured_async_corpus_mutations_are_deterministic_and_never_panic() {
    let seeds = [
        async_world_component(),
        async_intrinsics_component(),
        async_memory_intrinsics_component(),
        async_lower_component(),
        callback_lift_component(),
    ];
    for seed in seeds {
        assert!(matches!(outcome(&seed), Outcome::Accepted(_)));

        for end in 0..seed.len() {
            let truncated = &seed[..end];
            assert_eq!(outcome(truncated), outcome(truncated));
        }
        for index in 0..seed.len() {
            let mut flipped = seed.clone();
            flipped[index] ^= 1_u8 << (index % 8);
            assert_eq!(outcome(&flipped), outcome(&flipped));

            let mut deleted = seed.clone();
            deleted.remove(index);
            assert_eq!(outcome(&deleted), outcome(&deleted));

            let mut inserted = seed.clone();
            inserted.insert(index, 0x80 | (index as u8 & 0x7f));
            assert_eq!(outcome(&inserted), outcome(&inserted));
        }
    }
}
