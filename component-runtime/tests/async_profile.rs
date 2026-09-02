use vibeos_component_format::{ProfileIdentity, PROFILE_1_LIMITS};
use vibeos_component_runtime::{
    decode::{
        inspect_component_for_profile, AsyncCanonicalFunctionPlan, AsyncComponentFunctionSource,
        AsyncCoreFunctionSource, AsyncCoreValueType, AsyncStreamPlan, ComponentSummary,
        DecodeError, NativeAsyncCanonicalFunctionPlan, NativeAsyncCoreImportPlan,
        NativeAsyncFuturePlan, NativeAsyncStreamPlan, NativeAsyncWaitablePlan,
    },
    sync::{SyncError, SynchronousComponent},
    value::ValueType,
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
const NATIVE_STREAM_WAT: &str = include_str!(
    "../../component-format/tests/corpus/component/native-async-stream-0.255.0.component.wat"
);
const NATIVE_SMOKE_WAT: &str = include_str!(
    "../../component-format/tests/corpus/component/native-async-smoke-0.255.0.component.wat"
);

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

fn native_resource_free_intrinsics_component() -> Vec<u8> {
    let mut types = ComponentTypeSection::new();
    types.defined_type().future(None);
    types.defined_type().stream(None);

    let mut canon = CanonicalFunctionSection::new();
    canon.task_return(None, []);
    canon.task_cancel();
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

    let mut component = Component::new();
    component.section(&types);
    component.section(&canon);
    component.finish()
}

fn native_task_return_bridge_component() -> Vec<u8> {
    wat::parse_str(
        r#"(component
              (core module $m
                (import "canon" "task-return" (func $task-return))
                (func (export "run") (result i32)
                  call $task-return
                  i32.const 0)
                (func (export "callback") (param i32 i32 i32) (result i32)
                  i32.const 0))
              (core func $task-return (canon task.return))
              (core instance $canon
                (export "task-return" (func $task-return)))
              (core instance $i
                (instantiate $m (with "canon" (instance $canon))))
              (alias core export $i "run" (core func $run))
              (alias core export $i "callback" (core func $callback))
              (type $t (func async))
              (func $lifted (type $t)
                (canon lift (core func $run) async
                  (callback (core func $callback))))
              (export "run" (func $lifted)))"#,
    )
    .unwrap()
}

fn resource_type_component() -> Vec<u8> {
    let mut types = ComponentTypeSection::new();
    types.resource(wasm_encoder::ValType::I32, None);
    let mut component = Component::new();
    component.section(&types);
    component.finish()
}

fn aggregate_native_bridge_component(bindings: usize, runtime_instances: usize) -> Vec<u8> {
    use std::fmt::Write as _;

    let mut source = String::from("(component (core module $guest");
    for index in 0..bindings {
        write!(
            source,
            " (import \"canon\" \"b{index}\" (func $import{index}))"
        )
        .unwrap();
    }
    source.push(')');
    for index in 0..bindings {
        write!(source, " (core func $builtin{index} (canon task.return))").unwrap();
    }
    source.push_str(" (core instance $builtins");
    for index in 0..bindings {
        write!(source, " (export \"b{index}\" (func $builtin{index}))").unwrap();
    }
    source.push(')');
    for index in 0..runtime_instances {
        write!(
            source,
            " (core instance $guest{index} (instantiate $guest (with \"canon\" (instance $builtins))))"
        )
        .unwrap();
    }
    source.push(')');
    wat::parse_str(source).unwrap()
}

fn synthetic_function_forward_component() -> Vec<u8> {
    wat::parse_str(
        r#"(component
              (core module $provider (func (export "ordinary")))
              (core module $guest (import "bundle" "ordinary" (func)))
              (core instance $provider-instance (instantiate $provider))
              (alias core export $provider-instance "ordinary" (core func $ordinary))
              (core instance $bundle (export "ordinary" (func $ordinary)))
              (core instance $guest-instance
                (instantiate $guest (with "bundle" (instance $bundle)))))"#,
    )
    .unwrap()
}

fn synthetic_memory_forward_component() -> Vec<u8> {
    wat::parse_str(
        r#"(component
              (core module $provider (memory (export "memory") 1 1))
              (core module $guest (import "bundle" "memory" (memory 1 1)))
              (core instance $provider-instance (instantiate $provider))
              (alias core export $provider-instance "memory" (core memory $memory))
              (core instance $bundle (export "memory" (memory $memory)))
              (core instance $guest-instance
                (instantiate $guest (with "bundle" (instance $bundle)))))"#,
    )
    .unwrap()
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
    callback_lift_component_with(
        r#"(func (export "callback") (param i32 i32 i32) (result i32)
                  i32.const 0)"#,
    )
}

fn callback_lift_component_with(callback: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(component
              (core module $m
                (func (export "run") (result i32) i32.const 0)
                {callback})
              (core instance $i (instantiate $m))
              (alias core export $i "run" (core func $run))
              (alias core export $i "callback" (core func $callback))
              (type $t (func async))
              (func $lifted (type $t)
                (canon lift (core func $run) async (callback (core func $callback))))
              (export "run" (func $lifted)))"#
    ))
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
    assert!(plan.native_async_execution_plan().is_none());
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
    assert_eq!(plan.async_canonical_plans().len(), 26);
    let stream_read = &plan.async_canonical_plans()[8];
    let AsyncCanonicalFunctionPlan::Stream(AsyncStreamPlan::Read {
        value_type,
        options,
        ..
    }) = &stream_read.function
    else {
        panic!("canonical entry 8 must be stream.read")
    };
    assert!(matches!(
        value_type,
        ValueType::Stream { element: None, .. }
    ));
    assert!(options.async_);
    assert!(!plan.runtime_ready());
}

#[test]
fn native_resource_free_plan_is_total_owned_and_inert() {
    let bytes = wat::parse_str(NATIVE_STREAM_WAT).unwrap();
    let plan = inspect_component_for_profile(
        &bytes,
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    )
    .unwrap();
    assert_eq!(
        plan.profile(),
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
    );
    assert!(!plan.runtime_ready());
    assert!(!plan.native_async_runtime_ready());
    assert_eq!(plan.runtime_instance_count(), 1);
    assert_eq!(plan.executable_exports().count(), 0);

    let native = plan.native_async_execution_plan().unwrap();
    assert_eq!(native.instances().len(), 1);
    assert_eq!(native.canonical_plans().len(), 1);
    assert_eq!(
        native.canonical_plans().len(),
        plan.summary().canonical_functions as usize
    );
    assert!(native.canonical_import_bridges().is_empty());
    assert_eq!(native.exports().len(), 1);
    assert_eq!(native.exports()[0].name, "run");
    assert_eq!(native.exports()[0].canonical, 0);
    let NativeAsyncCanonicalFunctionPlan::Lift {
        core_function,
        callback,
        options,
        ..
    } = &native.canonical_plans()[0].function
    else {
        panic!("native export must resolve to a callback lift")
    };
    assert_eq!(
        (core_function.core_instance, core_function.export.as_str()),
        (0, "run")
    );
    assert_eq!(
        (callback.core_instance, callback.export.as_str()),
        (0, "callback")
    );
    assert!(options.async_);
}

#[test]
fn native_resource_free_builtin_subset_is_exact_and_total() {
    let bytes = native_resource_free_intrinsics_component();
    let plan = inspect_component_for_profile(
        &bytes,
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    )
    .unwrap();
    assert_eq!(plan.runtime_instance_count(), 0);
    let native = plan.native_async_execution_plan().unwrap();
    assert_eq!(plan.summary().canonical_functions, 19);
    assert_eq!(native.canonical_plans().len(), 19);
    assert!(native.instances().is_empty());
    assert!(native.canonical_import_bridges().is_empty());
    assert!(native.exports().is_empty());
    assert!(matches!(
        native.canonical_plans()[16].function,
        NativeAsyncCanonicalFunctionPlan::Waitable(NativeAsyncWaitablePlan::SetNew)
    ));
    assert!(matches!(
        native.canonical_plans()[17].function,
        NativeAsyncCanonicalFunctionPlan::Waitable(NativeAsyncWaitablePlan::SetDrop)
    ));
    assert!(matches!(
        native.canonical_plans()[18].function,
        NativeAsyncCanonicalFunctionPlan::Waitable(NativeAsyncWaitablePlan::Join)
    ));
}

#[test]
fn native_canonical_import_bridge_retains_exact_core_signature_and_origin() {
    let bytes = native_task_return_bridge_component();
    let plan = inspect_component_for_profile(
        &bytes,
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    )
    .unwrap();
    assert_eq!(plan.runtime_instance_count(), 1);
    let native = plan.native_async_execution_plan().unwrap();
    assert_eq!(native.instances().len(), 1);
    assert_eq!(native.canonical_plans().len(), 2);
    assert_eq!(native.canonical_import_bridges().len(), 1);
    let bridge = &native.canonical_import_bridges()[0];
    assert_eq!(bridge.core_instance, 0);
    assert_eq!(bridge.core_module, "canon");
    assert_eq!(bridge.core_field, "task-return");
    assert_eq!(bridge.canonical, 0);
    assert_eq!(bridge.signature.parameters, []);
    assert_eq!(bridge.signature.results, []);
    assert!(matches!(
        native.instances()[0].imports.as_slice(),
        [NativeAsyncCoreImportPlan::Canonical { bridge: 0 }]
    ));
    assert!(matches!(
        native.canonical_plans()[0].function,
        NativeAsyncCanonicalFunctionPlan::TaskReturn { .. }
    ));
    assert!(matches!(
        native.canonical_plans()[1].function,
        NativeAsyncCanonicalFunctionPlan::Lift { .. }
    ));
    assert_eq!(native.exports()[0].canonical, 1);
}

#[test]
fn native_smoke_plan_resolves_every_bridge_signature_and_memory_origin() {
    use AsyncCoreValueType::{I32, I64};

    let bytes = wat::parse_str(NATIVE_SMOKE_WAT).unwrap();
    let plan = inspect_component_for_profile(
        &bytes,
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    )
    .unwrap();
    assert_eq!(plan.runtime_instance_count(), 2);
    let native = plan.native_async_execution_plan().unwrap();
    assert_eq!(native.instances().len(), 2);
    assert_eq!(native.canonical_plans().len(), 19);
    assert_eq!(
        native.canonical_plans().len(),
        plan.summary().canonical_functions as usize
    );
    assert_eq!(native.canonical_import_bridges().len(), 18);
    assert!(native.instances()[0].imports.is_empty());
    assert_eq!(native.instances()[1].imports.len(), 19);
    assert!(matches!(
        &native.instances()[1].imports[0],
        NativeAsyncCoreImportPlan::InstanceExport {
            module,
            field,
            core_instance: 0,
            export,
        } if module == "env" && field == "memory" && export == "memory"
    ));
    for (position, import) in native.instances()[1].imports[1..].iter().enumerate() {
        assert!(matches!(
            import,
            NativeAsyncCoreImportPlan::Canonical { bridge }
                if *bridge == u32::try_from(position).unwrap()
        ));
    }

    let expected = [
        (vec![], vec![]),
        (vec![], vec![I64]),
        (vec![I32, I32, I32], vec![I32]),
        (vec![I32, I32, I32], vec![I32]),
        (vec![I32], vec![I32]),
        (vec![I32], vec![I32]),
        (vec![I32], vec![]),
        (vec![I32], vec![]),
        (vec![], vec![I64]),
        (vec![I32, I32], vec![I32]),
        (vec![I32, I32], vec![I32]),
        (vec![I32], vec![I32]),
        (vec![I32], vec![I32]),
        (vec![I32], vec![]),
        (vec![I32], vec![]),
        (vec![], vec![I32]),
        (vec![I32], vec![]),
        (vec![I32, I32], vec![]),
    ];
    for (position, (bridge, (parameters, results))) in native
        .canonical_import_bridges()
        .iter()
        .zip(expected.iter())
        .enumerate()
    {
        assert_eq!(bridge.core_instance, 1);
        assert_eq!(bridge.core_module, "vibe:async");
        assert_eq!(bridge.canonical, u32::try_from(position).unwrap());
        assert_eq!(&bridge.signature.parameters, parameters);
        assert_eq!(&bridge.signature.results, results);
    }

    for canonical in [2_usize, 3, 9, 10] {
        let options = match &native.canonical_plans()[canonical].function {
            NativeAsyncCanonicalFunctionPlan::Stream(NativeAsyncStreamPlan::Read {
                options,
                ..
            })
            | NativeAsyncCanonicalFunctionPlan::Stream(NativeAsyncStreamPlan::Write {
                options,
                ..
            })
            | NativeAsyncCanonicalFunctionPlan::Future(NativeAsyncFuturePlan::Read {
                options,
                ..
            })
            | NativeAsyncCanonicalFunctionPlan::Future(NativeAsyncFuturePlan::Write {
                options,
                ..
            }) => options,
            _ => panic!("canonical {canonical} must be a memory-bearing transfer"),
        };
        let memory = options.memory.as_ref().unwrap();
        assert_eq!(
            (memory.core_instance, memory.export.as_str()),
            (0, "memory")
        );
    }
    let NativeAsyncCanonicalFunctionPlan::Lift {
        core_function,
        callback,
        ..
    } = &native.canonical_plans()[18].function
    else {
        panic!("last canonical must be the exported lift")
    };
    assert_eq!(core_function.core_instance, 1);
    assert_eq!(callback.core_instance, 1);
    assert_eq!(native.exports()[0].canonical, 18);
}

#[test]
fn native_canonical_bridge_limit_is_aggregate_across_runtime_instances() {
    let profile = ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE;
    let at_limit = aggregate_native_bridge_component(128, 2);
    let plan = inspect_component_for_profile(&at_limit, profile).unwrap();
    assert_eq!(plan.runtime_instance_count(), 2);
    assert_eq!(
        plan.native_async_execution_plan()
            .unwrap()
            .canonical_import_bridges()
            .len(),
        PROFILE_1_LIMITS.max_imports as usize
    );

    let over_limit = aggregate_native_bridge_component(129, 2);
    assert_eq!(
        inspect_component_for_profile(&over_limit, profile).err(),
        Some(DecodeError::Limit)
    );
}

#[test]
fn native_synthetic_instances_are_canonical_builtin_bundles_only() {
    let profile = ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE;
    for bytes in [
        synthetic_function_forward_component(),
        synthetic_memory_forward_component(),
    ] {
        // Both are valid Component grammar and remain acceptable to the broad
        // validation-only identity. The native grammar rejects their live
        // forwarding authority before creating executor wiring.
        assert!(inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).is_ok());
        assert_eq!(
            inspect_component_for_profile(&bytes, profile).err(),
            Some(DecodeError::Unsupported)
        );
    }
}

#[test]
fn native_resource_free_profile_rejects_authority_and_async_supersets() {
    let profile = ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE;
    for bytes in [
        wat::parse_str(include_str!(
            "../../component-format/tests/corpus/component/typed.component.wat"
        ))
        .unwrap(),
        resource_type_component(),
        async_lower_component(),
        async_intrinsics_component(),
        async_memory_intrinsics_component(),
        wat::parse_str(
            r#"(component
                  (type $t (func async))
                  (import "run" (func (type $t))))"#,
        )
        .unwrap(),
        wat::parse_str(
            r#"(component
                  (type $api (instance))
                  (import "api" (instance (type $api))))"#,
        )
        .unwrap(),
        wat::parse_str(r#"(component (import "authority" (type (sub resource))))"#).unwrap(),
        wat::parse_str(
            r#"(component
                  (type $api
                    (instance
                      (export "authority" (type (sub resource))))))"#,
        )
        .unwrap(),
        wat::parse_str(
            r#"(component
                  (type $api
                    (instance
                      (export "authority" (type (sub resource)))
                      (type $borrowed (borrow 0)))))"#,
        )
        .unwrap(),
    ] {
        assert_eq!(
            inspect_component_for_profile(&bytes, profile).err(),
            Some(DecodeError::Unsupported)
        );
    }

    let mut more_async = CanonicalFunctionSection::new();
    more_async.stream_cancel_read(0, true);
    let mut component = Component::new();
    component.section(&more_async);
    assert_eq!(
        inspect_component_for_profile(&component.finish(), profile).err(),
        Some(DecodeError::Unsupported)
    );
}

#[test]
fn native_identity_cannot_enter_the_synchronous_runtime_even_with_no_async_entries() {
    let bytes = Component::new().finish();
    let plan = inspect_component_for_profile(
        &bytes,
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    )
    .unwrap();
    assert!(plan.summary().async_abi.is_empty());
    assert!(!plan.runtime_ready());
    assert!(!plan.native_async_runtime_ready());
    assert!(plan.native_async_execution_plan().is_some());
    assert_eq!(
        SynchronousComponent::instantiate(
            &plan,
            &ProfileEngine::new(),
            OwnerAllocationReservation::new(1_000_000),
        )
        .err(),
        Some(SyncError::AsyncUnavailable)
    );
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
    let [typed] = plan.async_canonical_plans() else {
        panic!("async lower must have exactly one typed plan entry")
    };
    let AsyncCanonicalFunctionPlan::Lower {
        component_function,
        function_type,
        options,
    } = &typed.function
    else {
        panic!("typed plan must retain async lower")
    };
    assert_eq!(function_type.effect, FunctionEffect::Async);
    assert!(options.async_);
    assert!(matches!(
        component_function.source,
        AsyncComponentFunctionSource::Import { .. }
    ));
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
    let [typed] = plan.async_canonical_plans() else {
        panic!("async lift must have exactly one typed plan entry")
    };
    let AsyncCanonicalFunctionPlan::Lift {
        core_function,
        function_type,
        callback,
        options,
    } = &typed.function
    else {
        panic!("typed plan must retain async lift")
    };
    assert_eq!(function_type.effect, FunctionEffect::Async);
    assert!(options.async_);
    let AsyncCoreFunctionSource::Export(core_export) = &core_function.source else {
        panic!("lifted core function must retain its export source")
    };
    assert_eq!(
        (core_export.core_instance, core_export.export.as_str()),
        (0, "run")
    );
    let AsyncCoreFunctionSource::Export(callback_export) = &callback.source else {
        panic!("callback must retain its export source")
    };
    assert_eq!(
        (
            callback_export.core_instance,
            callback_export.export.as_str()
        ),
        (0, "callback")
    );
    assert!(!plan.runtime_ready());
    assert_eq!(plan.executable_exports().count(), 0);
}

#[test]
fn vibe_callback_signature_is_exact() {
    for callback in [
        r#"(func (export "callback") (param i32) (result i32) i32.const 0)"#,
        r#"(func (export "callback") (param i32 i32 i32))"#,
    ] {
        assert_eq!(
            inspect_component_for_profile(
                &callback_lift_component_with(callback),
                ProfileIdentity::PROFILE_1_ASYNC,
            )
            .err(),
            Some(DecodeError::InvalidCallbackSignature)
        );
    }
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
    assert!(executable.native_async_execution_plan().is_none());
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
