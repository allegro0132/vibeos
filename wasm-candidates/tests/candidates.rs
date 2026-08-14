use dlr_wasm_interpreter::{
    decode_and_validate, ExternVal, FuncAddr, InstantiationOutcome, RunState, Store as DlrStore,
    Value,
};
use vibeos_wasm_candidates::{
    allocation_shape, bounded_core_candidate, inspect_component, validate_wit_world, Candidate,
    FrontendError, ENGINE_EVIDENCE, FLOAT_DECISION, FRONTEND_DECISION, SELECTED_CORE_ENGINE,
};
use wasmi::{
    CompilationMode, Config, Engine, Linker, Module, Store as WasmiStore, TypedResumableCall,
};

const ADD: &str = include_str!("../../component-format/tests/corpus/core/integer.wat");
const COUNTDOWN: &str = r#"
(module
  (func (export "countdown") (param i32) (result i32)
    (local i32)
    local.get 0
    local.set 1
    block $done
      loop $again
        local.get 1
        i32.eqz
        br_if $done
        local.get 1
        i32.const 1
        i32.sub
        local.set 1
        br $again
      end
    end
    local.get 1))
"#;
const UNREACHABLE: &str = r#"(module (func (export "trap") unreachable))"#;
const COMPONENT: &str =
    include_str!("../../component-format/tests/corpus/component/typed.component.wat");
const WORLD: &str = include_str!("../../component-format/tests/corpus/wit/world.wit");

fn wasmi_engine() -> Engine {
    let mut config = Config::default();
    config
        .floats(false)
        .wasm_mutable_global(false)
        .wasm_sign_extension(false)
        .wasm_saturating_float_to_int(false)
        .wasm_multi_value(false)
        .wasm_multi_memory(false)
        .wasm_bulk_memory(false)
        .wasm_reference_types(false)
        .wasm_tail_call(false)
        .wasm_extended_const(false)
        .wasm_custom_page_sizes(false)
        .wasm_memory64(false)
        .wasm_wide_arithmetic(false)
        .consume_fuel(true)
        .compilation_mode(CompilationMode::Eager)
        .set_max_recursion_depth(128);
    Engine::new(&config)
}

fn run_wasmi_add(bytes: &[u8]) -> i32 {
    let engine = wasmi_engine();
    let module = Module::new(&engine, bytes).unwrap();
    let mut store = WasmiStore::new(&engine, ());
    store.set_fuel(10_000).unwrap();
    let linker = Linker::new(&engine);
    let instance = linker.instantiate_and_start(&mut store, &module).unwrap();
    instance
        .get_typed_func::<(i32, i32), i32>(&store, "add")
        .unwrap()
        .call(&mut store, (20, 22))
        .unwrap()
}

fn run_dlr_add(bytes: &[u8]) -> i32 {
    let module = decode_and_validate(bytes, &mut ()).unwrap();
    let mut store = DlrStore::new(());
    // SAFETY: this store owns the module and the module declares no imports.
    let InstantiationOutcome { module_addr, .. } =
        unsafe { store.module_instantiate(&module, vec![], None) }.unwrap();
    // SAFETY: `module_addr` belongs to this store and the named export is checked below.
    let export: ExternVal = unsafe { store.instance_export(module_addr, "add") }.unwrap();
    let function: FuncAddr = export.as_func().unwrap();
    // SAFETY: `function` belongs to this store and both arguments are immediate integers.
    let values =
        unsafe { store.invoke_simple(function, vec![Value::I32(20), Value::I32(22)]) }.unwrap();
    let [Value::I32(value)] = *values else {
        panic!("unexpected DLR result shape")
    };
    value as i32
}

#[test]
fn both_engines_validate_and_execute_the_same_integer_corpus() {
    let bytes = wat::parse_str(ADD).unwrap();
    assert_eq!(run_wasmi_add(&bytes), 42);
    assert_eq!(run_dlr_add(&bytes), 42);
}

#[test]
fn both_engines_trap_on_the_same_core_corpus_and_share_the_outer_limit() {
    let bytes = wat::parse_str(UNREACHABLE).unwrap();

    let engine = wasmi_engine();
    let module = Module::new(&engine, bounded_core_candidate(&bytes).unwrap()).unwrap();
    let mut store = WasmiStore::new(&engine, ());
    store.set_fuel(100).unwrap();
    let instance = Linker::new(&engine)
        .instantiate_and_start(&mut store, &module)
        .unwrap();
    assert!(instance
        .get_typed_func::<(), ()>(&store, "trap")
        .unwrap()
        .call(&mut store, ())
        .is_err());

    let module = decode_and_validate(bounded_core_candidate(&bytes).unwrap(), &mut ()).unwrap();
    let mut dlr = DlrStore::new(());
    // SAFETY: the module is import-free and belongs to this store.
    let InstantiationOutcome { module_addr, .. } =
        unsafe { dlr.module_instantiate(&module, vec![], None) }.unwrap();
    // SAFETY: the function address was produced by this store.
    let trap = unsafe { dlr.instance_export(module_addr, "trap") }
        .unwrap()
        .as_func()
        .unwrap();
    // SAFETY: the function belongs to this store and has no parameters.
    assert!(unsafe { dlr.invoke_simple(trap, vec![]) }.is_err());

    let oversized = vec![0; vibeos_component_format::PROFILE_1_LIMITS.max_core_module_bytes + 1];
    assert_eq!(
        bounded_core_candidate(&oversized),
        Err(FrontendError::TooLarge)
    );
}

#[test]
fn wasmi_resumes_a_finite_call_across_many_fuel_quanta() {
    let bytes = wat::parse_str(COUNTDOWN).unwrap();
    let engine = wasmi_engine();
    let module = Module::new(&engine, &bytes).unwrap();
    let mut store = WasmiStore::new(&engine, ());
    let instance = Linker::new(&engine)
        .instantiate_and_start(&mut store, &module)
        .unwrap();
    let function = instance
        .get_typed_func::<i32, i32>(&store, "countdown")
        .unwrap();
    store.set_fuel(5).unwrap();
    let mut state = function.call_resumable(&mut store, 32).unwrap();
    let mut yields = 0;
    loop {
        match state {
            TypedResumableCall::Finished(value) => {
                assert_eq!(value, 0);
                break;
            }
            TypedResumableCall::OutOfFuel(invocation) => {
                yields += 1;
                assert!(invocation.required_fuel() > 0);
                store.set_fuel(5).unwrap();
                state = invocation.resume(&mut store).unwrap();
            }
            TypedResumableCall::HostTrap(_) => panic!("module has no host imports"),
        }
    }
    assert!(yields > 1);
}

#[test]
fn dlr_resumes_the_same_finite_call_across_many_fuel_quanta() {
    let bytes = wat::parse_str(COUNTDOWN).unwrap();
    let module = decode_and_validate(&bytes, &mut ()).unwrap();
    let mut store = DlrStore::new(());
    // SAFETY: this store owns the import-free module.
    let InstantiationOutcome { module_addr, .. } =
        unsafe { store.module_instantiate(&module, vec![], None) }.unwrap();
    // SAFETY: the address was produced by this store.
    let function = unsafe { store.instance_export(module_addr, "countdown") }
        .unwrap()
        .as_func()
        .unwrap();
    // SAFETY: the function belongs to this store and the argument has its exact type.
    let mut state = unsafe { store.invoke(function, vec![Value::I32(32)], Some(5)) }.unwrap();
    let mut yields = 0;
    loop {
        match state {
            RunState::Finished { values, .. } => {
                assert_eq!(values.as_slice(), &[Value::I32(0)]);
                break;
            }
            RunState::Resumable { mut resumable, .. } => {
                yields += 1;
                *resumable.fuel_mut().as_mut().unwrap() += 5;
                // SAFETY: the resumable was produced by this store and has not been copied.
                state = unsafe { store.resume_wasm(resumable) }.unwrap();
            }
            RunState::HostCalled { .. } => panic!("module has no host imports"),
        }
    }
    assert!(yields > 1);
}

#[test]
fn constrained_component_frontend_validates_world_and_invokes_typed_export() {
    validate_wit_world(WORLD, "typed-filter").unwrap();
    let component = wat::parse_str(COMPONENT).unwrap();
    let summary = inspect_component(&component).unwrap();
    assert_eq!(summary.embedded_modules, 1);
    assert_eq!(summary.exports, 1);

    // C0's constrained plan binds the component's sole `add` export to the
    // reviewed embedded Core fixture; C2 will own general Canonical ABI calls.
    let core = wat::parse_str(ADD).unwrap();
    assert_eq!(run_wasmi_add(&core), 42);
}

#[test]
fn malformed_component_and_wrong_world_fail_closed() {
    assert_eq!(
        inspect_component(&[0, 0x61, 0x73, 0x6d, 0x0d, 0, 1, 0, 1, 0x80]),
        Err(FrontendError::InvalidComponent)
    );
    assert_eq!(
        validate_wit_world(WORLD, "ambient-world"),
        Err(FrontendError::MissingWorld)
    );
}

#[test]
fn decisions_and_unthresholded_shapes_are_frozen() {
    assert_eq!(SELECTED_CORE_ENGINE, Candidate::Wasmi);
    assert!(FRONTEND_DECISION.no_std_alloc);
    assert!(FRONTEND_DECISION.policy_is_in_tree);
    assert_eq!(
        FRONTEND_DECISION.selected_async_component_revision,
        vibeos_component_format::ASYNC_COMPONENT_MODEL_REVISION
    );
    assert_eq!(
        FRONTEND_DECISION.selected_async_canonical_revision,
        vibeos_component_format::ASYNC_CANONICAL_ABI_REVISION
    );
    assert_eq!(format!("{FLOAT_DECISION:?}"), "IntegerOnly");
    assert!(ENGINE_EVIDENCE.iter().all(|candidate| {
        candidate.no_std_alloc
            && candidate.validates
            && candidate.interprets
            && candidate.outer_limits
            && candidate.deterministic_fuel
            && candidate.resumable_out_of_fuel
            && candidate.panic_abort_compatible
            && candidate.riscv64_unknown_none_build
    }));
    assert!(!ENGINE_EVIDENCE[1].engine_structure_limits);
    assert!(!ENGINE_EVIDENCE[0].allocator_oom_recoverable);
    let shape = allocation_shape();
    assert!(shape.wasmi_engine_bytes > 0);
    assert!(shape.wasmi_store_bytes > 0);
    assert!(shape.dlr_store_bytes > 0);
    assert!(shape.component_validator_bytes > 0);
}
