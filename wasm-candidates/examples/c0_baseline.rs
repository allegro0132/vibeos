use std::time::Instant;

use dlr_wasm_interpreter::{decode_and_validate, InstantiationOutcome, Store as DlrStore, Value};
use vibeos_wasm_candidates::{allocation_shape, inspect_component};
use wasmi::{CompilationMode, Config, Engine, Linker, Module, Store};

const ADD: &str = include_str!("../../component-format/tests/corpus/core/integer.wat");
const COMPONENT: &str =
    include_str!("../../component-format/tests/corpus/component/typed.component.wat");

fn main() {
    let core = wat::parse_str(ADD).unwrap();
    let component = wat::parse_str(COMPONENT).unwrap();
    let iterations = 10_000u32;

    let started = Instant::now();
    for _ in 0..iterations {
        inspect_component(&component).unwrap();
    }
    let component_validate_ns = started.elapsed().as_nanos() / u128::from(iterations);

    let mut config = Config::default();
    config
        .floats(false)
        .consume_fuel(true)
        .compilation_mode(CompilationMode::Eager);
    let engine = Engine::new(&config);
    let started = Instant::now();
    for _ in 0..iterations {
        Module::new(&engine, &core).unwrap();
    }
    let wasmi_validate_ns = started.elapsed().as_nanos() / u128::from(iterations);

    let started = Instant::now();
    for _ in 0..iterations {
        decode_and_validate(&core, &mut ()).unwrap();
    }
    let dlr_validate_ns = started.elapsed().as_nanos() / u128::from(iterations);

    let module = Module::new(&engine, &core).unwrap();
    let mut store = Store::new(&engine, ());
    store.set_fuel(u64::MAX).unwrap();
    let instance = Linker::new(&engine)
        .instantiate_and_start(&mut store, &module)
        .unwrap();
    let add = instance
        .get_typed_func::<(i32, i32), i32>(&store, "add")
        .unwrap();
    let started = Instant::now();
    for _ in 0..iterations {
        assert_eq!(add.call(&mut store, (20, 22)).unwrap(), 42);
    }
    let wasmi_call_ns = started.elapsed().as_nanos() / u128::from(iterations);

    let module = decode_and_validate(&core, &mut ()).unwrap();
    let mut dlr = DlrStore::new(());
    // SAFETY: the module is import-free and belongs to this store.
    let InstantiationOutcome { module_addr, .. } =
        unsafe { dlr.module_instantiate(&module, vec![], None) }.unwrap();
    // SAFETY: the address was produced by this store.
    let add = unsafe { dlr.instance_export(module_addr, "add") }
        .unwrap()
        .as_func()
        .unwrap();
    let started = Instant::now();
    for _ in 0..iterations {
        // SAFETY: the address belongs to this store and arguments are immediate integers.
        let result =
            unsafe { dlr.invoke_simple(add, vec![Value::I32(20), Value::I32(22)]) }.unwrap();
        assert_eq!(result.as_slice(), &[Value::I32(42)]);
    }
    let dlr_call_ns = started.elapsed().as_nanos() / u128::from(iterations);

    let shape = allocation_shape();
    println!("metric,value,unit");
    println!("wasmi_engine_inline,{},bytes", shape.wasmi_engine_bytes);
    println!("wasmi_store_inline,{},bytes", shape.wasmi_store_bytes);
    println!("dlr_store_inline,{},bytes", shape.dlr_store_bytes);
    println!(
        "component_validator_inline,{},bytes",
        shape.component_validator_bytes
    );
    println!("wasmi_validate,{wasmi_validate_ns},ns/op");
    println!("dlr_validate,{dlr_validate_ns},ns/op");
    println!("component_validate,{component_validate_ns},ns/op");
    println!("wasmi_integer_call,{wasmi_call_ns},ns/op");
    println!("dlr_integer_call,{dlr_call_ns},ns/op");
}
