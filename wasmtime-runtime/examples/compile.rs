//! Exercise the ported compiler on all real module bodies, without executing code.
use wasmtime_environ::{FuncKey, ModuleEnvironment, ModuleTypesBuilder, StaticModuleIndex, Tunables};
fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).expect("MODULE.wasm")).unwrap();
    let output = std::env::args().nth(2).map(std::path::PathBuf::from);
    if let Some(path) = &output { std::fs::create_dir_all(path).unwrap(); }
    let mut tunables = Tunables::default_u64();
    tunables.consume_fuel = true;
    tunables.signals_based_traps = false;
    tunables.memory_guard_size = 0;
    tunables.memory_reservation = 16 * 1024 * 1024;
    tunables.memory_reservation_for_growth = 0;
    let features = wasmparser::WasmFeatures::MUTABLE_GLOBAL
        | wasmparser::WasmFeatures::SATURATING_FLOAT_TO_INT
        | wasmparser::WasmFeatures::SIGN_EXTENSION
        | wasmparser::WasmFeatures::MULTI_VALUE
        | wasmparser::WasmFeatures::BULK_MEMORY
        | wasmparser::WasmFeatures::REFERENCE_TYPES
        | wasmparser::WasmFeatures::FLOATS
        | wasmparser::WasmFeatures::GC_TYPES;
    let mut validator = wasmparser::Validator::new_with_features(features);
    let mut parser = wasmparser::Parser::new(0);
    parser.set_features(features);
    let mut types = ModuleTypesBuilder::new(&validator);
    let module_index = StaticModuleIndex::from_u32(0);
    let mut translation = ModuleEnvironment::new(&tunables, &mut validator, &mut types, module_index)
        .translate(parser, &bytes).expect("module translation");
    let mut builder = wasmtime_cranelift::builder(Some("riscv64-unknown-none-elf".parse().unwrap())).unwrap();
    builder.set("opt_level", "speed").unwrap();
    builder.set_tunables(tunables).unwrap();
    let compiler = builder.build().unwrap();
    let bodies = std::mem::take(&mut translation.function_body_inputs);
    let mut functions = 0;
    let mut code_bytes = 0;
    let mut relocations = 0;
    for (index, data) in bodies {
        let input = data.body.clone();
        let name = format!("body{}", index.as_u32());
        let key = FuncKey::DefinedWasmFunction(module_index, index);
        let mut function = compiler.compile_function(&translation, key, data, &types, &name).expect("function translation");
        compiler.inlining_compiler().unwrap().finish_compiling(&mut function, Some(input), &name).expect("native code generation");
        let native = function.code.downcast_ref::<wasmtime_cranelift::CompiledFunction>().unwrap();
        let code = native.buffer.data();
        assert!(!code.is_empty());
        if let Some(path) = &output {
            std::fs::write(path.join(format!("{}.bin", index.as_u32())), code).unwrap();
            std::fs::write(path.join(format!("{}.relocs", index.as_u32())), format!("{:?}", native.relocations().collect::<Vec<_>>())).unwrap();
        }
        functions += 1;
        code_bytes += code.len();
        relocations += native.relocations().count();
    }
    println!("functions={functions} code_bytes={code_bytes} relocations={relocations} fuel=true signals=false target=riscv64");
}
