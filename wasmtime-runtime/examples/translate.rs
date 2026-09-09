//! Compare the upstream and ported module translation before code generation.
use wasmtime_environ::{ModuleEnvironment, ModuleTypesBuilder, StaticModuleIndex, Tunables};
fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).expect("MODULE.wasm")).unwrap();
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
    let translation = ModuleEnvironment::new(
        &Tunables::default_u64(), &mut validator, &mut types, StaticModuleIndex::from_u32(0),
    ).translate(parser, &bytes).expect("module translation");
    println!("functions={} bodies={} memories={} tables={} globals={} imports={}",
        translation.module.functions.len(), translation.function_body_inputs.len(),
        translation.module.memories.len(), translation.module.tables.len(),
        translation.module.globals.len(), translation.module.imports().count());
}
