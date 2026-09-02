use std::{
    env, fs,
    path::{Path, PathBuf},
};

use serde_json::Value;

fn compile_wat(source: &str, destination: &str) {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest.join(source);
    println!("cargo:rerun-if-changed={}", source.display());
    let bytes = wat::parse_file(&source)
        .unwrap_or_else(|error| panic!("failed to compile {}: {error}", source.display()));
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join(destination);
    fs::write(&output, bytes)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", output.display()));
}

fn unsigned(object: &Value, key: &str) -> u64 {
    object
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("C0.7 workload field {key} is not an unsigned integer"))
}

fn write_contract(manifest: &Path, output: &Path) {
    println!("cargo:rerun-if-changed={}", manifest.display());
    let document: Value = serde_json::from_slice(
        &fs::read(manifest)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", manifest.display())),
    )
    .unwrap_or_else(|error| panic!("failed to parse {}: {error}", manifest.display()));
    let sampling = document
        .get("sampling")
        .unwrap_or_else(|| panic!("{} has no sampling contract", manifest.display()));
    let generated = format!(
        concat!(
            "pub const PROBE_HEAP_BYTES: usize = {};\n",
            "pub const TIMING_SAMPLES: usize = {};\n",
            "pub const STARTUP_OPERATIONS: u64 = {};\n",
            "pub const FUEL_OPERATIONS: u64 = {};\n",
            "pub const FRONTEND_OPERATIONS: u64 = {};\n",
            "pub const CANONICAL_OPERATIONS: u64 = {};\n",
            "pub const STARTUP_INPUT: i32 = {};\n",
            "pub const FUEL_INPUT: i32 = {};\n",
            "pub const FUEL_BUDGET: u64 = {};\n",
            "pub const CANONICAL_TEXT_BYTES: usize = {};\n",
            "pub const CANONICAL_LIST_ELEMENTS: usize = {};\n",
        ),
        unsigned(&document, "probe_heap_bytes"),
        unsigned(sampling, "timing_samples"),
        unsigned(sampling, "startup_operations_per_sample"),
        unsigned(sampling, "fuel_operations_per_sample"),
        unsigned(sampling, "frontend_operations_per_sample"),
        unsigned(sampling, "canonical_operations_per_sample"),
        unsigned(sampling, "startup_input"),
        unsigned(sampling, "fuel_input"),
        unsigned(sampling, "fuel_budget"),
        unsigned(sampling, "canonical_text_bytes"),
        unsigned(sampling, "canonical_list_elements"),
    );
    fs::write(output.join("c0_contract.rs"), generated)
        .unwrap_or_else(|error| panic!("failed to write generated C0.7 contract: {error}"));
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    write_contract(&manifest.join("evidence/workloads-v1.json"), &output);
    compile_wat("fixtures/empty.wat", "c0_empty.wasm");
    compile_wat("fixtures/fuel.wat", "c0_fuel.wasm");
    compile_wat(
        "../component-format/tests/corpus/component/typed.component.wat",
        "c0_typed_component.wasm",
    );
}
