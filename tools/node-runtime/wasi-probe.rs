//! Host-side admission diagnostic, never evidence of execution inside VibeOS.
use std::{env, fs, process};
use vibeos_wasi_runtime::{WasiInvocation, WasiLimits};
use wasmparser::{Parser, Payload, TypeRef};

fn main() {
    let path = env::args().nth(1).expect("usage: wasi-probe MODULE.wasm");
    let bytes = fs::read(&path).expect("read module");
    let limits = WasiLimits::default();
    println!("backend=host-admission-only guest_executed=false");
    println!("module_bytes={} module_ceiling={}", bytes.len(), limits.module_bytes);
    println!("memory_ceiling={} allocation_ceiling={}", limits.memory_bytes, limits.allocation_bytes);
    println!("allocation_estimate={}", bytes.len() * 32 + 256 * 1024);
    for payload in Parser::new(0).parse_all(&bytes) {
        match payload.expect("valid wasm encoding") {
            Payload::ImportSection(imports) => {
                for import in imports.into_imports() {
                    let import = import.expect("valid import");
                    println!("import={}:{} kind={}", import.module, import.name,
                        if matches!(import.ty, TypeRef::Func(_)) { "function" } else { "other" });
                }
            }
            Payload::MemorySection(memories) => {
                for memory in memories {
                    let memory = memory.expect("valid memory");
                    println!("initial_memory_pages={} maximum_memory_pages={:?}", memory.initial, memory.maximum);
                }
            }
            Payload::FunctionSection(functions) => println!("defined_functions={}", functions.count()),
            Payload::CustomSection(section) => println!("custom_section={} bytes={}", section.name(), section.range().len()),
            _ => (),
        }
    }
    match WasiInvocation::new(&bytes, &[path, "--version".into()], limits) {
        Ok(_) => println!("admission=accepted guest_executed=false"),
        Err(error) => {
            println!("admission=rejected error={error:?}");
            process::exit(1);
        }
    }
}
