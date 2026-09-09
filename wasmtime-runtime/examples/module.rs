// Exercise the complete module optimization, trampoline and object-link pipeline.
// This cross-compiles only; the returned object is not executed on the host.
fn main() {
    let mut args = std::env::args().skip(1);
    let wasm = std::fs::read(args.next().expect("MODULE.wasm")).unwrap();
    let output = args.next().expect("OUTPUT.cwasm");
    let mut config = vibeos_wasmtime_runtime::configuration();
    config.target("riscv64-unknown-none-elf").unwrap();
    config.cranelift_opt_level(wasmtime::OptLevel::Speed);
    let engine = wasmtime::Engine::new(&config).expect("engine configuration");
    let object = engine.precompile_module(&wasm).expect("module compilation");
    std::fs::write(output, &object).unwrap();
    #[cfg(feature = "host-custom")]
    eprintln!("heap_live={} heap_peak={} mapped_live={} mapped_peak={}", host_platform::memory_counts().0, host_platform::memory_counts().1, host_platform::memory_counts().2, host_platform::memory_counts().3);
    println!(
        "module_bytes={} object_bytes={} fuel=true signals=false target=riscv64",
        wasm.len(),
        object.len()
    );
}
