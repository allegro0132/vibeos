//! Wasmtime platform port, selected by the opt-in kernel `wasmtime-command` feature.
#![no_std]
extern crate alloc;
pub mod memory;
pub mod riscv_isa;
#[cfg(feature = "compiler")]
pub mod wasi;

pub use wasmtime::{Config, Engine, Linker, Module, Store};

/// Keep guest bounds checks explicit until native trap integration is verified.
/// The final command path must also attach the existing capability and quota policy.
pub fn configuration() -> Config {
    let mut config = Config::new();
    config.consume_fuel(true)
        .wasm_simd(false)
        .wasm_relaxed_simd(false)
        .wasm_memory64(false)
        .wasm_multi_memory(false)
        .signals_based_traps(false)
        .memory_guard_size(0)
        .memory_reservation(0)
        .memory_may_move(true)
        .memory_reservation_for_growth(0)
        .memory_init_cow(false);
    // no_std cannot use Linux CPU discovery. The Rust target contract still
    // guarantees C on RV64GC, so retain that baseline in generated guest code.
    // Other extensions require platform discovery and are not assumed here.
    #[cfg(all(feature = "compiler", target_arch = "riscv64", target_feature = "c"))]
    unsafe {
        config.cranelift_flag_enable("has_c");
    }
    config.with_host_memory(alloc::sync::Arc::new(memory::BoundedMemoryCreator));
    // Compiling the threads proposal in must not widen the ordinary command
    // profile: shared memory and atomics stay opt-in per engine.
    #[cfg(feature = "threads")]
    config.wasm_threads(false);
    config
}

/// Enable wasi-threads on this configuration. The hooks connect shared-memory
/// waits and notifies to the embedding's scheduler; the memory creator must
/// keep shared memories at a fixed base.
#[cfg(all(feature = "threads", not(feature = "host-tools")))]
pub fn enable_threads(config: &mut Config, hooks: alloc::sync::Arc<dyn wasmtime::ThreadHooks>) {
    config.wasm_threads(true).shared_memory(true).with_thread_hooks(hooks);
}

#[cfg(feature = "native-riscv")]
pub mod riscv;

pub use wasmtime;
