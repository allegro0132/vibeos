//! Execute compiled code through the host test implementation of the custom API.
#[path = "support/host_platform.rs"]
mod host_platform;
#[cfg(feature = "native-riscv")]
#[path = "support/fp_probe.rs"]
mod fp_probe;
use wasmtime::{Engine, Instance, Module, Store, Trap, Linker};

fn module(body: &[u8], returns_i32: bool) -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    let mut section = |id: u8, data: &[u8]| {
        assert!(data.len() < 128);
        wasm.extend([id, data.len() as u8]);
        wasm.extend(data);
    };
    section(1, if returns_i32 { &[1, 0x60, 0, 1, 0x7f] } else { &[1, 0x60, 0, 0] });
    section(3, &[1, 0]);
    section(5, &[1, 1, 1, 1]); // One page, maximum one page.
    section(7, &[1, 3, b'r', b'u', b'n', 0, 0]);
    let mut code = vec![1, (body.len() + 2) as u8, 0];
    code.extend(body);
    code.push(0x0b);
    section(10, &code);
    wasm
}
fn main() -> wasmtime::Result<()> {
    #[cfg(feature = "native-riscv")]
    for _ in 0..100 { assert_eq!(unsafe { fp_probe::wasmtime_fp_context_probe() }, 0); }
    #[cfg(feature = "native-riscv")]
    eprintln!("PASS fp context: 100 cycles, all 32 registers and FCSR, direct readback");
    let engine = Engine::new(&vibeos_wasmtime_runtime::configuration())?;
    let mut baseline = None;
    // f64 host-call ABI: (import "h" "f" (func (param f64) (result f64)))
    // (func (export "run") (result f64) f64.const 3.5 call 0).
    let float_wasm = [
        0,97,115,109,1,0,0,0,
        1,10,2,0x60,1,0x7c,1,0x7c,0x60,0,1,0x7c,
        2,7,1,1,b'h',1,b'f',0,0,
        3,2,1,1,
        7,7,1,3,b'r',b'u',b'n',0,1,
        10,15,1,13,0,0x44,0,0,0,0,0,0,0x0c,0x40,0x10,0,0x0b,
    ];
    let mut linker = Linker::<()>::new(&engine);
    linker.func_wrap("h", "f", |x: f64| -> f64 { assert_eq!(x, 3.5); x * 2.0 })?;
    let float_code = Module::new(&engine, float_wasm)?;
    let retained_maps = host_platform::memory_counts().2;
    for iteration in 0..100 {
        {
            let mut store = Store::new(&engine, ());
            store.set_fuel(10_000)?;
            let instance = linker.instantiate(&mut store, &float_code)?;
            assert_eq!(instance.get_typed_func::<(), f64>(&mut store, "run")?.call(&mut store, ())?, 7.0);
        }

        let mut store = Store::new(&engine, ());
        store.set_fuel(10_000)?;
        let code = Module::new(&engine, module(&[0x41, 42], true))?;
        let instance = Instance::new(&mut store, &code, &[])?;
        assert_eq!(instance.get_typed_func::<(), i32>(&mut store, "run")?.call(&mut store, ())?, 42);
        drop((instance, code, store));
        for (name, body, result, expected) in [
            ("unreachable", vec![0x00], false, Trap::UnreachableCodeReached),
            ("divide", vec![0x41, 1, 0x41, 0, 0x6d], true, Trap::IntegerDivisionByZero),
            ("bounds", vec![0x41, 0x7f, 0x28, 2, 0], true, Trap::MemoryOutOfBounds),
            ("fuel", vec![0x03, 0x40, 0x0c, 0, 0x0b], false, Trap::OutOfFuel),
        ] {
            let code = Module::new(&engine, module(&body, result))?;
            let mut store = Store::new(&engine, ());
            store.set_fuel(10_000)?;
            let instance = Instance::new(&mut store, &code, &[])?;
            let error = if result {
                instance.get_typed_func::<(), i32>(&mut store, "run")?.call(&mut store, ()).unwrap_err()
            } else {
                instance.get_typed_func::<(), ()>(&mut store, "run")?.call(&mut store, ()).unwrap_err()
            };
            assert_eq!(error.downcast_ref::<Trap>(), Some(&expected), "{name} cycle {iteration}: {error:#}");
        }
        let live = host_platform::memory_counts();
        assert_eq!(live.2, retained_maps, "mapping leak after cycle {iteration}");
        if iteration == 0 { baseline = Some(live.0); }
        assert_eq!(Some(live.0), baseline, "heap drift after cycle {iteration}");
    }
    drop((float_code, linker));
    assert_eq!(host_platform::memory_counts().2, 0);
    eprintln!("memory_counts={:?}", host_platform::memory_counts());
    println!("PASS custom-platform native execution: 100 cycles, return/float-host-call/bounds/divide/unreachable/fuel");
    Ok(())
}
