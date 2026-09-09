//! Trusted ABI probe: clock_time_get(1,0,16), fd_write(1,[32,5],1,8),
//! proc_exit(7), unreachable. Data at 32 is "WASI\n"; one 64 KiB memory.
use vibeos_wasmtime_runtime::{
    wasi::{self, Clock, Invocation},
    wasmtime::{self, Engine, Store},
};
pub(super) struct KernelClock;
impl Clock for KernelClock {
    fn time(&mut self, id: u32, precision: u64) -> Result<u64, i32> {
        crate::wasi_clock::time(id, precision)
    }
    fn resolution(&mut self, id: u32) -> Result<u64, i32> {
        crate::wasi_clock::resolution(id)
    }
}
const WASM: &[u8] = &[
    0, 97, 115, 109, 1, 0, 0, 0, 1, 23, 4, 96, 3, 127, 126, 127, 1, 127, 96, 4, 127, 127, 127, 127,
    1, 127, 96, 1, 127, 0, 96, 0, 0, 2, 110, 3, 22, 119, 97, 115, 105, 95, 115, 110, 97, 112, 115,
    104, 111, 116, 95, 112, 114, 101, 118, 105, 101, 119, 49, 14, 99, 108, 111, 99, 107, 95, 116,
    105, 109, 101, 95, 103, 101, 116, 0, 0, 22, 119, 97, 115, 105, 95, 115, 110, 97, 112, 115, 104,
    111, 116, 95, 112, 114, 101, 118, 105, 101, 119, 49, 8, 102, 100, 95, 119, 114, 105, 116, 101,
    0, 1, 22, 119, 97, 115, 105, 95, 115, 110, 97, 112, 115, 104, 111, 116, 95, 112, 114, 101, 118,
    105, 101, 119, 49, 9, 112, 114, 111, 99, 95, 101, 120, 105, 116, 0, 2, 3, 2, 1, 3, 5, 4, 1, 1,
    1, 1, 7, 19, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 6, 95, 115, 116, 97, 114, 116, 0, 3, 10,
    35, 1, 33, 0, 65, 1, 66, 0, 65, 16, 16, 0, 4, 64, 0, 11, 65, 1, 65, 0, 65, 1, 65, 8, 16, 1, 4,
    64, 0, 11, 65, 7, 16, 2, 0, 11, 11, 43, 1, 0, 65, 0, 11, 37, 32, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 87, 65, 83, 73, 10,
];
pub fn run(engine: &Engine) -> wasmtime::Result<()> {
    let module = wasi::compile(engine, WASM)?;
    let linker = wasi::linker::<KernelClock>(engine, &module)?;
    for _ in 0..100 {
        let mut store = Store::new(
            engine,
            Invocation::new(&[], alloc::vec::Vec::new(), KernelClock)?,
        );
        store.set_fuel(10_000)?;
        let instance = linker.instantiate(&mut store, &module)?;
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
        let result = super::call(&start, &mut store, ());
        assert!(result.is_err());
        assert_eq!(store.data().exit, Some(7));
        assert_eq!(store.data().stdout, b"WASI\n");
        assert!(store.data().stderr.is_empty());
        let memory = instance.get_memory(&mut store, "memory").unwrap();
        let data = memory.data(&store);
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 5);
        assert!(u64::from_le_bytes(data[16..24].try_into().unwrap()) > 0);
        // The error retains a Wasm backtrace and therefore module code. Drop it
        // before testing resource reclamation at the enclosing selftest boundary.
        drop(result);
    }
    crate::println!("  WASMTIME WASI PASS cycles=100 clock=1 stdout=1 exit=7");
    Ok(())
}
