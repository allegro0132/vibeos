//! Test the production host-memory creator through Wasmtime's public memory API.
#[path = "support/host_platform.rs"]
mod host_platform;
use wasmtime::{Engine, Instance, Module, Store};
fn main() -> wasmtime::Result<()> {
    let engine = Engine::new(&vibeos_wasmtime_runtime::configuration())?;
    let module = Module::new(&engine, b"\0asm\x01\0\0\0\x05\x03\x01\0\x01\x07\x0a\x01\x06memory\x02\0")?;
    let oversized = Module::new(&engine, b"\0asm\x01\0\0\0\x05\x04\x01\0\x81\x02\x07\x0a\x01\x06memory\x02\0")?;
    let mappings = host_platform::memory_counts().2;
    let mut baseline = None;
    for _ in 0..20 {
        {
            let mut store = Store::new(&engine, ());
            // Omitted guest maximum: the host still enforces 16 MiB.
            let instance = Instance::new(&mut store, &module, &[])?;
            let memory = instance.get_memory(&mut store, "memory").unwrap();
            assert!(memory.data(&store).iter().all(|b| *b == 0));
            let base = memory.data_ptr(&store);
            memory.write(&mut store, 65532, &[1, 2, 3, 4])?;
            assert_eq!(memory.grow(&mut store, 1)?, 1);
            assert_eq!(base, memory.data_ptr(&store));
            assert_eq!(&memory.data(&store)[65532..65536], &[1, 2, 3, 4]);
            assert!(memory.data(&store)[65536..].iter().all(|b| *b == 0));
            assert_eq!(memory.grow(&mut store, 1)?, 2);
            assert_ne!(base, memory.data_ptr(&store));
            assert_eq!(&memory.data(&store)[65532..65536], &[1, 2, 3, 4]);
            assert!(memory.data(&store)[131072..].iter().all(|b| *b == 0));
            assert!(memory.grow(&mut store, 254).is_err());
            assert_eq!(memory.size(&store), 3);
        }
        let now = host_platform::memory_counts();
        if baseline.is_none() { baseline = Some(now.0); }
        assert_eq!(Some(now.0), baseline);
        assert_eq!(now.2, mappings);
    }
    let mut store = Store::new(&engine, ());
    assert!(Instance::new(&mut store, &oversized, &[]).is_err());
    println!("PASS bounded host memory: 20 cycles; growth, base preservation/relocation, zero fill, omitted maximum, 16 MiB cap, baseline");
    Ok(())
}
