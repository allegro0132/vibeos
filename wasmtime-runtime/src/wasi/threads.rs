//! wasi-threads: one bounded shared memory, one Store and Instance per guest
//! thread, and the `wasi::thread-spawn` import routed to the embedding.
//!
//! The embedding owns scheduling. It creates the shared memory once, defines
//! it as `env.memory` in every thread's linker before instantiation, and runs
//! `wasi_thread_start(tid, start_arg)` on a store of its own for each spawn.
use super::*;
use alloc::sync::Arc;
use wasmtime::{AsContext, Instance, MemoryType, SharedMemory, Store, TypedFunc};

/// Spawn policy supplied by the embedding. `spawn` runs on the calling guest
/// thread's fiber and must not block; it returns the new thread id (>= 1) or a
/// negative errno such as `-AGAIN` when the thread cap is reached.
pub trait ThreadSpawner: Send + Sync + 'static {
    fn spawn(&self, start_arg: i32) -> i32;
}
/// errno returned by `thread-spawn` when no further thread may be created.
pub const SPAWN_AGAIN: i32 = -AGAIN;
/// The imported shared `env.memory` type, if the module uses wasi-threads.
pub fn shared_memory_type(module: &Module) -> Option<MemoryType> {
    module.imports().find(|i| i.module() == "env" && i.name() == "memory").and_then(|i| match i.ty() {
        ExternType::Memory(m) if m.is_shared() => Some(m),
        _ => None,
    })
}
/// Allocate the memory every thread of this module instantiates against.
pub fn create_shared_memory(engine: &Engine, module: &Module) -> wasmtime::Result<SharedMemory> {
    let ty = shared_memory_type(module).ok_or_else(|| wasmtime::format_err!("module does not import a shared memory"))?;
    SharedMemory::new(engine, ty)
}
/// The streaming Preview 1 linker plus `wasi::thread-spawn`. Call
/// [`define_shared_memory`] on each store before instantiating.
pub fn linker_threads<C: Clock>(engine: &Engine, module: &Module, spawner: Arc<dyn ThreadSpawner>) -> wasmtime::Result<Linker<Invocation<C>>> {
    let mut linker = linker_streams(engine, module)?;
    if module.imports().any(|i| i.module() == THREAD_SPAWN_MODULE && i.name() == THREAD_SPAWN_NAME) {
        linker.func_wrap(THREAD_SPAWN_MODULE, THREAD_SPAWN_NAME, move |caller: Caller<'_, Invocation<C>>, start_arg: i32| -> i32 {
            if caller.data().exit.is_some() || caller.data().resource_limit_hit() {
                return SPAWN_AGAIN;
            }
            spawner.spawn(start_arg)
        })?;
    }
    Ok(linker)
}
/// Bind the shared memory as this store's `env.memory` import.
pub fn define_shared_memory<C: Clock>(linker: &mut Linker<Invocation<C>>, store: impl AsContext<Data = Invocation<C>>, memory: &SharedMemory) -> wasmtime::Result<()> {
    linker.define(store, "env", "memory", memory.clone())?;
    Ok(())
}
/// The per-thread entry `wasi_thread_start(tid, start_arg)`.
pub fn thread_start<C: Clock>(instance: &Instance, store: &mut Store<Invocation<C>>) -> wasmtime::Result<TypedFunc<(i32, i32), ()>> {
    instance.get_typed_func::<(i32, i32), ()>(store, THREAD_START_EXPORT)
}
