//! Explicit trusted publication boundary for the experimental RV64 cache.
use alloc::{boxed::Box, sync::Arc};
#[cfg(target_arch = "riscv64")]
use alloc::{collections::BTreeMap, vec::Vec};
use core::fmt::Debug;

/// Maximum execute-only storage per engine, included by the embedding in its
/// invocation allocation reservation. Every image is charged in 4 KiB pages.
pub const CODE_BUDGET: usize = 1024 * 1024;

/// An immutable executable allocation, reclaimed when the handle is dropped.
///
/// # Safety
/// Entry must be aligned and execute the exact words passed to publish, remain
/// immutable/alive until Drop, and be executable only after coherent W^X sealing.
pub unsafe trait Executable: Debug + Send + Sync {
    fn entry(&self) -> usize;
}

/// Trusted platform code allocator. No guest or external native bytes enter it.
///
/// # Safety
/// Publish must copy exactly the supplied words into exclusively owned pages,
/// enforce W^X and synchronize instruction caches before returning. Handles must
/// belong to the current invocation's reclaimable domain, including fault cleanup.
pub unsafe trait CodeMemory: Debug + Send + Sync {
    fn publish(&self, words: &[u32]) -> Option<Box<dyn Executable>>;
}

#[derive(Debug)]
#[cfg(target_arch = "riscv64")]
pub(crate) struct Body {
    pub end: usize,
    pub image: Option<(Box<dyn Executable>, Vec<usize>, Vec<bool>)>,
}

#[derive(Debug, Default)]
pub(crate) struct Cache {
    pub backend: Option<Arc<dyn CodeMemory>>,
    #[cfg(target_arch = "riscv64")]
    pub bodies: BTreeMap<usize, Arc<Body>>,
    #[cfg(target_arch = "riscv64")]
    pub bytes: usize,
}

#[cfg(target_arch = "riscv64")]
pub(crate) use vibeos_wasm_rv64::{compile, Context};
