//! Pinned, immutable tool files, independently authorized from each project.
use alloc::sync::Arc;
use core::{future::{poll_fn, Future}, pin::pin, sync::atomic::{AtomicBool, Ordering}};
use crate::{cap::Rights, native_files::FileGrant, sync::SpinLock};
use vibeos_core::{exec, heap::{self, AllocationDomain}};
use vibeos_file_store::{FileError, FileTreeRoot, RelPath};

static PACK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/node-toolkit.pack"));
static TOOLS: SpinLock<Option<FileGrant>> = SpinLock::new(None);
static INITIALIZING: AtomicBool = AtomicBool::new(false);
struct Initialization;
impl Drop for Initialization {
    fn drop(&mut self) { INITIALIZING.store(false, Ordering::Release); }
}

/// Storage is retained for image lifetime. Scope each poll to SYSTEM, never a
/// heap-domain guard or cache lock across suspension. Large tool files must not
/// monopolize the SSH/event-loop hart during the first tool invocation.
pub(super) async fn grant() -> Result<FileGrant, FileError> {
    loop {
        if let Some(grant) = TOOLS.lock().as_ref().cloned() { return Ok(grant); }
        if INITIALIZING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() { break; }
        exec::yield_now().await;
    }
    let _initialization = Initialization;
    // A prior initializer may have published between the cache read and CAS.
    if let Some(grant) = TOOLS.lock().as_ref().cloned() { return Ok(grant); }
    let mut build = pin!(initialize());
    poll_fn(|cx| {
        let _system = unsafe { heap::enter_domain(AllocationDomain::SYSTEM) };
        build.as_mut().poll(cx)
    }).await
}

async fn initialize() -> Result<FileGrant, FileError> {
    let root = Arc::new(FileTreeRoot::new_empty(0x6e6f6465746f6f6c)?);
    let mut input = PACK;
    if take(&mut input, 9)? != b"VIBETOOL1" { return Err(FileError::InvalidType); }
    let count = u32::from_le_bytes(take(&mut input, 4)?.try_into().unwrap());
    if count == 0 || count > 4096 { return Err(FileError::InvalidType); }
    let mut tx = root.begin()?;
    let mut previous = None;
    for _ in 0..count {
        let path_len = u16::from_le_bytes(take(&mut input, 2)?.try_into().unwrap()) as usize;
        let data_len = u32::from_le_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
        let path = core::str::from_utf8(take(&mut input, path_len)?)
            .map_err(|_| FileError::InvalidPath)?;
        // Require canonical sorted selectors, no duplicates or path aliases.
        let parsed = RelPath::parse(path)?;
        if parsed.is_root() || parsed.to_selector_string() != path ||
           previous.is_some_and(|old| old >= path) { return Err(FileError::InvalidPath); }
        previous = Some(path);
        let bytes = take(&mut input, data_len)?;
        let (parent, _) = parsed.parent_and_name()?;
        if !parent.is_root() { tx.mkdir(&parent, true)?; }
        if bytes.is_empty() { tx.write_chunks(&parsed, [bytes], false)?; }
        for (index, chunk) in bytes.chunks(64 * 1024).enumerate() {
            tx.write_chunks(&parsed, [chunk], index != 0)?;
            exec::yield_now().await;
        }
        exec::yield_now().await;
    }
    if !input.is_empty() { return Err(FileError::InvalidType); }
    tx.commit()?;
    let space = crate::world::Space::new("node-readonly-tools");
    let cap = space.0.lock().mint(root, Rights::READ);
    let grant = FileGrant::new(space, cap).ok_or(FileError::ServiceUnavailable)?;
    *TOOLS.lock() = Some(grant.clone());
    Ok(grant)
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], FileError> {
    if length > input.len() { return Err(FileError::InvalidType); }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}
