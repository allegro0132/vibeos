//! Native file operations admitted through an explicit FileTreeRoot capability.
use alloc::sync::Arc;
use crate::{cap::{Cap, InvocationLease, Rights}, world::Space};
use vibeos_file_store::{FileError, FileTreeRoot, RelPath};
#[derive(Clone)]
pub(super) struct FileGrant { space: Arc<Space>, root: Cap }
impl FileGrant {
    pub(super) fn new(space: Arc<Space>, root: Cap) -> Option<Self> {
        let grant = Self { space, root };
        drop(grant.lease(Rights::READ)?);
        Some(grant)
    }
    fn lease(&self, rights: Rights) -> Option<InvocationLease<FileTreeRoot>> {
        self.space.0.lock().lookup_lease(self.root, rights).ok()
    }
}
fn error(error: FileError) -> i32 {
    match error {
        FileError::EscapeRoot | FileError::RootProtected => -3,
        FileError::NotFound => -6,
        FileError::IsDirectory => -7,
        FileError::Busy | FileError::Conflict => -8,
        FileError::InvalidName | FileError::InvalidPath | FileError::InvalidType => -9,
        FileError::PathTooLong => -10,
        FileError::NotDirectory => -11,
        FileError::SymlinkLoop => -12,
        _ => -5,
    }
}
// Caller supplies a readable UTF-8 path of bounded length. Absolute paths are
// rooted in this invocation's granted tree, never the kernel namespace.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_unlink(input: *const u8, length: usize) -> i32 {
    let Some(grant) = crate::native_tls::file_grant() else { return -3; };
    let Some(lease) = grant.lease(Rights::WRITE) else { return -3; };
    if length == 0 { return -6; }
    if length > 4096 { return -10; }
    if input.is_null() { return -2; }
    let bytes = unsafe { core::slice::from_raw_parts(input, length) };
    let Ok(text) = core::str::from_utf8(bytes) else { return -9; };
    let path = match RelPath::parse(text.trim_start_matches('/')) {
        Ok(path) => path,
        Err(failure) => return error(failure),
    };
    let mut transaction = match lease.with(|root| root.begin()) {
        Ok(transaction) => transaction,
        Err(failure) => return error(failure),
    };
    if let Err(failure) = transaction.remove(&path, false, false) { return error(failure); }
    let mut result = Err(FileError::ServiceUnavailable);
    // The invocation lease stays live through publication, following CSpace's
    // active-invocation contract. No CSpace lock survives suspension.
    if !crate::native_tls::park(async { result = transaction.commit_authoritative().await; }) { return -5; }
    result.map_or_else(error, |_| 0)
}

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use vibeos_file_store::FsFileReader;
struct OpenFile { grant: FileGrant, reader: FsFileReader, size: u64, position: AtomicU64 }
pub(super) struct FileTable { next: i32, entries: Vec<(i32, Arc<OpenFile>)> }
impl FileTable {
    pub(super) fn new() -> Self { Self { next: 3, entries: Vec::new() } }
    fn insert(&mut self, file: OpenFile) -> i32 {
        if self.entries.len() == 64 || self.next == i32::MAX { return -14; }
        if self.entries.try_reserve(1).is_err() { return -5; }
        let fd = self.next;
        self.next += 1;
        self.entries.push((fd, Arc::new(file)));
        fd
    }
}
fn lookup(fd: i32) -> Option<Arc<OpenFile>> {
    crate::native_tls::with_file_table(|table| table.entries.iter()
        .find(|(number, _)| *number == fd).map(|(_, file)| file.clone()))
}
pub(super) fn close(fd: i32) -> i32 {
    crate::native_tls::with_file_table(|table| {
        let Some(index) = table.entries.iter().position(|(number, _)| *number == fd) else { return -1; };
        table.entries.swap_remove(index);
        0
    })
}
pub(super) fn kind(fd: i32) -> i32 {
    let Some(file) = lookup(fd) else { return -1; };
    if file.grant.lease(Rights::READ).is_none() { return -3; }
    2
}
#[no_mangle]
pub(super) extern "C" fn vibeos_native_file_size(fd: i32) -> i64 {
    let Some(file) = lookup(fd) else { return -1; };
    if file.grant.lease(Rights::READ).is_none() { return -3; }
    file.size as i64
}
#[no_mangle]
pub(super) extern "C" fn vibeos_native_file_seek(fd: i32, offset: i64, whence: i32) -> i64 {
    let Some(file) = lookup(fd) else { return -1; };
    if file.grant.lease(Rights::READ).is_none() { return -3; }
    let base = match whence { 0 => 0, 1 => file.position.load(Ordering::Relaxed), 2 => file.size, _ => return -9 };
    let Some(next) = base.checked_add_signed(offset).filter(|value| *value <= i64::MAX as u64) else { return -9; };
    file.position.store(next, Ordering::Relaxed);
    next as i64
}
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_open(input: *const u8, length: usize, flags: u32) -> i32 {
    let Some(grant) = crate::native_tls::file_grant() else { return -3; };
    let Some(lease) = grant.lease(Rights::READ) else { return -3; };
    // ABI mode 0 is read-only. Write/create/truncate are not silently ignored.
    if flags != 0 { return -13; }
    if length == 0 { return -6; }
    if length > 4096 { return -10; }
    if input.is_null() { return -2; }
    let bytes = unsafe { core::slice::from_raw_parts(input, length) };
    let Ok(text) = core::str::from_utf8(bytes) else { return -9; };
    let path = match RelPath::parse(text.trim_start_matches('/')) { Ok(path) => path, Err(e) => return error(e) };
    let (metadata, reader) = match lease.with(|root| root.regular_reader(&path)) {
        Ok(file) => file, Err(e) => return error(e),
    };
    if metadata.size > i64::MAX as u64 { return -5; }
    crate::native_tls::with_file_table(|table| table.insert(OpenFile {
        grant, reader, size: metadata.size, position: AtomicU64::new(0),
    }))
}
pub(super) unsafe fn read(fd: i32, output: *mut u8, length: usize) -> isize {
    let Some(file) = lookup(fd) else { return -1; };
    let Some(_lease) = file.grant.lease(Rights::READ) else { return -3; };
    if output.is_null() && length != 0 { return -2; }
    let position = file.position.load(Ordering::Relaxed);
    if position >= file.size || length == 0 { return 0; }
    let count = length.min(1024).min((file.size - position) as usize);
    let mut bytes = [0u8; 1024];
    let mut result = Err(FileError::ServiceUnavailable);
    if !crate::native_tls::park(async {
        let mut skip = position;
        for index in 0..file.reader.chunk_count() {
            let chunk = match file.reader.read_chunk(index).await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(e) => { result = Err(e); return; }
            };
            if skip >= chunk.len() as u64 { skip -= chunk.len() as u64; continue; }
            let start = skip as usize;
            let size = count.min(chunk.len() - start);
            bytes[..size].copy_from_slice(&chunk[start..start + size]);
            result = Ok(size);
            return;
        }
    }) { return -5; }
    let size = match result { Ok(size) => size, Err(e) => return error(e) as isize };
    // Revalidate before exposing data obtained during suspended backend IO.
    let Some(_delivery) = file.grant.lease(Rights::READ) else { return -3; };
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), output, size); }
    file.position.store(position + size as u64, Ordering::Relaxed);
    size as isize
}

#[cfg(feature = "native-cxx-probe")]
pub(super) fn revoke_probe_grant() {
    let grant = crate::native_tls::file_grant().unwrap();
    grant.space.0.lock().revoke(grant.root).unwrap();
}
