//! Native file operations admitted through an explicit FileTreeRoot capability.
use alloc::sync::Arc;
use alloc::string::String;
use crate::{cap::{Cap, InvocationLease, Rights}, world::Space};
use vibeos_file_store::{FileError, FileTreeRoot, RelPath};
#[derive(Clone)]
pub(super) struct FileGrant {
    lookup: Arc<dyn Fn(Rights) -> Option<FileLease> + Send + Sync>,
    #[cfg(feature = "native-cxx-probe")]
    probe_authority: Option<(Arc<Space>, Cap)>,
}
#[cfg(feature = "node-lifecycle-audit")]
pub(super) struct GrantAudit(alloc::sync::Weak<()>);
#[cfg(feature = "node-lifecycle-audit")]
impl GrantAudit {
    pub(super) fn assert_reclaimed(self, kind: &str) {
        assert_eq!(self.0.strong_count(), 0, "native grant provider or lease outlived invocation");
        crate::println!("NATIVE GRANT RECLAIM kind={} providers=0 leases=0", kind);
    }
}
impl FileGrant {
    /// Observe this invocation's provider and all leases acquired through it.
    /// The process-wide tool provider remains independently owned by its cache.
    #[cfg(feature = "node-lifecycle-audit")]
    pub(super) fn audited(self) -> (Self, GrantAudit) {
        let lifetime = Arc::new(());
        let audit = GrantAudit(Arc::downgrade(&lifetime));
        #[cfg(feature = "native-cxx-probe")]
        let probe_authority = self.probe_authority.clone();
        let grant = Self {
            lookup: Arc::new(move |rights| {
                let mut lease = self.lease(rights)?;
                assert!(lease.audit.is_none(), "grant already has an invocation audit owner");
                lease.audit = Some(lifetime.clone());
                Some(lease)
            }),
            #[cfg(feature = "native-cxx-probe")]
            probe_authority,
        };
        (grant, audit)
    }
    #[cfg(feature = "node-toolkit")]
    pub(super) async fn load_module(&self, path: &RelPath) -> Result<Vec<u8>, i32> {
        let lease = self.lease(Rights::READ).ok_or(-3)?;
        let (metadata, reader) = lease.with(|root| root.regular_reader(path)).map_err(error)?;
        let result = vibeos_wasi_command::load_reader(reader, metadata.size).await
            .map_err(|_| -5)?;
        if !self.live() { return Err(-3); }
        drop(lease);
        Ok(result)
    }
    /// Attenuate a tool mount without disconnecting its original revocation
    /// lineage. Open descriptors retain this same restricted provider.
    pub(super) fn read_only(self) -> Self {
        #[cfg(feature = "native-cxx-probe")]
        let probe_authority = self.probe_authority.clone();
        Self {
            lookup: Arc::new(move |rights| {
                if !Rights::READ.contains(rights) { return None; }
                self.lease(rights)
            }),
            #[cfg(feature = "native-cxx-probe")]
            probe_authority,
        }
    }
    pub(super) fn live(&self) -> bool { self.lease(Rights::READ).is_some() }
    pub(super) fn new(space: Arc<Space>, root: Cap) -> Option<Self> {
        let source = space.clone();
        let mut grant = Self::from_provider(move |rights| source.0.lock().lookup_lease(root, rights).ok())?;
        #[cfg(feature = "native-cxx-probe")]
        { grant.probe_authority = Some((space, root)); }
        Some(grant)
    }
    /// Launcher admission retains a lease provider, never a cached resource or
    /// lease. Every existing file operation therefore rechecks live authority.
    pub(super) fn from_provider(
        lookup: impl Fn(Rights) -> Option<InvocationLease<FileTreeRoot>> + Send + Sync + 'static,
    ) -> Option<Self> {
        let grant = Self {
            lookup: Arc::new(move |rights| lookup(rights).map(|authority| FileLease {
                authority, view: None,
                #[cfg(feature = "node-lifecycle-audit")]
                audit: None,
            })),
            #[cfg(feature = "native-cxx-probe")]
            probe_authority: None,
        };
        drop(grant.lease(Rights::READ)?);
        Some(grant)
    }
    /// Bind a project path without minting a disconnected capability. Recheck
    /// both original authority and the directory identity on every operation.
    pub(super) fn directory(self, path: RelPath) -> Option<Self> {
        let identity = self.lease(Rights::READ)?.with(|root|
            root.snapshot().directory(&path)?.stat(&RelPath::root(), true)).ok()?.file_id;
        #[cfg(feature = "native-cxx-probe")]
        let probe_authority = self.probe_authority.clone();
        let grant = Self {
            lookup: Arc::new(move |rights| {
                let mut lease = self.lease(rights)?;
                let view = lease.with(|root| root.directory(&path)).ok()?;
                if view.snapshot().stat(&RelPath::root(), true).ok()?.file_id != identity { return None; }
                lease.view = Some(view);
                Some(lease)
            }),
            #[cfg(feature = "native-cxx-probe")]
            probe_authority,
        };
        drop(grant.lease(Rights::READ)?);
        Some(grant)
    }
    fn lease(&self, rights: Rights) -> Option<FileLease> {
        (self.lookup)(rights)
    }
}
// Keep the source lease alive through the complete projected operation. This
// preserves the CSpace active-invocation publication/revocation contract.
struct FileLease {
    authority: InvocationLease<FileTreeRoot>,
    view: Option<FileTreeRoot>,
    // Last field: retained until both the actual authority and view are dropped.
    #[cfg(feature = "node-lifecycle-audit")]
    audit: Option<Arc<()>>,
}
impl FileLease {
    fn with<R>(&self, operation: impl for<'a> FnOnce(&'a FileTreeRoot) -> R) -> R {
        self.authority.with(|root| operation(self.view.as_ref().unwrap_or(root)))
    }
}

fn error(error: FileError) -> i32 {
    match error {
        FileError::EscapeRoot | FileError::RootProtected => -3,
        FileError::NotFound => -6,
        FileError::Exists => -17,
        FileError::DirectoryNotEmpty => -18,
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
    let path = match unsafe { native_path(input, length) } { Ok(path) => path, Err(e) => return e };
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

// Async requests retain only Rust-owned transaction/lease state, never C buffers.
type PendingMutation = core::pin::Pin<alloc::boxed::Box<dyn core::future::Future<Output = i32> + Send>>;
static NEXT_MUTATION: AtomicU64 = AtomicU64::new(1);
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_unlink_begin(input: *const u8, length: usize) -> i64 {
    let Some(grant) = crate::native_tls::file_grant() else { return -3; };
    let Some(lease) = grant.lease(Rights::WRITE) else { return -3; };
    let path = match unsafe { native_path(input, length) } { Ok(path) => path, Err(e) => return i64::from(e) };
    let mut transaction = match lease.with(|root| root.begin()) {
        Ok(tx) => tx, Err(e) => return i64::from(error(e)),
    };
    if let Err(e) = transaction.remove(&path, false, false) { return i64::from(error(e)); }
    crate::native_tls::with_file_table(|table| {
        if table.mutations.len() >= 64 || table.mutations.try_reserve(1).is_err() { return -14; }
        let Ok(id) = NEXT_MUTATION.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |id| id.checked_add(1).filter(|id| *id <= i64::MAX as u64)) else { return -14; };
        table.mutations.push((id, alloc::boxed::Box::pin(async move {
            let result = transaction.commit_authoritative().await;
            drop(lease); // Hold authority through publication, matching synchronous unlink.
            result.map_or_else(error, |_| 0)
        })));
        id as i64
    })
}
// Operations: 1 mkdir, 2 rmdir, 3 rename, 4 symlink, 5 hard link.
// Mode bits are a libuv concern;
// authority remains capability-based, with no per-inode Unix credentials.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_tree_change(
    operation: u32, input: *const u8, length: usize,
    destination: *const u8, destination_length: usize, asynchronous: u32,
) -> i64 {
    if !(1..=5).contains(&operation) || asynchronous > 1 { return -9; }
    let Some(grant) = crate::native_tls::file_grant() else { return -3; };
    let Some(lease) = grant.lease(Rights::WRITE) else { return -3; };
    // A symlink target is literal text relative to its link's parent, not cwd.
    let target = if operation == 4 {
        if length == 0 { return -6; }
        if length > 4096 { return -10; }
        if input.is_null() { return -2; }
        let bytes = unsafe { core::slice::from_raw_parts(input, length) };
        let Ok(text) = core::str::from_utf8(bytes) else { return -9; };
        // FileTreeRoot currently stores relative links only; do not rewrite
        // an absolute target and falsely report a different readlink value.
        if text.starts_with('/') { return -13; }
        Some(text)
    } else { None };
    let path = match unsafe { if operation == 4 { native_path(destination, destination_length) }
                             else { native_path(input, length) } } {
        Ok(p) => p, Err(e) => return i64::from(e),
    };
    let mut tx = match lease.with(|root| root.begin()) {
        Ok(tx) => tx, Err(e) => return i64::from(error(e)),
    };
    let changed = match operation {
        1 => tx.mkdir(&path, false),
        2 => {
            // remove(directory=true) also admits regular files; rmdir must not.
            match lease.with(|root| root.snapshot().stat(&path, false)) {
                Ok(meta) if meta.file_type == vibeos_file_store::FileType::Directory =>
                    tx.remove(&path, false, true),
                Ok(_) => Err(FileError::NotDirectory),
                Err(e) => Err(e),
            }
        }
        3 => {
            let destination = match unsafe { native_path(destination, destination_length) } {
                Ok(p) => p, Err(e) => return i64::from(e),
            };
            let types = lease.with(|root| {
                let snapshot = root.snapshot();
                (snapshot.stat(&path, false), snapshot.stat(&destination, false))
            });
            if let (Ok(source), Ok(target)) = types {
                let directory = vibeos_file_store::FileType::Directory;
                if source.file_type == directory && target.file_type != directory { return -11; }
                if source.file_type != directory && target.file_type == directory { return -7; }
            }
            tx.rename(&path, &destination, false)
        }
        4 => tx.symlink(target.unwrap(), &path),
        5 => {
            let destination = match unsafe { native_path(destination, destination_length) } {
                Ok(p) => p, Err(e) => return i64::from(e),
            };
            tx.hard_link(&path, &destination, false)
        }
        _ => unreachable!(),
    };
    if let Err(e) = changed { return i64::from(error(e)); }
    if asynchronous == 0 {
        let mut outcome = Err(FileError::ServiceUnavailable);
        if !crate::native_tls::park(async { outcome = tx.commit_authoritative().await; }) {
            return -5;
        }
        return i64::from(outcome.map_or_else(error, |_| 0));
    }
    crate::native_tls::with_file_table(|table| {
        if table.mutations.len() >= 64 || table.mutations.try_reserve(1).is_err() { return -14; }
        let Ok(id) = NEXT_MUTATION.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |id| id.checked_add(1).filter(|id| *id <= i64::MAX as u64)) else { return -14; };
        table.mutations.push((id, alloc::boxed::Box::pin(async move {
            let outcome = tx.commit_authoritative().await;
            drop(lease);
            outcome.map_or_else(error, |_| 0)
        })));
        id as i64
    })
}

// Copy one regular file within the granted root, publishing atomically. The
// transaction holds the writer claim while paths/identity are checked. Shared
// immutable content is detached by subsequent writes; no host copying occurs.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_copyfile(
    source: *const u8, source_length: usize, destination: *const u8,
    destination_length: usize, flags: u32,
) -> i32 {
    if flags & !7 != 0 { return -9; }
    if flags & 4 != 0 { return -13; } // No guaranteed storage reflink contract.
    let Some(grant) = crate::native_tls::file_grant() else { return -3; };
    let Some(lease) = grant.lease(Rights::READ.union(Rights::WRITE)) else { return -3; };
    let source = match unsafe { native_path(source, source_length) } { Ok(p) => p, Err(e) => return e };
    let mut destination = match unsafe { native_path(destination, destination_length) } { Ok(p) => p, Err(e) => return e };
    let mut tx = match lease.with(|root| root.begin()) { Ok(tx) => tx, Err(e) => return error(e) };
    let snapshot = lease.with(|root| root.snapshot());
    let source_info = match snapshot.stat(&source, true) { Ok(m) => m, Err(e) => return error(e) };
    if source_info.file_type != vibeos_file_store::FileType::Regular { return -7; }
    match snapshot.stat(&destination, false) {
        Ok(_) if flags & 1 != 0 => return -17,
        Ok(_) => {
            let target = match snapshot.stat(&destination, true) {
                Ok(m) => m, Err(FileError::NotFound) => return -13, Err(e) => return error(e),
            };
            if target.file_type != vibeos_file_store::FileType::Regular { return -7; }
            if target.file_id == source_info.file_id { return -9; }
            destination = match snapshot.canonical_path(&destination).and_then(|p| RelPath::parse(&p)) {
                Ok(p) => p, Err(e) => return error(e),
            };
        }
        Err(FileError::NotFound) => (),
        Err(e) => return error(e),
    }
    if let Err(e) = tx.copy_from(&snapshot, &source, &destination, false, true, false) { return error(e); }
    let mut outcome = Err(FileError::ServiceUnavailable);
    if !crate::native_tls::park(async { outcome = tx.commit_authoritative().await; }) { return -5; }
    outcome.map_or_else(error, |_| 0)
}

#[no_mangle]
pub(super) extern "C" fn vibeos_native_mutation_poll(id: u64) -> i32 {
    let waker = core::task::Waker::from(crate::native_tls::io_notification());
    let mut context = core::task::Context::from_waker(&waker);
    crate::native_tls::with_file_table(|table| {
        let Some(index) = table.mutations.iter().position(|(handle, _)| *handle == id) else { return -1; };
        match table.mutations[index].1.as_mut().poll(&mut context) {
            core::task::Poll::Pending => -15,
            core::task::Poll::Ready(result) => { drop(table.mutations.swap_remove(index)); result }
        }
    })
}

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use vibeos_file_store::FsFileReader;
struct OpenFile { grant: FileGrant, file_id: u64, mode: u32, append: bool, position: AtomicU64 }
impl OpenFile {
    fn snapshot(&self) -> Result<(vibeos_file_store::Metadata, FsFileReader), i32> {
        let lease = self.grant.lease(Rights::READ).ok_or(-3)?;
        lease.with(|root| root.regular_reader_by_id(self.file_id)).map_err(error)
    }
}

#[repr(C)]
pub(super) struct NativeFileStat { file_id: u64, size: u64, links: u64, generation: u64, kind: u64 }
impl From<&vibeos_file_store::Metadata> for NativeFileStat {
    fn from(metadata: &vibeos_file_store::Metadata) -> Self {
        use vibeos_file_store::FileType;
        Self { file_id: metadata.file_id, size: metadata.size,
            links: metadata.link_count, generation: metadata.change_generation,
            kind: match metadata.file_type { FileType::Regular => 2, FileType::Directory => 3,
                                             FileType::Symlink => 4 } }
    }
}

// Metadata and reads resolve the admitted identity in the current root generation.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_file_stat(fd: i32, output: *mut NativeFileStat) -> i32 {
    let Some(file) = lookup(fd) else { return -1; };
    let Some(_lease) = file.grant.lease(Rights::READ) else { return -3; };
    if output.is_null() { return -2; }
    let (metadata, _) = match file.snapshot() { Ok(value) => value, Err(e) => return e };
    unsafe { output.write(NativeFileStat::from(&metadata)); }
    0
}

const TOOL_MOUNT: &str = ".vibeos-tools";

// Mutation operations use the project-only selector. They must never fall
// through to a project entry shadowed by the separately admitted tool mount.
unsafe fn native_path(input: *const u8, length: usize) -> Result<RelPath, i32> {
    let path = unsafe { virtual_path(input, length) }?;
    if is_tool_path(&path) && crate::native_tls::tool_grant().is_some() { return Err(-3); }
    Ok(path)
}

unsafe fn virtual_path(input: *const u8, length: usize) -> Result<RelPath, i32> {
    if length == 0 { return Err(-6); }
    if length > 4096 { return Err(-10); }
    if input.is_null() { return Err(-2); }
    let bytes = unsafe { core::slice::from_raw_parts(input, length) };
    let text = core::str::from_utf8(bytes).map_err(|_| -9)?;
    if text.starts_with('/') { return RelPath::parse(text.trim_start_matches('/')).map_err(error); }
    let mut directory = current_directory()?;
    if !directory.is_empty() { directory.push('/'); }
    directory.push_str(text);
    RelPath::parse(&directory).map_err(error)
}

fn is_tool_path(path: &RelPath) -> bool {
    path.components().first().is_some_and(|name| name == TOOL_MOUNT)
}

struct RoutedPath { grant: FileGrant, path: RelPath, tool: bool }
impl RoutedPath {
    fn canonical(&self, path: String) -> String {
        if !self.tool { return path; }
        let mut mounted = String::from(TOOL_MOUNT);
        if !path.is_empty() { mounted.push('/'); mounted.push_str(&path); }
        mounted
    }
}

fn route_path(path: RelPath) -> Result<RoutedPath, i32> {
    if is_tool_path(&path) {
        if let Some(grant) = crate::native_tls::tool_grant() {
            let path = RelPath::parse(&path.components()[1..].join("/")).map_err(error)?;
            return Ok(RoutedPath { grant, path, tool: true });
        }
    }
    Ok(RoutedPath { grant: crate::native_tls::file_grant().ok_or(-3)?, path, tool: false })
}

unsafe fn resolve_path(input: *const u8, length: usize) -> Result<RoutedPath, i32> {
    route_path(unsafe { virtual_path(input, length) }?)
}

// The cwd is invocation-owned and canonical within the admitted root. Remember
// its identity so deleting/replacing that directory cannot silently retarget it.
fn current_directory() -> Result<String, i32> {
    let (path, identity) = crate::native_tls::with_file_table(|table| (table.cwd.clone(), table.cwd_id));
    let routed = route_path(RelPath::parse(&path).map_err(error)?)?;
    let lease = routed.grant.lease(Rights::READ).ok_or(-3)?;
    let metadata = lease.with(|root| root.snapshot().stat(&routed.path, true)).map_err(error)?;
    if metadata.file_type != vibeos_file_store::FileType::Directory { return Err(-11); }
    if identity.is_some_and(|id| id != metadata.file_id) { return Err(-6); }
    Ok(path)
}

#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_chdir(input: *const u8, length: usize) -> i32 {
    let routed = match unsafe { resolve_path(input, length) } { Ok(p) => p, Err(e) => return e };
    let grant = &routed.grant;
    let Some(lease) = grant.lease(Rights::READ) else { return -3; };
    let path = &routed.path;
    let resolved = lease.with(|root| {
        let snapshot = root.snapshot();
        let metadata = snapshot.stat(&path, true)?;
        if metadata.file_type != vibeos_file_store::FileType::Directory { return Err(FileError::NotDirectory); }
        Ok((snapshot.canonical_path(&path)?, metadata.file_id))
    });
    let (canonical, id) = match resolved { Ok(value) => value, Err(e) => return error(e) };
    crate::native_tls::with_file_table(|table| { table.cwd = routed.canonical(canonical); table.cwd_id = Some(id); });
    0
}

// A null output with zero capacity queries length excluding NUL. Other short
// buffers remain untouched; the path is never a kernel namespace path.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_getcwd(output: *mut u8, capacity: usize) -> isize {
    let path = match current_directory() { Ok(path) => path, Err(e) => return e as isize };
    let length = path.len() + 1;
    if output.is_null() { return if capacity == 0 { length as isize } else { -2 }; }
    if capacity <= length { return -10; }
    unsafe {
        output.write(b'/');
        core::ptr::copy_nonoverlapping(path.as_ptr(), output.add(1), path.len());
        output.add(length).write(0);
    }
    length as isize
}

#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_path_stat(
    input: *const u8, length: usize, follow: i32, output: *mut NativeFileStat,
) -> i32 {
    let routed = match unsafe { resolve_path(input, length) } { Ok(p) => p, Err(e) => return e };
    let grant = &routed.grant;
    let Some(lease) = grant.lease(Rights::READ) else { return -3; };
    if output.is_null() { return -2; }
    if follow != 0 && follow != 1 { return -9; }
    let path = &routed.path;
    let metadata = match lease.with(|root| root.snapshot().stat(&path, follow == 1)) {
        Ok(metadata) => metadata, Err(e) => return error(e),
    };
    unsafe { output.write(NativeFileStat::from(&metadata)); }
    0
}

// Mode uses F_OK=0, R_OK=4, W_OK=2, X_OK=1. Capability rights are
// authoritative; no fabricated Unix uid/gid permission checks are performed.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_access(input: *const u8, length: usize, mode: u32) -> i32 {
    if mode & !7 != 0 { return -9; }
    let routed = match unsafe { resolve_path(input, length) } { Ok(p) => p, Err(e) => return e };
    let grant = &routed.grant;
    let rights = if mode & 2 != 0 { Rights::READ.union(Rights::WRITE) } else { Rights::READ };
    let Some(lease) = grant.lease(rights) else { return -3; };
    let path = &routed.path;
    if let Err(e) = lease.with(|root| root.snapshot().stat(&path, true)) { return error(e); }
    // Native executable-file permission is not part of the first port.
    if mode & 1 != 0 { return -13; }
    0
}

// Enumerate one retained snapshot. Callback pointers are borrowed only for this
// call; the native consumer copies names into its own request storage.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_scandir(
    input: *const u8, length: usize,
    emit: unsafe extern "C" fn(*mut core::ffi::c_void, *const u8, usize, u32) -> i32,
    context: *mut core::ffi::c_void,
) -> i32 {
    let routed = match unsafe { resolve_path(input, length) } { Ok(p) => p, Err(e) => return e };
    let grant = &routed.grant;
    let Some(lease) = grant.lease(Rights::READ) else { return -3; };
    let path = &routed.path;
    let entries = match lease.with(|root| root.snapshot().list(&path, true)) {
        Ok(entries) => entries, Err(e) => return error(e),
    };
    for (name, metadata) in entries {
        let kind = NativeFileStat::from(&metadata).kind as u32;
        let status = unsafe { emit(context, name.as_ptr(), name.len(), kind) };
        if status != 0 { return status; }
    }
    0
}

// A canonical path is absolute only inside this invocation's granted root.
// Success returns bytes excluding the NUL; insufficient capacity writes nothing.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_realpath(
    input: *const u8, length: usize, output: *mut u8, capacity: usize,
) -> isize {
    let routed = match unsafe { resolve_path(input, length) } { Ok(p) => p, Err(e) => return e as isize };
    let grant = &routed.grant;
    let Some(lease) = grant.lease(Rights::READ) else { return -3; };
    if output.is_null() { return -2; }
    let path = &routed.path;
    let canonical = match lease.with(|root| root.snapshot().canonical_path(&path)) {
        Ok(path) => path, Err(e) => return error(e) as isize,
    };
    let canonical = routed.canonical(canonical);
    let length = canonical.len() + 1;
    if capacity <= length { return -10; }
    unsafe {
        output.write(b'/');
        core::ptr::copy_nonoverlapping(canonical.as_ptr(), output.add(1), canonical.len());
        output.add(length).write(0);
    }
    length as isize
}
// Return the stored target without following the final symlink. The returned
// text confers no authority to resolve it outside this invocation's root.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_readlink(
    input: *const u8, length: usize, output: *mut u8, capacity: usize,
) -> isize {
    let routed = match unsafe { resolve_path(input, length) } { Ok(p) => p, Err(e) => return e as isize };
    let grant = &routed.grant;
    let Some(lease) = grant.lease(Rights::READ) else { return -3; };
    if output.is_null() { return -2; }
    let path = &routed.path;
    let snapshot = lease.with(|root| root.snapshot());
    let target = match snapshot.readlink(&path) { Ok(value) => value, Err(e) => return error(e) as isize };
    if capacity <= target.len() { return -10; }
    unsafe {
        core::ptr::copy_nonoverlapping(target.as_ptr(), output, target.len());
        output.add(target.len()).write(0);
    }
    target.len() as isize
}

type ReadFuture = core::pin::Pin<alloc::boxed::Box<dyn core::future::Future<Output = Result<Vec<u8>, FileError>> + Send>>;
struct PendingRead {
    file: Arc<OpenFile>, position: u64, advance: bool, capacity: usize, future: ReadFuture,
    _lease: FileLease,
}
pub(super) struct FileTable { next: i32, entries: Vec<(i32, Arc<OpenFile>)>,
    cwd: String, cwd_id: Option<u64>,
    mutations: Vec<(u64, PendingMutation)>, reads: Vec<(u64, PendingRead)> }
impl FileTable {
    pub(super) fn new() -> Self { Self { next: 3, entries: Vec::new(), cwd: String::new(), cwd_id: None, mutations: Vec::new(), reads: Vec::new() } }
    fn insert(&mut self, file: OpenFile) -> i32 {
        if self.entries.len() == 64 || self.next == i32::MAX { return -14; }
        if self.entries.try_reserve(1).is_err() { return -5; }
        let fd = self.next;
        self.next += 1;
        self.entries.push((fd, Arc::new(file)));
        fd
    }
}
impl Drop for FileTable {
    fn drop(&mut self) {
        assert!(self.mutations.is_empty(), "native mutation must complete before invocation teardown");
        assert!(self.reads.is_empty(), "native reads must complete before invocation teardown");
        assert!(self.entries.iter().all(|(_, file)| Arc::strong_count(file) == 1),
                "native file users outlived invocation");
        // Release descriptors and their grant providers before recording the
        // audit. Pending operations have already relinquished their leases.
        self.entries.clear();
        #[cfg(feature = "node-lifecycle-audit")]
        crate::println!("NATIVE FILE RECLAIM descriptors=0 reads=0 mutations=0");
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
pub(super) extern "C" fn vibeos_native_file_sync(fd: i32) -> i32 {
    if fd < 3 {
        return match crate::native_stdio::vibeos_native_fd_kind(fd) { 1 => -9, error if error < 0 => error, _ => -1 };
    }
    let Some(file) = lookup(fd) else { return -1; };
    let Some(lease) = file.grant.lease(Rights::READ) else { return -3; };
    lease.with(|root| {
        root.regular_reader_by_id(file.file_id)?;
        root.completed_generation()
    }).map_or_else(error, |_| 0)
}
#[no_mangle]
pub(super) extern "C" fn vibeos_native_file_size(fd: i32) -> i64 {
    let Some(file) = lookup(fd) else { return -1; };
    if file.grant.lease(Rights::READ).is_none() { return -3; }
    match file.snapshot() { Ok((metadata, _)) => metadata.size as i64, Err(e) => i64::from(e) }
}
#[no_mangle]
pub(super) extern "C" fn vibeos_native_file_seek(fd: i32, offset: i64, whence: i32) -> i64 {
    let Some(file) = lookup(fd) else { return -1; };
    if file.grant.lease(Rights::READ).is_none() { return -3; }
    let size = match file.snapshot() { Ok((metadata, _)) => metadata.size, Err(e) => return i64::from(e) };
    let base = match whence { 0 => 0, 1 => file.position.load(Ordering::Relaxed), 2 => size, _ => return -9 };
    let Some(next) = base.checked_add_signed(offset).filter(|value| *value <= i64::MAX as u64) else { return -9; };
    file.position.store(next, Ordering::Relaxed);
    next as i64
}
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_open(input: *const u8, length: usize, flags: u32) -> i32 {
    // Low two bits are access mode; CREATE=4, EXCL=8, TRUNC=16, APPEND=32.
    let mode = flags & 3;
    if flags & !63 != 0 || mode == 3 { return -13; }
    if flags & 8 != 0 && flags & 4 == 0 { return -9; }
    if flags & (16 | 32) != 0 && mode == 0 { return -9; }
    let routed = match unsafe { resolve_path(input, length) } { Ok(p) => p, Err(e) => return e };
    let grant = &routed.grant;
    let rights = if mode != 0 || flags & 4 != 0 {
        Rights::READ.union(Rights::WRITE)
    } else { Rights::READ };
    let Some(lease) = grant.lease(rights) else { return -3; };
    let path = &routed.path;
    // Reserve descriptor capacity before a create/truncate can publish.
    let room = crate::native_tls::with_file_table(|table| {
        table.entries.len() < 64 && table.next < i32::MAX && table.entries.try_reserve(1).is_ok()
    });
    if !room { return -14; }
    let file_id = if flags & (4 | 16) != 0 {
        let mut tx = match lease.with(|root| root.begin()) { Ok(tx) => tx, Err(e) => return error(e) };
        if flags & 8 != 0 {
            match lease.with(|root| root.snapshot().stat(&path, false)) {
                Ok(_) => return -17,
                Err(FileError::NotFound) => (),
                Err(e) => return error(e),
            }
        }
        let mut changed = false;
        let id = match tx.regular_file_id(&path) {
            Ok(id) => id,
            Err(FileError::NotFound) if flags & 4 != 0 => {
                if let Err(e) = tx.write_chunks(&path, core::iter::empty::<&[u8]>(), false) { return error(e); }
                changed = true;
                match tx.regular_file_id(&path) { Ok(id) => id, Err(e) => return error(e) }
            }
            Err(e) => return error(e),
        };
        if changed || flags & 16 != 0 {
            let mut outcome = Err(FileError::ServiceUnavailable);
            if !crate::native_tls::park(async {
                if flags & 16 != 0 {
                    if let Err(e) = tx.truncate_file(id, 0).await { outcome = Err(e); return; }
                }
                outcome = tx.commit_authoritative().await.map(|_| ());
            }) { return -5; }
            if let Err(e) = outcome { return error(e); }
        }
        id
    } else {
        match lease.with(|root| root.resolved_regular_reader(&path)) {
            Ok((metadata, _)) => metadata.file_id, Err(e) => return error(e),
        }
    };
    let metadata = match lease.with(|root| root.regular_reader_by_id(file_id)) {
        Ok((metadata, _)) => metadata, Err(e) => return error(e),
    };
    if metadata.size > i64::MAX as u64 { return -5; }
    crate::native_tls::with_file_table(|table| table.insert(OpenFile {
        grant: routed.grant.clone(), file_id, mode, append: flags & 32 != 0, position: AtomicU64::new(0),
    }))
}
pub(super) unsafe fn read(fd: i32, output: *mut u8, length: usize) -> isize {
    unsafe { vibeos_native_file_read_at(fd, output, length, -1) }
}
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_file_read_at(fd: i32, output: *mut u8, length: usize, offset: i64) -> isize {
    if offset < -1 { return -9; }
    let Some(file) = lookup(fd) else { return -1; };
    let Some(_lease) = file.grant.lease(Rights::READ) else { return -3; };
    if output.is_null() && length != 0 { return -2; }
    let position = if offset == -1 { file.position.load(Ordering::Relaxed) } else { offset as u64 };
    if file.mode == 1 { return -1; }
    let (metadata, reader) = match file.snapshot() { Ok(value) => value, Err(e) => return e as isize };
    if position >= metadata.size || length == 0 { return 0; }
    let count = length.min(1024).min((metadata.size - position) as usize);
    let mut bytes = [0u8; 1024];
    let mut result = Err(FileError::ServiceUnavailable);
    if !crate::native_tls::park(async {
        // Even memory-backed reads must bound a synchronous native turn: a
        // large readFileSync otherwise resumes thousands of ready reads in
        // one scheduler poll and starves SSH keepalives/cancellation.
        crate::exec::yield_now().await;
        result = reader.read_at(position, count).await.and_then(|chunk| {
            if chunk.is_empty() { return Err(FileError::ServiceUnavailable); }
            bytes[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        });
    }) { return -5; }
    let size = match result { Ok(size) => size, Err(e) => return error(e) as isize };
    // Revalidate before exposing data obtained during suspended backend IO.
    let Some(_delivery) = file.grant.lease(Rights::READ) else { return -3; };
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), output, size); }
    if offset == -1 { file.position.store(position + size as u64, Ordering::Relaxed); }
    size as isize
}

pub(super) unsafe fn write(fd: i32, input: *const u8, length: usize) -> isize {
    unsafe { vibeos_native_file_write_at(fd, input, length, -1) }
}
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_file_write_at(fd: i32, input: *const u8, length: usize, offset: i64) -> isize {
    if offset < -1 { return -9; }
    let Some(file) = lookup(fd) else { return -1; };
    let Some(_lease) = file.grant.lease(Rights::WRITE) else { return -3; };
    if file.mode == 0 { return -1; }
    if input.is_null() && length != 0 { return -2; }
    if length == 0 { return 0; }
    let count = length.min(1024);
    let mut bytes = [0u8; 1024];
    unsafe { core::ptr::copy_nonoverlapping(input, bytes.as_mut_ptr(), count); }
    let mut tx = match _lease.with(|root| root.begin()) { Ok(tx) => tx, Err(e) => return error(e) as isize };
    // Select append offset while holding the root's writer claim.
    let position = if file.append {
        match file.snapshot() { Ok((metadata, _)) => metadata.size, Err(e) => return e as isize }
    } else if offset == -1 { file.position.load(Ordering::Relaxed) } else { offset as u64 };
    if position.checked_add(count as u64).is_none_or(|end| end > i64::MAX as u64) { return -9; }
    let mut outcome = Err(FileError::ServiceUnavailable);
    if !crate::native_tls::park(async {
        outcome = match tx.write_file_range(file.file_id, position, &bytes[..count]).await {
            Ok(()) => tx.commit_authoritative().await.map(|_| ()), Err(e) => Err(e),
        };
    }) { return -5; }
    if let Err(e) = outcome { return error(e) as isize; }
    if offset == -1 { file.position.store(position + count as u64, Ordering::Relaxed); }
    count as isize
}

#[no_mangle]
pub(super) extern "C" fn vibeos_native_file_truncate(fd: i32, length: i64) -> i32 {
    let Some(file) = lookup(fd) else { return -1; };
    let Some(lease) = file.grant.lease(Rights::WRITE) else { return -3; };
    if file.mode == 0 { return -1; }
    if length < 0 { return -9; }
    let mut tx = match lease.with(|root| root.begin()) { Ok(tx) => tx, Err(e) => return error(e) };
    let mut outcome = Err(FileError::ServiceUnavailable);
    if !crate::native_tls::park(async {
        outcome = match tx.truncate_file(file.file_id, length as u64).await {
            Ok(()) => tx.commit_authoritative().await.map(|_| ()), Err(e) => Err(e),
        };
    }) { return -5; }
    outcome.map_or_else(error, |_| 0)
}

#[no_mangle]
pub(super) extern "C" fn vibeos_native_file_read_begin(fd: i32, length: usize) -> i64 {
    vibeos_native_file_read_begin_at(fd, length, -1)
}
#[no_mangle]
pub(super) extern "C" fn vibeos_native_file_read_begin_at(fd: i32, length: usize, offset: i64) -> i64 {
    if offset < -1 { return -9; }
    let Some(file) = lookup(fd) else { return -1; };
    let Some(lease) = file.grant.lease(Rights::READ) else { return -3; };
    if file.mode == 1 { return -1; }
    let (metadata, reader) = match file.snapshot() { Ok(value) => value, Err(e) => return i64::from(e) };
    let position = if offset == -1 { file.position.load(Ordering::Relaxed) } else { offset as u64 };
    let count = length.min(1024).min(metadata.size.saturating_sub(position) as usize);
    let future: ReadFuture = alloc::boxed::Box::pin(async move {
        if count == 0 { return Ok(Vec::new()); }
        crate::exec::yield_now().await;
        let bytes = reader.read_at(position, count).await?;
        if bytes.is_empty() { return Err(FileError::ServiceUnavailable); }
        Ok(bytes)
    });
    crate::native_tls::with_file_table(|table| {
        if table.reads.len() >= 64 || table.reads.try_reserve(1).is_err() { return -14; }
        let Ok(id) = NEXT_MUTATION.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |id| id.checked_add(1).filter(|id| *id <= i64::MAX as u64)) else { return -14; };
        table.reads.push((id, PendingRead { file, position, advance: offset == -1, capacity: count, future, _lease: lease }));
        id as i64
    })
}

// Output is borrowed only for this poll. Invalid output can be retried; a ready
// result or denied capability consumes the request and releases its snapshot.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_file_read_poll(
    id: u64, output: *mut u8, capacity: usize,
) -> isize {
    let waker = core::task::Waker::from(crate::native_tls::io_notification());
    let mut context = core::task::Context::from_waker(&waker);
    crate::native_tls::with_file_table(|table| {
        let Some(index) = table.reads.iter().position(|(handle, _)| *handle == id) else { return -1; };
        let read = &mut table.reads[index].1;
        let Some(_delivery) = read.file.grant.lease(Rights::READ) else {
            table.reads.swap_remove(index);
            return -3;
        };
        if capacity < read.capacity { return -9; }
        if output.is_null() && read.capacity != 0 { return -2; }
        match read.future.as_mut().poll(&mut context) {
            core::task::Poll::Pending => -15,
            core::task::Poll::Ready(result) => {
                let (_, read) = table.reads.swap_remove(index);
                match result {
                    Err(e) => error(e) as isize,
                    Ok(bytes) => {
                        if !bytes.is_empty() {
                            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()); }
                        }
                        if read.advance { read.file.position.store(read.position + bytes.len() as u64, Ordering::Relaxed); }
                        bytes.len() as isize
                    }
                }
            }
        }
    })
}

fn retain_mutation(future: PendingMutation) -> i64 {
    crate::native_tls::with_file_table(|table| {
        if table.mutations.len() >= 64 || table.mutations.try_reserve(1).is_err() { return -14; }
        let Ok(id) = NEXT_MUTATION.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |id| id.checked_add(1).filter(|id| *id <= i64::MAX as u64)) else { return -14; };
        table.mutations.push((id, future));
        id as i64
    })
}

// Copies input before returning; no C pointer is retained by the future.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_file_write_begin(
    fd: i32, input: *const u8, length: usize,
) -> i64 {
    unsafe { vibeos_native_file_write_begin_at(fd, input, length, -1) }
}
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_file_write_begin_at(
    fd: i32, input: *const u8, length: usize, offset: i64,
) -> i64 {
    if offset < -1 { return -9; }
    let Some(file) = lookup(fd) else { return -1; };
    let Some(lease) = file.grant.lease(Rights::WRITE) else { return -3; };
    if file.mode == 0 { return -1; }
    if input.is_null() && length != 0 { return -2; }
    let count = length.min(1024);
    if count == 0 { return retain_mutation(alloc::boxed::Box::pin(async { 0 })); }
    let mut bytes = [0u8; 1024];
    if count != 0 { unsafe { core::ptr::copy_nonoverlapping(input, bytes.as_mut_ptr(), count); } }
    let mut tx = match lease.with(|root| root.begin()) { Ok(tx) => tx, Err(e) => return i64::from(error(e)) };
    let position = if file.append {
        match file.snapshot() { Ok((metadata, _)) => metadata.size, Err(e) => return i64::from(e) }
    } else if offset == -1 { file.position.load(Ordering::Relaxed) } else { offset as u64 };
    if position.checked_add(count as u64).is_none_or(|end| end > i64::MAX as u64) { return -9; }
    retain_mutation(alloc::boxed::Box::pin(async move {
        let outcome = match tx.write_file_range(file.file_id, position, &bytes[..count]).await {
            Ok(()) => tx.commit_authoritative().await.map(|_| ()), Err(e) => Err(e),
        };
        drop(lease);
        match outcome {
            Ok(()) => { if offset == -1 { file.position.store(position + count as u64, Ordering::Relaxed); } count as i32 }
            Err(e) => error(e),
        }
    }))
}

#[no_mangle]
pub(super) extern "C" fn vibeos_native_file_truncate_begin(fd: i32, length: i64) -> i64 {
    let Some(file) = lookup(fd) else { return -1; };
    let Some(lease) = file.grant.lease(Rights::WRITE) else { return -3; };
    if file.mode == 0 { return -1; }
    if length < 0 { return -9; }
    let mut tx = match lease.with(|root| root.begin()) { Ok(tx) => tx, Err(e) => return i64::from(error(e)) };
    retain_mutation(alloc::boxed::Box::pin(async move {
        let outcome = match tx.truncate_file(file.file_id, length as u64).await {
            Ok(()) => tx.commit_authoritative().await.map(|_| ()), Err(e) => Err(e),
        };
        drop(lease);
        outcome.map_or_else(error, |_| 0)
    }))
}

#[cfg(feature = "native-cxx-probe")]
pub(super) fn revoke_probe_grant() {
    let grant = crate::native_tls::file_grant().unwrap();
    let (space, root) = grant.probe_authority.as_ref().expect("fixture authority only");
    space.0.lock().revoke(*root).unwrap();
}

#[cfg(feature = "node-runtime")]
pub(super) async fn directory_grant_probe() {
    let root = Arc::new(FileTreeRoot::new_empty(0x6e6f646561757468).unwrap());
    let project = RelPath::parse("project").unwrap();
    let replacement = RelPath::parse("replacement").unwrap();
    let mut tx = root.begin().unwrap();
    tx.mkdir(&project, false).unwrap();
    tx.mkdir(&replacement, false).unwrap();
    tx.write_chunks(&RelPath::parse("project/value").unwrap(), [b"original".as_slice()], false).unwrap();
    tx.symlink("project", &RelPath::parse("alias").unwrap()).unwrap();
    tx.commit_authoritative().await.unwrap();
    let space = crate::world::Space::new("native-directory-authority");
    let cap = space.0.lock().mint(root.clone(), Rights::READ.union(Rights::WRITE).union(Rights::REVOKE));
    let base = FileGrant::new(space.clone(), cap).unwrap();
    let projected = base.clone().directory(project.clone()).unwrap();
    let alias = base.clone().directory(RelPath::parse("alias").unwrap()).unwrap();
    assert!(projected.lease(Rights::READ).is_some());
    let mut tx = root.begin().unwrap();
    tx.remove(&RelPath::parse("alias").unwrap(), false, false).unwrap();
    tx.symlink("replacement", &RelPath::parse("alias").unwrap()).unwrap();
    tx.rename(&project, &RelPath::parse("old-project").unwrap(), false).unwrap();
    tx.mkdir(&project, false).unwrap();
    tx.commit_authoritative().await.unwrap();
    assert!(projected.lease(Rights::READ).is_none());
    assert!(alias.lease(Rights::READ).is_none());
    let fresh = base.clone().directory(project.clone()).unwrap();
    let readonly = space.0.lock().mint(root, Rights::READ);
    let readonly = FileGrant::new(space.clone(), readonly).unwrap().directory(project).unwrap();
    assert!(readonly.lease(Rights::WRITE).is_none());
    let admitted = fresh.lease(Rights::READ).unwrap();
    space.0.lock().revoke(cap).unwrap();
    assert!(base.lease(Rights::READ).is_none());
    assert!(fresh.lease(Rights::READ).is_none());
    assert!(admitted.with(|root| root.snapshot().stat(&RelPath::root(), true)).is_ok());
    drop(admitted);
    crate::println!("NATIVE PROJECT AUTH revoked=1 replaced=1 retargeted=1 readonly=1 PASS");
}
