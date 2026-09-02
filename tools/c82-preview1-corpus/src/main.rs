#![forbid(unsafe_code)]

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::{
    env,
    ffi::OsString,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};
use vibeos_c81_preview1_componentizer::ADAPTER_BYTES;
use vibeos_c82_preview1_corpus::{
    componentize_corpus_core, hex_sha256, sha256, OutputDirection, OutputKind,
    MAX_COMPILER_CORE_BYTES,
};

struct Arguments {
    core: PathBuf,
    adapter: PathBuf,
    sanitized_core_output: PathBuf,
    component_output: PathBuf,
}

#[derive(Clone, Copy)]
enum InputLength {
    AtMost(usize),
    Exact(usize),
}

impl InputLength {
    fn allocation_ceiling(self) -> usize {
        match self {
            Self::AtMost(ceiling) | Self::Exact(ceiling) => ceiling,
        }
    }

    fn accepts_metadata(self, length: u64) -> bool {
        match self {
            Self::AtMost(ceiling) => length <= ceiling as u64,
            Self::Exact(expected) => length == expected as u64,
        }
    }

    fn accepts_read(self, length: usize) -> bool {
        match self {
            Self::AtMost(ceiling) => length <= ceiling,
            Self::Exact(expected) => length == expected,
        }
    }

    fn description(self) -> String {
        match self {
            Self::AtMost(ceiling) => format!("at most {ceiling} bytes"),
            Self::Exact(expected) => format!("exactly {expected} bytes"),
        }
    }
}

struct BoundedInput {
    bytes: Vec<u8>,
    canonical_path: PathBuf,
    metadata: Metadata,
}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_left: &Metadata, _right: &Metadata) -> bool {
    false
}

fn unchanged_file(left: &Metadata, right: &Metadata) -> bool {
    if !same_file(left, right) || left.len() != right.len() {
        return false;
    }
    let modified_matches = match (left.modified(), right.modified()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    };
    modified_matches && unix_change_time_matches(left, right)
}

#[cfg(unix)]
fn unix_change_time_matches(left: &Metadata, right: &Metadata) -> bool {
    left.ctime() == right.ctime() && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn unix_change_time_matches(_left: &Metadata, _right: &Metadata) -> bool {
    false
}

fn read_bounded_input(
    label: &str,
    path: &Path,
    expected: InputLength,
) -> Result<BoundedInput, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {path:?}: {error}"))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(format!("{label} must name one regular non-symlink file"));
    }
    if !expected.accepts_metadata(before.len()) {
        return Err(format!(
            "{label} length must be {} before reading",
            expected.description()
        ));
    }

    let canonical_before = fs::canonicalize(path)
        .map_err(|error| format!("failed to resolve {label} {path:?}: {error}"))?;
    let mut file =
        File::open(path).map_err(|error| format!("failed to open {label} {path:?}: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("failed to inspect opened {label} {path:?}: {error}"))?;
    let after_open = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to re-inspect {label} {path:?}: {error}"))?;
    let canonical_after = fs::canonicalize(path)
        .map_err(|error| format!("failed to re-resolve {label} {path:?}: {error}"))?;
    if after_open.file_type().is_symlink()
        || !opened.is_file()
        || !same_file(&before, &opened)
        || !same_file(&opened, &after_open)
        || canonical_before != canonical_after
    {
        return Err(format!("{label} changed identity while it was opened"));
    }

    if !expected.accepts_metadata(opened.len()) {
        return Err(format!(
            "{label} length must remain {} before allocation",
            expected.description()
        ));
    }
    let ceiling = expected.allocation_ceiling();
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(ceiling)
        .map_err(|_| format!("failed to reserve bounded {label} input buffer"))?;
    bytes.resize(ceiling, 0);
    let mut received = 0_usize;
    while received < ceiling {
        let count = file
            .read(&mut bytes[received..])
            .map_err(|error| format!("failed to read {label} {path:?}: {error}"))?;
        if count == 0 {
            break;
        }
        received = received
            .checked_add(count)
            .ok_or_else(|| format!("{label} read length overflow"))?;
    }
    bytes.truncate(received);
    let mut overflow_probe = [0_u8; 1];
    let has_extra = file
        .read(&mut overflow_probe)
        .map_err(|error| format!("failed to probe bounded {label} {path:?}: {error}"))?
        != 0;
    let after_read = file
        .metadata()
        .map_err(|error| format!("failed to re-inspect opened {label} {path:?}: {error}"))?;
    if has_extra || !expected.accepts_read(bytes.len()) {
        return Err(format!(
            "{label} length must remain {} while reading",
            expected.description()
        ));
    }
    if !unchanged_file(&opened, &after_read) {
        return Err(format!("{label} changed while it was read"));
    }

    Ok(BoundedInput {
        bytes,
        canonical_path: canonical_before,
        metadata: opened,
    })
}

#[derive(Clone)]
struct OutputTarget {
    path: PathBuf,
    canonical_parent: PathBuf,
    canonical_path: PathBuf,
    parent_metadata: Metadata,
    parent_namespace: Vec<DirectoryBoundary>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileSnapshot {
    dev: u64,
    ino: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
impl FileSnapshot {
    fn capture(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    fn same_inode(self, metadata: &Metadata) -> bool {
        self.dev == metadata.dev() && self.ino == metadata.ino()
    }

    fn matches(self, metadata: &Metadata) -> bool {
        self == Self::capture(metadata)
    }
}

#[derive(Clone)]
struct DirectoryBoundary {
    path: PathBuf,
    snapshot: FileSnapshot,
    owner: u32,
    mode: u32,
}

#[cfg(unix)]
fn capture_output_namespace(parent: &Path) -> Result<Vec<DirectoryBoundary>, String> {
    let mut boundaries = Vec::new();
    let mut path = parent.to_path_buf();
    loop {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("failed to inspect output namespace {path:?}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "output namespace component {path:?} is not one resolved directory"
            ));
        }
        boundaries.push(DirectoryBoundary {
            path: path.clone(),
            snapshot: FileSnapshot::capture(&metadata),
            owner: metadata.uid(),
            mode: metadata.mode(),
        });
        match path.parent() {
            Some(ancestor) if ancestor != path => path = ancestor.to_path_buf(),
            _ => break,
        }
    }
    validate_output_namespace_policy(&boundaries)?;
    Ok(boundaries)
}

#[cfg(not(unix))]
fn capture_output_namespace(_parent: &Path) -> Result<Vec<DirectoryBoundary>, String> {
    Err(String::from(
        "C8.2 output publication requires Unix namespace ownership semantics",
    ))
}

fn validate_output_namespace_policy(boundaries: &[DirectoryBoundary]) -> Result<(), String> {
    let Some(output_parent) = boundaries.first() else {
        return Err(String::from("output namespace must include a parent"));
    };
    let output_owner = output_parent.owner;
    for (index, boundary) in boundaries.iter().enumerate() {
        if boundary.owner != 0 && boundary.owner != output_owner {
            return Err(format!(
                "output namespace component {:?} has an untrusted owner",
                boundary.path
            ));
        }
        if boundary.mode & 0o022 == 0 {
            continue;
        }
        if index == 0 {
            return Err(String::from(
                "output parent must not be writable by another Unix group or user",
            ));
        }
        let child_owner = boundaries[index - 1].owner;
        if boundary.mode & 0o1000 == 0 || (child_owner != 0 && child_owner != output_owner) {
            return Err(format!(
                "output namespace has an unsafe writable ancestor {:?}",
                boundary.path
            ));
        }
    }
    Ok(())
}

fn verify_output_namespace(boundaries: &[DirectoryBoundary]) -> Result<(), String> {
    for boundary in boundaries {
        let current = fs::symlink_metadata(&boundary.path).map_err(|error| {
            format!(
                "failed to re-inspect output namespace {:?}: {error}",
                boundary.path
            )
        })?;
        if current.file_type().is_symlink() || !current.is_dir() {
            return Err(String::from("output namespace changed identity"));
        }
        #[cfg(unix)]
        if !boundary.snapshot.same_inode(&current)
            || boundary.owner != current.uid()
            || boundary.mode != current.mode()
        {
            return Err(String::from(
                "output namespace changed identity or permissions",
            ));
        }
        #[cfg(not(unix))]
        return Err(String::from(
            "C8.2 output publication requires Unix namespace ownership semantics",
        ));
    }
    validate_output_namespace_policy(boundaries)
}

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileSnapshot;

#[cfg(not(unix))]
impl FileSnapshot {
    fn capture(_metadata: &Metadata) -> Self {
        Self
    }

    fn same_inode(self, _metadata: &Metadata) -> bool {
        false
    }

    fn matches(self, _metadata: &Metadata) -> bool {
        false
    }
}

fn explicit_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn prepare_output_target(label: &str, path: &Path) -> Result<OutputTarget, String> {
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| format!("{label} must include a file name"))?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(format!(
                "{label} already exists; C8.2 outputs never overwrite files or aliases"
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("failed to inspect {label} {path:?}: {error}")),
    }
    let canonical_parent = fs::canonicalize(explicit_parent(path))
        .map_err(|error| format!("failed to resolve {label} parent for {path:?}: {error}"))?;
    let parent_metadata = fs::symlink_metadata(&canonical_parent).map_err(|error| {
        format!("failed to inspect {label} parent {canonical_parent:?}: {error}")
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(format!("{label} parent is not one resolved directory"));
    }
    if !exclusive_output_parent(&parent_metadata) {
        return Err(format!(
            "{label} parent must not be writable by another Unix group or user"
        ));
    }
    let parent_namespace = capture_output_namespace(&canonical_parent)
        .map_err(|error| format!("invalid {label} namespace: {error}"))?;
    let canonical_path = canonical_parent.join(file_name);
    Ok(OutputTarget {
        path: canonical_path.clone(),
        canonical_path,
        canonical_parent,
        parent_metadata,
        parent_namespace,
    })
}

#[cfg(unix)]
fn exclusive_output_parent(metadata: &Metadata) -> bool {
    metadata.mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn exclusive_output_parent(_metadata: &Metadata) -> bool {
    false
}

fn verify_parent(target: &OutputTarget) -> Result<(), String> {
    verify_output_namespace(&target.parent_namespace)?;
    let current = fs::symlink_metadata(&target.canonical_parent).map_err(|error| {
        format!(
            "failed to re-inspect output parent {:?}: {error}",
            target.canonical_parent
        )
    })?;
    if current.file_type().is_symlink()
        || !current.is_dir()
        || !same_file(&target.parent_metadata, &current)
        || !exclusive_output_parent(&current)
    {
        return Err(String::from("output parent changed identity"));
    }
    Ok(())
}

struct OutputTransaction {
    path: PathBuf,
    snapshot: FileSnapshot,
    parent: PathBuf,
    parent_namespace: Vec<DirectoryBoundary>,
    active: bool,
}

impl OutputTransaction {
    fn create(sanitized: &OutputTarget, component: &OutputTarget) -> Result<Self, String> {
        if sanitized.canonical_parent != component.canonical_parent
            || !same_file(&sanitized.parent_metadata, &component.parent_metadata)
        {
            return Err(String::from(
                "both C8.2 outputs must use the same resolved output directory",
            ));
        }
        verify_parent(sanitized)?;
        for attempt in 0_u32..64 {
            let path = sanitized
                .canonical_parent
                .join(format!(".c82-transaction-{}-{attempt}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => {
                    let metadata = match fs::symlink_metadata(&path) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            let cleanup = fs::remove_dir(&path).map_err(|cleanup| {
                                format!(
                                    "failed to remove uninspected transaction directory: {cleanup}"
                                )
                            });
                            let parent_sync = sync_directory(&sanitized.canonical_parent);
                            return Err(append_cleanup(
                                format!(
                                    "failed to inspect private transaction directory after its atomic creation: {error}"
                                ),
                                [
                                    ("transaction-directory", cleanup),
                                    ("parent-sync", parent_sync),
                                ],
                            ));
                        }
                    };
                    #[cfg(unix)]
                    let private_mode = metadata.mode() & 0o777 == 0o700;
                    #[cfg(unix)]
                    let private_owner = metadata.uid() == sanitized.parent_metadata.uid();
                    #[cfg(not(unix))]
                    let private_mode = false;
                    #[cfg(not(unix))]
                    let private_owner = false;
                    if metadata.file_type().is_symlink()
                        || !metadata.is_dir()
                        || !private_mode
                        || !private_owner
                    {
                        let cleanup = if metadata.is_dir() && !metadata.file_type().is_symlink() {
                            fs::remove_dir(&path).map_err(|error| {
                                format!("failed to remove invalid transaction directory: {error}")
                            })
                        } else {
                            Err(String::from(
                                "refused to remove changed non-directory transaction path",
                            ))
                        };
                        let parent_sync = sync_directory(&sanitized.canonical_parent);
                        return Err(append_cleanup(
                            String::from(
                                "private transaction path is not one real mode-0700 directory owned by the output principal",
                            ),
                            [
                                ("transaction-directory", cleanup),
                                ("parent-sync", parent_sync),
                            ],
                        ));
                    }
                    let mut transaction = Self {
                        path,
                        snapshot: FileSnapshot::capture(&metadata),
                        parent: sanitized.canonical_parent.clone(),
                        parent_namespace: sanitized.parent_namespace.clone(),
                        active: true,
                    };
                    if let Err(error) = verify_parent(sanitized) {
                        let cleanup = transaction.cleanup();
                        let parent_sync = sync_directory(&transaction.parent);
                        return Err(append_cleanup(
                            error,
                            [
                                ("transaction-directory", cleanup),
                                ("parent-sync", parent_sync),
                            ],
                        ));
                    }
                    return Ok(transaction);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "failed to create private output transaction directory: {error}"
                    ));
                }
            }
        }
        Err(String::from(
            "failed to reserve a private output transaction directory",
        ))
    }

    fn verify(&self) -> Result<(), String> {
        verify_output_namespace(&self.parent_namespace)?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("failed to inspect transaction directory: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !self.snapshot.same_inode(&metadata)
        {
            return Err(String::from("transaction directory changed identity"));
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        self.verify()?;
        fs::remove_dir(&self.path)
            .map_err(|error| format!("failed to remove private transaction directory: {error}"))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for OutputTransaction {
    fn drop(&mut self) {
        if self.active && self.verify().is_ok() && fs::remove_dir(&self.path).is_ok() {
            self.active = false;
            let _ = sync_directory(&self.parent);
        }
    }
}

struct StagedOutput {
    path: PathBuf,
    file: File,
    initial_snapshot: FileSnapshot,
    current_snapshot: FileSnapshot,
    expected_len: usize,
    expected_sha256: [u8; 32],
    active: bool,
}

impl StagedOutput {
    fn create(
        transaction: &OutputTransaction,
        file_name: &str,
        label: &str,
        bytes: &[u8],
    ) -> Result<Self, String> {
        transaction.verify()?;
        let path = transaction.path.join(file_name);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&path)
            .map_err(|error| format!("failed to create staged {label}: {error}"))?;
        let created = file
            .metadata()
            .map_err(|error| format!("failed to inspect new staged {label}: {error}"))?;
        let created_snapshot = FileSnapshot::capture(&created);
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let current = fs::symlink_metadata(&path);
            let cleanup = match current {
                Ok(metadata)
                    if !metadata.file_type().is_symlink()
                        && metadata.is_file()
                        && created_snapshot.same_inode(&metadata) =>
                {
                    fs::remove_file(&path)
                        .map_err(|cleanup| format!("failed to remove partial stage: {cleanup}"))
                }
                Ok(_) => Err(String::from("refused to remove changed partial stage path")),
                Err(cleanup) => Err(format!("failed to inspect partial stage: {cleanup}")),
            };
            let directory_sync = sync_directory(&transaction.path);
            return Err(append_cleanup(
                format!("failed to write staged {label}: {error}"),
                [
                    ("partial-stage", cleanup),
                    ("transaction-sync", directory_sync),
                ],
            ));
        }
        let current = file
            .metadata()
            .map_err(|error| format!("failed to inspect written staged {label}: {error}"))?;
        let initial_snapshot = FileSnapshot::capture(&current);
        let current_snapshot = initial_snapshot;
        let mut staged = Self {
            path,
            file,
            initial_snapshot,
            current_snapshot,
            expected_len: bytes.len(),
            expected_sha256: sha256(bytes),
            active: true,
        };
        staged.verify(transaction, label)?;
        Ok(staged)
    }

    fn verify(&mut self, transaction: &OutputTransaction, label: &str) -> Result<(), String> {
        transaction.verify()?;
        let descriptor = self
            .file
            .metadata()
            .map_err(|error| format!("failed to inspect staged {label} descriptor: {error}"))?;
        if !self.current_snapshot.matches(&descriptor)
            || !self.initial_snapshot.same_inode(&descriptor)
            || descriptor.len() != self.expected_len as u64
        {
            return Err(format!("staged {label} descriptor changed"));
        }
        let path_metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("failed to inspect staged {label} path: {error}"))?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || !self.current_snapshot.matches(&path_metadata)
        {
            return Err(format!("staged {label} path changed identity"));
        }
        if hash_exact_file(&self.file, self.expected_len, label)? != self.expected_sha256 {
            return Err(format!("staged {label} content changed"));
        }
        Ok(())
    }

    fn refresh_after_link(&mut self, label: &str) -> Result<(), String> {
        let metadata = self
            .file
            .metadata()
            .map_err(|error| format!("failed to refresh staged {label}: {error}"))?;
        if !self.initial_snapshot.same_inode(&metadata)
            || metadata.len() != self.expected_len as u64
            || hash_exact_file(&self.file, self.expected_len, label)? != self.expected_sha256
        {
            return Err(format!("staged {label} changed while publishing"));
        }
        self.current_snapshot = FileSnapshot::capture(&metadata);
        Ok(())
    }

    fn publish_no_replace<F>(
        &mut self,
        transaction: &OutputTransaction,
        target: &OutputTarget,
        label: &str,
        after_link: &mut F,
    ) -> Result<PublishedLink, String>
    where
        F: FnMut(&str, &Path) -> Result<(), String>,
    {
        self.verify(transaction, label)?;
        verify_parent(target)?;
        fs::hard_link(&self.path, &target.path)
            .map_err(|error| format!("failed to atomically publish {label}: {error}"))?;
        let mut published = PublishedLink::new(
            target,
            transaction,
            self.initial_snapshot,
            self.expected_len,
            self.expected_sha256,
            label,
        );
        if let Err(error) = self.refresh_after_link(label) {
            return Err(published.rollback_with_context(error));
        }
        published.expected = self.current_snapshot;
        if let Err(error) = after_link(label, &target.path) {
            return Err(published.rollback_with_context(error));
        }
        if let Err(error) = published.verify() {
            return Err(published.rollback_with_context(error));
        }
        self.verify(transaction, label)
            .map_err(|error| published.rollback_with_context(error))?;
        Ok(published)
    }

    fn cleanup(&mut self, transaction: &OutputTransaction, label: &str) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        let descriptor = self
            .file
            .metadata()
            .map_err(|error| format!("failed to inspect staged {label} for cleanup: {error}"))?;
        self.current_snapshot = FileSnapshot::capture(&descriptor);
        self.verify(transaction, label)?;
        fs::remove_file(&self.path)
            .map_err(|error| format!("failed to remove staged {label}: {error}"))?;
        self.active = false;
        Ok(())
    }
}

fn hash_exact_file(file: &File, expected_len: usize, label: &str) -> Result<[u8; 32], String> {
    let mut reader = file
        .try_clone()
        .map_err(|error| format!("failed to clone {label} descriptor: {error}"))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("failed to seek {label}: {error}"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_len)
        .map_err(|_| format!("failed to reserve {label} verification buffer"))?;
    bytes.resize(expected_len, 0);
    reader
        .read_exact(&mut bytes)
        .map_err(|error| format!("failed to read exact staged {label}: {error}"))?;
    let mut probe = [0_u8; 1];
    if reader
        .read(&mut probe)
        .map_err(|error| format!("failed to probe staged {label}: {error}"))?
        != 0
    {
        return Err(format!("staged {label} grew during verification"));
    }
    Ok(sha256(&bytes))
}

struct PublishedLink {
    target: PathBuf,
    parent: PathBuf,
    parent_snapshot: FileSnapshot,
    parent_namespace: Vec<DirectoryBoundary>,
    expected: FileSnapshot,
    expected_len: usize,
    expected_sha256: [u8; 32],
    transaction_path: PathBuf,
    transaction_snapshot: FileSnapshot,
    label: String,
    active: bool,
}

impl PublishedLink {
    fn new(
        target: &OutputTarget,
        transaction: &OutputTransaction,
        expected: FileSnapshot,
        expected_len: usize,
        expected_sha256: [u8; 32],
        label: &str,
    ) -> Self {
        Self {
            target: target.path.clone(),
            parent: target.canonical_parent.clone(),
            parent_snapshot: FileSnapshot::capture(&target.parent_metadata),
            parent_namespace: target.parent_namespace.clone(),
            expected,
            expected_len,
            expected_sha256,
            transaction_path: transaction.path.clone(),
            transaction_snapshot: transaction.snapshot,
            label: label.into(),
            active: true,
        }
    }

    fn stable_owned_snapshot(&self) -> Result<FileSnapshot, String> {
        self.verify_parent()?;
        let before = fs::symlink_metadata(&self.target)
            .map_err(|error| format!("failed to inspect published {}: {error}", self.label))?;
        if before.file_type().is_symlink()
            || !before.is_file()
            || !self.expected.same_inode(&before)
            || before.len() != self.expected_len as u64
        {
            return Err(format!("published {} changed identity", self.label));
        }
        let before_snapshot = FileSnapshot::capture(&before);
        let file = File::open(&self.target)
            .map_err(|error| format!("failed to open published {}: {error}", self.label))?;
        let opened = file
            .metadata()
            .map_err(|error| format!("failed to inspect published {} fd: {error}", self.label))?;
        let opened_snapshot = FileSnapshot::capture(&opened);
        let observed_sha256 = hash_exact_file(&file, self.expected_len, &self.label)?;
        let after = fs::symlink_metadata(&self.target)
            .map_err(|error| format!("failed to re-inspect published {}: {error}", self.label))?;
        let after_snapshot = FileSnapshot::capture(&after);
        if after.file_type().is_symlink()
            || !after.is_file()
            || !self.expected.same_inode(&opened)
            || !self.expected.same_inode(&after)
            || opened.len() != self.expected_len as u64
            || after.len() != self.expected_len as u64
            || before_snapshot != opened_snapshot
            || opened_snapshot != after_snapshot
            || observed_sha256 != self.expected_sha256
        {
            return Err(format!(
                "published {} failed exact verification",
                self.label
            ));
        }
        Ok(after_snapshot)
    }

    fn verify(&self) -> Result<(), String> {
        if self.stable_owned_snapshot()? != self.expected {
            return Err(format!("published {} changed identity", self.label));
        }
        Ok(())
    }

    fn refresh_expected(&mut self) -> Result<(), String> {
        self.expected = self.stable_owned_snapshot()?;
        Ok(())
    }

    fn rollback_with_context(&mut self, error: String) -> String {
        match self.rollback() {
            Ok(()) => error,
            Err(rollback) => format!("{error}; published-link rollback failed: {rollback}"),
        }
    }

    fn rollback(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        // The final name is never moved until it has been proven to retain
        // the inode and exact bytes created by this transaction. In a shared
        // namespace a foreign replacement is preserved in place.
        let _ = self.stable_owned_snapshot()?;
        let transaction = fs::symlink_metadata(&self.transaction_path)
            .map_err(|error| format!("failed to inspect rollback transaction: {error}"))?;
        if transaction.file_type().is_symlink()
            || !transaction.is_dir()
            || !self.transaction_snapshot.same_inode(&transaction)
        {
            return Err(String::from(
                "rollback transaction directory changed identity",
            ));
        }
        let quarantine = self.transaction_path.join(format!(
            "rollback-{}",
            self.label.trim_start_matches("--").replace('/', "_")
        ));
        if fs::symlink_metadata(&quarantine).is_ok() {
            return Err(String::from("rollback quarantine path already exists"));
        }
        fs::rename(&self.target, &quarantine)
            .map_err(|error| format!("failed to quarantine published {}: {error}", self.label))?;
        let moved = fs::symlink_metadata(&quarantine).map_err(|error| {
            format!(
                "failed to inspect quarantined published {}: {error}",
                self.label
            )
        })?;
        if moved.file_type().is_symlink() || !self.expected.same_inode(&moved) {
            let restore = fs::hard_link(&quarantine, &self.target)
                .and_then(|()| fs::remove_file(&quarantine));
            return match restore {
                Ok(()) => Err(format!(
                    "refused to remove foreign replacement at published {}",
                    self.label
                )),
                Err(error) => Err(format!(
                    "foreign replacement at published {} was preserved at {:?}: {error}",
                    self.label, quarantine
                )),
            };
        }
        fs::remove_file(&quarantine)
            .map_err(|error| format!("failed to remove quarantined {}: {error}", self.label))?;
        self.active = false;
        Ok(())
    }

    fn commit(&mut self) {
        self.active = false;
    }

    fn verify_parent(&self) -> Result<(), String> {
        verify_output_namespace(&self.parent_namespace)?;
        let parent = fs::symlink_metadata(&self.parent)
            .map_err(|error| format!("failed to inspect published-link parent: {error}"))?;
        if parent.file_type().is_symlink()
            || !parent.is_dir()
            || !self.parent_snapshot.same_inode(&parent)
        {
            return Err(String::from("published-link parent changed identity"));
        }
        Ok(())
    }
}

impl Drop for PublishedLink {
    fn drop(&mut self) {
        let _ = self.rollback();
    }
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to sync output directory {path:?}: {error}"))
}

/// Publish both names within one resolved parent using privately staged
/// inodes and conservative rollback guards.
///
/// Two independent pathnames cannot be made crash-atomic with portable
/// `std::fs`, and a malicious process with the same Unix uid can mutate any
/// mode-0700 namespace owned by that uid. This protocol therefore rejects
/// cross-directory pairs, detects namespace replacement, preserves foreign
/// replacements instead of deleting them, and reports success only after the
/// pair and its explicit cleanup have been directory-synchronized. It does
/// not claim stronger same-uid or multi-path atomicity.
fn write_output_pair_with_hooks<F, G, S>(
    sanitized_target: &OutputTarget,
    sanitized: &[u8],
    component_target: &OutputTarget,
    component: &[u8],
    before_publish: F,
    mut after_link: G,
    mut sync_commit_directory: S,
) -> Result<Option<String>, String>
where
    F: FnOnce(&Path, &Path) -> Result<(), String>,
    G: FnMut(&str, &Path) -> Result<(), String>,
    S: FnMut(&Path) -> Result<(), String>,
{
    let mut transaction = OutputTransaction::create(sanitized_target, component_target)?;
    let mut staged_sanitized = match StagedOutput::create(
        &transaction,
        "sanitized.stage",
        "--sanitized-core-output",
        sanitized,
    ) {
        Ok(staged) => staged,
        Err(error) => {
            let cleanup = transaction.cleanup();
            let parent_sync = sync_directory(&transaction.parent);
            return Err(append_cleanup(
                error,
                [
                    ("transaction-directory", cleanup),
                    ("parent-sync", parent_sync),
                ],
            ));
        }
    };
    let mut staged_component =
        match StagedOutput::create(&transaction, "component.stage", "--output", component) {
            Ok(staged) => staged,
            Err(error) => {
                return Err(abort_output_transaction(
                    error,
                    &mut transaction,
                    &mut staged_sanitized,
                    None,
                    None,
                    None,
                ));
            }
        };
    if let Err(error) = before_publish(&staged_sanitized.path, &staged_component.path) {
        return Err(abort_output_transaction(
            error,
            &mut transaction,
            &mut staged_sanitized,
            Some(&mut staged_component),
            None,
            None,
        ));
    }

    let mut published_sanitized = match staged_sanitized.publish_no_replace(
        &transaction,
        sanitized_target,
        "--sanitized-core-output",
        &mut after_link,
    ) {
        Ok(published) => published,
        Err(error) => {
            return Err(abort_output_transaction(
                error,
                &mut transaction,
                &mut staged_sanitized,
                Some(&mut staged_component),
                None,
                None,
            ));
        }
    };
    let mut published_component = match staged_component.publish_no_replace(
        &transaction,
        component_target,
        "--output",
        &mut after_link,
    ) {
        Ok(published) => published,
        Err(error) => {
            return Err(abort_output_transaction(
                error,
                &mut transaction,
                &mut staged_sanitized,
                Some(&mut staged_component),
                Some(&mut published_sanitized),
                None,
            ));
        }
    };

    if let Err(error) = sync_commit_directory(&transaction.parent) {
        return Err(abort_output_transaction(
            error,
            &mut transaction,
            &mut staged_sanitized,
            Some(&mut staged_component),
            Some(&mut published_sanitized),
            Some(&mut published_component),
        ));
    }
    if let Err(error) = staged_sanitized
        .cleanup(&transaction, "--sanitized-core-output")
        .and_then(|()| staged_component.cleanup(&transaction, "--output"))
        .and_then(|()| sync_directory(&transaction.path))
    {
        return Err(abort_output_transaction(
            error,
            &mut transaction,
            &mut staged_sanitized,
            Some(&mut staged_component),
            Some(&mut published_sanitized),
            Some(&mut published_component),
        ));
    }

    // Removing the private stage links changes ctime/nlink on the published
    // inodes. Refresh that expected metadata from the still-bound inode and
    // then perform one final independent identity+content verification as
    // close as portable std::fs permits to the commit point.
    let final_verification = published_sanitized
        .refresh_expected()
        .and_then(|()| published_component.refresh_expected())
        .and_then(|()| published_sanitized.verify())
        .and_then(|()| published_component.verify());
    if let Err(error) = final_verification {
        return Err(abort_output_transaction(
            error,
            &mut transaction,
            &mut staged_sanitized,
            Some(&mut staged_component),
            Some(&mut published_sanitized),
            Some(&mut published_component),
        ));
    }

    // This is the sole commit point. Every error before it retains live
    // rollback guards. Cleanup after it cannot revoke the already durable,
    // freshly verified pair, so cleanup failures are returned as an explicit
    // success warning rather than a contradictory Err with committed files.
    published_sanitized.commit();
    published_component.commit();
    let transaction_cleanup = transaction.cleanup();
    let parent_sync = sync_directory(&sanitized_target.canonical_parent);
    Ok(summarize_cleanup([
        ("transaction-directory", transaction_cleanup),
        ("parent-sync", parent_sync),
    ])
    .map(|failure| format!("post-commit cleanup warning: {failure}")))
}

fn summarize_cleanup<const N: usize>(cleanup: [(&str, Result<(), String>); N]) -> Option<String> {
    cleanup
        .into_iter()
        .filter_map(|(label, result)| result.err().map(|failure| format!("{label}={failure}")))
        .fold(None, |summary, failure| {
            Some(match summary {
                Some(summary) => format!("{summary}; {failure}"),
                None => failure,
            })
        })
}

fn append_cleanup<const N: usize>(
    error: String,
    cleanup: [(&str, Result<(), String>); N],
) -> String {
    match summarize_cleanup(cleanup) {
        Some(warning) => format!("{error}; cleanup failed: {warning}"),
        None => error,
    }
}

fn abort_output_transaction(
    error: String,
    transaction: &mut OutputTransaction,
    staged_sanitized: &mut StagedOutput,
    staged_component: Option<&mut StagedOutput>,
    published_sanitized: Option<&mut PublishedLink>,
    published_component: Option<&mut PublishedLink>,
) -> String {
    let component_rollback = published_component.map_or(Ok(()), PublishedLink::rollback);
    let sanitized_rollback = published_sanitized.map_or(Ok(()), PublishedLink::rollback);
    let component_cleanup =
        staged_component.map_or(Ok(()), |staged| staged.cleanup(transaction, "--output"));
    let sanitized_cleanup = staged_sanitized.cleanup(transaction, "--sanitized-core-output");
    let transaction_sync = sync_directory(&transaction.path);
    let transaction_cleanup = transaction.cleanup();
    let parent_sync = sync_directory(&transaction.parent);
    append_cleanup(
        error,
        [
            ("component-link", component_rollback),
            ("sanitized-link", sanitized_rollback),
            ("component-stage", component_cleanup),
            ("sanitized-stage", sanitized_cleanup),
            ("transaction-sync", transaction_sync),
            ("transaction-directory", transaction_cleanup),
            ("parent-sync", parent_sync),
        ],
    )
}

fn write_output_pair(
    sanitized_target: &OutputTarget,
    sanitized: &[u8],
    component_target: &OutputTarget,
    component: &[u8],
) -> Result<Option<String>, String> {
    write_output_pair_with_hooks(
        sanitized_target,
        sanitized,
        component_target,
        component,
        |_, _| Ok(()),
        |_, _| Ok(()),
        sync_directory,
    )
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut core = None;
    let mut adapter = None;
    let mut sanitized_core_output = None;
    let mut component_output = None;
    let mut arguments = env::args_os().skip(1);
    while let Some(flag) = arguments.next() {
        let target = match flag.to_str() {
            Some("--core") => &mut core,
            Some("--adapter") => &mut adapter,
            Some("--sanitized-core-output") => &mut sanitized_core_output,
            Some("--output") => &mut component_output,
            _ => {
                return Err(format!(
                    "unknown argument {:?}; expected --core PATH --adapter PATH \
                     --sanitized-core-output PATH --output PATH",
                    flag
                ));
            }
        };
        if target.is_some() {
            return Err(format!("duplicate argument {:?}", flag));
        }
        let value: OsString = arguments
            .next()
            .ok_or_else(|| format!("missing path after {:?}", flag))?;
        *target = Some(PathBuf::from(value));
    }
    let result = Arguments {
        core: core.ok_or_else(|| String::from("missing --core PATH"))?,
        adapter: adapter.ok_or_else(|| String::from("missing --adapter PATH"))?,
        sanitized_core_output: sanitized_core_output
            .ok_or_else(|| String::from("missing --sanitized-core-output PATH"))?,
        component_output: component_output.ok_or_else(|| String::from("missing --output PATH"))?,
    };
    let paths = [
        &result.core,
        &result.adapter,
        &result.sanitized_core_output,
        &result.component_output,
    ];
    for (index, path) in paths.iter().enumerate() {
        if paths[..index].contains(path) {
            return Err(String::from("all input and output paths must differ"));
        }
    }
    Ok(result)
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    let core = read_bounded_input(
        "--core",
        &arguments.core,
        InputLength::AtMost(MAX_COMPILER_CORE_BYTES),
    )?;
    let adapter = read_bounded_input(
        "--adapter",
        &arguments.adapter,
        InputLength::Exact(ADAPTER_BYTES),
    )?;
    if same_file(&core.metadata, &adapter.metadata) || core.canonical_path == adapter.canonical_path
    {
        return Err(String::from(
            "--core and --adapter must be distinct real files, not aliases",
        ));
    }
    let sanitized_target =
        prepare_output_target("--sanitized-core-output", &arguments.sanitized_core_output)?;
    let component_target = prepare_output_target("--output", &arguments.component_output)?;
    if sanitized_target.canonical_path == component_target.canonical_path {
        return Err(String::from(
            "--sanitized-core-output and --output resolve to the same path",
        ));
    }
    for (label, target) in [
        ("--sanitized-core-output", &sanitized_target),
        ("--output", &component_target),
    ] {
        if target.canonical_path == core.canonical_path
            || target.canonical_path == adapter.canonical_path
        {
            return Err(format!("{label} resolves to an input path"));
        }
    }

    let transformed = componentize_corpus_core(&core.bytes, &adapter.bytes)
        .map_err(|error| format!("C8.2 transformation rejected: {error}"))?;
    let cleanup_warning = write_output_pair(
        &sanitized_target,
        transformed.sanitized_core().bytes(),
        &component_target,
        transformed.component_bytes(),
    )?;
    if let Some(warning) = cleanup_warning {
        eprintln!("C8.2 output pair committed; {warning}");
    }

    let report = transformed.report();
    let sanitization = report.sanitization;
    println!("compiler_core_bytes={}", sanitization.compiler_core_bytes);
    println!(
        "compiler_core_sha256={}",
        hex_sha256(&sanitization.compiler_core_sha256)
    );
    println!(
        "removed_global_section_bytes={}",
        sanitization.removed_global_section_bytes
    );
    println!("stack_pointer_value={}", sanitization.stack_pointer_value);
    println!("global_references={}", sanitization.global_references);
    println!("sanitized_core_bytes={}", sanitization.sanitized_core_bytes);
    println!(
        "sanitized_core_sha256={}",
        hex_sha256(&sanitization.sanitized_core_sha256)
    );
    println!("adapter_bytes={}", report.adapter_bytes);
    println!("adapter_sha256={}", hex_sha256(&report.adapter_sha256));
    println!("component_bytes={}", report.component_bytes);
    println!("component_sha256={}", hex_sha256(&report.component_sha256));
    println!("outer_imports={}", report.outer_imports);
    println!("outer_exports={}", report.outer_exports);
    println!("embedded_core_modules={}", report.embedded_core_modules);
    println!("nested_components={}", report.nested_components);
    println!("canonical_lowers={}", report.canonical_lowers);
    println!(
        "canonical_lowering_sha256={}",
        hex_sha256(&transformed.pins().canonical_lowering_sha256)
    );
    for module in &transformed.pins().embedded_core_modules {
        println!(
            "embedded_core_module ordinal={} raw_bytes={} raw_sha256={}",
            module.ordinal,
            module.raw_bytes,
            hex_sha256(&module.raw_sha256)
        );
    }
    for entry in &transformed.pins().entries {
        let direction = match entry.direction {
            OutputDirection::Import => "import",
            OutputDirection::Export => "export",
        };
        let kind = match entry.kind {
            OutputKind::Module => "module",
            OutputKind::Function => "function",
            OutputKind::Value => "value",
            OutputKind::Type => "type",
            OutputKind::Component => "component",
            OutputKind::Instance => "instance",
        };
        println!(
            "outer_entry direction={direction} kind={kind} name={} raw_bytes={} raw_sha256={}",
            entry.name,
            entry.raw_bytes,
            hex_sha256(&entry.raw_sha256)
        );
    }
    println!("runtime_ready={}", report.runtime_ready);
    println!("guest_calls={}", report.guest_calls);
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::SystemTime;

    fn test_directory(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "vibeos-c82-file-boundary-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("test directory must be created");
        #[cfg(unix)]
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("test directory permissions must be private");
        directory
    }

    #[test]
    fn oversized_input_is_rejected_from_metadata_before_a_bounded_read() {
        let directory = test_directory("oversized");
        let input = directory.join("oversized.core.wasm");
        File::create(&input)
            .expect("sparse input must be created")
            .set_len(MAX_COMPILER_CORE_BYTES as u64 + 1)
            .expect("sparse input length must be set");

        let error = read_bounded_input(
            "--core",
            &input,
            InputLength::AtMost(MAX_COMPILER_CORE_BYTES),
        )
        .err()
        .expect("oversized input must fail");
        assert!(error.contains("before reading"), "{error}");

        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[test]
    fn exact_ceiling_input_uses_only_the_fixed_bounded_buffer() {
        let directory = test_directory("exact-ceiling");
        let input = directory.join("bounded.core.wasm");
        File::create(&input)
            .expect("bounded input must be created")
            .set_len(MAX_COMPILER_CORE_BYTES as u64)
            .expect("bounded input length must be set");

        let bounded = read_bounded_input(
            "--core",
            &input,
            InputLength::AtMost(MAX_COMPILER_CORE_BYTES),
        )
        .expect("an exact-ceiling file must fit the fixed buffer");
        assert_eq!(bounded.bytes.len(), MAX_COMPILER_CORE_BYTES);
        assert_eq!(bounded.bytes.capacity(), MAX_COMPILER_CORE_BYTES);

        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inputs_and_existing_hardlink_outputs_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = test_directory("aliases");
        let input = directory.join("input.wasm");
        let linked_input = directory.join("linked-input.wasm");
        let symlink_input = directory.join("symlink-input.wasm");
        fs::write(&input, b"wasm").expect("input must be written");
        fs::hard_link(&input, &linked_input).expect("hard link must be created");
        symlink(&input, &symlink_input).expect("symlink must be created");

        let symlink_error = read_bounded_input(
            "--core",
            &symlink_input,
            InputLength::AtMost(MAX_COMPILER_CORE_BYTES),
        )
        .err()
        .expect("symlink input must fail");
        assert!(symlink_error.contains("non-symlink"), "{symlink_error}");
        assert!(same_file(
            &fs::metadata(&input).unwrap(),
            &fs::metadata(&linked_input).unwrap()
        ));
        let output_error = prepare_output_target("--output", &linked_input)
            .err()
            .expect("existing hardlink output must fail");
        assert!(output_error.contains("never overwrite"), "{output_error}");

        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[test]
    fn normalized_output_aliases_resolve_to_one_target() {
        let directory = test_directory("normalized");
        let child = directory.join("child");
        fs::create_dir(&child).expect("child directory must be created");
        let direct = prepare_output_target("--sanitized-core-output", &directory.join("out.wasm"))
            .expect("direct target must validate");
        let aliased = prepare_output_target("--output", &child.join("../out.wasm"))
            .expect("normalized target must validate");
        assert_eq!(direct.canonical_path, aliased.canonical_path);

        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[test]
    fn second_publish_failure_rolls_back_the_first_output() {
        let directory = test_directory("rollback");
        let sanitized_path = directory.join("sanitized.core.wasm");
        let component_path = directory.join("wrapped.component.wasm");
        let sanitized = prepare_output_target("--sanitized-core-output", &sanitized_path)
            .expect("sanitized target must validate");
        let component = prepare_output_target("--output", &component_path)
            .expect("component target must validate");

        let error = write_output_pair_with_hooks(
            &sanitized,
            b"sanitized",
            &component,
            b"component",
            |_, _| {
                fs::write(&component_path, b"racing-file")
                    .map_err(|error| format!("failed to create collision: {error}"))
            },
            |_, _| Ok(()),
            sync_directory,
        )
        .expect_err("second publish collision must fail the pair");
        assert!(error.contains("atomically publish --output"), "{error}");
        assert!(!sanitized_path.exists(), "first output must be rolled back");
        assert_eq!(
            fs::read(&component_path).unwrap(),
            b"racing-file",
            "pre-existing collision must never be overwritten"
        );
        let transaction_directories = fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".c82-transaction-")
            })
            .count();
        assert_eq!(
            transaction_directories, 0,
            "private transaction directories must be cleaned up"
        );

        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn swapped_stage_hardlink_and_symlink_never_publish_or_delete_the_input() {
        use std::os::unix::fs::symlink;

        for use_symlink in [false, true] {
            let directory = test_directory(if use_symlink {
                "stage-symlink"
            } else {
                "stage-hardlink"
            });
            let input = directory.join("input.wasm");
            let sanitized_path = directory.join("sanitized.core.wasm");
            let component_path = directory.join("wrapped.component.wasm");
            fs::write(&input, b"immutable-input").unwrap();
            let sanitized =
                prepare_output_target("--sanitized-core-output", &sanitized_path).unwrap();
            let component = prepare_output_target("--output", &component_path).unwrap();

            let error = write_output_pair_with_hooks(
                &sanitized,
                b"sanitized",
                &component,
                b"component",
                |sanitized_stage, _| {
                    fs::remove_file(sanitized_stage)
                        .map_err(|error| format!("failed to swap stage: {error}"))?;
                    if use_symlink {
                        symlink(&input, sanitized_stage)
                            .map_err(|error| format!("failed to install stage symlink: {error}"))
                    } else {
                        fs::hard_link(&input, sanitized_stage)
                            .map_err(|error| format!("failed to install stage hardlink: {error}"))
                    }
                },
                |_, _| Ok(()),
                sync_directory,
            )
            .expect_err("a replaced stage path must fail closed");
            assert!(error.contains("changed identity"), "{error}");
            assert!(!sanitized_path.exists());
            assert!(!component_path.exists());
            assert_eq!(fs::read(&input).unwrap(), b"immutable-input");

            // The fail-closed cleanup deliberately preserves an unowned
            // replacement inside the test-owned transaction directory.
            fs::remove_dir_all(directory).expect("test directory must be removed");
        }
    }

    #[test]
    fn post_link_target_swap_preserves_foreign_replacement_and_aborts_the_pair() {
        let directory = test_directory("post-link-swap");
        let sanitized_path = directory.join("sanitized.core.wasm");
        let component_path = directory.join("wrapped.component.wasm");
        let sanitized = prepare_output_target("--sanitized-core-output", &sanitized_path).unwrap();
        let component = prepare_output_target("--output", &component_path).unwrap();
        let mut swapped = false;

        let error = write_output_pair_with_hooks(
            &sanitized,
            b"sanitized",
            &component,
            b"component",
            |_, _| Ok(()),
            |label, target| {
                if label == "--sanitized-core-output" && !swapped {
                    fs::remove_file(target)
                        .map_err(|error| format!("failed to remove published link: {error}"))?;
                    fs::write(target, b"foreign-replacement")
                        .map_err(|error| format!("failed to install foreign target: {error}"))?;
                    swapped = true;
                }
                Ok(())
            },
            sync_directory,
        )
        .expect_err("post-link replacement must abort publication");
        assert!(error.contains("changed identity"), "{error}");
        assert!(error.contains("rollback failed"), "{error}");
        assert_eq!(fs::read(&sanitized_path).unwrap(), b"foreign-replacement");
        assert!(!component_path.exists());

        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[test]
    fn directory_sync_failure_rolls_back_both_published_outputs() {
        let directory = test_directory("sync-failure");
        let sanitized_path = directory.join("sanitized.core.wasm");
        let component_path = directory.join("wrapped.component.wasm");
        let sanitized = prepare_output_target("--sanitized-core-output", &sanitized_path).unwrap();
        let component = prepare_output_target("--output", &component_path).unwrap();

        let error = write_output_pair_with_hooks(
            &sanitized,
            b"sanitized",
            &component,
            b"component",
            |_, _| Ok(()),
            |_, _| Ok(()),
            |_| Err(String::from("injected directory sync failure")),
        )
        .expect_err("directory sync failure must abort publication");
        assert!(error.contains("injected directory sync failure"), "{error}");
        assert!(!sanitized_path.exists());
        assert!(!component_path.exists());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);

        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[test]
    fn final_verification_detects_a_late_swap_and_preserves_the_foreign_file() {
        let directory = test_directory("final-verification-swap");
        let sanitized_path = directory.join("sanitized.core.wasm");
        let component_path = directory.join("wrapped.component.wasm");
        let sanitized = prepare_output_target("--sanitized-core-output", &sanitized_path).unwrap();
        let component = prepare_output_target("--output", &component_path).unwrap();
        let mut injected = false;

        let error = write_output_pair_with_hooks(
            &sanitized,
            b"sanitized",
            &component,
            b"component",
            |_, _| Ok(()),
            |_, _| Ok(()),
            |_| {
                if !injected {
                    fs::remove_file(&sanitized_path)
                        .map_err(|error| format!("failed to remove late target: {error}"))?;
                    fs::write(&sanitized_path, b"late-foreign-replacement")
                        .map_err(|error| format!("failed to install late target: {error}"))?;
                    injected = true;
                }
                Ok(())
            },
        )
        .expect_err("a replacement before the final verification must fail closed");
        assert!(error.contains("changed identity"), "{error}");
        assert!(error.contains("sanitized-link="), "{error}");
        assert_eq!(
            fs::read(&sanitized_path).unwrap(),
            b"late-foreign-replacement"
        );
        assert!(!component_path.exists());

        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[test]
    fn foreign_directory_replacement_is_preserved_and_aborts_the_pair() {
        let directory = test_directory("foreign-directory");
        let sanitized_path = directory.join("sanitized.core.wasm");
        let component_path = directory.join("wrapped.component.wasm");
        let sanitized = prepare_output_target("--sanitized-core-output", &sanitized_path).unwrap();
        let component = prepare_output_target("--output", &component_path).unwrap();

        let error = write_output_pair_with_hooks(
            &sanitized,
            b"sanitized",
            &component,
            b"component",
            |_, _| Ok(()),
            |label, target| {
                if label == "--sanitized-core-output" {
                    fs::remove_file(target)
                        .map_err(|error| format!("failed to remove published file: {error}"))?;
                    fs::create_dir(target)
                        .map_err(|error| format!("failed to install foreign directory: {error}"))?;
                }
                Ok(())
            },
            sync_directory,
        )
        .expect_err("a foreign directory replacement must fail closed");
        assert!(error.contains("changed identity"), "{error}");
        assert!(error.contains("rollback failed"), "{error}");
        assert!(
            sanitized_path.is_dir(),
            "foreign directory must remain in place"
        );
        assert!(!component_path.exists());

        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[test]
    fn post_commit_cleanup_failure_is_an_explicit_success_warning() {
        let directory = test_directory("post-commit-cleanup");
        let sanitized_path = directory.join("sanitized.core.wasm");
        let component_path = directory.join("wrapped.component.wasm");
        let sanitized = prepare_output_target("--sanitized-core-output", &sanitized_path).unwrap();
        let component = prepare_output_target("--output", &component_path).unwrap();

        let warning = write_output_pair_with_hooks(
            &sanitized,
            b"sanitized",
            &component,
            b"component",
            |sanitized_stage, _| {
                let blocker = sanitized_stage
                    .parent()
                    .expect("stage must have a transaction parent")
                    .join("cleanup-blocker");
                fs::write(blocker, b"block transaction removal")
                    .map_err(|error| format!("failed to create cleanup blocker: {error}"))
            },
            |_, _| Ok(()),
            sync_directory,
        )
        .expect("post-commit cleanup failure must not contradict a committed pair")
        .expect("the injected cleanup failure must be reported");
        assert!(warning.contains("post-commit cleanup warning"), "{warning}");
        assert!(warning.contains("transaction-directory"), "{warning}");
        assert_eq!(fs::read(&sanitized_path).unwrap(), b"sanitized");
        assert_eq!(fs::read(&component_path).unwrap(), b"component");

        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn group_or_other_writable_output_parent_is_rejected() {
        let directory = test_directory("writable-parent");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o733))
            .expect("test directory permissions must be relaxed");
        let output = directory.join("output.wasm");

        let error = prepare_output_target("--output", &output)
            .err()
            .expect("a shared writable output parent must fail closed");
        assert!(error.contains("must not be writable"), "{error}");

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("test directory permissions must be restored");
        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn nonsticky_writable_ancestor_is_rejected_even_with_a_private_parent() {
        let directory = test_directory("writable-ancestor");
        let shared = directory.join("shared");
        let private = shared.join("private");
        fs::create_dir(&shared).expect("shared ancestor must be created");
        fs::create_dir(&private).expect("private parent must be created");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o733))
            .expect("ancestor permissions must be relaxed");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))
            .expect("direct parent must remain private");

        let error = prepare_output_target("--output", &private.join("output.wasm"))
            .err()
            .expect("a writable non-sticky ancestor must fail closed");
        assert!(error.contains("unsafe writable ancestor"), "{error}");

        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700))
            .expect("ancestor permissions must be restored");
        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn sticky_writable_ancestor_accepts_its_owned_private_child() {
        let directory = test_directory("sticky-ancestor");
        let sticky = directory.join("sticky");
        let private = sticky.join("private");
        fs::create_dir(&sticky).expect("sticky ancestor must be created");
        fs::create_dir(&private).expect("private parent must be created");
        fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1733))
            .expect("sticky ancestor permissions must be installed");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))
            .expect("direct parent must remain private");

        prepare_output_target("--output", &private.join("output.wasm"))
            .expect("sticky ownership semantics must protect the child namespace");

        fs::set_permissions(&sticky, fs::Permissions::from_mode(0o700))
            .expect("ancestor permissions must be restored");
        fs::remove_dir_all(directory).expect("test directory must be removed");
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_permission_change_invalidates_a_prepared_output_target() {
        let directory = test_directory("ancestor-permission-change");
        let ancestor = directory.join("ancestor");
        let private = ancestor.join("private");
        fs::create_dir(&ancestor).expect("ancestor must be created");
        fs::create_dir(&private).expect("private parent must be created");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))
            .expect("ancestor must start private");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))
            .expect("direct parent must start private");
        let target = prepare_output_target("--output", &private.join("output.wasm"))
            .expect("initial namespace must validate");

        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o733))
            .expect("ancestor permissions must change");
        let error = verify_parent(&target)
            .expect_err("a prepared target must reject changed ancestor permissions");
        assert!(error.contains("changed identity or permissions"), "{error}");

        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))
            .expect("ancestor permissions must be restored");
        fs::remove_dir_all(directory).expect("test directory must be removed");
    }
}
