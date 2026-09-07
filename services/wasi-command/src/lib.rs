//! Bounded command transport and atomic raw-module upload. No execution authority
//! is minted by uploading bytes. The kernel supplies an authorized file root.
#![no_std]
extern crate alloc;
use alloc::{string::String, sync::Arc, vec::Vec};
use core::{
    future::poll_fn,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    task::{Context, Poll, Waker},
};
use sha2::{Digest, Sha256};
use vibeos_core::sync::SpinLock;
use vibeos_file_store::{FileTreeRoot, FileType, RelPath};
use vibeos_wasi_runtime::{WasiIo, WasiIoError, WasiTerminal, IO_CHUNK};

const DEPTH: usize = 8;
struct PipeState {
    data: [[u8; IO_CHUNK]; DEPTH],
    sizes: [usize; DEPTH],
    head: usize,
    count: usize,
    offset: usize,
    closed: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}
pub struct Pipe(SpinLock<PipeState>);
impl Pipe {
    fn new() -> Self {
        Self(SpinLock::new(PipeState {
            data: [[0; IO_CHUNK]; DEPTH],
            sizes: [0; DEPTH],
            head: 0,
            count: 0,
            offset: 0,
            closed: false,
            reader: None,
            writer: None,
        }))
    }
    pub fn read(&self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<Result<usize, WasiIoError>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut s = self.0.lock();
        if s.count == 0 {
            if s.closed {
                return Poll::Ready(Ok(0));
            }
            s.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = out.len().min(s.sizes[s.head] - s.offset);
        out[..n].copy_from_slice(&s.data[s.head][s.offset..s.offset + n]);
        s.offset += n;
        if s.offset == s.sizes[s.head] {
            s.head = (s.head + 1) % DEPTH;
            s.count -= 1;
            s.offset = 0;
        }
        let wake = s.writer.take();
        drop(s);
        if let Some(w) = wake {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }
    pub fn write(&self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<Result<usize, WasiIoError>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut s = self.0.lock();
        if s.closed {
            return Poll::Ready(Err(WasiIoError::Closed));
        }
        if s.count == DEPTH {
            s.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = bytes.len().min(IO_CHUNK);
        let tail = (s.head + s.count) % DEPTH;
        s.data[tail][..n].copy_from_slice(&bytes[..n]);
        s.sizes[tail] = n;
        s.count += 1;
        let wake = s.reader.take();
        drop(s);
        if let Some(w) = wake {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }
    pub fn close(&self) {
        let mut s = self.0.lock();
        s.closed = true;
        let r = s.reader.take();
        let w = s.writer.take();
        drop(s);
        if let Some(w) = r {
            w.wake();
        }
        if let Some(w) = w {
            w.wake();
        }
    }
    pub fn drained(&self) -> bool {
        let s = self.0.lock();
        s.closed && s.count == 0
    }
    fn pending_waiters(&self) -> usize {
        let s = self.0.lock();
        usize::from(s.reader.is_some()) + usize::from(s.writer.is_some())
    }
}
pub struct CommandIo {
    pub stdin: Pipe,
    pub stdout: Pipe,
    pub stderr: Pipe,
    cancel: Arc<AtomicBool>,
    cancel_reason: AtomicU8,
    terminal: SpinLock<Option<WasiTerminal>>,
    completed: SpinLock<Option<Waker>>,
}
impl Default for CommandIo {
    fn default() -> Self {
        Self::new()
    }
}
impl CommandIo {
    pub fn new() -> Self {
        Self {
            stdin: Pipe::new(),
            stdout: Pipe::new(),
            stderr: Pipe::new(),
            cancel: Arc::new(AtomicBool::new(false)),
            cancel_reason: AtomicU8::new(0),
            terminal: SpinLock::new(None),
            completed: SpinLock::new(None),
        }
    }
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }
    pub fn cancel(&self) {
        self.cancel_with_reason(1);
    }
    pub fn deny(&self) {
        self.cancel_with_reason(2);
    }
    pub fn denied(&self) -> bool {
        self.cancel_reason.load(Ordering::Acquire) == 2
    }
    fn cancel_with_reason(&self, reason: u8) {
        let _ = self
            .cancel_reason
            .compare_exchange(0, reason, Ordering::AcqRel, Ordering::Acquire);
        self.cancel.store(true, Ordering::Release);
        self.stdin.close();
        self.stdout.close();
        self.stderr.close();
    }
    pub fn complete(&self, t: WasiTerminal) {
        let mut terminal = self.terminal.lock();
        if terminal.is_none() {
            *terminal = Some(t);
        }
        drop(terminal);
        if let Some(w) = self.completed.lock().take() {
            w.wake();
        }
        self.stdin.close();
        self.stdout.close();
        self.stderr.close();
    }
    pub fn terminal(&self) -> Option<WasiTerminal> {
        *self.terminal.lock()
    }
    pub fn pending_waiters(&self) -> usize {
        self.stdin.pending_waiters()
            + self.stdout.pending_waiters()
            + self.stderr.pending_waiters()
            + usize::from(self.completed.lock().is_some())
    }
    pub fn poll_terminal(&self, cx: &mut Context<'_>) -> Poll<WasiTerminal> {
        let mut wake = self.completed.lock();
        if let Some(t) = self.terminal() {
            Poll::Ready(t)
        } else {
            *wake = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
/// Borrowed only while polling; no arena-owned pointers enter CommandIo.
pub struct GuestIo<'a>(pub &'a CommandIo);
impl WasiIo for GuestIo<'_> {
    fn read(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<Result<usize, WasiIoError>> {
        if self.0.cancelled() {
            return Poll::Ready(Err(WasiIoError::Denied));
        }
        self.0.stdin.read(cx, bytes)
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        fd: u32,
        bytes: &[u8],
    ) -> Poll<Result<usize, WasiIoError>> {
        if self.0.cancelled() {
            return Poll::Ready(Err(WasiIoError::Denied));
        }
        if fd == 1 {
            self.0.stdout.write(cx, bytes)
        } else {
            self.0.stderr.write(cx, bytes)
        }
    }
}
pub fn valid_name(name: &str) -> bool {
    name.len() <= 128
        && name.ends_with(".wasm")
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
pub fn upload_path(name: &str) -> Result<RelPath, u32> {
    if !valid_name(name) {
        return Err(2);
    }
    RelPath::parse(&alloc::format!("wasm/{name}")).map_err(|_| 2)
}
pub fn digest(text: &str) -> Result<[u8; 32], u32> {
    if text.len() != 64 {
        return Err(2);
    }
    let mut hash = [0; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let nib = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        hash[i] = nib(pair[0]).ok_or(2u32)? * 16 + nib(pair[1]).ok_or(2u32)?;
    }
    Ok(hash)
}
/// Exact source snapshot; only regular files are loadable. The reader pins
/// its immutable content while uploads can publish a later namespace version.
pub async fn load(root: &FileTreeRoot, path: &RelPath) -> Result<Vec<u8>, u32> {
    let (meta, reader) = root.regular_reader(path).map_err(|_| 126u32)?;
    if meta.file_type != FileType::Regular || meta.size > 512 * 1024 {
        return Err(126);
    }
    load_reader(reader).await
}
pub async fn load_reader(reader: vibeos_file_store::FsFileReader) -> Result<Vec<u8>, u32> {
    let mut bytes = Vec::new();
    for i in 0..reader.chunk_count() {
        let chunk = reader
            .read_chunk(i)
            .await
            .map_err(|_| 125u32)?
            .ok_or(125u32)?;
        if bytes.len() + chunk.len() > 512 * 1024 {
            return Err(126);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub async fn upload(
    root: &FileTreeRoot,
    name: &str,
    length: usize,
    expected: [u8; 32],
    io: &CommandIo,
) -> Result<(), u32> {
    if length > 512 * 1024 || length == 0 {
        return Err(2);
    }
    let path = upload_path(name)?;
    let dir = RelPath::parse("wasm").unwrap();
    // A dedicated directory, never a symlink to another part of the namespace.
    match root.snapshot().stat(&dir, false) {
        Ok(m) if m.file_type == FileType::Directory => (),
        Err(vibeos_file_store::FileError::NotFound) => {
            let mut tx = root.begin().map_err(|_| 125u32)?;
            tx.cancel_on(io.cancel.clone());
            tx.mkdir(&dir, false).map_err(|_| 125u32)?;
            tx.commit_authoritative().await.map_err(|_| 125u32)?;
        }
        _ => return Err(126),
    }
    let generation = root.snapshot().generation();
    if root
        .snapshot()
        .stat(&path, false)
        .is_ok_and(|m| m.file_type != FileType::Regular)
    {
        return Err(126);
    }
    let mut stager = root
        .begin_content_stager(&path, false)
        .map_err(|_| 125u32)?;
    let mut hash = Sha256::new();
    let mut count = 0usize;
    let mut buffer = [0; IO_CHUNK];
    loop {
        if io.cancelled() {
            return Err(130);
        }
        let n = poll_fn(|cx| io.stdin.read(cx, &mut buffer))
            .await
            .map_err(|_| 130u32)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n).ok_or(2u32)?;
        if count > length {
            return Err(2);
        }
        hash.update(&buffer[..n]);
        stager.push(&buffer[..n]).await.map_err(|_| 125u32)?;
    }
    if io.cancelled() {
        return Err(130);
    }
    let actual: [u8; 32] = hash.finalize().into();
    if count != length || actual != expected {
        return Err(2);
    }
    let staged = stager.finish().await.map_err(|_| 125u32)?;
    if io.cancelled() || root.snapshot().generation() != generation {
        return Err(126);
    }
    let mut tx = root.begin().map_err(|_| 125u32)?;
    tx.cancel_on(io.cancel.clone());
    if tx.base_generation() != generation || io.cancelled() {
        return Err(126);
    }
    // The commit itself also compares the namespace generation.
    tx.write_staged(&path, staged).map_err(|_| 125u32)?;
    tx.commit_authoritative().await.map_err(|_| 125u32)?;
    Ok(())
}
/// Parsed SSH request contains values, never capability handles or shell code.
#[derive(Debug, Clone)]
pub enum Request {
    Upload {
        name: String,
        length: usize,
        sha256: [u8; 32],
    },
    Run {
        name: String,
        args: Vec<String>,
    },
}
/// Small value-only lexer. No expansion, operators, paths, or command substitution.
pub fn parse_request(source: &str) -> Option<Request> {
    if source.len() > 4096 {
        return None;
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escape = false;
    let mut active = false;
    for c in source.chars() {
        if c == '\0' || c == '\n' || c == '\r' {
            return None;
        }
        if escape {
            word.push(c);
            escape = false;
            active = true;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escape = true;
            active = true;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
            active = true;
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            active = true;
            continue;
        }
        if c == ' ' || c == '\t' {
            if active {
                words.push(core::mem::take(&mut word));
                active = false;
            }
            continue;
        }
        if "|;&<>`$".contains(c) {
            return None;
        }
        word.push(c);
        active = true;
    }
    if escape || quote.is_some() {
        return None;
    }
    if active {
        words.push(word);
    }
    if words.len() < 2 || words.len() > 129 || !valid_name(&words[1]) {
        return None;
    }
    match words[0].as_str() {
        "wasm-run" => Some(Request::Run {
            name: words[1].clone(),
            args: words[2..].to_vec(),
        }),
        "wasm-upload" if words.len() == 4 => {
            let length = words[2].parse::<usize>().ok()?;
            if length == 0 || length > 512 * 1024 {
                return None;
            }
            Some(Request::Upload {
                name: words[1].clone(),
                length,
                sha256: digest(&words[3]).ok()?,
            })
        }
        _ => None,
    }
}
pub fn exit_status(t: WasiTerminal) -> u32 {
    match t {
        WasiTerminal::Exited(n) => n,
        WasiTerminal::Cancelled => 130,
        WasiTerminal::Denied => 126,
        WasiTerminal::LimitExceeded => 124,
        WasiTerminal::Trapped => 125,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::future::Future;
    #[test]
    fn request_values_are_never_reparsed_as_authority() {
        assert!(
            matches!(parse_request("wasm-run a.wasm 'a b' \"中文\""),Some(Request::Run{args,..}) if args==["a b","中文"])
        );
        for source in [
            "wasm-run ../a.wasm",
            "wasm-run @home/a.wasm",
            "wasm-run a.wasm; reboot",
            "wasm-run a.wasm $(echo x)",
            "wasm-run a.wasm 'unfinished",
        ] {
            assert!(parse_request(source).is_none(), "{source}");
        }
        assert!(parse_request("wasm-upload a.wasm 999999999 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").is_none());
    }
    #[test]
    fn pipe_backpressure_eof_and_cancel() {
        let io = CommandIo::new();
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..DEPTH {
            assert_eq!(io.stdin.write(&mut cx, b"hello"), Poll::Ready(Ok(5)));
        }
        assert_eq!(io.stdin.write(&mut cx, b"x"), Poll::Pending);
        let mut buf = [0; 3];
        assert_eq!(io.stdin.read(&mut cx, &mut buf), Poll::Ready(Ok(3)));
        assert_eq!(&buf, b"hel");
        assert_eq!(io.stdin.read(&mut cx, &mut buf), Poll::Ready(Ok(2)));
        assert_eq!(io.stdin.write(&mut cx, b"x"), Poll::Ready(Ok(1)));
        io.cancel();
        assert!(io.cancelled());
        assert_eq!(
            io.stdin.write(&mut cx, b"x"),
            Poll::Ready(Err(WasiIoError::Closed))
        );
        while !io.stdin.drained() {
            assert!(matches!(
                io.stdin.read(&mut cx, &mut buf),
                Poll::Ready(Ok(_))
            ));
        }
        assert_eq!(io.stdin.read(&mut cx, &mut buf), Poll::Ready(Ok(0)));
    }
    #[test]
    fn first_cancellation_reason_survives_teardown_revocation() {
        let cancelled = CommandIo::new();
        cancelled.cancel();
        cancelled.deny();
        assert!(!cancelled.denied());
        let denied = CommandIo::new();
        denied.deny();
        denied.cancel();
        assert!(denied.denied());
        denied.complete(WasiTerminal::Denied);
        assert_eq!(denied.pending_waiters(), 0);
    }

    #[test]
    fn pinned_reader_survives_replacement_and_rejects_symlinks() {
        let root = FileTreeRoot::new_empty(123).unwrap();
        let path = RelPath::parse("a.wasm").unwrap();
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path, [b"old"], false).unwrap();
        tx.commit().unwrap();
        let (meta, reader) = root.regular_reader(&path).unwrap();
        assert_eq!(meta.size, 3);
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path, [b"new version"], false).unwrap();
        tx.symlink("a.wasm", &RelPath::parse("link.wasm").unwrap())
            .unwrap();
        tx.commit().unwrap();
        assert!(root
            .regular_reader(&RelPath::parse("link.wasm").unwrap())
            .is_err());
        let mut future = core::pin::pin!(reader.read_chunk(0));
        assert!(
            matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),Poll::Ready(Ok(Some(bytes))) if bytes==b"old")
        );
    }
}
