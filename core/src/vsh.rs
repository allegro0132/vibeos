//! Capability-native shell parser, planner, streams, and first audited applets.
//!
//! This module is intentionally portable: the kernel supplies the interactive
//! line editor, while parsing and Job execution are exercised on the host.

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::cap::{self, CSpace, Cap, CapError, Resource, Revocable, Rights};
use crate::exec::{self, TaskHandle, TaskState, WaitQueue};
use crate::sync::SpinLock;

pub const MAX_INPUT_BYTES: usize = 4 * 1024;
pub const MAX_TOKENS: usize = 256;
pub const MAX_AST_NODES: usize = 512;
pub const MAX_PIPELINE_STAGES: usize = 16;
pub const MAX_ARGS: usize = 128;
pub const MAX_EXPANDED_BYTES: usize = 16 * 1024;
pub const MAX_BINDINGS: usize = 128;
pub const MAX_BINDING_BYTES: usize = 4 * 1024;
pub const MAX_STREAM_CHUNK_BYTES: usize = 1024;
pub const STREAM_BUFFER_CHUNKS: usize = 8;
pub const MAX_CAPTURED_OUTPUT: usize = 64 * 1024;
pub const DEFAULT_STAGE_MEMORY: usize = 256 * 1024;
pub const MAX_STAGE_MEMORY: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub span: Span,
    pub message: &'static str,
}

impl Diagnostic {
    fn new(start: usize, end: usize, message: &'static str) -> Self {
        Self {
            span: Span { start, end },
            message,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WordPart {
    Literal(String),
    Value(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Word {
    pub parts: Vec<WordPart>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Argument {
    Word(Word),
    Capability { name: String, span: Span },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectKind {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redirect {
    pub kind: RedirectKind,
    pub target: String,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandAst {
    pub name: Word,
    pub args: Vec<Argument>,
    pub redirects: Vec<Redirect>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineAst {
    pub commands: Vec<CommandAst>,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    And,
    Or,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndOrAst {
    pub first: PipelineAst,
    pub rest: Vec<(Condition, PipelineAst)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListItem {
    pub command: AndOrAst,
    pub background: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script {
    pub items: Vec<ListItem>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operator {
    Pipe,
    And,
    Or,
    Semi,
    Background,
    In,
    Out,
    Err,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenKind {
    Word(Word),
    Cap(String),
    Op(Operator),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    span: Span,
}

fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}
fn is_name_continue(b: u8) -> bool {
    is_name_start(b) || b.is_ascii_digit() || b == b'-'
}
fn is_delimiter(b: u8) -> bool {
    b.is_ascii_whitespace() || b"|&;<>".contains(&b)
}

fn push_literal(parts: &mut Vec<WordPart>, text: &str) {
    if text.is_empty() {
        return;
    }
    if let Some(WordPart::Literal(last)) = parts.last_mut() {
        last.push_str(text);
    } else {
        parts.push(WordPart::Literal(text.to_string()));
    }
}

fn lex(source: &str) -> Result<Vec<Token>, Diagnostic> {
    if source.len() > MAX_INPUT_BYTES {
        return Err(Diagnostic::new(
            MAX_INPUT_BYTES,
            source.len(),
            "input exceeds 4 KiB",
        ));
    }
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        let (op, consumed) = match bytes[i] {
            b'|' if bytes.get(i + 1) == Some(&b'|') => (Some(Operator::Or), 2),
            b'&' if bytes.get(i + 1) == Some(&b'&') => (Some(Operator::And), 2),
            b'2' if bytes.get(i + 1) == Some(&b'>') => (Some(Operator::Err), 2),
            b'|' => (Some(Operator::Pipe), 1),
            b'&' => (Some(Operator::Background), 1),
            b';' => (Some(Operator::Semi), 1),
            b'<' => (Some(Operator::In), 1),
            b'>' => (Some(Operator::Out), 1),
            _ => (None, 0),
        };
        if let Some(op) = op {
            i += consumed;
            out.push(Token {
                kind: TokenKind::Op(op),
                span: Span { start, end: i },
            });
        } else if bytes[i] == b'@' && bytes.get(i + 1).copied().is_some_and(is_name_start) {
            i += 2;
            while i < bytes.len() && is_name_continue(bytes[i]) {
                i += 1;
            }
            if i == bytes.len() || is_delimiter(bytes[i]) {
                out.push(Token {
                    kind: TokenKind::Cap(source[start + 1..i].to_string()),
                    span: Span { start, end: i },
                });
            } else {
                i = start;
                let word = lex_word(source, &mut i)?;
                out.push(Token {
                    span: word.span,
                    kind: TokenKind::Word(word),
                });
            }
        } else {
            let word = lex_word(source, &mut i)?;
            out.push(Token {
                span: word.span,
                kind: TokenKind::Word(word),
            });
        }
        if out.len() > MAX_TOKENS {
            return Err(Diagnostic::new(start, i, "token limit exceeded"));
        }
    }
    Ok(out)
}

fn lex_word(source: &str, i: &mut usize) -> Result<Word, Diagnostic> {
    let bytes = source.as_bytes();
    let start = *i;
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut quote = 0u8;
    while *i < bytes.len() {
        let b = bytes[*i];
        if quote == 0 && is_delimiter(b) {
            break;
        }
        if quote == 0 && (b == b'(' || b == b')') {
            return Err(Diagnostic::new(
                *i,
                *i + 1,
                "reserved syntax is not supported",
            ));
        }
        if quote == 0 && (b == b'\'' || b == b'"') {
            quote = b;
            *i += 1;
            continue;
        }
        if quote != 0 && b == quote {
            quote = 0;
            *i += 1;
            continue;
        }
        if b == b'\\' && quote != b'\'' {
            *i += 1;
            let Some(&escaped) = bytes.get(*i) else {
                return Err(Diagnostic::new(*i - 1, *i, "trailing backslash"));
            };
            literal.push(escaped as char);
            *i += 1;
            continue;
        }
        if b == b'$' && quote != b'\'' {
            push_literal(&mut parts, &literal);
            literal.clear();
            let value_start = *i;
            *i += 1;
            let braced = bytes.get(*i) == Some(&b'{');
            if braced {
                *i += 1;
            }
            let name_start = *i;
            if !bytes.get(*i).copied().is_some_and(is_name_start) {
                return Err(Diagnostic::new(value_start, *i, "invalid value reference"));
            }
            *i += 1;
            while *i < bytes.len() && is_name_continue(bytes[*i]) {
                *i += 1;
            }
            let name = source[name_start..*i].to_string();
            if braced {
                if bytes.get(*i) != Some(&b'}') {
                    return Err(Diagnostic::new(
                        value_start,
                        *i,
                        "unterminated value reference",
                    ));
                }
                *i += 1;
            }
            parts.push(WordPart::Value(name));
            continue;
        }
        literal.push(b as char);
        *i += 1;
    }
    if quote != 0 {
        return Err(Diagnostic::new(start, *i, "unterminated quote"));
    }
    push_literal(&mut parts, &literal);
    if parts.is_empty() {
        parts.push(WordPart::Literal(String::new()));
    }
    Ok(Word {
        parts,
        span: Span { start, end: *i },
    })
}

pub fn parse(source: &str) -> Result<Script, Diagnostic> {
    let tokens = lex(source)?;
    Parser {
        tokens,
        at: 0,
        nodes: 0,
    }
    .script()
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    nodes: usize,
}
impl Parser {
    fn bump_node(&mut self, span: Span) -> Result<(), Diagnostic> {
        self.nodes += 1;
        if self.nodes > MAX_AST_NODES {
            Err(Diagnostic::new(
                span.start,
                span.end,
                "AST node limit exceeded",
            ))
        } else {
            Ok(())
        }
    }
    fn peek_op(&self, op: Operator) -> bool {
        self.tokens
            .get(self.at)
            .is_some_and(|t| t.kind == TokenKind::Op(op))
    }
    fn take(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.at).cloned()?;
        self.at += 1;
        Some(t)
    }
    fn script(mut self) -> Result<Script, Diagnostic> {
        let mut items = Vec::new();
        while self.at < self.tokens.len() {
            let command = self.and_or()?;
            let background = if self.peek_op(Operator::Background) {
                self.at += 1;
                true
            } else if self.peek_op(Operator::Semi) {
                self.at += 1;
                false
            } else {
                false
            };
            items.push(ListItem {
                command,
                background,
            });
        }
        Ok(Script { items })
    }
    fn and_or(&mut self) -> Result<AndOrAst, Diagnostic> {
        let first = self.pipeline()?;
        let mut rest = Vec::new();
        loop {
            let condition = if self.peek_op(Operator::And) {
                Condition::And
            } else if self.peek_op(Operator::Or) {
                Condition::Or
            } else {
                break;
            };
            self.at += 1;
            rest.push((condition, self.pipeline()?));
        }
        Ok(AndOrAst { first, rest })
    }
    fn pipeline(&mut self) -> Result<PipelineAst, Diagnostic> {
        let first = self.command()?;
        let start = first.span.start;
        let mut commands = vec![first];
        while self.peek_op(Operator::Pipe) {
            self.at += 1;
            commands.push(self.command()?);
        }
        if commands.len() > MAX_PIPELINE_STAGES {
            return Err(Diagnostic::new(
                start,
                commands.last().unwrap().span.end,
                "pipeline stage limit exceeded",
            ));
        }
        let end = commands.last().unwrap().span.end;
        self.bump_node(Span { start, end })?;
        Ok(PipelineAst {
            commands,
            span: Span { start, end },
        })
    }
    fn command(&mut self) -> Result<CommandAst, Diagnostic> {
        let token = self
            .take()
            .ok_or_else(|| Diagnostic::new(0, 0, "expected command"))?;
        let TokenKind::Word(name) = token.kind else {
            return Err(Diagnostic::new(
                token.span.start,
                token.span.end,
                "expected command name",
            ));
        };
        let mut args = Vec::new();
        let mut redirects = Vec::new();
        let mut end = token.span.end;
        while let Some(next) = self.tokens.get(self.at).cloned() {
            match next.kind {
                TokenKind::Word(word) => {
                    self.at += 1;
                    end = next.span.end;
                    args.push(Argument::Word(word));
                }
                TokenKind::Cap(name) => {
                    self.at += 1;
                    end = next.span.end;
                    args.push(Argument::Capability {
                        name,
                        span: next.span,
                    });
                }
                TokenKind::Op(op @ (Operator::In | Operator::Out | Operator::Err)) => {
                    self.at += 1;
                    let target = self.take().ok_or_else(|| {
                        Diagnostic::new(
                            next.span.start,
                            next.span.end,
                            "redirection requires a capability",
                        )
                    })?;
                    let TokenKind::Cap(name) = target.kind else {
                        return Err(Diagnostic::new(
                            target.span.start,
                            target.span.end,
                            "redirection target must be an unquoted capability",
                        ));
                    };
                    let kind = match op {
                        Operator::In => RedirectKind::Stdin,
                        Operator::Out => RedirectKind::Stdout,
                        _ => RedirectKind::Stderr,
                    };
                    end = target.span.end;
                    redirects.push(Redirect {
                        kind,
                        target: name,
                        span: Span {
                            start: next.span.start,
                            end,
                        },
                    });
                }
                TokenKind::Op(_) => break,
            }
            if args.len() > MAX_ARGS {
                return Err(Diagnostic::new(
                    token.span.start,
                    end,
                    "argument limit exceeded",
                ));
            }
        }
        self.bump_node(Span {
            start: token.span.start,
            end,
        })?;
        Ok(CommandAst {
            name,
            args,
            redirects,
            span: Span {
                start: token.span.start,
                end,
            },
        })
    }
}

fn expand(word: &Word, values: &BTreeMap<String, String>) -> Result<String, Diagnostic> {
    let mut out = String::new();
    for part in &word.parts {
        match part {
            WordPart::Literal(s) => out.push_str(s),
            WordPart::Value(name) => {
                out.push_str(values.get(name).map(String::as_str).unwrap_or(""))
            }
        }
        if out.len() > MAX_BINDING_BYTES {
            return Err(Diagnostic::new(
                word.span.start,
                word.span.end,
                "expanded word exceeds 4 KiB",
            ));
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Success,
    Returned(u8),
    Usage,
    Unavailable,
    Denied,
    BudgetExceeded,
    Faulted,
    Cancelled,
}
impl Status {
    pub fn succeeded(self) -> bool {
        self == Self::Success
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMode {
    Required,
    Optional,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgumentMode {
    ValuesOnly,
    ValuesOrCapabilities,
}

#[derive(Clone, Debug)]
pub struct CommandManifest {
    pub name: &'static str,
    pub abi: u16,
    pub min_args: usize,
    pub max_args: usize,
    pub argument_mode: ArgumentMode,
    pub stdin: StreamMode,
    pub stdout: StreamMode,
    pub stderr: StreamMode,
    pub memory_bytes: usize,
    pub operation_budget: u64,
    pub early_close_is_success: bool,
}

#[derive(Clone, Copy, Debug)]
enum Applet {
    Echo,
    Wc,
    False,
    Deny,
    Fault,
    Spin,
    Host(fn(&[String]) -> Result<String, Status>),
}

pub struct Command {
    manifest: CommandManifest,
    applet: Applet,
}
impl Resource for Command {
    fn kind(&self) -> &'static str {
        "command"
    }
    fn describe(&self) -> String {
        format!("{} ABI {}", self.manifest.name, self.manifest.abi)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    Normal,
    Failed(Status),
    Cancelled,
}

struct StreamState {
    queue: VecDeque<Vec<u8>>,
    writer: Option<CloseReason>,
    reader: Option<CloseReason>,
}
pub struct ByteStream {
    state: SpinLock<StreamState>,
    readable: WaitQueue,
    writable: WaitQueue,
    peak_depth: AtomicUsize,
}
impl ByteStream {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: SpinLock::new(StreamState {
                queue: VecDeque::with_capacity(STREAM_BUFFER_CHUNKS),
                writer: None,
                reader: None,
            }),
            readable: WaitQueue::new(),
            writable: WaitQueue::new(),
            peak_depth: AtomicUsize::new(0),
        })
    }
    pub async fn send(&self, bytes: Vec<u8>) -> Result<(), CloseReason> {
        if bytes.is_empty() || bytes.len() > MAX_STREAM_CHUNK_BYTES {
            return Err(CloseReason::Failed(Status::Usage));
        }
        let mut pending = Some(bytes);
        loop {
            let wait = self.writable.wait();
            {
                let mut state = self.state.lock();
                if let Some(reason) = &state.reader {
                    return Err(reason.clone());
                }
                if state.writer.is_some() {
                    return Err(state.writer.clone().unwrap());
                }
                if state.queue.len() < STREAM_BUFFER_CHUNKS {
                    state.queue.push_back(pending.take().unwrap());
                    self.peak_depth.fetch_max(state.queue.len(), Ordering::Relaxed);
                    drop(state);
                    self.readable.wake_all();
                    return Ok(());
                }
            }
            wait.await;
        }
    }
    pub async fn recv(&self) -> Result<Option<Vec<u8>>, CloseReason> {
        loop {
            let wait = self.readable.wait();
            {
                let mut state = self.state.lock();
                if let Some(chunk) = state.queue.pop_front() {
                    drop(state);
                    self.writable.wake_all();
                    return Ok(Some(chunk));
                }
                if let Some(reason) = &state.writer {
                    return match reason {
                        CloseReason::Normal => Ok(None),
                        other => Err(other.clone()),
                    };
                }
                if let Some(reason) = &state.reader {
                    return Err(reason.clone());
                }
            }
            wait.await;
        }
    }
    pub fn close_write(&self, reason: CloseReason) {
        let mut s = self.state.lock();
        if s.writer.is_none() {
            if reason != CloseReason::Normal {
                s.queue.clear();
            }
            s.writer = Some(reason);
        }
        drop(s);
        self.readable.wake_all();
        self.writable.wake_all();
    }
    pub fn close_read(&self, reason: CloseReason) {
        let mut s = self.state.lock();
        if s.reader.is_none() {
            s.queue.clear();
            s.reader = Some(reason);
        }
        drop(s);
        self.readable.wake_all();
        self.writable.wake_all();
    }
    pub fn depth(&self) -> usize {
        self.state.lock().queue.len()
    }
    pub fn peak_depth(&self) -> usize { self.peak_depth.load(Ordering::Relaxed) }
}
impl Resource for ByteStream {
    fn kind(&self) -> &'static str {
        "byte-stream"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct OutputSink {
    bytes: SpinLock<Vec<u8>>,
}
impl OutputSink {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            bytes: SpinLock::new(Vec::new()),
        })
    }
    fn write(&self, bytes: &[u8]) -> Result<(), Status> {
        let mut out = self.bytes.lock();
        if out
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_CAPTURED_OUTPUT)
        {
            return Err(Status::BudgetExceeded);
        }
        out.extend_from_slice(bytes);
        Ok(())
    }
    pub fn take_string(&self) -> String {
        let mut out = self.bytes.lock();
        let bytes = core::mem::take(&mut *out);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}
impl Resource for OutputSink {
    fn kind(&self) -> &'static str {
        "byte-sink"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Ephemeral, non-delegable facade over one durable derivation. The broker
/// retains only a revocable parent token; every operation revalidates the
/// durable ancestry, and the installed stage cap deliberately omits GRANT and
/// REVOKE.
pub struct PersistentProxy<T: Resource> {
    parent: Revocable<T>,
    rights: Rights,
}

impl<T: Resource> PersistentProxy<T> {
    pub fn try_with<R>(&self, operation: impl FnOnce(&T) -> R) -> Result<R, CapError> {
        self.parent.try_with(operation)
    }
    pub const fn rights(&self) -> Rights { self.rights }
}

impl<T: Resource> Resource for PersistentProxy<T> {
    fn kind(&self) -> &'static str { "persistent-proxy" }
    fn describe(&self) -> String { format!("ephemeral {} proxy", self.rights) }
    fn as_any(&self) -> &dyn Any { self }
}

/// Trusted admission broker for persistent resources. Generic `grant` remains
/// fail-closed; this creates a fresh volatile proxy rather than a durable child
/// or an object-identity registry entry.
pub fn install_persistent_proxy<T: Resource>(source: &CSpace, cap: Cap, rights: Rights, stage: &mut CSpace) -> Result<Cap, CapError> {
    if rights.contains(Rights::GRANT) || rights.contains(Rights::REVOKE) || rights.contains(Rights::INVOKE) { return Err(CapError::Amplification); }
    let parent = source.persistent_witness::<T>(cap, rights)?.into_revocable();
    Ok(stage.mint(Arc::new(PersistentProxy { parent, rights }), rights))
}

#[derive(Clone)]
struct JobControl {
    live: Arc<AtomicBool>,
    pipes: Vec<Arc<ByteStream>>,
}
impl JobControl {
    fn fail(&self, status: Status) {
        if self.live.swap(false, Ordering::AcqRel) {
            let reason = if status == Status::Cancelled {
                CloseReason::Cancelled
            } else {
                CloseReason::Failed(status)
            };
            for p in &self.pipes {
                p.close_write(reason.clone());
                p.close_read(reason.clone());
            }
        }
    }
}

#[derive(Clone)]
enum LocalIo {
    Closed,
    Stream(Cap),
    Sink(Cap),
}
struct PlannedStage {
    cspace: Arc<SpinLock<CSpace>>,
    command: Cap,
    args: Vec<String>,
    stdin: LocalIo,
    stdout: LocalIo,
    _stderr: LocalIo,
    result: Arc<SpinLock<Option<Status>>>,
}
type RunningStage = (TaskHandle, Arc<SpinLock<Option<Status>>>, Arc<SpinLock<CSpace>>);

struct BackgroundJob {
    supervisor: TaskHandle,
    stages: Vec<TaskHandle>,
    control: JobControl,
    report: Arc<SpinLock<Option<JobReport>>>,
}

#[derive(Clone, Debug)]
pub struct StageReport {
    pub task: exec::TaskId,
    pub status: Status,
}
#[derive(Clone, Debug)]
pub struct JobReport {
    pub id: u64,
    pub status: Status,
    pub stages: Vec<StageReport>,
    pub output: String,
    pub peak_pipe_depth: usize,
}

pub struct Session {
    cspace: Arc<SpinLock<CSpace>>,
    commands: BTreeMap<String, Cap>,
    capabilities: BTreeMap<String, Cap>,
    values: BTreeMap<String, String>,
    console: Arc<OutputSink>,
    next_job: AtomicU64,
    revoke_next_job: Option<Cap>,
    cancel_next_job: bool,
    jobs: BTreeMap<u64, BackgroundJob>,
    external_cancel: Option<Arc<AtomicBool>>,
}

impl Session {
    pub fn new() -> Self {
        Self::with_cspace(Arc::new(SpinLock::new(CSpace::new("vsh"))))
    }

    pub fn with_cspace(cspace: Arc<SpinLock<CSpace>>) -> Self {
        let console = OutputSink::new();
        let console_cap = cspace.lock().mint(
            console.clone(),
            Rights::WRITE.union(Rights::GRANT).union(Rights::REVOKE),
        );
        let mut capabilities = BTreeMap::new();
        capabilities.insert("console".to_string(), console_cap);
        let mut session = Self {
            cspace,
            commands: BTreeMap::new(),
            capabilities,
            values: BTreeMap::new(),
            console,
            next_job: AtomicU64::new(1),
            revoke_next_job: None,
            cancel_next_job: false,
            jobs: BTreeMap::new(),
            external_cancel: None,
        };
        session.install("echo", Applet::Echo, 0, MAX_ARGS, StreamMode::Closed, true);
        session.install("wc", Applet::Wc, 0, 0, StreamMode::Required, false);
        session.install("false", Applet::False, 0, 0, StreamMode::Closed, false);
        session.install("deny", Applet::Deny, 0, 0, StreamMode::Closed, false);
        session.install("fault", Applet::Fault, 0, 0, StreamMode::Closed, false);
        session.install("spin", Applet::Spin, 0, 0, StreamMode::Closed, false);
        session
    }
    fn install(
        &mut self,
        name: &'static str,
        applet: Applet,
        min_args: usize,
        max_args: usize,
        stdin: StreamMode,
        early: bool,
    ) {
        let command = Arc::new(Command {
            manifest: CommandManifest {
                name,
                abi: 1,
                min_args,
                max_args,
                argument_mode: ArgumentMode::ValuesOnly,
                stdin,
                stdout: StreamMode::Required,
                stderr: StreamMode::Optional,
                memory_bytes: DEFAULT_STAGE_MEMORY,
                operation_budget: 65_536,
                early_close_is_success: early,
            },
            applet,
        });
        let cap = self.cspace.lock().mint(
            command,
            Rights::INVOKE.union(Rights::GRANT).union(Rights::REVOKE),
        );
        self.commands.insert(name.to_string(), cap);
    }
    /// Boot-policy hook for one audited, in-tree control command. Possession
    /// of the resulting Command capability is the authority to invoke the
    /// operation; the function pointer is never accepted from shell text.
    pub fn install_host_command(
        &mut self,
        name: &'static str,
        min_args: usize,
        max_args: usize,
        command: fn(&[String]) -> Result<String, Status>,
    ) {
        self.install(name, Applet::Host(command), min_args, max_args, StreamMode::Closed, false);
    }
    pub fn set_value(&mut self, name: &str, value: &str) -> Result<(), Diagnostic> {
        if !valid_name(name) {
            return Err(Diagnostic::new(0, name.len(), "invalid binding name"));
        }
        if value.len() > MAX_BINDING_BYTES {
            return Err(Diagnostic::new(0, value.len(), "binding exceeds 4 KiB"));
        }
        if !self.values.contains_key(name) && self.values.len() >= MAX_BINDINGS {
            return Err(Diagnostic::new(0, 0, "value binding limit exceeded"));
        }
        self.values.insert(name.to_string(), value.to_string());
        Ok(())
    }
    pub fn bind_capability(&mut self, name: &str, cap: Cap) -> Result<(), Diagnostic> {
        if !valid_name(name) {
            return Err(Diagnostic::new(
                0,
                name.len(),
                "invalid capability binding name",
            ));
        }
        self.cspace.lock()
            .rights_of(cap)
            .map_err(|_| Diagnostic::new(0, name.len(), "invalid capability"))?;
        self.capabilities.insert(name.to_string(), cap);
        Ok(())
    }
    /// Supervisor-only boot wiring for a resource intentionally exposed to
    /// this shell session. Text input can never reach this operation.
    pub fn install_capability(
        &mut self,
        name: &str,
        resource: Arc<dyn Resource>,
        rights: Rights,
    ) -> Result<Cap, Diagnostic> {
        if !valid_name(name) || self.capabilities.len() >= 256 {
            return Err(Diagnostic::new(
                0,
                name.len(),
                "capability binding rejected",
            ));
        }
        let cap = self.cspace.lock().mint(resource, rights);
        self.capabilities.insert(name.to_string(), cap);
        Ok(cap)
    }
    /// Replace a visible command with a non-delegable child. This is useful to
    /// prove that admission checks GRANT before executing any earlier stage.
    pub fn attenuate_command_for_test(&mut self, name: &str) -> bool {
        let Some(source) = self.commands.get(name).copied() else {
            return false;
        };
        let Ok(child) = self.cspace.lock().derive(source, Rights::INVOKE) else {
            return false;
        };
        self.commands.insert(name.to_string(), child);
        true
    }
    pub fn remove_command(&mut self, name: &str) {
        self.commands.remove(name);
    }
    pub fn console_cap(&self) -> Cap {
        self.capabilities["console"]
    }
    pub fn revoke_capability(&mut self, name: &str) -> bool {
        self.capabilities
            .get(name)
            .copied()
            .is_some_and(|cap| self.cspace.lock().revoke(cap).is_ok())
    }
    /// Acceptance hook modelling an asynchronous parent revocation after a Job
    /// is published but before its next resource operation.
    pub fn revoke_during_next_job_for_test(&mut self, name: &str) -> bool {
        let Some(cap) = self.capabilities.get(name).copied() else { return false; };
        self.revoke_next_job = Some(cap); true
    }
    /// Acceptance hook for the same supervisor path used by foreground Ctrl-C.
    pub fn cancel_next_job_for_test(&mut self) { self.cancel_next_job = true; }

    pub async fn execute(&mut self, source: &str) -> Result<Vec<JobReport>, Diagnostic> {
        let script = parse(source)?;
        let mut reports = Vec::new();
        for item in script.items {
            if let Some(special) = self.special_form(&item, source).await? {
                reports.extend(special);
                continue;
            }
            if item.background && !item.command.rest.is_empty() {
                return Err(Diagnostic::new(0, source.len(), "background conditional lists are not supported"));
            }
            let Some(mut report) = self.run_pipeline(&item.command.first, item.background).await? else { continue };
            let mut status = report.status; reports.push(report);
            for (condition, pipeline) in item.command.rest {
                let run = match condition {
                    Condition::And => status.succeeded(),
                    Condition::Or => !status.succeeded(),
                };
                if run {
                    report = self.run_pipeline(&pipeline, false).await?.unwrap();
                    status = report.status;
                    reports.push(report);
                }
            }
        }
        Ok(reports)
    }

    pub async fn execute_cancellable(&mut self, source: &str, cancel: Arc<AtomicBool>) -> Result<Vec<JobReport>, Diagnostic> {
        self.external_cancel = Some(cancel);
        let result = self.execute(source).await;
        self.external_cancel = None;
        result
    }

    async fn special_form(&mut self, item: &ListItem, _source: &str) -> Result<Option<Vec<JobReport>>, Diagnostic> {
        if !item.command.rest.is_empty() || item.command.first.commands.len() != 1 { return Ok(None); }
        let command = &item.command.first.commands[0];
        let name = expand(&command.name, &self.values)?;
        if !matches!(name.as_str(), "let" | "jobs" | "wait" | "cancel") { return Ok(None); }
        if item.background { return Err(Diagnostic::new(command.span.start, command.span.end, "special form must be foreground")); }
        if !command.redirects.is_empty() { return Err(Diagnostic::new(command.span.start, command.span.end, "special form cannot redirect")); }
        let mut args = Vec::new();
        for arg in &command.args { match arg { Argument::Word(word) => args.push(expand(word, &self.values)?), Argument::Capability { span, .. } => return Err(Diagnostic::new(span.start, span.end, "special form requires value arguments")) } }
        match name.as_str() {
            "let" => {
                if args.len() != 2 { return Err(Diagnostic::new(command.span.start, command.span.end, "usage: let NAME VALUE")); }
                self.set_value(&args[0], &args[1])?; Ok(Some(Vec::new()))
            }
            "jobs" => {
                if !args.is_empty() { return Err(Diagnostic::new(command.span.start, command.span.end, "usage: jobs")); }
                let mut output = String::new();
                for (id, job) in &self.jobs { let state = if job.supervisor.try_exit().is_some() { "done" } else { "running" }; output.push_str(&format!("%{id} {state}\n")); }
                Ok(Some(vec![JobReport { id: 0, status: Status::Success, stages: Vec::new(), output, peak_pipe_depth: 0 }]))
            }
            "wait" => {
                let id = parse_job_id(&args, command.span)?;
                let job = self.jobs.remove(&id).ok_or_else(|| Diagnostic::new(command.span.start, command.span.end, "unknown job"))?;
                let _ = job.supervisor.join().await;
                let report = job.report.lock().take().ok_or_else(|| Diagnostic::new(command.span.start, command.span.end, "job report unavailable"))?;
                Ok(Some(vec![report]))
            }
            "cancel" => {
                let id = parse_job_id(&args, command.span)?;
                let job = self.jobs.get(&id).ok_or_else(|| Diagnostic::new(command.span.start, command.span.end, "unknown job"))?;
                job.control.fail(Status::Cancelled); for stage in &job.stages { let _ = stage.cancel(); }
                Ok(Some(Vec::new()))
            }
            _ => unreachable!(),
        }
    }

    async fn run_pipeline(&mut self, ast: &PipelineAst, background: bool) -> Result<Option<JobReport>, Diagnostic> {
        let id = self.next_job.fetch_add(1, Ordering::Relaxed);
        let mut admission = CSpace::new("vsh-admission");
        let mut pipes = Vec::new();
        let mut roots = Vec::new();
        for _ in 1..ast.commands.len() {
            let p = ByteStream::new();
            let root = admission.mint(
                p.clone(),
                Rights::SEND
                    .union(Rights::RECV)
                    .union(Rights::GRANT)
                    .union(Rights::REVOKE),
            );
            pipes.push(p);
            roots.push(root);
        }
        let mut stages = Vec::new();
        for (index, command_ast) in ast.commands.iter().enumerate() {
            let command_name = expand(&command_ast.name, &self.values)?;
            let command_source = self.commands.get(&command_name).copied().ok_or_else(|| {
                Diagnostic::new(
                    command_ast.name.span.start,
                    command_ast.name.span.end,
                    "unknown command",
                )
            })?;
            let manifest = self
                .cspace
                .lock()
                .lookup_as::<Command>(command_source, Rights::INVOKE)
                .map_err(|_| {
                    Diagnostic::new(
                        command_ast.name.span.start,
                        command_ast.name.span.end,
                        "command is not invokable",
                    )
                })?
                .manifest
                .clone();
            if manifest.memory_bytes > MAX_STAGE_MEMORY {
                return Err(Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "stage memory request exceeds policy",
                ));
            }
            let mut args = Vec::new();
            let mut expanded_bytes = 0usize;
            for arg in &command_ast.args {
                match arg {
                    Argument::Word(word) => {
                        let value = expand(word, &self.values)?;
                        expanded_bytes =
                            expanded_bytes.checked_add(value.len()).ok_or_else(|| {
                                Diagnostic::new(
                                    word.span.start,
                                    word.span.end,
                                    "expanded argument size overflow",
                                )
                            })?;
                        args.push(value);
                    }
                    Argument::Capability { span, .. } => {
                        return Err(Diagnostic::new(
                            span.start,
                            span.end,
                            "command accepts value arguments only",
                        ))
                    }
                }
            }
            if args.len() < manifest.min_args || args.len() > manifest.max_args {
                return Err(Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "command argument count rejected by manifest",
                ));
            }
            if expanded_bytes > MAX_EXPANDED_BYTES {
                return Err(Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "expanded arguments exceed 16 KiB",
                ));
            }
            let mut stage = CSpace::new(&format!("vsh-job-{id}-stage-{index}"));
            let command = cap::grant(&self.cspace.lock(), command_source, Rights::INVOKE, &mut stage)
                .map_err(|_| {
                    Diagnostic::new(
                        command_ast.span.start,
                        command_ast.span.end,
                        "missing GRANT on command",
                    )
                })?;
            let stdin = if index > 0 {
                LocalIo::Stream(
                    cap::grant(&admission, roots[index - 1], Rights::RECV, &mut stage).map_err(
                        |_| {
                            Diagnostic::new(
                                command_ast.span.start,
                                command_ast.span.end,
                                "stdin admission failed",
                            )
                        },
                    )?,
                )
            } else {
                LocalIo::Closed
            };
            let stdout = if index + 1 < ast.commands.len() {
                LocalIo::Stream(
                    cap::grant(&admission, roots[index], Rights::SEND, &mut stage).map_err(
                        |_| {
                            Diagnostic::new(
                                command_ast.span.start,
                                command_ast.span.end,
                                "stdout admission failed",
                            )
                        },
                    )?,
                )
            } else {
                let console = self.capabilities["console"];
                LocalIo::Sink(cap::grant(&self.cspace.lock(), console, Rights::WRITE, &mut stage)
                    .map_err(|_| Diagnostic::new(command_ast.span.start, command_ast.span.end, "default stdout cannot be delegated"))?)
            };
            let mut stdin = stdin;
            let mut stdout = stdout;
            let console = self.capabilities["console"];
            let mut stderr = LocalIo::Sink(cap::grant(&self.cspace.lock(), console, Rights::WRITE, &mut stage)
                .map_err(|_| Diagnostic::new(command_ast.span.start, command_ast.span.end, "default stderr cannot be delegated"))?);
            for redirect in &command_ast.redirects {
                let source = self
                    .capabilities
                    .get(&redirect.target)
                    .copied()
                    .ok_or_else(|| {
                        Diagnostic::new(
                            redirect.span.start,
                            redirect.span.end,
                            "unknown capability",
                        )
                    })?;
                match redirect.kind {
                    RedirectKind::Stdin => {
                        let object = self.cspace.lock().lookup(source, Rights::RECV).map_err(|_| {
                            Diagnostic::new(
                                redirect.span.start,
                                redirect.span.end,
                                "input capability lacks required rights",
                            )
                        })?;
                        if object.kind() != "byte-stream" {
                            return Err(Diagnostic::new(
                                redirect.span.start,
                                redirect.span.end,
                                "input capability has wrong resource kind",
                            ));
                        }
                        stdin = LocalIo::Stream(
                            cap::grant(&self.cspace.lock(), source, Rights::RECV, &mut stage).map_err(
                                |_| {
                                    Diagnostic::new(
                                        redirect.span.start,
                                        redirect.span.end,
                                        "input capability cannot be delegated",
                                    )
                                },
                            )?,
                        );
                    }
                    RedirectKind::Stdout | RedirectKind::Stderr => {
                        let object = self.cspace.lock().lookup(source, Rights::WRITE).map_err(|_| {
                            Diagnostic::new(
                                redirect.span.start,
                                redirect.span.end,
                                "output capability lacks required rights",
                            )
                        })?;
                        if object.kind() != "byte-sink" {
                            return Err(Diagnostic::new(
                                redirect.span.start,
                                redirect.span.end,
                                "output capability has wrong resource kind",
                            ));
                        }
                        let local = LocalIo::Sink(
                            cap::grant(&self.cspace.lock(), source, Rights::WRITE, &mut stage).map_err(
                                |_| {
                                    Diagnostic::new(
                                        redirect.span.start,
                                        redirect.span.end,
                                        "output capability cannot be delegated",
                                    )
                                },
                            )?,
                        );
                        if redirect.kind == RedirectKind::Stdout {
                            stdout = local;
                        } else {
                            stderr = local;
                        }
                    }
                }
            }
            if manifest.stdin == StreamMode::Required && matches!(stdin, LocalIo::Closed) {
                return Err(Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "command requires stdin",
                ));
            }
            if manifest.stdin == StreamMode::Closed && !matches!(stdin, LocalIo::Closed) {
                return Err(Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "command requires closed stdin",
                ));
            }
            if manifest.stdout == StreamMode::Required && matches!(stdout, LocalIo::Closed) {
                return Err(Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "command requires stdout or redirection",
                ));
            }
            stages.push(PlannedStage {
                cspace: Arc::new(SpinLock::new(stage)),
                command,
                args,
                stdin,
                stdout,
                _stderr: stderr,
                result: Arc::new(SpinLock::new(None)),
            });
        }
        let job = JobControl {
            live: Arc::new(AtomicBool::new(true)),
            pipes: pipes.clone(),
        };
        let mut running: Vec<RunningStage> = Vec::new();
        for stage in stages {
            let result = stage.result.clone();
            let cspace = stage.cspace.clone();
            let control = job.clone();
            let handle = exec::spawn_tracked("vsh-stage", async move {
                let status = run_stage(&stage, &control).await;
                *stage.result.lock() = Some(status);
                close_stage_outputs(&stage, status);
                if severe(status) {
                    control.fail(status);
                }
            });
            running.push((handle, result, cspace));
        }
        if let Some(cap) = self.revoke_next_job.take() { let _ = self.cspace.lock().revoke(cap); }
        if core::mem::take(&mut self.cancel_next_job) {
            job.fail(Status::Cancelled);
            for (handle, _, _) in &running { let _ = handle.cancel(); }
        }
        if let Some(cancel) = self.external_cancel.take() {
            let control = job.clone();
            let handles: Vec<_> = running.iter().map(|(handle, _, _)| handle.clone()).collect();
            exec::spawn("vsh-ctrl-c", async move {
                while control.live.load(Ordering::Acquire) && !cancel.load(Ordering::Acquire) { exec::yield_now().await; }
                if cancel.load(Ordering::Acquire) { control.fail(Status::Cancelled); for handle in &handles { let _ = handle.cancel(); } }
            });
        }
        if background {
            let report = Arc::new(SpinLock::new(None)); let report_task = report.clone();
            let handles = running.iter().map(|(handle, _, _)| handle.clone()).collect();
            let control = job.clone(); let console = self.console.clone();
            let supervisor = exec::spawn_tracked("vsh-job-supervisor", async move {
                *report_task.lock() = Some(finish_job(id, running, admission, job, pipes, console).await);
            });
            self.jobs.insert(id, BackgroundJob { supervisor, stages: handles, control, report });
            return Ok(Some(JobReport { id, status: Status::Success, stages: Vec::new(), output: format!("[%{id}]\n"), peak_pipe_depth: 0 }));
        }
        Ok(Some(finish_job(id, running, admission, job, pipes, self.console.clone()).await))
    }
}

fn parse_job_id(args: &[String], span: Span) -> Result<u64, Diagnostic> {
    if args.len() != 1 || !args[0].starts_with('%') { return Err(Diagnostic::new(span.start, span.end, "job id must be %N")); }
    args[0][1..].parse().map_err(|_| Diagnostic::new(span.start, span.end, "invalid job id"))
}

async fn finish_job(id: u64, running: Vec<RunningStage>, mut admission: CSpace, job: JobControl, pipes: Vec<Arc<ByteStream>>, console: Arc<OutputSink>) -> JobReport {
    let mut stage_reports = Vec::new();
    for (handle, result, cspace) in &running {
        let exit = handle.join().await;
        let status = if exit.state() == TaskState::Faulted { Status::Faulted } else if exit.state() == TaskState::Cancelled { Status::Cancelled } else { (*result.lock()).unwrap_or(Status::Faulted) };
        stage_reports.push(StageReport { task: handle.id(), status });
        if severe(status) { job.fail(status); }
        cspace.lock().revoke_all();
    }
    admission.revoke_all(); job.live.store(false, Ordering::Release);
    JobReport { id, status: aggregate(&stage_reports), stages: stage_reports, output: console.take_string(), peak_pipe_depth: pipes.iter().map(|p| p.peak_depth()).max().unwrap_or(0) }
}

fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.first().copied().is_some_and(is_name_start) && b[1..].iter().copied().all(is_name_continue)
}
fn severe(status: Status) -> bool {
    matches!(
        status,
        Status::Faulted | Status::BudgetExceeded | Status::Denied | Status::Cancelled
    )
}
fn rank(status: Status) -> u8 {
    match status {
        Status::Faulted => 5,
        Status::BudgetExceeded => 4,
        Status::Denied => 3,
        Status::Cancelled => 2,
        Status::Success => 0,
        _ => 1,
    }
}
fn aggregate(stages: &[StageReport]) -> Status {
    let mut winner = Status::Success;
    let mut winner_rank = 0;
    for stage in stages {
        let r = rank(stage.status);
        if r >= winner_rank && stage.status != Status::Success {
            winner = stage.status;
            winner_rank = r;
        }
    }
    winner
}

async fn run_stage(stage: &PlannedStage, job: &JobControl) -> Status {
    let command = match stage
        .cspace
        .lock()
        .lookup_as::<Command>(stage.command, Rights::INVOKE)
    {
        Ok(c) => c,
        Err(_) => return Status::Denied,
    };
    if !job.live.load(Ordering::Acquire) {
        return Status::Cancelled;
    }
    match command.applet {
        Applet::Echo => {
            let mut bytes = stage.args.join(" ").into_bytes();
            bytes.push(b'\n');
            write_all(&stage.cspace, &stage.stdout, bytes, job).await
        }
        Applet::Wc => {
            let mut bytes = 0usize;
            let mut words = 0usize;
            let mut lines = 0usize;
            let mut in_word = false;
            loop {
                let chunk = match read_chunk(&stage.cspace, &stage.stdin).await {
                    Ok(Some(c)) => c,
                    Ok(None) => break,
                    Err(s) => return s,
                };
                bytes += chunk.len();
                for b in chunk {
                    if b == b'\n' {
                        lines += 1;
                    }
                    let space = b.is_ascii_whitespace();
                    if !space && !in_word {
                        words += 1;
                    }
                    in_word = !space;
                }
            }
            write_all(
                &stage.cspace,
                &stage.stdout,
                format!("{lines} {words} {bytes}\n").into_bytes(),
                job,
            )
            .await
        }
        Applet::False => Status::Returned(1),
        Applet::Deny => Status::Denied,
        Applet::Fault => Status::Faulted,
        Applet::Spin => {
            while job.live.load(Ordering::Acquire) { exec::yield_now().await; }
            Status::Cancelled
        }
        Applet::Host(command) => match command(&stage.args) {
            Ok(output) if output.is_empty() => Status::Success,
            Ok(output) => write_all(&stage.cspace, &stage.stdout, output.into_bytes(), job).await,
            Err(status) => status,
        },
    }
}

async fn read_chunk(
    space: &Arc<SpinLock<CSpace>>,
    io: &LocalIo,
) -> Result<Option<Vec<u8>>, Status> {
    let LocalIo::Stream(cap) = io else {
        return Ok(None);
    };
    let stream = space
        .lock()
        .lookup_as::<ByteStream>(*cap, Rights::RECV)
        .map_err(|_| Status::Denied)?;
    stream.recv().await.map_err(|r| match r {
        CloseReason::Cancelled => Status::Cancelled,
        CloseReason::Failed(s) => s,
        CloseReason::Normal => Status::Unavailable,
    })
}

async fn write_all(
    space: &Arc<SpinLock<CSpace>>,
    io: &LocalIo,
    bytes: Vec<u8>,
    job: &JobControl,
) -> Status {
    if !job.live.load(Ordering::Acquire) {
        return Status::Cancelled;
    }
    match io {
        LocalIo::Closed => Status::Unavailable,
        LocalIo::Sink(cap) => {
            let sink = match space.lock().lookup_as::<OutputSink>(*cap, Rights::WRITE) {
                Ok(s) => s,
                Err(_) => return Status::Denied,
            };
            if !job.live.load(Ordering::Acquire) {
                return Status::Cancelled;
            }
            match sink.write(&bytes) {
                Ok(()) => Status::Success,
                Err(s) => s,
            }
        }
        LocalIo::Stream(cap) => {
            let stream = match space.lock().lookup_as::<ByteStream>(*cap, Rights::SEND) {
                Ok(s) => s,
                Err(_) => return Status::Denied,
            };
            for chunk in bytes.chunks(MAX_STREAM_CHUNK_BYTES) {
                if !job.live.load(Ordering::Acquire) {
                    return Status::Cancelled;
                }
                if let Err(reason) = stream.send(chunk.to_vec()).await {
                    return match reason {
                        CloseReason::Cancelled => Status::Cancelled,
                        CloseReason::Failed(s) => s,
                        CloseReason::Normal => Status::Unavailable,
                    };
                }
            }
            Status::Success
        }
    }
}

fn close_stage_outputs(stage: &PlannedStage, status: Status) {
    let reason = if status == Status::Success {
        CloseReason::Normal
    } else if status == Status::Cancelled {
        CloseReason::Cancelled
    } else {
        CloseReason::Failed(status)
    };
    if let LocalIo::Stream(cap) = stage.stdout {
        if let Ok(stream) = stage
            .cspace
            .lock()
            .lookup_as::<ByteStream>(cap, Rights::SEND)
        {
            stream.close_write(reason);
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}
