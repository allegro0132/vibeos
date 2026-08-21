//! Capability-native shell parser, planner, streams, audited applets, and
//! bounded scripting.
//!
//! This module is intentionally portable: the kernel supplies the interactive
//! line editor, while parsing and Job execution are exercised on the host.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::future::{poll_fn, Future};
use core::num::NonZeroU64;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::Poll;

use vibeos_component_host::{
    ByteStream as ComponentByteStream, ByteStreamReader, ByteStreamSupervisor, ByteStreamWriter,
    StreamCloseOutcome,
};
use vibeos_core::cap::{self, CSpace, CSpaceIdentity, Cap, CapError, Resource, Revocable, Rights};
use vibeos_core::exec::{
    self, OneShotWaitError, OneShotWaitQueue, TaskHandle, TaskState, WaitQueue,
};
use vibeos_core::heap;
use vibeos_core::sync::SpinLock;

pub const MAX_INPUT_BYTES: usize = 4 * 1024;
pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
pub const MAX_TOKENS: usize = 256;
pub const MAX_AST_NODES: usize = 512;
pub const MAX_PARSER_NESTING: usize = 32;
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
pub const MAX_COMPONENT_RESOURCES: u16 = 256;
pub const MAX_FUNCTIONS: usize = 64;
pub const MAX_FUNCTION_CALL_DEPTH: usize = 32;
pub const MAX_LOOP_ITERATIONS: usize = 256;
pub const MAX_COMMAND_SUBSTITUTION_DEPTH: usize = 8;
pub const MAX_SCRIPT_CALL_DEPTH: usize = 8;
/// Maximum command-string size accepted by the deliberately small SSH `exec`
/// profile. The general interactive shell retains [`MAX_INPUT_BYTES`].
pub const SSH_EXEC_MAX_INPUT_BYTES: usize = 1024;
/// Exact managed command world authorized for the C5.3 SSH stream path.
pub const VIBE_STREAM_FILTER_WORLD: &str = "vibe:stream/filter@1.0.0";

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
    Command { source: String, span: Span },
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
    pub statements: Vec<Statement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    Command(ListItem),
    If {
        condition: AndOrAst,
        then_branch: Script,
        else_branch: Option<Script>,
        span: Span,
    },
    While {
        condition: AndOrAst,
        body: Script,
        span: Span,
    },
    Function {
        name: String,
        params: Vec<String>,
        body: Script,
        span: Span,
    },
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
    LeftBrace,
    RightBrace,
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
    b.is_ascii_whitespace() || b"|&;<>{}".contains(&b)
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

fn lex(source: &str, max_input_bytes: usize) -> Result<Vec<Token>, Diagnostic> {
    if source.len() > max_input_bytes {
        return Err(Diagnostic::new(
            max_input_bytes,
            source.len(),
            "source exceeds its byte limit",
        ));
    }
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' || bytes[i] == b'\r' {
            let start = i;
            if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                i += 2;
            } else {
                i += 1;
            }
            if !out.last().is_some_and(|token: &Token| {
                matches!(
                    token.kind,
                    TokenKind::Op(Operator::Semi | Operator::Background)
                )
            }) {
                out.push(Token {
                    kind: TokenKind::Op(Operator::Semi),
                    span: Span { start, end: i },
                });
            }
            continue;
        }
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
            b'{' => (Some(Operator::LeftBrace), 1),
            b'}' => (Some(Operator::RightBrace), 1),
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
            if bytes.get(*i) == Some(&b'(') {
                *i += 1;
                let command_start = *i;
                let command_end = scan_command_substitution(source, i, value_start)?;
                parts.push(WordPart::Command {
                    source: source[command_start..command_end].to_string(),
                    span: Span {
                        start: value_start,
                        end: *i,
                    },
                });
                continue;
            }
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

fn scan_command_substitution(
    source: &str,
    at: &mut usize,
    substitution_start: usize,
) -> Result<usize, Diagnostic> {
    let bytes = source.as_bytes();
    let mut depth = 1usize;
    let mut quote = 0u8;
    while *at < bytes.len() {
        let b = bytes[*at];
        if b == b'\\' && quote != b'\'' {
            *at += 1;
            if *at >= bytes.len() {
                return Err(Diagnostic::new(
                    substitution_start,
                    *at,
                    "unterminated command substitution",
                ));
            }
            *at += 1;
            continue;
        }
        if quote == 0 && (b == b'\'' || b == b'"') {
            quote = b;
            *at += 1;
            continue;
        }
        if quote != 0 && b == quote {
            quote = 0;
            *at += 1;
            continue;
        }
        if quote == 0 && b == b'$' && bytes.get(*at + 1) == Some(&b'(') {
            depth += 1;
            *at += 2;
            continue;
        }
        if quote == 0 && b == b')' {
            depth -= 1;
            let end = *at;
            *at += 1;
            if depth == 0 {
                return Ok(end);
            }
            continue;
        }
        *at += 1;
    }
    Err(Diagnostic::new(
        substitution_start,
        *at,
        "unterminated command substitution",
    ))
}

pub fn parse(source: &str) -> Result<Script, Diagnostic> {
    parse_with_limit(source, MAX_INPUT_BYTES)
}

pub fn parse_script(source: &str) -> Result<Script, Diagnostic> {
    parse_with_limit(source, MAX_SCRIPT_BYTES)
}

/// Validate the command language admitted by an SSH `exec` request.
///
/// This profile accepts one foreground invocation of `echo`, `true`, or
/// `false`. Words may use quoting and escaping to produce literals, but no
/// shell value/capability expansion or command substitution is performed.
pub fn validate_ssh_exec(source: &str) -> Result<(), Diagnostic> {
    validate_ssh_exec_with_policy(source, |_| false).map(|_| ())
}

/// Build the fail-closed diagnostic used when the trusted SSH platform's
/// captured Component descriptor no longer matches current image/session
/// policy immediately before installation.
pub fn ssh_exec_component_policy_rejected(command_name: &str) -> Diagnostic {
    Diagnostic::new(0, command_name.len(), "SSH component policy changed")
}

/// Validate the restricted SSH exec grammar while allowing one exact command
/// name selected by trusted image/session policy.
///
/// This does not install the command or grant authority. The session must
/// still install an exactly matching [`SshExecComponentPolicy`] before
/// execution. Keeping parsing here lets an SSH protocol frontend decide
/// whether to acknowledge an exec request without reimplementing or weakening
/// the syntax restrictions. `Ok(true)` means the policy name was selected;
/// `Ok(false)` means one of the built-in SSH commands was selected.
pub fn validate_ssh_exec_with_component_name(
    source: &str,
    component_name: &str,
) -> Result<bool, Diagnostic> {
    validate_ssh_exec_with_policy(source, |name| name == component_name)
}

fn validate_ssh_exec_with_policy(
    source: &str,
    policy_command: impl Fn(&str) -> bool,
) -> Result<bool, Diagnostic> {
    let script = parse_with_limit(source, SSH_EXEC_MAX_INPUT_BYTES)?;
    let item = match script.statements.as_slice() {
        [Statement::Command(item)] => item,
        [Statement::If { span, .. }
        | Statement::While { span, .. }
        | Statement::Function { span, .. }] => {
            return Err(Diagnostic::new(
                span.start,
                span.end,
                "SSH exec scripting syntax is not allowed",
            ));
        }
        _ => {
            return Err(Diagnostic::new(
                0,
                source.len(),
                "SSH exec requires exactly one command",
            ));
        }
    };

    if item.background {
        return Err(Diagnostic::new(
            item.command.first.span.start,
            item.command.first.span.end,
            "SSH exec background jobs are not allowed",
        ));
    }
    if !item.command.rest.is_empty() {
        return Err(Diagnostic::new(
            item.command.first.span.start,
            item.command.first.span.end,
            "SSH exec conditional lists are not allowed",
        ));
    }
    let [command] = item.command.first.commands.as_slice() else {
        return Err(Diagnostic::new(
            item.command.first.span.start,
            item.command.first.span.end,
            "SSH exec pipelines are not allowed",
        ));
    };
    if !command.redirects.is_empty() {
        return Err(Diagnostic::new(
            command.span.start,
            command.span.end,
            "SSH exec redirection is not allowed",
        ));
    }
    let Some(name) = literal_word(&command.name) else {
        return Err(Diagnostic::new(
            command.name.span.start,
            command.name.span.end,
            "SSH exec command name must be literal",
        ));
    };
    let builtin = matches!(name, "echo" | "true" | "false");
    let selected_policy_command = !builtin && policy_command(name);
    if !builtin && !selected_policy_command {
        return Err(Diagnostic::new(
            command.name.span.start,
            command.name.span.end,
            "command is outside the SSH exec profile",
        ));
    }
    for argument in &command.args {
        match argument {
            Argument::Word(word)
                if word
                    .parts
                    .iter()
                    .all(|part| matches!(part, WordPart::Literal(_))) => {}
            Argument::Word(word) => {
                return Err(Diagnostic::new(
                    word.span.start,
                    word.span.end,
                    "SSH exec substitution is not allowed",
                ));
            }
            Argument::Capability { span, .. } => {
                return Err(Diagnostic::new(
                    span.start,
                    span.end,
                    "SSH exec capability arguments are not allowed",
                ));
            }
        }
    }
    if matches!(name, "true" | "false") && !command.args.is_empty() {
        return Err(Diagnostic::new(
            command.span.start,
            command.span.end,
            "command argument count rejected by SSH exec profile",
        ));
    }
    Ok(selected_policy_command)
}

fn parse_with_limit(source: &str, max_input_bytes: usize) -> Result<Script, Diagnostic> {
    let tokens = lex(source, max_input_bytes)?;
    let mut parser = Parser {
        tokens,
        at: 0,
        nodes: 0,
        nesting: 0,
    };
    let script = parser.block(&[], false)?;
    if parser.at != parser.tokens.len() {
        let span = parser.tokens[parser.at].span;
        return Err(Diagnostic::new(
            span.start,
            span.end,
            "unexpected closing syntax",
        ));
    }
    Ok(script)
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    nodes: usize,
    nesting: usize,
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

    fn peek_keyword(&self, keyword: &str) -> bool {
        self.tokens
            .get(self.at)
            .is_some_and(|token| match &token.kind {
                TokenKind::Word(Word { parts, .. }) => {
                    matches!(parts.as_slice(), [WordPart::Literal(word)] if word == keyword)
                }
                _ => false,
            })
    }

    fn take_keyword(&mut self, keyword: &str) -> Result<Token, Diagnostic> {
        if self.peek_keyword(keyword) {
            return Ok(self.take().unwrap());
        }
        let span = self
            .tokens
            .get(self.at)
            .map(|token| token.span)
            .unwrap_or(Span { start: 0, end: 0 });
        Err(Diagnostic::new(
            span.start,
            span.end,
            "expected scripting keyword",
        ))
    }

    fn block(
        &mut self,
        stop_keywords: &[&str],
        stop_at_right_brace: bool,
    ) -> Result<Script, Diagnostic> {
        let mut statements = Vec::new();
        while self.at < self.tokens.len() {
            while self.peek_op(Operator::Semi) {
                self.at += 1;
            }
            if self.at >= self.tokens.len()
                || stop_keywords
                    .iter()
                    .any(|keyword| self.peek_keyword(keyword))
                || (stop_at_right_brace && self.peek_op(Operator::RightBrace))
            {
                break;
            }
            if self.peek_op(Operator::RightBrace)
                || ["then", "else", "fi", "do", "done"]
                    .iter()
                    .any(|keyword| self.peek_keyword(keyword))
            {
                let span = self.tokens[self.at].span;
                return Err(Diagnostic::new(
                    span.start,
                    span.end,
                    "unexpected closing keyword",
                ));
            }

            let statement = if self.peek_keyword("if") {
                self.if_statement()?
            } else if self.peek_keyword("while") {
                self.while_statement()?
            } else if self.peek_keyword("function") {
                self.function_statement()?
            } else {
                Statement::Command(self.command_statement()?)
            };
            let span = statement_span(&statement);
            self.bump_node(span)?;
            let background_separator =
                matches!(&statement, Statement::Command(item) if item.background);
            statements.push(statement);

            if self.peek_op(Operator::Semi) {
                self.at += 1;
            } else if background_separator {
                continue;
            } else if self.at < self.tokens.len()
                && !stop_keywords
                    .iter()
                    .any(|keyword| self.peek_keyword(keyword))
                && !(stop_at_right_brace && self.peek_op(Operator::RightBrace))
            {
                let span = self.tokens[self.at].span;
                return Err(Diagnostic::new(
                    span.start,
                    span.end,
                    "expected command separator",
                ));
            }
        }
        Ok(Script { statements })
    }

    fn command_statement(&mut self) -> Result<ListItem, Diagnostic> {
        let command = self.and_or()?;
        let background = if self.peek_op(Operator::Background) {
            self.at += 1;
            true
        } else {
            false
        };
        Ok(ListItem {
            command,
            background,
        })
    }

    fn enter_nesting(&mut self, span: Span) -> Result<(), Diagnostic> {
        self.nesting += 1;
        if self.nesting > MAX_PARSER_NESTING {
            self.nesting -= 1;
            Err(Diagnostic::new(
                span.start,
                span.end,
                "parser nesting limit exceeded",
            ))
        } else {
            Ok(())
        }
    }

    fn if_statement(&mut self) -> Result<Statement, Diagnostic> {
        let start = self.take_keyword("if")?.span.start;
        self.enter_nesting(Span {
            start,
            end: start + 2,
        })?;
        let result = (|| {
            let condition = self.and_or()?;
            if !self.peek_op(Operator::Semi) {
                return Err(Diagnostic::new(
                    start,
                    condition.first.span.end,
                    "if condition must end with `;`",
                ));
            }
            self.at += 1;
            self.take_keyword("then")?;
            if self.peek_op(Operator::Semi) {
                self.at += 1;
            }
            let then_branch = self.block(&["else", "fi"], false)?;
            let else_branch = if self.peek_keyword("else") {
                self.at += 1;
                if self.peek_op(Operator::Semi) {
                    self.at += 1;
                }
                Some(self.block(&["fi"], false)?)
            } else {
                None
            };
            let end = self.take_keyword("fi")?.span.end;
            Ok(Statement::If {
                condition,
                then_branch,
                else_branch,
                span: Span { start, end },
            })
        })();
        self.nesting -= 1;
        result
    }

    fn while_statement(&mut self) -> Result<Statement, Diagnostic> {
        let start = self.take_keyword("while")?.span.start;
        self.enter_nesting(Span {
            start,
            end: start + 5,
        })?;
        let result = (|| {
            let condition = self.and_or()?;
            if !self.peek_op(Operator::Semi) {
                return Err(Diagnostic::new(
                    start,
                    condition.first.span.end,
                    "while condition must end with `;`",
                ));
            }
            self.at += 1;
            self.take_keyword("do")?;
            if self.peek_op(Operator::Semi) {
                self.at += 1;
            }
            let body = self.block(&["done"], false)?;
            let end = self.take_keyword("done")?.span.end;
            Ok(Statement::While {
                condition,
                body,
                span: Span { start, end },
            })
        })();
        self.nesting -= 1;
        result
    }

    fn function_statement(&mut self) -> Result<Statement, Diagnostic> {
        let start = self.take_keyword("function")?.span.start;
        self.enter_nesting(Span {
            start,
            end: start + 8,
        })?;
        let result = (|| {
            let name_token = self
                .take()
                .ok_or_else(|| Diagnostic::new(start, start + 8, "function requires a name"))?;
            let name = plain_word_name(&name_token).ok_or_else(|| {
                Diagnostic::new(
                    name_token.span.start,
                    name_token.span.end,
                    "function name must be a literal identifier",
                )
            })?;
            let mut params = Vec::new();
            while !self.peek_op(Operator::LeftBrace) {
                let token = self.take().ok_or_else(|| {
                    Diagnostic::new(start, name_token.span.end, "function requires `{` body")
                })?;
                let param = plain_word_name(&token).ok_or_else(|| {
                    Diagnostic::new(
                        token.span.start,
                        token.span.end,
                        "function parameter must be a literal identifier",
                    )
                })?;
                if params.iter().any(|existing| existing == &param) {
                    return Err(Diagnostic::new(
                        token.span.start,
                        token.span.end,
                        "duplicate function parameter",
                    ));
                }
                params.push(param);
                if params.len() > MAX_ARGS {
                    return Err(Diagnostic::new(
                        token.span.start,
                        token.span.end,
                        "function parameter limit exceeded",
                    ));
                }
            }
            self.at += 1;
            let body = self.block(&[], true)?;
            let end = self
                .take()
                .filter(|token| token.kind == TokenKind::Op(Operator::RightBrace))
                .ok_or_else(|| {
                    Diagnostic::new(start, name_token.span.end, "unterminated function body")
                })?
                .span
                .end;
            Ok(Statement::Function {
                name,
                params,
                body,
                span: Span { start, end },
            })
        })();
        self.nesting -= 1;
        result
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

fn plain_word_name(token: &Token) -> Option<String> {
    let TokenKind::Word(word) = &token.kind else {
        return None;
    };
    let [WordPart::Literal(name)] = word.parts.as_slice() else {
        return None;
    };
    valid_name(name).then(|| name.clone())
}

fn statement_span(statement: &Statement) -> Span {
    match statement {
        Statement::Command(item) => item.command.first.span,
        Statement::If { span, .. }
        | Statement::While { span, .. }
        | Statement::Function { span, .. } => *span,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Success,
    Returned(u8),
    Usage,
    Unavailable,
    Denied,
    BackendFault,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandManifest {
    pub name: String,
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

/// Immutable, policy-owned description of a Component command.
///
/// This is deliberately independent of the Component decoder's borrowed plan:
/// an image-policy adapter must copy the validated fields into this value and
/// may retain the admitted artifact privately in its runner. No byte slice,
/// decoded-plan pointer, capability handle, or backend pointer is stored here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentCommandManifest {
    name: String,
    abi: u16,
    artifact: ComponentArtifactIdentity,
    world: String,
    entrypoint: String,
    min_args: usize,
    max_args: usize,
    stdin: StreamMode,
    stdout: StreamMode,
    stderr: StreamMode,
    memory_bytes: usize,
    total_fuel: u64,
    poll_quantum: u64,
    resource_limit: u16,
    requirements: Vec<ComponentAuthorityRequirement>,
}

/// Exact trusted-setup description for one Component command admitted into an
/// SSH exec session.
///
/// This is not an unforgeable capability: the actual authorization boundary is
/// the image-private SSH platform hook that chooses whether to call
/// installation for a committed profile. This value prevents that trusted
/// setup path from using a zero-sized "enable Components" switch:
/// it must independently copy every pinned manifest field, which installation
/// compares with the runner's immutable admitted manifest. There is no
/// constructor that accepts a runner or an existing [`ComponentCommandManifest`],
/// so setup cannot accidentally bless bytes by reflecting their self-reported
/// identity back into the policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshExecComponentPolicy {
    pinned: ComponentCommandManifest,
}

impl SshExecComponentPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn from_image_pin(
        name: &str,
        abi: u16,
        artifact: ComponentArtifactIdentity,
        world: &str,
        entrypoint: &str,
        min_args: usize,
        max_args: usize,
        stdin: StreamMode,
        stdout: StreamMode,
        stderr: StreamMode,
        memory_bytes: usize,
        total_fuel: u64,
        poll_quantum: u64,
        resource_limit: u16,
        requirements: Vec<ComponentAuthorityRequirement>,
    ) -> Result<Self, Diagnostic> {
        Ok(Self {
            pinned: ComponentCommandManifest::try_from_borrowed(
                name,
                abi,
                artifact,
                world,
                entrypoint,
                min_args,
                max_args,
                stdin,
                stdout,
                stderr,
                memory_bytes,
                total_fuel,
                poll_quantum,
                resource_limit,
                requirements,
            )?,
        })
    }

    /// Check an independently constructed image pin against one immutable
    /// admitted manifest. This comparison conveys no execution authority; the
    /// trusted session-installation hook remains the authorization boundary.
    pub fn admits_manifest(&self, manifest: &ComponentCommandManifest) -> bool {
        self.pinned == *manifest
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComponentArtifactIdentity([u8; 32]);

impl ComponentArtifactIdentity {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for ComponentArtifactIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ComponentArtifactIdentity(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentAuthorityRequirement {
    label: String,
    interface: String,
    resource: String,
    resource_kind: String,
    rights: Rights,
}

impl ComponentAuthorityRequirement {
    pub fn new(
        label: impl Into<String>,
        interface: impl Into<String>,
        resource: impl Into<String>,
        resource_kind: impl Into<String>,
        rights: Rights,
    ) -> Self {
        Self {
            label: label.into(),
            interface: interface.into(),
            resource: resource.into(),
            resource_kind: resource_kind.into(),
            rights,
        }
    }

    pub fn try_from_borrowed(
        label: &str,
        interface: &str,
        resource: &str,
        resource_kind: &str,
        rights: Rights,
    ) -> Result<Self, Diagnostic> {
        Ok(Self {
            label: try_component_string(label)?,
            interface: try_component_string(interface)?,
            resource: try_component_string(resource)?,
            resource_kind: try_component_string(resource_kind)?,
            rights,
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn resource_kind(&self) -> &str {
        &self.resource_kind
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub const fn rights(&self) -> Rights {
        self.rights
    }
}

impl ComponentCommandManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        abi: u16,
        artifact: ComponentArtifactIdentity,
        world: impl Into<String>,
        entrypoint: impl Into<String>,
        min_args: usize,
        max_args: usize,
        stdin: StreamMode,
        stdout: StreamMode,
        stderr: StreamMode,
        memory_bytes: usize,
        total_fuel: u64,
        poll_quantum: u64,
        resource_limit: u16,
        requirements: impl IntoIterator<Item = ComponentAuthorityRequirement>,
    ) -> Result<Self, Diagnostic> {
        let manifest = Self {
            name: name.into(),
            abi,
            artifact,
            world: world.into(),
            entrypoint: entrypoint.into(),
            min_args,
            max_args,
            stdin,
            stdout,
            stderr,
            memory_bytes,
            total_fuel,
            poll_quantum,
            resource_limit,
            requirements: requirements.into_iter().collect(),
        };
        manifest.validate(Span { start: 0, end: 0 })?;
        Ok(manifest)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_from_borrowed(
        name: &str,
        abi: u16,
        artifact: ComponentArtifactIdentity,
        world: &str,
        entrypoint: &str,
        min_args: usize,
        max_args: usize,
        stdin: StreamMode,
        stdout: StreamMode,
        stderr: StreamMode,
        memory_bytes: usize,
        total_fuel: u64,
        poll_quantum: u64,
        resource_limit: u16,
        requirements: Vec<ComponentAuthorityRequirement>,
    ) -> Result<Self, Diagnostic> {
        let manifest = Self {
            name: try_component_string(name)?,
            abi,
            artifact,
            world: try_component_string(world)?,
            entrypoint: try_component_string(entrypoint)?,
            min_args,
            max_args,
            stdin,
            stdout,
            stderr,
            memory_bytes,
            total_fuel,
            poll_quantum,
            resource_limit,
            requirements,
        };
        manifest.validate(Span { start: 0, end: 0 })?;
        Ok(manifest)
    }

    fn validate(&self, span: Span) -> Result<(), Diagnostic> {
        if !valid_name(&self.name)
            || self.abi == 0
            || self.world.is_empty()
            || self.entrypoint.is_empty()
            || self.min_args > self.max_args
            || self.max_args > MAX_ARGS
            || self.memory_bytes == 0
            || self.memory_bytes > MAX_STAGE_MEMORY
            || self.total_fuel == 0
            || self.poll_quantum == 0
            || self.poll_quantum > self.total_fuel
            || self.resource_limit == 0
            || self.resource_limit > MAX_COMPONENT_RESOURCES
        {
            return Err(Diagnostic::new(
                span.start,
                span.end,
                "invalid component command manifest",
            ));
        }
        let mut labels = BTreeSet::new();
        for requirement in &self.requirements {
            if !valid_name(&requirement.label)
                || !valid_component_manifest_text(&requirement.interface)
                || !valid_component_manifest_text(&requirement.resource)
                || !valid_component_manifest_text(&requirement.resource_kind)
                || requirement.rights == Rights::NONE
                || requirement.rights.contains(Rights::GRANT)
                || requirement.rights.contains(Rights::REVOKE)
                || requirement.rights.contains(Rights::INVOKE)
                || !labels.insert(requirement.label.clone())
            {
                return Err(Diagnostic::new(
                    span.start,
                    span.end,
                    "invalid component authority requirement",
                ));
            }
        }
        Ok(())
    }

    fn command_manifest(&self) -> CommandManifest {
        CommandManifest {
            name: self.name.clone(),
            abi: self.abi,
            min_args: self.min_args,
            max_args: self.max_args,
            argument_mode: ArgumentMode::ValuesOnly,
            stdin: self.stdin,
            stdout: self.stdout,
            stderr: self.stderr,
            memory_bytes: self.memory_bytes,
            operation_budget: self.total_fuel,
            early_close_is_success: false,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn abi(&self) -> u16 {
        self.abi
    }

    pub const fn artifact(&self) -> ComponentArtifactIdentity {
        self.artifact
    }

    pub fn world(&self) -> &str {
        &self.world
    }

    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    pub const fn min_args(&self) -> usize {
        self.min_args
    }

    pub const fn max_args(&self) -> usize {
        self.max_args
    }

    pub const fn stdin(&self) -> StreamMode {
        self.stdin
    }

    pub const fn stdout(&self) -> StreamMode {
        self.stdout
    }

    pub const fn stderr(&self) -> StreamMode {
        self.stderr
    }

    pub const fn memory_bytes(&self) -> usize {
        self.memory_bytes
    }

    pub const fn total_fuel(&self) -> u64 {
        self.total_fuel
    }

    pub const fn poll_quantum(&self) -> u64 {
        self.poll_quantum
    }

    pub const fn resource_limit(&self) -> u16 {
        self.resource_limit
    }

    pub fn requirements(&self) -> &[ComponentAuthorityRequirement] {
        &self.requirements
    }
}

/// Stable VSH-side trap detail. The numeric value is the Component ABI trap
/// code, not an address or a capability identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentTrapCode(u16);

impl ComponentTrapCode {
    pub const fn new(code: u16) -> Self {
        Self(code)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentTerminal {
    Success,
    Returned(u8),
    Usage,
    Denied,
    Unavailable,
    BackendFault,
    BudgetExceeded,
    Cancelled,
    RunnerFault,
    Trapped(ComponentTrapCode),
}

impl ComponentTerminal {
    pub const fn status(self) -> Status {
        match self {
            Self::Success => Status::Success,
            Self::Returned(code) => Status::Returned(code),
            Self::Usage => Status::Usage,
            Self::Denied => Status::Denied,
            Self::Unavailable => Status::Unavailable,
            Self::BackendFault => Status::BackendFault,
            Self::BudgetExceeded => Status::BudgetExceeded,
            Self::Cancelled => Status::Cancelled,
            Self::RunnerFault => Status::Faulted,
            Self::Trapped(_) => Status::Faulted,
        }
    }

    /// Stable C5.3 close mapping. `Returned` is a generic component failure;
    /// malformed command use maps to the WIT `invalid` case, and lifecycle or
    /// trap corruption maps to `backend-fault` without exposing detail.
    pub const fn stream_close_reason(self) -> vibeos_component_host::StreamCloseReason {
        use vibeos_component_host::StreamCloseReason;
        match self {
            Self::Success => StreamCloseReason::Normal,
            Self::Returned(_) => StreamCloseReason::Failure,
            Self::Usage => StreamCloseReason::Invalid,
            Self::Denied => StreamCloseReason::Denied,
            Self::Unavailable => StreamCloseReason::Unavailable,
            Self::BudgetExceeded => StreamCloseReason::Exhausted,
            Self::Cancelled => StreamCloseReason::Cancelled,
            Self::BackendFault | Self::RunnerFault | Self::Trapped(_) => {
                StreamCloseReason::BackendFault
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentCommandResult {
    terminal: ComponentTerminal,
    output: Vec<u8>,
}

impl ComponentCommandResult {
    /// Construct a bounded result envelope. Fault terminals cannot smuggle
    /// bytes past a failed component invocation, while successful and
    /// non-zero returned statuses may publish at most the shell capture bound.
    pub fn try_new(
        terminal: ComponentTerminal,
        output: Vec<u8>,
    ) -> Result<Self, ComponentCommandResultError> {
        if output.len() > MAX_CAPTURED_OUTPUT {
            return Err(ComponentCommandResultError::OutputLimit);
        }
        if !matches!(
            terminal,
            ComponentTerminal::Success | ComponentTerminal::Returned(_)
        ) && !output.is_empty()
        {
            return Err(ComponentCommandResultError::OutputForFailure);
        }
        Ok(Self { terminal, output })
    }

    pub const fn terminal(&self) -> ComponentTerminal {
        self.terminal
    }

    pub fn output(&self) -> &[u8] {
        &self.output
    }

    pub fn into_parts(self) -> (ComponentTerminal, Vec<u8>) {
        (self.terminal, self.output)
    }

    pub const fn budget_exceeded() -> Self {
        Self {
            terminal: ComponentTerminal::BudgetExceeded,
            output: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentCommandResultError {
    OutputLimit,
    OutputForFailure,
}

#[derive(Clone)]
pub struct ComponentCancellation {
    live: Arc<AtomicBool>,
}

impl ComponentCancellation {
    pub fn is_cancelled(&self) -> bool {
        !self.live.load(Ordering::Acquire)
    }
}

struct CancellationSignalInner {
    cancelled: AtomicBool,
    waiter: OneShotWaitQueue,
}

#[derive(Clone)]
/// A bounded, one-shot cancellation edge shared with one foreground request.
///
/// The signal owns exactly one fixed-capacity waiter slot. One VSH watcher
/// fans cancellation out to every stage handle in a pipeline, so capacity is
/// independent of the stage count. Calling [`cancel`](Self::cancel) before the
/// watcher registers is remembered, repeated cancellation is idempotent, and
/// a second concurrent watcher fails closed instead of growing a collection.
pub struct CancellationSignal {
    inner: Arc<CancellationSignalInner>,
}

impl CancellationSignal {
    pub fn new() -> Self {
        // TaskStatus may need to unregister the wait edge after reclaiming a
        // faulting task's arena. Keep the queue itself in SYSTEM so even a
        // caller-owned outer Arc may be conservatively leaked without leaving
        // cleanup with an arena-backed pointer.
        let mut system = heap::enter_owner(heap::OwnerId::SYSTEM);
        let inner = Arc::new(CancellationSignalInner {
            cancelled: AtomicBool::new(false),
            waiter: OneShotWaitQueue::new(),
        });
        system.restore();
        Self { inner }
    }

    /// Publish cancellation once and wake the exact registered task after the
    /// queue lock has been released. Returns `true` only for the first signal.
    pub fn cancel(&self) -> bool {
        let first = !self.inner.cancelled.swap(true, Ordering::AcqRel);
        let wake = self
            .inner
            .waiter
            .publish(1)
            .expect("cancellation signal generation is fixed and monotonic");
        wake.dispatch();
        first
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Wait without polling for the signal. Exactly one concurrent listener
    /// is supported; callers receive the bounded queue error on misuse.
    pub async fn cancelled(&self) -> Result<(), OneShotWaitError> {
        let listener = self.inner.waiter.wait(1);
        if self.is_cancelled() {
            return Ok(());
        }
        listener.await?;
        if self.is_cancelled() {
            Ok(())
        } else {
            Err(OneShotWaitError::RegistrationMismatch)
        }
    }
}

impl Default for CancellationSignal {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct PreparedComponentAuthority {
    label: String,
    resource_kind: String,
    rights: Rights,
    cap: Cap,
}

impl core::fmt::Debug for PreparedComponentAuthority {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedComponentAuthority")
            .field("label", &self.label)
            .field("resource_kind", &self.resource_kind)
            .field("rights", &self.rights)
            .field("authority", &"<stage-local>")
            .finish()
    }
}

impl PreparedComponentAuthority {
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn resource_kind(&self) -> &str {
        &self.resource_kind
    }

    pub const fn rights(&self) -> Rights {
        self.rights
    }

    /// Return the stage-local handle to the trusted runner adapter. This value
    /// is never serialized or accepted from shell text.
    pub const fn stage_cap(&self) -> Cap {
        self.cap
    }
}

pub struct PreparedComponentStage {
    manifest: Arc<ComponentCommandManifest>,
    arguments: Vec<String>,
    input: Vec<u8>,
    cspace: Arc<SpinLock<CSpace>>,
    authorities: Vec<PreparedComponentAuthority>,
    cancellation: ComponentCancellation,
}

impl core::fmt::Debug for PreparedComponentStage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedComponentStage")
            .field("manifest", &self.manifest)
            .field("arguments", &self.arguments)
            .field("input_bytes", &self.input.len())
            .field("execution_context", &"<stage-local>")
            .field("authorities", &self.authorities)
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish()
    }
}

impl PreparedComponentStage {
    pub fn manifest(&self) -> &ComponentCommandManifest {
        &self.manifest
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub fn input(&self) -> &[u8] {
        &self.input
    }

    pub fn authorities(&self) -> &[PreparedComponentAuthority] {
        &self.authorities
    }

    pub fn authority(&self, label: &str) -> Option<&PreparedComponentAuthority> {
        self.authorities
            .iter()
            .find(|authority| authority.label == label)
    }

    pub fn stage_cspace(&self) -> Arc<SpinLock<CSpace>> {
        self.cspace.clone()
    }

    pub fn cancellation(&self) -> ComponentCancellation {
        self.cancellation.clone()
    }
}

pub type ComponentCommandFuture<'a> =
    Pin<Box<dyn Future<Output = ComponentCommandResult> + Send + 'a>>;

/// Kernel adapters implement this seam around an already admitted immutable
/// Component. `preflight` must be synchronous and side-effect-free; `run` is
/// called only after the complete pipeline has prepared and committed.
pub trait ComponentCommandRunner: Send + Sync {
    /// The one immutable manifest owned by this admitted runner. Session
    /// installation copies this value; callers cannot pair arbitrary artifact
    /// and manifest objects at the registration boundary.
    fn manifest(&self) -> &ComponentCommandManifest;

    fn preflight(&self, manifest: &ComponentCommandManifest) -> Result<(), ComponentTerminal>;

    fn run<'a>(&'a self, stage: PreparedComponentStage) -> ComponentCommandFuture<'a>;
}

/// Opaque, non-owning reference to one Component invocation managed by the
/// trusted SYSTEM lifecycle service.
///
/// Copying this value neither extends the invocation's lifetime nor grants
/// authority over its child task, arena, or CSpace. Safe code can observe and
/// return a token supplied by [`ManagedComponentLifecycle`], but cannot forge
/// one or extract the lifecycle-private lookup key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ManagedComponentToken(NonZeroU64);

impl ManagedComponentToken {
    /// Construct a token at the trusted lifecycle boundary.
    ///
    /// # Safety
    ///
    /// `raw` must name a live entry in the implementing lifecycle service and
    /// must never be reused while an older generation can still be observed.
    pub const unsafe fn from_trusted_raw(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    /// Recover the lifecycle-private lookup key.
    ///
    /// # Safety
    ///
    /// The caller must be the same trusted lifecycle implementation that
    /// issued this token. The returned value must not be accepted as identity
    /// without that service's full generation and object-identity checks.
    pub const unsafe fn trusted_raw(self) -> NonZeroU64 {
        self.0
    }
}

impl core::fmt::Debug for ManagedComponentToken {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ManagedComponentToken(<opaque>)")
    }
}

/// Copy-only state published by a trusted managed Component lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedComponentState {
    /// The lifecycle control gate is held by another bounded operation. This
    /// is not a semantic instance state; asynchronous observers must yield and
    /// retry rather than interpreting transient contention as Running or Lost.
    Busy,
    /// The child remains live. VSH awaits the lifecycle's bounded state-change
    /// future; the SSH supervisor provides the enclosing cancellation bound.
    Running,
    /// Stable terminal scalar. Until the sole VSH consumer explicitly
    /// acknowledges it, every later exact lookup must return the same value.
    Complete(ComponentTerminal),
    /// The token no longer resolves exactly. VSH fails closed and never asks
    /// the lifecycle to reclaim an ambiguous instance.
    Lost,
}

pub type ManagedComponentStateFuture<'a> =
    Pin<Box<dyn Future<Output = ManagedComponentState> + Send + 'a>>;

/// Result of a cooperative cancellation request for a managed invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedComponentCancel {
    /// The lifecycle control gate is held by another bounded operation. The
    /// caller must asynchronously yield and retry the same opaque token.
    Busy,
    /// The lifecycle atomically published a cooperative cancel word and woke
    /// the exact child. `state` may remain `Running` until a next/future child
    /// poll observes the word and publishes terminal state; under the enclosing
    /// SSH supervisor bound it must eventually leave `Running`, or return
    /// `Lost` and apply the mismatch quarantine contract.
    Requested,
    /// An exact terminal candidate or core terminal transition already won
    /// the race, but outer terminal publication is not necessarily complete.
    /// Cancellation did not mutate the candidate or publish a cancel word.
    AlreadyCompleting,
    /// The exact token already has a stable [`ManagedComponentState::Complete`]
    /// value; cancellation did not change or republish terminal state.
    AlreadyComplete,
    /// The token did not resolve exactly. The lifecycle remains responsible
    /// for quarantining or conservatively leaking the ambiguous instance.
    Lost,
}

/// Exact result of consuming one stable managed terminal tombstone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedComponentAcknowledge {
    /// The lifecycle CONTROL gate is transiently held. The SYSTEM reaper must
    /// yield and retry without releasing its slot or publishing completion.
    Busy,
    /// The exact terminal generation is acknowledged and may be reused.
    Acknowledged,
    /// The token or its complete identity tuple was lost. The reaper must stop
    /// conservatively and must never make its own slot reusable.
    Lost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedComponentStartAbort {
    CleanAborted,
    Quarantined,
}

const MANAGED_REAPER_SLOTS: usize = 16;
const MANAGED_REAPER_SLOT_BITS: u32 = 8;
const MAX_MANAGED_REAPER_GENERATION: u64 = u64::MAX >> MANAGED_REAPER_SLOT_BITS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManagedReaperKey {
    slot: u8,
    generation: u64,
}

impl ManagedReaperKey {
    const fn encode(self) -> Option<u64> {
        let slot = self.slot as u64 + 1;
        let raw = (self.generation << MANAGED_REAPER_SLOT_BITS) | slot;
        if self.generation == 0 || self.generation > MAX_MANAGED_REAPER_GENERATION {
            None
        } else {
            Some(raw)
        }
    }

    const fn decode(raw: u64) -> Option<Self> {
        let slot = (raw & ((1 << MANAGED_REAPER_SLOT_BITS) - 1)) as usize;
        let generation = raw >> MANAGED_REAPER_SLOT_BITS;
        if slot == 0 || slot > MANAGED_REAPER_SLOTS || generation == 0 {
            None
        } else {
            Some(Self {
                slot: (slot - 1) as u8,
                generation,
            })
        }
    }
}

/// Copy-only handoff installed before a managed child can become runnable.
///
/// The private fields contain only generation/task/domain/status-registration
/// scalars. They own no Session, endpoint, CSpace, task handle, queue, arena,
/// runtime payload, or reference-counted object. The stable state they name is
/// held exclusively by the fixed SYSTEM reaper registry and TaskStatus ledger.
#[derive(Clone, Copy)]
pub struct ManagedComponentStartLease {
    reaper: ManagedReaperKey,
    parent: exec::CurrentTaskDetachLease,
}

/// Deferred scheduler wake detached from a fixed SYSTEM reaper queue.
/// Lifecycle CONTROL code publishes the state edge while holding its own
/// serialization gate, then dispatches this value only after releasing every
/// CONTROL/registry/scheduler lock.
#[must_use = "the reaper wake must be dispatched after CONTROL and scheduler locks are released"]
pub struct ManagedComponentReaperWake {
    wake: Option<exec::OneShotWake>,
    reaper: Option<exec::ExactTaskWake>,
}

impl ManagedComponentReaperWake {
    pub fn dispatch(mut self) -> bool {
        let dispatched = self.wake.take().is_some_and(exec::OneShotWake::dispatch);
        dispatched
            || self
                .reaper
                .take()
                .is_some_and(|reaper| reaper.wake_if_exact())
    }
}

impl core::fmt::Debug for ManagedComponentStartLease {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ManagedComponentStartLease(<opaque>)")
    }
}

impl ManagedComponentStartLease {
    /// Exact parent identity captured from the executor's private TaskStatus
    /// projection. Shared raw-reclaimable SSH parents are accepted.
    pub const fn parent_task_id(self) -> exec::TaskId {
        self.parent.task_id()
    }

    pub const fn parent_allocation_domain(self) -> heap::AllocationDomain {
        self.parent.allocation_domain()
    }

    /// Compare the hidden reaper generation and exact parent TaskStatus
    /// registration without exposing either scalar. Kernel CONTROL retains
    /// the original copy and uses this only as an ABA/mismatch gate.
    pub fn matches_exact(self, other: Self) -> bool {
        self.reaper == other.reaper && self.parent.matches_exact(other.parent)
    }

    /// Bind the opaque child token before the child batch is published to any
    /// hart. This does not wake the reaper: CONTROL must first commit the
    /// child and its SYSTEM supervisor as one publication transaction.
    pub fn bind_before_child_publication(self, token: ManagedComponentToken) -> bool {
        bind_managed_reaper(self, token)
    }

    /// Move the stable prestart IO envelope into lifecycle CONTROL only after
    /// this exact token has been bound. No parent future owns endpoints across
    /// the preceding Armed await.
    pub fn claim_bound_io(self, token: ManagedComponentToken) -> Option<ManagedComponentIo> {
        claim_managed_reaper_io(self, token)
    }

    /// Commit the already-bound child publication and wake the armed reaper.
    /// No allocation or task creation is permitted between child publication
    /// and this fixed state transition.
    pub fn commit_child_publication(
        self,
        token: ManagedComponentToken,
    ) -> Option<ManagedComponentReaperWake> {
        commit_managed_reaper_publication(self, token)
    }

    /// Revalidate the exact prepublication binding retained in CONTROL.
    pub fn is_bound_for(self, token: ManagedComponentToken) -> bool {
        let Some(slot) = managed_reaper_slot(self.reaper) else {
            return false;
        };
        let record = slot.record.lock();
        managed_reaper_matches_lease(&record, self)
            && record.phase == ManagedReaperPhase::Bound
            && record.component == Some(token)
            && record
                .reaper_task
                .as_ref()
                .is_some_and(|handle| handle.is_published() && handle.state() == TaskState::Running)
    }

    /// Revalidate the exact live SYSTEM reaper task and bound child token.
    /// CONTROL uses this before publication and whenever it validates its
    /// retained orphan projection.
    pub fn is_active_for(self, token: ManagedComponentToken) -> bool {
        let Some(slot) = managed_reaper_slot(self.reaper) else {
            return false;
        };
        let record = slot.record.lock();
        managed_reaper_matches_lease(&record, self)
            && record.phase == ManagedReaperPhase::Active
            && record.component == Some(token)
            && record
                .reaper_task
                .as_ref()
                .is_some_and(|handle| handle.is_published() && handle.state() == TaskState::Running)
    }

    /// Publish a lifecycle state-change edge after stable CONTROL state has
    /// changed. This performs no lookup or lifecycle action itself.
    pub fn notify_state_change(self) -> Option<ManagedComponentReaperWake> {
        notify_managed_reaper_state(self)
    }

    /// Stage one exact lifecycle terminal together with its sole reaper edge.
    /// The unsafe lifecycle implementation is the only holder of this bound
    /// lease/token pair after IO claim; later fail-stop code may preserve this
    /// value but cannot introduce a different terminal.
    pub fn notify_complete(
        self,
        token: ManagedComponentToken,
        terminal: ComponentTerminal,
    ) -> Option<ManagedComponentReaperWake> {
        notify_managed_reaper_complete(self, token, terminal)
    }

    /// Quarantine only an already-staged exact terminal. This is the poisoned
    /// CONTROL fallback for the window before acknowledgement and deliberately
    /// refuses to manufacture a terminal in an empty/mismatched record.
    pub fn quarantine_staged_complete(
        self,
        token: ManagedComponentToken,
        terminal: ComponentTerminal,
    ) -> bool {
        quarantine_managed_reaper_staged_complete(self, token, terminal)
    }

    /// Mark a start failure which is known to precede child publication.
    /// Unpublished resources may be released after the exact parent detach
    /// registration is disarmed.
    pub fn abort_before_child_publication(
        self,
        terminal: ComponentTerminal,
    ) -> ManagedComponentStartAbort {
        abort_managed_reaper_start(self, false, terminal)
    }

    /// Mark an ambiguous or post-publication start failure. This wakes the
    /// reaper but permanently quarantines its generation.
    pub fn quarantine_partial_start(self) {
        let _ = abort_managed_reaper_start(self, true, ComponentTerminal::RunnerFault);
    }
}

/// One invocation's exact C5.3 transport endpoints.
///
/// The endpoint implementations guarantee SYSTEM-owned backing storage. This
/// envelope is constructed only after source capability and CSpace checks,
/// then consumed by the lifecycle start transaction. It is intentionally not
/// cloneable: once `start` returns, VSH retains only a
/// [`ManagedComponentToken`].
pub struct ManagedComponentIo {
    stdin: Arc<ByteStreamReader>,
    stdout: Arc<ByteStreamWriter>,
    stdin_supervisor: Arc<ByteStreamSupervisor>,
    stdout_supervisor: Arc<ByteStreamSupervisor>,
}

impl core::fmt::Debug for ManagedComponentIo {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ManagedComponentIo")
            .field("stdin", &"<system-owned>")
            .field("stdout", &"<system-owned>")
            .field("stdin_supervisor", &"<system-owned>")
            .field("stdout_supervisor", &"<system-owned>")
            .finish()
    }
}

impl ManagedComponentIo {
    fn new(
        stdin: Arc<ByteStreamReader>,
        stdout: Arc<ByteStreamWriter>,
        stdin_supervisor: Arc<ByteStreamSupervisor>,
        stdout_supervisor: Arc<ByteStreamSupervisor>,
    ) -> Self {
        Self {
            stdin,
            stdout,
            stdin_supervisor,
            stdout_supervisor,
        }
    }

    /// Make a pre-lifecycle terminal observable on both transport directions.
    /// No child or registry owner exists while this envelope remains in VSH.
    fn finalize_unpublished(&self, terminal: ComponentTerminal) -> ComponentTerminal {
        let reason = terminal.stream_close_reason();
        let stdin = self.stdin_supervisor.finalize(reason);
        let stdout = self.stdout_supervisor.finalize(reason);
        if matches!(
            stdin,
            StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
        ) && matches!(
            stdout,
            StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
        ) && self.stdin_supervisor.final_reason() == Some(reason)
            && self.stdout_supervisor.final_reason() == Some(reason)
            && !self.stdin_supervisor.is_fail_stopped()
            && !self.stdout_supervisor.is_fail_stopped()
        {
            terminal
        } else {
            ComponentTerminal::RunnerFault
        }
    }

    /// Transfer the exact endpoint and terminal-authority objects into the
    /// stable lifecycle registry.
    pub fn into_parts(
        self,
    ) -> (
        Arc<ByteStreamReader>,
        Arc<ByteStreamWriter>,
        Arc<ByteStreamSupervisor>,
        Arc<ByteStreamSupervisor>,
    ) {
        (
            self.stdin,
            self.stdout,
            self.stdin_supervisor,
            self.stdout_supervisor,
        )
    }
}

/// Opaque component-facing half of one SSH stream installation. Only the
/// explicit image/session-policy installer can consume this value.
pub struct SshExecComponentIoInstall {
    component: ManagedComponentIo,
}

/// Pump-facing half of one SSH stream installation. It exposes only the
/// directions needed by the trusted transport pump, never the component's
/// reader/writer capabilities.
///
/// The terminal-authority accessors deliberately do not exist:
///
/// ```compile_fail
/// let (_, pump) = vibeos_vsh::new_ssh_exec_component_io();
/// let _ = pump.stdin_supervisor();
/// ```
pub struct SshExecComponentIoPump {
    stdin: Arc<ByteStreamWriter>,
    stdout: Arc<ByteStreamReader>,
}

impl core::fmt::Debug for SshExecComponentIoPump {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SshExecComponentIoPump(<opaque>)")
    }
}

impl SshExecComponentIoPump {
    pub fn stdin(&self) -> &Arc<ByteStreamWriter> {
        &self.stdin
    }

    pub fn stdout(&self) -> &Arc<ByteStreamReader> {
        &self.stdout
    }
}

/// Create two distinct fixed-capacity SYSTEM-owned streams and split their
/// directional authority. The install half can only enter a managed component
/// through [`Session::install_ssh_exec_managed_component_io`].
pub fn new_ssh_exec_component_io() -> (SshExecComponentIoInstall, SshExecComponentIoPump) {
    let stdin = ComponentByteStream::new();
    let stdout = ComponentByteStream::new();
    let component = ManagedComponentIo::new(
        stdin.reader(),
        stdout.writer(),
        stdin.supervisor(),
        stdout.supervisor(),
    );
    let pump = SshExecComponentIoPump {
        stdin: stdin.writer(),
        stdout: stdout.reader(),
    };
    (SshExecComponentIoInstall { component }, pump)
}

#[derive(Clone, Copy)]
struct ManagedComponentIoSource {
    space: CSpaceIdentity,
    incarnation: u64,
    stdin: Cap,
    stdout: Cap,
    stdin_supervisor: Cap,
    stdout_supervisor: Cap,
}

struct ValidatedManagedComponentIo {
    stdin: Arc<ByteStreamReader>,
    stdout: Arc<ByteStreamWriter>,
    stdin_supervisor: Arc<ByteStreamSupervisor>,
    stdout_supervisor: Arc<ByteStreamSupervisor>,
}

/// Trusted SYSTEM boundary for the narrow, scalar-only SSH Component path.
///
/// # Safety
///
/// Implementations must be globally stable for the lifetime of every token,
/// and `manifest` must return one immutable, image-admitted pin for the entire
/// lifetime of the service. Every `start` must execute exactly that manifest;
/// it may not select bytes, entrypoints, or policy from caller-controlled
/// state.
///
/// Before `start` returns a token, the implementation must have completed the
/// full registry binding, SYSTEM control-record installation, and exclusive
/// executor publication transaction. The registry owns the runtime payload,
/// arena, and CSpace. The published Component child future may contain only
/// the opaque core registry token; VSH's token is a separate non-owning lookup
/// key. A failed or partially published `start` leaves no resource owned by
/// VSH. If `start` fails before any object is published into the registry, it
/// must use the two supplied supervisors to finalize both streams with the
/// exact returned terminal reason before returning `Err`; no later lifecycle
/// owner exists for that invocation. A partially published or identity-unsafe
/// failure must instead fail-stop, quarantine, or conservatively leak it.
/// `start` may install a registry-owned lazy driver containing only static pin
/// and copy fields; no trait method may construct, poll, or drop the runtime
/// payload on the VSH caller, or re-enter/drive executor task polling.
///
/// Every method must be bounded and nonblocking. No method may poll WASM, call
/// `TaskHandle::cancel`, allocate in caller-owned storage, or retain any caller
/// reference, caller-owned `Arc`, CSpace, `OutputSink`, or other VSH execution
/// object. `start` is the sole exception for the four SYSTEM-owned objects in
/// [`ManagedComponentIo`]: it must transfer them into the stable registry and
/// must not leave any of their `Arc`s in a child future. Any allocation must be
/// charged to lifecycle-owned SYSTEM/reserved storage.
/// `state` may only read a stable copy-only scalar; `Complete` is immutable.
/// `request_cancel` may only atomically set a cooperative cancellation word
/// and wake the exact child. No trait method may terminalize, drop, reclaim,
/// unregister, retire, or reset child state; those operations belong only to
/// the independent SYSTEM lifecycle/child path.
///
/// `state`, `wait_state`, and `request_cancel` must at least verify the lifecycle-token
/// generation/control entry plus TaskId/status, owner/arena domain, and Space
/// structural identity. Cancellation only writes the stable word and wakes;
/// it must not hold a registry lock while waiting for CSpace access. The next
/// child poll performs the complete CSpace identity/incarnation gate. Before
/// any irreversible fault reclaim, payload Drop/tombstone, owner retirement,
/// or reset, the lifecycle must simultaneously verify generation, TaskId and
/// status, owner/arena, Space object identity, and CSpace object identity plus
/// incarnation. Any mismatch must quarantine and conservatively leak or
/// fail-stop; it must never reset or reclaim. A parent VSH fault does not
/// authorize reclaim of its managed child. Terminal collection and CSpace
/// reset remain entirely internal to a SYSTEM lifecycle task after the child
/// has published terminal state.
pub unsafe trait ManagedComponentLifecycle: Send + Sync + 'static {
    /// Immutable manifest for the one image-admitted Component pinned to this
    /// service. Installation snapshots and compares it with independent image
    /// policy before the command becomes visible.
    fn manifest(&self) -> &ComponentCommandManifest;

    /// Allocate and start one zero-shell-argument stream invocation. This is
    /// called only after every grammar, image-policy, session-policy,
    /// immutable-manifest, source-CSpace, endpoint-kind, and exact-rights gate
    /// has passed. The lifecycle must move both endpoints and their two
    /// terminal authorities into the registry's candidate CSpace before
    /// publishing a token; on return VSH owns none of those objects and
    /// retains only that opaque non-owning token. An unpublished `Err` must
    /// first make both streams immutably observable with
    /// `terminal.stream_close_reason()` as required by the trait contract.
    fn start(
        &self,
        cleanup: ManagedComponentStartLease,
    ) -> Result<ManagedComponentToken, ComponentTerminal>;

    /// Read copy-only lifecycle state for a token. This is a completion-table
    /// lookup, not a future/WASM poll operation.
    fn state(&self, token: ManagedComponentToken) -> ManagedComponentState;

    /// Await the first non-`Running` scalar for this exact token without
    /// repeatedly scheduling the VSH task. The implementation may retain only
    /// the opaque token and a fixed-capacity SYSTEM-owned registration. It
    /// must close the register/recheck race, reject concurrent duplicate
    /// listeners, and treat a stale generation or ABA mismatch as `Lost`.
    fn wait_state<'a>(&'a self, token: ManagedComponentToken) -> ManagedComponentStateFuture<'a>;

    /// Request cooperative cancellation. The lifecycle wakes its owned child;
    /// VSH never cancels or retains that child's executor handle.
    fn request_cancel(
        &self,
        token: ManagedComponentToken,
        terminal: ComponentTerminal,
    ) -> ManagedComponentCancel;

    /// Acknowledge that VSH consumed the exact stable terminal scalar.
    ///
    /// This is the only permission to make a completed control-table entry
    /// reusable. It must not reset a CSpace, reclaim an arena, drop a payload,
    /// or otherwise participate in child teardown: all of those actions must
    /// already have completed before `state` returned `Complete`. Unknown,
    /// stale, running, or quarantined tokens are ignored conservatively.
    fn acknowledge_complete(&self, _token: ManagedComponentToken) -> ManagedComponentAcknowledge {
        ManagedComponentAcknowledge::Lost
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagedReaperPhase {
    Vacant,
    Reserved,
    Armed,
    Bound,
    Active,
    Terminal,
    Aborted,
    Quarantined,
}

struct ManagedReaperRecord {
    generation: u64,
    phase: ManagedReaperPhase,
    lifecycle: Option<&'static dyn ManagedComponentLifecycle>,
    parent_task: Option<exec::TaskId>,
    parent_domain: Option<heap::AllocationDomain>,
    parent_wake: Option<exec::CurrentTaskDetachLease>,
    component: Option<ManagedComponentToken>,
    terminal: Option<ComponentTerminal>,
    prestart_io: Option<ManagedComponentIo>,
    prestart_terminal: Option<ComponentTerminal>,
    prestart_finalized: bool,
    cancel_terminal: Option<ComponentTerminal>,
    detached: bool,
    foreground_disarmed: bool,
    reaper_finished: bool,
    reaper_task: Option<TaskHandle>,
}

impl ManagedReaperRecord {
    const fn new() -> Self {
        Self {
            generation: 0,
            phase: ManagedReaperPhase::Vacant,
            lifecycle: None,
            parent_task: None,
            parent_domain: None,
            parent_wake: None,
            component: None,
            terminal: None,
            prestart_io: None,
            prestart_terminal: None,
            prestart_finalized: false,
            cancel_terminal: None,
            detached: false,
            foreground_disarmed: false,
            reaper_finished: false,
            reaper_task: None,
        }
    }

    fn exact(&self, key: ManagedReaperKey) -> bool {
        self.generation == key.generation && self.phase != ManagedReaperPhase::Vacant
    }

    fn clear_for_reuse(&mut self) {
        debug_assert!(matches!(
            self.phase,
            ManagedReaperPhase::Terminal | ManagedReaperPhase::Aborted
        ));
        debug_assert!(self.reaper_finished);
        debug_assert!(self.detached || self.foreground_disarmed);
        self.phase = ManagedReaperPhase::Vacant;
        self.lifecycle = None;
        self.parent_task = None;
        self.parent_domain = None;
        self.parent_wake = None;
        self.component = None;
        self.terminal = None;
        self.prestart_io = None;
        self.prestart_terminal = None;
        self.prestart_finalized = false;
        self.cancel_terminal = None;
        self.detached = false;
        self.foreground_disarmed = false;
        self.reaper_finished = false;
        self.reaper_task = None;
    }

    fn maybe_clear_for_reuse(&mut self) {
        if self.reaper_finished
            && (self.detached || self.foreground_disarmed)
            && (self.phase == ManagedReaperPhase::Terminal
                || (self.phase == ManagedReaperPhase::Aborted && self.prestart_finalized))
        {
            self.clear_for_reuse();
        }
    }
}

struct ManagedReaperSlot {
    record: SpinLock<ManagedReaperRecord>,
    activation: OneShotWaitQueue,
    control: OneShotWaitQueue,
    lifecycle: OneShotWaitQueue,
    completion: OneShotWaitQueue,
}

impl ManagedReaperSlot {
    const fn new() -> Self {
        Self {
            record: SpinLock::new(ManagedReaperRecord::new()),
            activation: OneShotWaitQueue::new(),
            control: OneShotWaitQueue::new(),
            lifecycle: OneShotWaitQueue::new(),
            completion: OneShotWaitQueue::new(),
        }
    }
}

static MANAGED_REAPERS: [ManagedReaperSlot; MANAGED_REAPER_SLOTS] =
    [const { ManagedReaperSlot::new() }; MANAGED_REAPER_SLOTS];

fn managed_reaper_slot(key: ManagedReaperKey) -> Option<&'static ManagedReaperSlot> {
    MANAGED_REAPERS.get(key.slot as usize)
}

fn managed_reaper_matches_lease(
    record: &ManagedReaperRecord,
    lease: ManagedComponentStartLease,
) -> bool {
    record.exact(lease.reaper)
        && record.parent_task == Some(lease.parent.task_id())
        && record.parent_domain == Some(lease.parent.allocation_domain())
        && record
            .parent_wake
            .is_some_and(|stored| stored.matches_exact(lease.parent))
}

struct ManagedReaperDispatch {
    activation: Option<exec::OneShotWake>,
    control: Option<exec::OneShotWake>,
    lifecycle: Option<exec::OneShotWake>,
    completion: Option<exec::OneShotWake>,
    reaper: Option<exec::ExactTaskWake>,
    parent: Option<exec::CurrentTaskDetachLease>,
}

impl ManagedReaperDispatch {
    const fn empty() -> Self {
        Self {
            activation: None,
            control: None,
            lifecycle: None,
            completion: None,
            reaper: None,
            parent: None,
        }
    }

    fn dispatch(self) {
        let reaper_dispatched = self.activation.is_some_and(exec::OneShotWake::dispatch)
            | self.control.is_some_and(exec::OneShotWake::dispatch)
            | self.lifecycle.is_some_and(exec::OneShotWake::dispatch);
        let completion_dispatched = self.completion.is_some_and(exec::OneShotWake::dispatch);
        if !reaper_dispatched {
            if let Some(reaper) = self.reaper {
                let _ = reaper.wake_if_exact();
            }
        }
        if !completion_dispatched {
            if let Some(parent) = self.parent {
                let _ = parent.wake_if_exact();
            }
        }
    }
}

fn quarantine_managed_reaper_locked(
    slot: &ManagedReaperSlot,
    key: ManagedReaperKey,
    record: &mut ManagedReaperRecord,
) -> ManagedReaperDispatch {
    record.phase = ManagedReaperPhase::Quarantined;
    let mut dispatch = ManagedReaperDispatch {
        activation: slot.activation.publish(key.generation).ok(),
        control: slot.control.publish(key.generation).ok(),
        lifecycle: slot.lifecycle.publish(key.generation).ok(),
        completion: None,
        reaper: record.reaper_task.as_ref().map(TaskHandle::exact_wake),
        parent: record.parent_wake,
    };
    match slot.completion.publish(key.generation) {
        Ok(wake) => dispatch.completion = Some(wake),
        Err(_) => {}
    }
    dispatch
}

unsafe fn managed_parent_detached(
    raw: u64,
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    reason: exec::TaskDetachReason,
) {
    let Some(key) = ManagedReaperKey::decode(raw) else {
        return;
    };
    let Some(slot) = managed_reaper_slot(key) else {
        return;
    };
    let prestart_terminal = match reason {
        exec::TaskDetachReason::Cancelled => ComponentTerminal::Cancelled,
        exec::TaskDetachReason::Exited | exec::TaskDetachReason::Faulted => {
            ComponentTerminal::RunnerFault
        }
    };
    let dispatch = {
        let mut record = slot.record.lock();
        if !record.exact(key) {
            // A delayed old-generation callback is observationally inert.
            return;
        }
        if record.parent_task != Some(task) || record.parent_domain != Some(domain) {
            record.reaper_finished = false;
            quarantine_managed_reaper_locked(slot, key, &mut record)
        } else {
            record.detached = true;
            record.cancel_terminal.get_or_insert(prestart_terminal);
            match record.phase {
                ManagedReaperPhase::Reserved | ManagedReaperPhase::Armed => {
                    let unpublished = record
                        .reaper_task
                        .as_ref()
                        .is_none_or(|handle| !handle.is_published());
                    if record.prestart_io.is_none() || unpublished {
                        quarantine_managed_reaper_locked(slot, key, &mut record)
                    } else {
                        record.phase = ManagedReaperPhase::Aborted;
                        record.prestart_terminal = Some(prestart_terminal);
                        record.prestart_finalized = false;
                        record.reaper_finished = false;
                        match slot.activation.publish(key.generation) {
                            Ok(wake) => ManagedReaperDispatch {
                                activation: Some(wake),
                                reaper: record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                                ..ManagedReaperDispatch::empty()
                            },
                            Err(_) => quarantine_managed_reaper_locked(slot, key, &mut record),
                        }
                    }
                }
                // A permanently detached starter can no longer complete the
                // Bound publication transaction. Quarantine the partial start
                // and release both preinstalled reaper waits; registry/arena/
                // CSpace state is deliberately leaked rather than observed or
                // reclaimed through a token that was never Active.
                ManagedReaperPhase::Bound => {
                    quarantine_managed_reaper_locked(slot, key, &mut record)
                }
                ManagedReaperPhase::Active => match slot.control.publish(key.generation) {
                    Ok(wake) => ManagedReaperDispatch {
                        control: Some(wake),
                        reaper: record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                        ..ManagedReaperDispatch::empty()
                    },
                    Err(_) => quarantine_managed_reaper_locked(slot, key, &mut record),
                },
                ManagedReaperPhase::Terminal => {
                    record.maybe_clear_for_reuse();
                    ManagedReaperDispatch::empty()
                }
                ManagedReaperPhase::Aborted => {
                    let reaper = record.reaper_task.as_ref().map(TaskHandle::exact_wake);
                    record.maybe_clear_for_reuse();
                    ManagedReaperDispatch {
                        reaper,
                        ..ManagedReaperDispatch::empty()
                    }
                }
                ManagedReaperPhase::Quarantined => {
                    quarantine_managed_reaper_locked(slot, key, &mut record)
                }
                ManagedReaperPhase::Vacant => ManagedReaperDispatch::empty(),
            }
        }
    };
    dispatch.dispatch();
}

/// Fault/cancellation fallback for the SYSTEM reaper itself. Executor detach
/// invokes this only after removing every activation/control/lifecycle waiter
/// owned by that exact TaskStatus, so publishing outer completion cannot race
/// a stale self-listener.
unsafe fn managed_reaper_detached(
    raw: u64,
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    _reason: exec::TaskDetachReason,
) {
    let Some(key) = ManagedReaperKey::decode(raw) else {
        return;
    };
    let Some(slot) = managed_reaper_slot(key) else {
        return;
    };
    let (completion, fallback) = {
        let mut record = slot.record.lock();
        if !record.exact(key) {
            return;
        }
        let self_exact = record
            .reaper_task
            .as_ref()
            .is_some_and(|handle| handle.id() == task && handle.allocation_domain() == domain);
        if !self_exact {
            record.terminal = None;
        }
        record.phase = ManagedReaperPhase::Quarantined;
        record.reaper_finished = true;
        let fallback = record.parent_wake;
        match slot.completion.publish(key.generation) {
            Ok(wake) => (Some(wake), fallback),
            Err(_) => (None, fallback),
        }
    };
    if !completion.is_some_and(exec::OneShotWake::dispatch) {
        if let Some(parent) = fallback {
            let _ = parent.wake_if_exact();
        }
    }
}

fn reserve_managed_reaper(
    lifecycle: &'static dyn ManagedComponentLifecycle,
) -> Result<ManagedComponentStartLease, ComponentTerminal> {
    for (index, slot) in MANAGED_REAPERS.iter().enumerate() {
        let key = {
            let mut record = slot.record.lock();
            if record.phase != ManagedReaperPhase::Vacant
                || slot.activation.waiter_count() != 0
                || slot.control.waiter_count() != 0
                || slot.lifecycle.waiter_count() != 0
                || slot.completion.waiter_count() != 0
            {
                continue;
            }
            let Some(generation) = record.generation.checked_add(1).filter(|generation| {
                *generation != 0 && *generation <= MAX_MANAGED_REAPER_GENERATION
            }) else {
                record.phase = ManagedReaperPhase::Quarantined;
                continue;
            };
            let key = ManagedReaperKey {
                slot: index as u8,
                generation,
            };
            record.generation = generation;
            record.phase = ManagedReaperPhase::Reserved;
            record.lifecycle = Some(lifecycle);
            record.parent_task = None;
            record.parent_domain = None;
            record.parent_wake = None;
            record.component = None;
            record.terminal = None;
            record.prestart_io = None;
            record.prestart_terminal = None;
            record.prestart_finalized = false;
            record.cancel_terminal = None;
            record.detached = false;
            record.foreground_disarmed = false;
            record.reaper_finished = false;
            record.reaper_task = None;
            key
        };
        let Some(raw) = key.encode() else {
            slot.record.lock().phase = ManagedReaperPhase::Quarantined;
            continue;
        };
        let target = unsafe { exec::TaskDetachTarget::new(raw, managed_parent_detached) };
        let parent = match unsafe { exec::register_current_task_detach(target) } {
            Ok(parent) => parent,
            Err(_) => {
                let mut record = slot.record.lock();
                if record.exact(key) && record.phase == ManagedReaperPhase::Reserved {
                    record.phase = ManagedReaperPhase::Aborted;
                    // No IO envelope or reaper task exists yet, so this is an
                    // exact clean rollback with no pending terminalization.
                    record.prestart_finalized = true;
                    record.reaper_finished = true;
                    record.foreground_disarmed = true;
                    record.maybe_clear_for_reuse();
                }
                return Err(ComponentTerminal::RunnerFault);
            }
        };
        {
            let mut record = slot.record.lock();
            if !record.exact(key)
                || record.phase != ManagedReaperPhase::Reserved
                || record.parent_task.is_some()
                || record.parent_domain.is_some()
            {
                let _ = parent.disarm();
                record.phase = ManagedReaperPhase::Quarantined;
                return Err(ComponentTerminal::RunnerFault);
            }
            record.parent_task = Some(parent.task_id());
            record.parent_domain = Some(parent.allocation_domain());
            record.parent_wake = Some(parent);
        }
        return Ok(ManagedComponentStartLease {
            reaper: key,
            parent,
        });
    }
    Err(ComponentTerminal::Unavailable)
}

fn install_managed_reaper_io(
    lease: ManagedComponentStartLease,
    io: ManagedComponentIo,
) -> Result<(), ManagedComponentIo> {
    let Some(slot) = managed_reaper_slot(lease.reaper) else {
        return Err(io);
    };
    let mut record = slot.record.lock();
    if !managed_reaper_matches_lease(&record, lease)
        || record.phase != ManagedReaperPhase::Reserved
        || record.prestart_io.is_some()
    {
        if record.exact(lease.reaper) {
            record.phase = ManagedReaperPhase::Quarantined;
        }
        return Err(io);
    }
    record.prestart_io = Some(io);
    Ok(())
}

fn publish_managed_reaper_task(lease: ManagedComponentStartLease) -> Result<(), ComponentTerminal> {
    let mut system = heap::enter_owner(heap::OwnerId::SYSTEM);
    let result = (|| {
        let mut batch = exec::PreparedTaskBatch::new();
        batch
            .try_reserve(1)
            .map_err(|_| ComponentTerminal::RunnerFault)?;
        batch.prepare(
            "vsh-managed-system-reaper",
            run_managed_reaper(lease.reaper),
        );
        let prepared_handle = batch
            .prepared_handles()
            .first()
            .expect("managed reaper batch contains one prepared handle")
            .clone();
        {
            let Some(slot) = managed_reaper_slot(lease.reaper) else {
                return Err(ComponentTerminal::RunnerFault);
            };
            let mut record = slot.record.lock();
            if !managed_reaper_matches_lease(&record, lease)
                || record.phase != ManagedReaperPhase::Reserved
                || record.reaper_task.is_some()
            {
                record.phase = ManagedReaperPhase::Quarantined;
                return Err(ComponentTerminal::RunnerFault);
            }
            record.reaper_task = Some(prepared_handle);
        }
        let mut handles = batch
            .publish()
            .map_err(|_| ComponentTerminal::RunnerFault)?;
        let Some(handle) = handles.pop() else {
            return Err(ComponentTerminal::RunnerFault);
        };
        if !handles.is_empty() || !handle.is_published() {
            return Err(ComponentTerminal::RunnerFault);
        }
        let Some(slot) = managed_reaper_slot(lease.reaper) else {
            return Err(ComponentTerminal::RunnerFault);
        };
        let record = slot.record.lock();
        let exact_handle = record.reaper_task.as_ref().is_some_and(|prepared| {
            prepared.id() == handle.id()
                && prepared.shares_status_with(&handle)
                && prepared.is_published()
        });
        let clean_reaper_abort = managed_reaper_matches_lease(&record, lease)
            && exact_handle
            && record.phase == ManagedReaperPhase::Aborted
            && record.prestart_finalized
            && record.reaper_finished
            && record.prestart_io.is_none()
            && record.prestart_terminal == Some(ComponentTerminal::RunnerFault)
            && matches!(handle.state(), TaskState::Running | TaskState::Exited);
        if clean_reaper_abort {
            return Err(ComponentTerminal::RunnerFault);
        }
        if !managed_reaper_matches_lease(&record, lease)
            || !exact_handle
            || !matches!(
                record.phase,
                ManagedReaperPhase::Reserved | ManagedReaperPhase::Armed
            )
            || handle.state() != TaskState::Running
            || record.reaper_task.as_ref().is_none_or(|prepared| {
                prepared.id() != handle.id()
                    || !prepared.shares_status_with(&handle)
                    || !prepared.is_published()
                    || prepared.state() != TaskState::Running
            })
        {
            drop(record);
            slot.record.lock().phase = ManagedReaperPhase::Quarantined;
            return Err(ComponentTerminal::RunnerFault);
        }
        Ok(())
    })();
    system.restore();
    result
}

enum ManagedPrepareFailure {
    Terminal(ComponentTerminal),
    Lost,
}

async fn prepare_managed_reaper(
    lifecycle: &'static dyn ManagedComponentLifecycle,
    io: ManagedComponentIo,
) -> Result<ManagedComponentStartLease, ManagedPrepareFailure> {
    let lease = match reserve_managed_reaper(lifecycle) {
        Ok(lease) => lease,
        Err(terminal) => {
            return Err(ManagedPrepareFailure::Terminal(
                io.finalize_unpublished(terminal),
            ));
        }
    };
    let mut foreground = ManagedForegroundGuard::new(lease);
    if let Err(io) = install_managed_reaper_io(lease, io) {
        let terminal = io.finalize_unpublished(ComponentTerminal::RunnerFault);
        disarm_managed_reaper_foreground(lease);
        return Err(ManagedPrepareFailure::Terminal(terminal));
    }
    if !exec::try_reserve_current_task_registrations(2) {
        let outcome = abort_managed_reaper_start(lease, false, ComponentTerminal::RunnerFault);
        disarm_managed_reaper_foreground(lease);
        return Err(match outcome {
            ManagedComponentStartAbort::CleanAborted => {
                ManagedPrepareFailure::Terminal(ComponentTerminal::RunnerFault)
            }
            ManagedComponentStartAbort::Quarantined => ManagedPrepareFailure::Lost,
        });
    }
    if publish_managed_reaper_task(lease).is_err() {
        let outcome = abort_managed_reaper_start(lease, false, ComponentTerminal::RunnerFault);
        disarm_managed_reaper_foreground(lease);
        return Err(match outcome {
            ManagedComponentStartAbort::CleanAborted => {
                ManagedPrepareFailure::Terminal(ComponentTerminal::RunnerFault)
            }
            ManagedComponentStartAbort::Quarantined => ManagedPrepareFailure::Lost,
        });
    }
    loop {
        let (phase, reaper_running, prestart_terminal, prestart_finalized) =
            managed_reaper_slot(lease.reaper)
                .map(|slot| {
                    let record = slot.record.lock();
                    if managed_reaper_matches_lease(&record, lease) {
                        (
                            record.phase,
                            record.reaper_task.as_ref().is_some_and(|handle| {
                                handle.is_published() && handle.state() == TaskState::Running
                            }),
                            record.prestart_terminal,
                            record.prestart_finalized,
                        )
                    } else {
                        (ManagedReaperPhase::Quarantined, false, None, false)
                    }
                })
                .unwrap_or((ManagedReaperPhase::Quarantined, false, None, false));
        match phase {
            ManagedReaperPhase::Armed => {
                foreground.release();
                return Ok(lease);
            }
            ManagedReaperPhase::Reserved if reaper_running => exec::yield_now().await,
            ManagedReaperPhase::Aborted if reaper_running && !prestart_finalized => {
                exec::yield_now().await
            }
            ManagedReaperPhase::Vacant
            | ManagedReaperPhase::Bound
            | ManagedReaperPhase::Active
            | ManagedReaperPhase::Terminal
            | ManagedReaperPhase::Aborted
            | ManagedReaperPhase::Quarantined => {
                disarm_managed_reaper_foreground(lease);
                return Err(match (phase, prestart_terminal) {
                    (ManagedReaperPhase::Aborted, Some(terminal)) => {
                        ManagedPrepareFailure::Terminal(terminal)
                    }
                    _ => ManagedPrepareFailure::Lost,
                });
            }
            ManagedReaperPhase::Reserved => {
                let _ = abort_managed_reaper_start(lease, true, ComponentTerminal::RunnerFault);
                disarm_managed_reaper_foreground(lease);
                return Err(ManagedPrepareFailure::Lost);
            }
        }
    }
}

fn bind_managed_reaper(lease: ManagedComponentStartLease, token: ManagedComponentToken) -> bool {
    let Some(slot) = managed_reaper_slot(lease.reaper) else {
        return false;
    };
    {
        let mut record = slot.record.lock();
        if !managed_reaper_matches_lease(&record, lease)
            || record.phase != ManagedReaperPhase::Armed
            || record.component.is_some()
            || record.prestart_io.is_none()
            || record
                .reaper_task
                .as_ref()
                .is_none_or(|handle| !handle.is_published() || handle.state() != TaskState::Running)
        {
            if record.exact(lease.reaper) {
                record.phase = ManagedReaperPhase::Quarantined;
            }
            return false;
        }
        record.component = Some(token);
        record.phase = ManagedReaperPhase::Bound;
    }
    true
}

fn claim_managed_reaper_io(
    lease: ManagedComponentStartLease,
    token: ManagedComponentToken,
) -> Option<ManagedComponentIo> {
    let slot = managed_reaper_slot(lease.reaper)?;
    let mut record = slot.record.lock();
    if !managed_reaper_matches_lease(&record, lease)
        || record.phase != ManagedReaperPhase::Bound
        || record.component != Some(token)
    {
        if record.exact(lease.reaper) {
            record.phase = ManagedReaperPhase::Quarantined;
        }
        return None;
    }
    record.prestart_io.take()
}

fn commit_managed_reaper_publication(
    lease: ManagedComponentStartLease,
    token: ManagedComponentToken,
) -> Option<ManagedComponentReaperWake> {
    let Some(slot) = managed_reaper_slot(lease.reaper) else {
        return None;
    };
    let (wake, reaper) = {
        let mut record = slot.record.lock();
        if !managed_reaper_matches_lease(&record, lease)
            || record.phase != ManagedReaperPhase::Bound
            || record.component != Some(token)
            || record.prestart_io.is_some()
            || record.reaper_finished
            || record
                .reaper_task
                .as_ref()
                .is_none_or(|handle| !handle.is_published() || handle.state() != TaskState::Running)
        {
            if record.exact(lease.reaper) {
                record.phase = ManagedReaperPhase::Quarantined;
            }
            return None;
        }
        record.phase = ManagedReaperPhase::Active;
        let reaper = record.reaper_task.as_ref().map(TaskHandle::exact_wake);
        match slot.activation.publish(lease.reaper.generation) {
            Ok(wake) => (wake, reaper),
            Err(_) => {
                record.phase = ManagedReaperPhase::Quarantined;
                return None;
            }
        }
    };
    Some(ManagedComponentReaperWake {
        wake: Some(wake),
        reaper,
    })
}

fn notify_managed_reaper_state(
    lease: ManagedComponentStartLease,
) -> Option<ManagedComponentReaperWake> {
    let Some(slot) = managed_reaper_slot(lease.reaper) else {
        return None;
    };
    let (wake, reaper) = {
        let mut record = slot.record.lock();
        if !managed_reaper_matches_lease(&record, lease) {
            return None;
        }
        if record.phase == ManagedReaperPhase::Terminal
            || (record.phase == ManagedReaperPhase::Quarantined && record.terminal.is_some())
        {
            return Some(ManagedComponentReaperWake {
                wake: None,
                reaper: record.reaper_task.as_ref().map(TaskHandle::exact_wake),
            });
        }
        if record.phase != ManagedReaperPhase::Active || record.component.is_none() {
            return None;
        }
        let reaper = record.reaper_task.as_ref().map(TaskHandle::exact_wake);
        match slot.lifecycle.publish(lease.reaper.generation) {
            Ok(wake) => (wake, reaper),
            Err(_) => {
                record.phase = ManagedReaperPhase::Quarantined;
                return None;
            }
        }
    };
    Some(ManagedComponentReaperWake {
        wake: Some(wake),
        reaper,
    })
}

fn notify_managed_reaper_complete(
    lease: ManagedComponentStartLease,
    token: ManagedComponentToken,
    terminal: ComponentTerminal,
) -> Option<ManagedComponentReaperWake> {
    let Some(slot) = managed_reaper_slot(lease.reaper) else {
        return None;
    };
    let (wake, reaper) = {
        let mut record = slot.record.lock();
        if !managed_reaper_matches_lease(&record, lease)
            || record.phase != ManagedReaperPhase::Active
            || record.component != Some(token)
            || record.reaper_finished
        {
            return None;
        }
        match record.terminal {
            None => record.terminal = Some(terminal),
            Some(existing) if existing == terminal => {}
            Some(_) => {
                record.phase = ManagedReaperPhase::Quarantined;
                return None;
            }
        }
        let reaper = record.reaper_task.as_ref().map(TaskHandle::exact_wake);
        match slot.lifecycle.publish(lease.reaper.generation) {
            Ok(wake) => (wake, reaper),
            Err(_) => {
                record.phase = ManagedReaperPhase::Quarantined;
                return None;
            }
        }
    };
    Some(ManagedComponentReaperWake {
        wake: Some(wake),
        reaper,
    })
}

fn quarantine_managed_reaper_staged_complete(
    lease: ManagedComponentStartLease,
    token: ManagedComponentToken,
    terminal: ComponentTerminal,
) -> bool {
    let Some(slot) = managed_reaper_slot(lease.reaper) else {
        return false;
    };
    let (wake, publish_failed, parent_fallback, reaper_fallback) = {
        let mut record = slot.record.lock();
        if !managed_reaper_matches_lease(&record, lease)
            || record.component != Some(token)
            || !matches!(
                record.phase,
                ManagedReaperPhase::Active | ManagedReaperPhase::Quarantined
            )
        {
            return false;
        }
        match record.terminal {
            None => record.terminal = Some(terminal),
            Some(existing) if existing == terminal => {}
            Some(_) => return false,
        }
        record.phase = ManagedReaperPhase::Quarantined;
        let parent_fallback = record.parent_wake;
        let reaper_fallback = record.reaper_task.as_ref().map(TaskHandle::exact_wake);
        match slot.lifecycle.publish(lease.reaper.generation) {
            Ok(wake) => (Some(wake), false, parent_fallback, reaper_fallback),
            Err(_) => (None, true, parent_fallback, reaper_fallback),
        }
    };
    let dispatched = wake.is_some_and(exec::OneShotWake::dispatch);
    // `publish` removes the registered waiter before returning its detached
    // wake. If the lifecycle publisher faults after staging the terminal but
    // before dispatch, replaying the same generation succeeds with no queue
    // wake. A failed publication likewise cannot be trusted to retain one.
    // The stable reaper TaskStatus is the exact recovery edge which makes it
    // poll the already-published watermark instead of remaining parked.
    if !dispatched {
        if let Some(fallback) = reaper_fallback {
            let _ = fallback.wake_if_exact();
        }
    }
    if publish_failed {
        if let Some(fallback) = parent_fallback {
            let _ = fallback.wake_if_exact();
        }
    }
    true
}

fn abort_managed_reaper_start(
    lease: ManagedComponentStartLease,
    quarantine: bool,
    terminal: ComponentTerminal,
) -> ManagedComponentStartAbort {
    let Some(slot) = managed_reaper_slot(lease.reaper) else {
        return ManagedComponentStartAbort::Quarantined;
    };
    let (
        mut activation,
        mut lifecycle,
        io,
        definitely_no_reaper,
        mut outcome,
        mut reaper_fallback,
        mut reaper_wake_required,
    ) = {
        let mut record = slot.record.lock();
        if !managed_reaper_matches_lease(&record, lease) {
            return ManagedComponentStartAbort::Quarantined;
        }
        if quarantine
            || matches!(
                record.phase,
                ManagedReaperPhase::Bound | ManagedReaperPhase::Active
            )
        {
            record.phase = ManagedReaperPhase::Quarantined;
            (
                slot.activation.publish(lease.reaper.generation).ok(),
                slot.lifecycle.publish(lease.reaper.generation).ok(),
                None,
                false,
                ManagedComponentStartAbort::Quarantined,
                record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                true,
            )
        } else if matches!(
            record.phase,
            ManagedReaperPhase::Reserved | ManagedReaperPhase::Armed
        ) && record.prestart_io.is_some()
        {
            // Move the envelope only into this caller's local finalization
            // transaction. Keep the phase Reserved/Armed until the immutable
            // stream terminal is committed: a concurrently polling reaper
            // must not observe Aborted with an empty envelope and mistake the
            // in-flight finalization for identity loss.
            let io = record.prestart_io.take();
            let definitely_no_reaper = record
                .reaper_task
                .as_ref()
                .is_none_or(|handle| !handle.is_published());
            record.prestart_terminal = Some(terminal);
            if definitely_no_reaper {
                record.reaper_finished = true;
                record.reaper_task = None;
            }
            (
                None,
                None,
                io,
                definitely_no_reaper,
                ManagedComponentStartAbort::CleanAborted,
                record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                false,
            )
        } else if record.phase == ManagedReaperPhase::Aborted
            && record.prestart_terminal == Some(terminal)
            && record.prestart_finalized
        {
            (
                None,
                None,
                None,
                false,
                ManagedComponentStartAbort::CleanAborted,
                record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                !record.reaper_finished,
            )
        } else {
            record.phase = ManagedReaperPhase::Quarantined;
            (
                slot.activation.publish(lease.reaper.generation).ok(),
                slot.lifecycle.publish(lease.reaper.generation).ok(),
                None,
                false,
                ManagedComponentStartAbort::Quarantined,
                record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                true,
            )
        }
    };
    if let Some(io) = io {
        let finalized = io.finalize_unpublished(terminal) == terminal;
        let mut record = slot.record.lock();
        if managed_reaper_matches_lease(&record, lease)
            && matches!(
                record.phase,
                ManagedReaperPhase::Reserved | ManagedReaperPhase::Armed
            )
            && record.prestart_terminal == Some(terminal)
            && record.prestart_io.is_none()
        {
            if finalized {
                record.phase = ManagedReaperPhase::Aborted;
                record.prestart_finalized = true;
                if !definitely_no_reaper {
                    activation = slot.activation.publish(lease.reaper.generation).ok();
                    reaper_fallback = record.reaper_task.as_ref().map(TaskHandle::exact_wake);
                    reaper_wake_required = true;
                }
                record.maybe_clear_for_reuse();
            } else {
                record.phase = ManagedReaperPhase::Quarantined;
                record.prestart_terminal = None;
                record.prestart_finalized = false;
                activation = slot.activation.publish(lease.reaper.generation).ok();
                lifecycle = slot.lifecycle.publish(lease.reaper.generation).ok();
                reaper_fallback = record.reaper_task.as_ref().map(TaskHandle::exact_wake);
                reaper_wake_required = true;
            }
        } else {
            // A detach/self-fault or identity mismatch won while finalization
            // ran outside the fixed lock. Never turn that partial result back
            // into a clean abort or make the generation reusable.
            outcome = ManagedComponentStartAbort::Quarantined;
        }
        if !finalized {
            outcome = ManagedComponentStartAbort::Quarantined;
        }
    }
    let reaper_dispatched = activation.is_some_and(exec::OneShotWake::dispatch)
        | lifecycle.is_some_and(exec::OneShotWake::dispatch);
    if reaper_wake_required && !reaper_dispatched {
        if let Some(reaper) = reaper_fallback {
            let _ = reaper.wake_if_exact();
        }
    }
    outcome
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagedReaperCancelOwnership {
    Published,
    Retired,
    Lost,
}

fn request_managed_reaper_cancel(
    lease: ManagedComponentStartLease,
) -> ManagedReaperCancelOwnership {
    let Some(slot) = managed_reaper_slot(lease.reaper) else {
        return ManagedReaperCancelOwnership::Lost;
    };
    let prestart = {
        let record = slot.record.lock();
        managed_reaper_matches_lease(&record, lease)
            && matches!(
                record.phase,
                ManagedReaperPhase::Reserved | ManagedReaperPhase::Armed
            )
    };
    if prestart {
        return match abort_managed_reaper_start(lease, false, ComponentTerminal::Cancelled) {
            ManagedComponentStartAbort::CleanAborted => ManagedReaperCancelOwnership::Retired,
            ManagedComponentStartAbort::Quarantined => ManagedReaperCancelOwnership::Lost,
        };
    }
    let (control, activation, lifecycle, completion, fallback, reaper_fallback, outcome) = {
        let mut record = slot.record.lock();
        if !managed_reaper_matches_lease(&record, lease) {
            return ManagedReaperCancelOwnership::Lost;
        }
        match record.phase {
            ManagedReaperPhase::Active => {
                record
                    .cancel_terminal
                    .get_or_insert(ComponentTerminal::Cancelled);
                match slot.control.publish(lease.reaper.generation) {
                    Ok(wake) => (
                        Some(wake),
                        None,
                        None,
                        None,
                        None,
                        record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                        ManagedReaperCancelOwnership::Published,
                    ),
                    Err(_) => {
                        record.phase = ManagedReaperPhase::Quarantined;
                        let activation = slot.activation.publish(lease.reaper.generation).ok();
                        let lifecycle = slot.lifecycle.publish(lease.reaper.generation).ok();
                        match slot.completion.publish(lease.reaper.generation) {
                            Ok(completion) => (
                                None,
                                activation,
                                lifecycle,
                                Some(completion),
                                record.parent_wake,
                                record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                                ManagedReaperCancelOwnership::Lost,
                            ),
                            Err(_) => (
                                None,
                                activation,
                                lifecycle,
                                None,
                                record.parent_wake,
                                record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                                ManagedReaperCancelOwnership::Lost,
                            ),
                        }
                    }
                }
            }
            // A foreground operation cannot safely retire a Bound partial
            // start. Quarantine and release every installed SYSTEM listener;
            // the child-side publication transaction must fail-stop/leak.
            ManagedReaperPhase::Bound => {
                record.phase = ManagedReaperPhase::Quarantined;
                let activation = slot.activation.publish(lease.reaper.generation).ok();
                let lifecycle = slot.lifecycle.publish(lease.reaper.generation).ok();
                match slot.completion.publish(lease.reaper.generation) {
                    Ok(completion) => (
                        None,
                        activation,
                        lifecycle,
                        Some(completion),
                        record.parent_wake,
                        record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                        ManagedReaperCancelOwnership::Lost,
                    ),
                    Err(_) => (
                        None,
                        activation,
                        lifecycle,
                        None,
                        record.parent_wake,
                        record.reaper_task.as_ref().map(TaskHandle::exact_wake),
                        ManagedReaperCancelOwnership::Lost,
                    ),
                }
            }
            ManagedReaperPhase::Terminal | ManagedReaperPhase::Aborted => (
                None,
                None,
                None,
                None,
                None,
                None,
                ManagedReaperCancelOwnership::Retired,
            ),
            ManagedReaperPhase::Reserved
            | ManagedReaperPhase::Armed
            | ManagedReaperPhase::Vacant
            | ManagedReaperPhase::Quarantined => (
                None,
                None,
                None,
                None,
                None,
                None,
                ManagedReaperCancelOwnership::Lost,
            ),
        }
    };
    let reaper_dispatched = control.is_some_and(exec::OneShotWake::dispatch)
        | activation.is_some_and(exec::OneShotWake::dispatch)
        | lifecycle.is_some_and(exec::OneShotWake::dispatch);
    if !reaper_dispatched {
        if let Some(reaper) = reaper_fallback {
            let _ = reaper.wake_if_exact();
        }
    }
    if !completion.is_some_and(exec::OneShotWake::dispatch) {
        if let Some(parent) = fallback {
            let _ = parent.wake_if_exact();
        }
    }
    outcome
}

fn disarm_managed_reaper_foreground(lease: ManagedComponentStartLease) {
    disarm_managed_reaper_foreground_after_handoff(lease, false);
}

fn disarm_managed_reaper_foreground_after_handoff(
    lease: ManagedComponentStartLease,
    handoff_published: bool,
) {
    let disarmed = lease.parent.disarm();
    let Some(slot) = managed_reaper_slot(lease.reaper) else {
        return;
    };
    let mut record = slot.record.lock();
    if managed_reaper_matches_lease(&record, lease) {
        let terminal_or_aborted = matches!(
            record.phase,
            ManagedReaperPhase::Terminal | ManagedReaperPhase::Aborted
        );
        if matches!(
            disarmed,
            exec::TaskDetachDisarm::Disarmed | exec::TaskDetachDisarm::AlreadyDisarmed
        ) || handoff_published
            || terminal_or_aborted
        {
            // A cross-task Session handoff cannot remove the old TaskStatus
            // entry, but the SYSTEM slot already owns cancellation. Reuse is
            // safe: the later old-generation callback decodes this retired
            // key and is inert against the incremented slot generation.
            record.foreground_disarmed = true;
            record.maybe_clear_for_reuse();
        }
    }
}

fn handoff_managed_reaper(lease: ManagedComponentStartLease) {
    if lease.parent.is_current_reclaiming_exact() {
        // Whole-task Drop has not established its final reason yet. The core
        // detach pass runs after Drop (and after any destructor fault) and is
        // the only authority allowed to publish Cancelled versus RunnerFault.
        return;
    }
    // Publish independent ownership/cancellation before removing the parent's
    // exact detach callback. A fault between these operations therefore still
    // leaves the SYSTEM reaper responsible for the token.
    if !matches!(
        request_managed_reaper_cancel(lease),
        ManagedReaperCancelOwnership::Lost
    ) {
        disarm_managed_reaper_foreground_after_handoff(lease, true);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagedReaperCompletion {
    Terminal(ComponentTerminal),
    Lost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagedReaperStatus {
    Waiting,
    Acknowledged(ComponentTerminal),
    Quarantined(ManagedReaperCompletion),
    CleanRetired,
    IdentityLost,
}

fn managed_reaper_status(lease: ManagedComponentStartLease) -> ManagedReaperStatus {
    let Some(slot) = managed_reaper_slot(lease.reaper) else {
        return ManagedReaperStatus::IdentityLost;
    };
    let record = slot.record.lock();
    if record.generation > lease.reaper.generation {
        return ManagedReaperStatus::CleanRetired;
    }
    if record.generation != lease.reaper.generation {
        return ManagedReaperStatus::IdentityLost;
    }
    if record.phase == ManagedReaperPhase::Vacant {
        return ManagedReaperStatus::CleanRetired;
    }
    if !managed_reaper_matches_lease(&record, lease) {
        return ManagedReaperStatus::IdentityLost;
    }
    match (record.phase, record.terminal, record.reaper_finished) {
        (ManagedReaperPhase::Terminal, Some(terminal), true) => {
            ManagedReaperStatus::Acknowledged(terminal)
        }
        (ManagedReaperPhase::Quarantined, Some(terminal), true) => {
            ManagedReaperStatus::Quarantined(ManagedReaperCompletion::Terminal(terminal))
        }
        (ManagedReaperPhase::Quarantined, None, true) => {
            ManagedReaperStatus::Quarantined(ManagedReaperCompletion::Lost)
        }
        _ => ManagedReaperStatus::Waiting,
    }
}

fn managed_reaper_completion(lease: ManagedComponentStartLease) -> Option<ManagedReaperCompletion> {
    match managed_reaper_status(lease) {
        ManagedReaperStatus::Acknowledged(terminal) => {
            Some(ManagedReaperCompletion::Terminal(terminal))
        }
        ManagedReaperStatus::Quarantined(completion) => Some(completion),
        ManagedReaperStatus::Waiting
        | ManagedReaperStatus::CleanRetired
        | ManagedReaperStatus::IdentityLost => None,
    }
}

fn managed_reaper_completion_listener(
    lease: ManagedComponentStartLease,
) -> Option<exec::OneShotWaitFuture<'static>> {
    let slot = managed_reaper_slot(lease.reaper)?;
    if !managed_reaper_matches_lease(&slot.record.lock(), lease) {
        return None;
    }
    Some(slot.completion.wait(lease.reaper.generation))
}

fn finish_reaper_prearm_failure(key: ManagedReaperKey) {
    let Some(slot) = managed_reaper_slot(key) else {
        return;
    };
    let io = {
        let mut record = slot.record.lock();
        if !record.exact(key) {
            drop(record);
            finish_reaper_lost(key);
            return;
        }
        if record.phase == ManagedReaperPhase::Aborted {
            drop(record);
            finish_reaper_aborted(key);
            return;
        }
        if record.phase == ManagedReaperPhase::Reserved
            && record.prestart_terminal.is_some()
            && record.prestart_io.is_none()
            && !record.prestart_finalized
        {
            // The parent already owns an exact lock-free stream finalization
            // transaction. Do not replace its first-winner terminal or expose
            // Aborted before that immutable close commits; simply retire this
            // reaper. A parent fault in the outside-lock interval changes the
            // still-Reserved slot to Quarantined via TaskDetach.
            record.reaper_finished = true;
            return;
        }
        if record.phase != ManagedReaperPhase::Reserved {
            drop(record);
            finish_reaper_lost(key);
            return;
        }
        record.phase = ManagedReaperPhase::Aborted;
        record.prestart_terminal = Some(ComponentTerminal::RunnerFault);
        record.reaper_finished = true;
        record.prestart_io.take()
    };
    let finalized = io.is_some_and(|io| {
        io.finalize_unpublished(ComponentTerminal::RunnerFault) == ComponentTerminal::RunnerFault
    });
    let mut record = slot.record.lock();
    if record.exact(key) && record.phase == ManagedReaperPhase::Aborted {
        if finalized {
            record.prestart_finalized = true;
            record.maybe_clear_for_reuse();
        } else {
            record.phase = ManagedReaperPhase::Quarantined;
            record.prestart_terminal = None;
        }
    }
}

fn finish_reaper_aborted(key: ManagedReaperKey) {
    let Some(slot) = managed_reaper_slot(key) else {
        return;
    };
    let (io, terminal) = {
        let mut record = slot.record.lock();
        if !record.exact(key) || record.phase != ManagedReaperPhase::Aborted {
            drop(record);
            finish_reaper_lost(key);
            return;
        }
        let Some(terminal) = record.prestart_terminal else {
            drop(record);
            finish_reaper_lost(key);
            return;
        };
        if record.prestart_finalized {
            record.reaper_finished = true;
            record.maybe_clear_for_reuse();
            return;
        }
        (record.prestart_io.take(), terminal)
    };
    let finalized = io.is_some_and(|io| io.finalize_unpublished(terminal) == terminal);
    let mut record = slot.record.lock();
    if record.exact(key)
        && record.phase == ManagedReaperPhase::Aborted
        && record.prestart_terminal == Some(terminal)
    {
        record.reaper_finished = true;
        if finalized {
            record.prestart_finalized = true;
            record.maybe_clear_for_reuse();
        } else {
            record.phase = ManagedReaperPhase::Quarantined;
            record.prestart_terminal = None;
            record.prestart_finalized = false;
        }
    }
}

fn stage_reaper_terminal(key: ManagedReaperKey, terminal: ComponentTerminal) -> bool {
    let Some(slot) = managed_reaper_slot(key) else {
        return false;
    };
    let mut record = slot.record.lock();
    if !record.exact(key) || record.phase != ManagedReaperPhase::Active {
        return false;
    }
    match record.terminal {
        None => {
            record.terminal = Some(terminal);
            true
        }
        Some(existing) => existing == terminal,
    }
}

fn finish_reaper_terminal(key: ManagedReaperKey, terminal: ComponentTerminal, reusable: bool) {
    let Some(slot) = managed_reaper_slot(key) else {
        return;
    };
    let (wake, fallback) = {
        let mut record = slot.record.lock();
        if !record.exact(key) {
            return;
        }
        // Complete(T) was staged before CONTROL acknowledgement. Never repair
        // an absent or different value after ack: that would turn an identity
        // mismatch into a fabricated exact terminal/reuse proof.
        let staged_exact = record.terminal == Some(terminal);
        let phase_allows_reuse = staged_exact && record.phase == ManagedReaperPhase::Active;
        record.reaper_finished = true;
        record.phase = if staged_exact && reusable && phase_allows_reuse {
            ManagedReaperPhase::Terminal
        } else {
            ManagedReaperPhase::Quarantined
        };
        let fallback = record.parent_wake;
        match slot.completion.publish(key.generation) {
            Ok(wake) => {
                record.maybe_clear_for_reuse();
                (Some(wake), fallback)
            }
            Err(_) => {
                record.phase = ManagedReaperPhase::Quarantined;
                (None, fallback)
            }
        }
    };
    if !wake.is_some_and(exec::OneShotWake::dispatch) {
        if let Some(parent) = fallback {
            let _ = parent.wake_if_exact();
        }
    }
}

fn finish_reaper_lost(key: ManagedReaperKey) {
    let Some(slot) = managed_reaper_slot(key) else {
        return;
    };
    let (wake, fallback) = {
        let mut record = slot.record.lock();
        if !record.exact(key) {
            return;
        }
        record.phase = ManagedReaperPhase::Quarantined;
        // Never overwrite an exact terminal observed before a later Lost.
        // A terminal-less Lost remains distinguishable so callers cannot
        // fabricate a Component terminal reason.
        record.reaper_finished = true;
        let fallback = record.parent_wake;
        match slot.completion.publish(key.generation) {
            Ok(wake) => (Some(wake), fallback),
            Err(_) => (None, fallback),
        }
    };
    if !wake.is_some_and(exec::OneShotWake::dispatch) {
        if let Some(parent) = fallback {
            let _ = parent.wake_if_exact();
        }
    }
}

async fn run_managed_reaper(key: ManagedReaperKey) {
    if !exec::try_reserve_current_task_registrations(3) {
        finish_reaper_prearm_failure(key);
        return;
    }
    let Some(raw) = key.encode() else {
        finish_reaper_prearm_failure(key);
        return;
    };
    let target = unsafe { exec::TaskDetachTarget::new(raw, managed_reaper_detached) };
    let self_detach = match unsafe { exec::register_current_task_detach(target) } {
        Ok(lease) => lease,
        Err(_) => {
            finish_reaper_prearm_failure(key);
            return;
        }
    };
    run_managed_reaper_inner(key).await;
    if !matches!(
        self_detach.disarm(),
        exec::TaskDetachDisarm::Disarmed | exec::TaskDetachDisarm::AlreadyDisarmed
    ) {
        finish_reaper_lost(key);
    }
}

async fn run_managed_reaper_inner(key: ManagedReaperKey) {
    enum ReaperWake {
        Lifecycle(Result<(), OneShotWaitError>),
        Control(Result<(), OneShotWaitError>),
    }

    let Some(slot) = managed_reaper_slot(key) else {
        return;
    };
    let mut activation = core::pin::pin!(slot.activation.wait(key.generation));
    let mut initial_control = core::pin::pin!(slot.control.wait(key.generation));
    // Armed is published only after both fixed waiter registrations really
    // reached Pending. The parent awaits this phase before entering start, so
    // no post-child allocation/registration failure can remove the reaper.
    let armed = poll_fn(|context| {
        if !matches!(activation.as_mut().poll(context), Poll::Pending)
            || !matches!(initial_control.as_mut().poll(context), Poll::Pending)
        {
            return Poll::Ready(false);
        }
        let mut record = slot.record.lock();
        if record.exact(key)
            && record.phase == ManagedReaperPhase::Reserved
            && record
                .reaper_task
                .as_ref()
                .is_some_and(|handle| handle.is_published() && handle.state() == TaskState::Running)
        {
            record.phase = ManagedReaperPhase::Armed;
            Poll::Ready(true)
        } else {
            Poll::Ready(false)
        }
    })
    .await;
    if !armed {
        if slot.record.lock().phase == ManagedReaperPhase::Aborted {
            finish_reaper_aborted(key);
        } else {
            finish_reaper_lost(key);
        }
        return;
    }
    let mut activation_consumed = false;
    let mut control_consumed = false;
    let (lifecycle, token) = loop {
        let mut lost = false;
        let mut aborted = false;
        let snapshot = {
            let record = slot.record.lock();
            if !record.exact(key) {
                return;
            }
            match record.phase {
                ManagedReaperPhase::Reserved | ManagedReaperPhase::Armed => None,
                ManagedReaperPhase::Bound => None,
                ManagedReaperPhase::Active => record
                    .lifecycle
                    .zip(record.component)
                    .map(|(lifecycle, token)| (lifecycle, token)),
                ManagedReaperPhase::Aborted => {
                    aborted = true;
                    None
                }
                ManagedReaperPhase::Quarantined => {
                    lost = true;
                    None
                }
                ManagedReaperPhase::Terminal | ManagedReaperPhase::Vacant => return,
            }
        };
        if lost {
            finish_reaper_lost(key);
            return;
        }
        if aborted {
            finish_reaper_aborted(key);
            return;
        }
        if let Some(snapshot) = snapshot {
            // Active is published together with this exact activation
            // watermark. Consume it before installing the terminal listener
            // so its TaskStatus registration is deterministically disarmed.
            if !activation_consumed {
                if activation.as_mut().await.is_err() {
                    finish_reaper_lost(key);
                    return;
                }
            }
            break snapshot;
        }
        let wake = if control_consumed {
            ReaperWake::Lifecycle(activation.as_mut().await)
        } else {
            poll_fn(|context| {
                if let Poll::Ready(result) = activation.as_mut().poll(context) {
                    return Poll::Ready(ReaperWake::Lifecycle(result));
                }
                initial_control
                    .as_mut()
                    .poll(context)
                    .map(ReaperWake::Control)
            })
            .await
        };
        match wake {
            ReaperWake::Lifecycle(Ok(())) => activation_consumed = true,
            ReaperWake::Control(Ok(())) => control_consumed = true,
            ReaperWake::Lifecycle(Err(_)) | ReaperWake::Control(Err(_)) => {
                finish_reaper_lost(key);
                return;
            }
        }
    };

    let mut cancel_accepted = false;
    let mut lifecycle_notified = false;
    loop {
        let (phase, cancel_terminal) = {
            let record = slot.record.lock();
            if !record.exact(key) {
                return;
            }
            (record.phase, record.cancel_terminal)
        };
        if phase == ManagedReaperPhase::Quarantined {
            finish_reaper_lost(key);
            return;
        }
        if let Some(cancel_terminal) = cancel_terminal.filter(|_| !cancel_accepted) {
            match lifecycle.request_cancel(token, cancel_terminal) {
                ManagedComponentCancel::Busy => {
                    exec::yield_now().await;
                    continue;
                }
                ManagedComponentCancel::Requested
                | ManagedComponentCancel::AlreadyCompleting
                | ManagedComponentCancel::AlreadyComplete => {
                    cancel_accepted = true;
                    control_consumed = true;
                }
                ManagedComponentCancel::Lost => {
                    finish_reaper_lost(key);
                    return;
                }
            }
        }

        // The sole reaper is edge-driven. It never observes or acknowledges a
        // terminal before lifecycle CONTROL has published Complete and then
        // published this exact generation's terminal-only edge.
        if !lifecycle_notified {
            let mut lifecycle_event = core::pin::pin!(slot.lifecycle.wait(key.generation));
            if control_consumed {
                if lifecycle_event.await.is_err() {
                    finish_reaper_lost(key);
                    return;
                }
                lifecycle_notified = true;
                continue;
            }
            let wake = poll_fn(|context| {
                if let Poll::Ready(result) = lifecycle_event.as_mut().poll(context) {
                    return Poll::Ready(ReaperWake::Lifecycle(result));
                }
                initial_control
                    .as_mut()
                    .poll(context)
                    .map(ReaperWake::Control)
            })
            .await;
            match wake {
                ReaperWake::Lifecycle(Ok(())) => lifecycle_notified = true,
                ReaperWake::Control(Ok(())) => control_consumed = true,
                ReaperWake::Lifecycle(Err(_)) | ReaperWake::Control(Err(_)) => {
                    finish_reaper_lost(key);
                    return;
                }
            }
            continue;
        }

        match lifecycle.state(token) {
            ManagedComponentState::Busy => exec::yield_now().await,
            ManagedComponentState::Complete(terminal) => {
                if !stage_reaper_terminal(key, terminal) {
                    finish_reaper_lost(key);
                    return;
                }
                loop {
                    match lifecycle.acknowledge_complete(token) {
                        ManagedComponentAcknowledge::Busy => exec::yield_now().await,
                        ManagedComponentAcknowledge::Acknowledged => {
                            finish_reaper_terminal(key, terminal, true);
                            return;
                        }
                        ManagedComponentAcknowledge::Lost => {
                            finish_reaper_terminal(key, terminal, false);
                            return;
                        }
                    }
                }
            }
            ManagedComponentState::Lost | ManagedComponentState::Running => {
                finish_reaper_lost(key);
                return;
            }
        }
    }
}

#[cfg(test)]
mod managed_reaper_boundary_tests {
    use super::*;
    use core::num::NonZeroU64;
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    struct AckLostLifecycle {
        manifest: ComponentCommandManifest,
        acknowledgements: AtomicUsize,
        next_token: AtomicU64,
    }

    impl AckLostLifecycle {
        fn leaked() -> &'static Self {
            Box::leak(Box::new(Self {
                manifest: ComponentCommandManifest::new(
                    "managed-ack-lost-boundary",
                    1,
                    ComponentArtifactIdentity::new([0xac; 32]),
                    VIBE_STREAM_FILTER_WORLD,
                    "run",
                    0,
                    0,
                    StreamMode::Required,
                    StreamMode::Required,
                    StreamMode::Optional,
                    DEFAULT_STAGE_MEMORY,
                    10_000,
                    100,
                    256,
                    Vec::new(),
                )
                .unwrap(),
                acknowledgements: AtomicUsize::new(0),
                next_token: AtomicU64::new(3),
            }))
        }
    }

    unsafe impl ManagedComponentLifecycle for AckLostLifecycle {
        fn manifest(&self) -> &ComponentCommandManifest {
            &self.manifest
        }

        fn start(
            &self,
            cleanup: ManagedComponentStartLease,
        ) -> Result<ManagedComponentToken, ComponentTerminal> {
            let token = unsafe {
                ManagedComponentToken::from_trusted_raw(
                    NonZeroU64::new(self.next_token.fetch_add(1, Ordering::SeqCst)).unwrap(),
                )
            };
            assert!(cleanup.bind_before_child_publication(token));
            let io = cleanup
                .claim_bound_io(token)
                .expect("ack-lost fake claims exact bound IO");
            let (_, _, stdin, stdout) = io.into_parts();
            let reason = ComponentTerminal::Success.stream_close_reason();
            let _ = stdin.finalize(reason);
            let _ = stdout.finalize(reason);
            cleanup
                .commit_child_publication(token)
                .expect("ack-lost fake commits exact child")
                .dispatch();
            cleanup
                .notify_state_change()
                .expect("ack-lost fake publishes terminal edge")
                .dispatch();
            Ok(token)
        }

        fn state(&self, _token: ManagedComponentToken) -> ManagedComponentState {
            ManagedComponentState::Complete(ComponentTerminal::Success)
        }

        fn wait_state<'a>(
            &'a self,
            _token: ManagedComponentToken,
        ) -> ManagedComponentStateFuture<'a> {
            Box::pin(async { ManagedComponentState::Complete(ComponentTerminal::Success) })
        }

        fn request_cancel(
            &self,
            _token: ManagedComponentToken,
            _terminal: ComponentTerminal,
        ) -> ManagedComponentCancel {
            ManagedComponentCancel::AlreadyComplete
        }

        fn acknowledge_complete(
            &self,
            _token: ManagedComponentToken,
        ) -> ManagedComponentAcknowledge {
            self.acknowledgements.fetch_add(1, Ordering::SeqCst);
            ManagedComponentAcknowledge::Lost
        }
    }

    struct DroppedTerminalWakeLifecycle {
        manifest: ComponentCommandManifest,
    }

    impl DroppedTerminalWakeLifecycle {
        fn leaked() -> &'static Self {
            Box::leak(Box::new(Self {
                manifest: ComponentCommandManifest::new(
                    "managed-dropped-terminal-wake",
                    1,
                    ComponentArtifactIdentity::new([0xdd; 32]),
                    VIBE_STREAM_FILTER_WORLD,
                    "run",
                    0,
                    0,
                    StreamMode::Required,
                    StreamMode::Required,
                    StreamMode::Optional,
                    DEFAULT_STAGE_MEMORY,
                    10_000,
                    100,
                    256,
                    Vec::new(),
                )
                .unwrap(),
            }))
        }
    }

    unsafe impl ManagedComponentLifecycle for DroppedTerminalWakeLifecycle {
        fn manifest(&self) -> &ComponentCommandManifest {
            &self.manifest
        }

        fn start(
            &self,
            cleanup: ManagedComponentStartLease,
        ) -> Result<ManagedComponentToken, ComponentTerminal> {
            let token =
                unsafe { ManagedComponentToken::from_trusted_raw(NonZeroU64::new(2).unwrap()) };
            assert!(cleanup.bind_before_child_publication(token));
            let io = cleanup
                .claim_bound_io(token)
                .expect("dropped-wake fake claims exact bound IO");
            let (_, _, stdin, stdout) = io.into_parts();
            let reason = ComponentTerminal::Success.stream_close_reason();
            let _ = stdin.finalize(reason);
            let _ = stdout.finalize(reason);
            cleanup
                .commit_child_publication(token)
                .expect("dropped-wake fake commits exact child")
                .dispatch();
            Ok(token)
        }

        fn state(&self, _token: ManagedComponentToken) -> ManagedComponentState {
            ManagedComponentState::Lost
        }

        fn wait_state<'a>(
            &'a self,
            _token: ManagedComponentToken,
        ) -> ManagedComponentStateFuture<'a> {
            Box::pin(async { ManagedComponentState::Lost })
        }

        fn request_cancel(
            &self,
            _token: ManagedComponentToken,
            _terminal: ComponentTerminal,
        ) -> ManagedComponentCancel {
            ManagedComponentCancel::Lost
        }

        fn acknowledge_complete(
            &self,
            _token: ManagedComponentToken,
        ) -> ManagedComponentAcknowledge {
            ManagedComponentAcknowledge::Lost
        }
    }

    #[test]
    fn lost_terminal_edges_quarantine_all_sixteen_slots_without_stranding_reapers() {
        let lifecycle = AckLostLifecycle::leaked();
        let dropped_wake_lifecycle = DroppedTerminalWakeLifecycle::leaked();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_task = completed.clone();
        let parent = exec::spawn_tracked("managed-ack-lost-boundary-parent", async move {
            let (install, _pump) = new_ssh_exec_component_io();
            let dropped_wake_lease =
                match prepare_managed_reaper(dropped_wake_lifecycle, install.component).await {
                    Ok(lease) => lease,
                    Err(_) => panic!("a fresh fixed reaper slot is available"),
                };
            let token = dropped_wake_lifecycle
                .start(dropped_wake_lease)
                .expect("fake start commits exact child");
            let dropped_wake_slot = managed_reaper_slot(dropped_wake_lease.reaper)
                .expect("prepared lease names one fixed reaper slot");
            while dropped_wake_slot.lifecycle.waiter_count() == 0 {
                exec::yield_now().await;
            }
            assert_eq!(dropped_wake_slot.lifecycle.waiter_count(), 1);

            // Model a lifecycle fault after the one-shot queue removed its
            // installed waiter but before the detached wake was dispatched.
            drop(
                dropped_wake_lease
                    .notify_complete(token, ComponentTerminal::Success)
                    .expect("dropped-wake fake stages exact terminal"),
            );
            assert_eq!(dropped_wake_slot.lifecycle.waiter_count(), 0);
            assert!(
                dropped_wake_lease.quarantine_staged_complete(token, ComponentTerminal::Success)
            );
            loop {
                match managed_reaper_status(dropped_wake_lease) {
                    ManagedReaperStatus::Quarantined(ManagedReaperCompletion::Terminal(
                        ComponentTerminal::Success,
                    )) => break,
                    ManagedReaperStatus::Waiting => exec::yield_now().await,
                    other => panic!("unexpected dropped-wake status: {other:?}"),
                }
            }
            disarm_managed_reaper_foreground(dropped_wake_lease);

            for _ in 1..MANAGED_REAPER_SLOTS {
                let (install, _pump) = new_ssh_exec_component_io();
                let lease = match prepare_managed_reaper(lifecycle, install.component).await {
                    Ok(lease) => lease,
                    Err(_) => panic!("a fresh fixed reaper slot is available"),
                };
                let _token = lifecycle.start(lease).expect("fake start commits");
                loop {
                    match managed_reaper_status(lease) {
                        ManagedReaperStatus::Quarantined(ManagedReaperCompletion::Terminal(
                            ComponentTerminal::Success,
                        )) => break,
                        ManagedReaperStatus::Waiting => exec::yield_now().await,
                        other => panic!("unexpected ack-lost status: {other:?}"),
                    }
                }
                disarm_managed_reaper_foreground(lease);
            }

            let (install, _pump) = new_ssh_exec_component_io();
            assert!(matches!(
                prepare_managed_reaper(lifecycle, install.component).await,
                Err(ManagedPrepareFailure::Terminal(
                    ComponentTerminal::Unavailable
                ))
            ));
            completed_task.store(true, Ordering::Release);
        });
        exec::run_until_idle(1_000_000);
        assert_eq!(parent.state(), TaskState::Exited);
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(
            lifecycle.acknowledgements.load(Ordering::SeqCst),
            MANAGED_REAPER_SLOTS - 1
        );
    }
}

#[derive(Clone)]
enum Applet {
    Echo,
    Wc,
    True,
    False,
    Deny,
    Fault,
    Spin,
    Host {
        command: fn(&[String]) -> Result<String, Status>,
        observability: bool,
    },
    AsyncHost {
        command: fn(Vec<String>) -> crate::AsyncCommandFuture,
        observability: bool,
    },
    Component {
        manifest: Arc<ComponentCommandManifest>,
        runner: Arc<dyn ComponentCommandRunner>,
    },
    ManagedComponent {
        manifest: Arc<ComponentCommandManifest>,
        lifecycle: &'static dyn ManagedComponentLifecycle,
        io: ManagedComponentIoSource,
    },
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
pub struct ScriptRequirement {
    pub label: String,
    pub resource_kind: String,
    pub rights: Rights,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptManifest {
    pub name: String,
    pub abi: u16,
    pub requirements: Vec<ScriptRequirement>,
}

pub struct ScriptArtifact {
    source: String,
    script: Script,
    manifest: ScriptManifest,
}

impl ScriptArtifact {
    pub fn new(source: &str, manifest: ScriptManifest) -> Result<Arc<Self>, Diagnostic> {
        if manifest.abi != 1 || !valid_name(&manifest.name) {
            return Err(Diagnostic::new(0, source.len(), "invalid script manifest"));
        }
        let script = parse_script(source)?;
        let used = collect_script_requirements(&script)?;
        let mut declared = BTreeMap::new();
        for requirement in &manifest.requirements {
            if !valid_name(&requirement.label)
                || requirement.rights.contains(Rights::GRANT)
                || requirement.rights.contains(Rights::REVOKE)
                || requirement.rights.contains(Rights::INVOKE)
                || declared
                    .insert(
                        requirement.label.clone(),
                        (requirement.resource_kind.clone(), requirement.rights),
                    )
                    .is_some()
            {
                return Err(Diagnostic::new(
                    0,
                    source.len(),
                    "invalid script authority requirement",
                ));
            }
        }
        if used != declared {
            return Err(Diagnostic::new(
                0,
                source.len(),
                "script authority manifest is not exact",
            ));
        }
        Ok(Arc::new(Self {
            source: source.to_string(),
            script,
            manifest,
        }))
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub const fn manifest(&self) -> &ScriptManifest {
        &self.manifest
    }
}

impl Resource for ScriptArtifact {
    fn kind(&self) -> &'static str {
        "script-artifact"
    }

    fn describe(&self) -> String {
        format!("{} script ABI {}", self.manifest.name, self.manifest.abi)
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
                    self.peak_depth
                        .fetch_max(state.queue.len(), Ordering::Relaxed);
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
    pub fn peak_depth(&self) -> usize {
        self.peak_depth.load(Ordering::Relaxed)
    }
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
    pub const fn rights(&self) -> Rights {
        self.rights
    }
}

impl<T: Resource> Resource for PersistentProxy<T> {
    fn kind(&self) -> &'static str {
        "persistent-proxy"
    }
    fn describe(&self) -> String {
        format!("ephemeral {} proxy", self.rights)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Trusted admission broker for persistent resources. Generic `grant` remains
/// fail-closed; this creates a fresh volatile proxy rather than a durable child
/// or an object-identity registry entry.
pub fn install_persistent_proxy<T: Resource>(
    source: &CSpace,
    cap: Cap,
    rights: Rights,
    stage: &mut CSpace,
) -> Result<Cap, CapError> {
    if rights.contains(Rights::GRANT)
        || rights.contains(Rights::REVOKE)
        || rights.contains(Rights::INVOKE)
    {
        return Err(CapError::Amplification);
    }
    let parent = source.lookup_persistent_revocable::<T>(cap, rights)?;
    Ok(stage.mint(Arc::new(PersistentProxy { parent, rights }), rights))
}

#[derive(Clone)]
struct JobControl {
    live: Arc<AtomicBool>,
    completed: CancellationSignal,
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
            self.completed.cancel();
        }
    }

    fn finish(&self) {
        if self.live.swap(false, Ordering::AcqRel) {
            self.completed.cancel();
        }
    }
}

async fn watch_foreground_cancel(
    cancel: Arc<CancellationSignal>,
    control: JobControl,
    handles: Vec<TaskHandle>,
) {
    enum Wake {
        Cancelled(Result<(), OneShotWaitError>),
        Completed(Result<(), OneShotWaitError>),
    }

    let cancelled = cancel.cancelled();
    let completed = control.completed.cancelled();
    let mut cancelled = core::pin::pin!(cancelled);
    let mut completed = core::pin::pin!(completed);
    let wake = poll_fn(|context| {
        if let Poll::Ready(result) = cancelled.as_mut().poll(context) {
            return Poll::Ready(Wake::Cancelled(result));
        }
        completed.as_mut().poll(context).map(Wake::Completed)
    })
    .await;
    match wake {
        Wake::Cancelled(Ok(())) => {
            control.fail(Status::Cancelled);
            for handle in &handles {
                let _ = handle.cancel();
            }
        }
        Wake::Completed(Ok(())) => {}
        Wake::Cancelled(Err(_)) | Wake::Completed(Err(_)) => {
            control.fail(Status::BackendFault);
            for handle in &handles {
                let _ = handle.cancel();
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

struct PreflightStage {
    command: CommandAst,
    command_name: String,
    command_source: Cap,
    manifest: CommandManifest,
    component: Option<Arc<ComponentCommandManifest>>,
    managed_component: bool,
    managed_io: Option<ManagedComponentIoSource>,
}

/// Synchronous, inert result of validating every stage in one pipeline.
/// It owns the syntax and immutable manifest snapshots but no candidate task,
/// stream, CSpace, or live object pointer that can perform an operation.
pub struct PipelinePreflight {
    owner_identity: Arc<SessionIdentity>,
    stages: Vec<PreflightStage>,
}

impl PipelinePreflight {
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    pub fn command_names(&self) -> impl Iterator<Item = &str> {
        self.stages.iter().map(|stage| stage.command_name.as_str())
    }

    pub fn manifests(&self) -> impl Iterator<Item = &CommandManifest> {
        self.stages.iter().map(|stage| &stage.manifest)
    }
}

struct PreparedStage {
    cspace: Arc<SpinLock<CSpace>>,
    command: Cap,
    args: Vec<String>,
    stdin: LocalIo,
    stdout: LocalIo,
    _stderr: LocalIo,
    component_authorities: Vec<PreparedComponentAuthority>,
    is_component: bool,
    is_managed_component: bool,
    managed_io: Option<(ManagedComponentIo, Cap, Cap, Cap, Cap)>,
    result: Arc<SpinLock<Option<StageExit>>>,
}

impl PreparedStage {
    fn finalize_unpublished_managed_io(
        &mut self,
        terminal: ComponentTerminal,
    ) -> ComponentTerminal {
        self.managed_io.take().map_or(terminal, |(io, _, _, _, _)| {
            io.finalize_unpublished(terminal)
        })
    }
}

impl Drop for PreparedStage {
    fn drop(&mut self) {
        // Any unexpected pre-start unwind/error still leaves the pump with a
        // conservative immutable terminal instead of an indefinitely Open
        // stream. Explicit error paths take this field first with their exact
        // typed reason; after lifecycle.start it is also necessarily None.
        let _ = self.finalize_unpublished_managed_io(ComponentTerminal::RunnerFault);
    }
}

/// Fully admitted but unpublished pipeline candidates. Construction may await
/// bounded value expansion, but no stage task or runner is started until
/// [`PreparedPipeline::commit`].
pub struct PreparedPipeline {
    owner_identity: Arc<SessionIdentity>,
    owner: Arc<SpinLock<CSpace>>,
    id: u64,
    admission: CSpace,
    pipes: Vec<Arc<ByteStream>>,
    stages: Vec<PreparedStage>,
}

impl PreparedPipeline {
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

fn validate_managed_component_io_source(
    cspace: &CSpace,
    stdin: Cap,
    stdout: Cap,
    stdin_supervisor: Cap,
    stdout_supervisor: Cap,
    span: Span,
) -> Result<ValidatedManagedComponentIo, Diagnostic> {
    let stdin_rights = cspace.rights_of(stdin).map_err(|_| {
        Diagnostic::new(
            span.start,
            span.end,
            "managed component stdin authority is unavailable",
        )
    })?;
    let stdout_rights = cspace.rights_of(stdout).map_err(|_| {
        Diagnostic::new(
            span.start,
            span.end,
            "managed component stdout authority is unavailable",
        )
    })?;
    let stdin_supervisor_rights = cspace.rights_of(stdin_supervisor).map_err(|_| {
        Diagnostic::new(
            span.start,
            span.end,
            "managed component stdin terminal authority is unavailable",
        )
    })?;
    let stdout_supervisor_rights = cspace.rights_of(stdout_supervisor).map_err(|_| {
        Diagnostic::new(
            span.start,
            span.end,
            "managed component stdout terminal authority is unavailable",
        )
    })?;
    let stdin_required = Rights::RECV.union(Rights::GRANT);
    let stdout_required = Rights::SEND.union(Rights::GRANT);
    let stdin_forbidden = Rights::SEND
        .union(Rights::READ)
        .union(Rights::WRITE)
        .union(Rights::INVOKE);
    let stdout_forbidden = Rights::RECV
        .union(Rights::READ)
        .union(Rights::WRITE)
        .union(Rights::INVOKE);
    let supervisor_required = Rights::INVOKE.union(Rights::GRANT);
    let supervisor_forbidden = Rights::READ
        .union(Rights::WRITE)
        .union(Rights::SEND)
        .union(Rights::RECV);
    if !stdin_rights.contains(stdin_required)
        || stdin_rights.intersect(stdin_forbidden) != Rights::NONE
    {
        return Err(Diagnostic::new(
            span.start,
            span.end,
            "managed component stdin rights are not exact",
        ));
    }
    if !stdout_rights.contains(stdout_required)
        || stdout_rights.intersect(stdout_forbidden) != Rights::NONE
    {
        return Err(Diagnostic::new(
            span.start,
            span.end,
            "managed component stdout rights are not exact",
        ));
    }
    if !stdin_supervisor_rights.contains(supervisor_required)
        || stdin_supervisor_rights.intersect(supervisor_forbidden) != Rights::NONE
        || !stdout_supervisor_rights.contains(supervisor_required)
        || stdout_supervisor_rights.intersect(supervisor_forbidden) != Rights::NONE
    {
        return Err(Diagnostic::new(
            span.start,
            span.end,
            "managed component terminal rights are not exact",
        ));
    }
    let reader = cspace
        .lookup_as::<ByteStreamReader>(stdin, Rights::RECV)
        .map_err(|_| {
            Diagnostic::new(
                span.start,
                span.end,
                "managed component stdin has the wrong resource kind",
            )
        })?;
    let writer = cspace
        .lookup_as::<ByteStreamWriter>(stdout, Rights::SEND)
        .map_err(|_| {
            Diagnostic::new(
                span.start,
                span.end,
                "managed component stdout has the wrong resource kind",
            )
        })?;
    let stdin_supervisor = cspace
        .lookup_as::<ByteStreamSupervisor>(stdin_supervisor, Rights::INVOKE)
        .map_err(|_| {
            Diagnostic::new(
                span.start,
                span.end,
                "managed component stdin has the wrong terminal resource kind",
            )
        })?;
    let stdout_supervisor = cspace
        .lookup_as::<ByteStreamSupervisor>(stdout_supervisor, Rights::INVOKE)
        .map_err(|_| {
            Diagnostic::new(
                span.start,
                span.end,
                "managed component stdout has the wrong terminal resource kind",
            )
        })?;
    if Arc::ptr_eq(&stdin_supervisor, &stdout_supervisor) {
        return Err(Diagnostic::new(
            span.start,
            span.end,
            "managed component terminal authorities must be distinct",
        ));
    }
    Ok(ValidatedManagedComponentIo {
        stdin: reader,
        stdout: writer,
        stdin_supervisor,
        stdout_supervisor,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalDetail {
    Command(Status),
    Component(ComponentTerminal),
}

#[derive(Clone, Copy)]
enum StageFlavor {
    Command,
    Component,
}

#[derive(Clone)]
struct StageExit {
    status: Status,
    detail: TerminalDetail,
}

type RunningStage = (
    TaskHandle,
    Arc<SpinLock<Option<StageExit>>>,
    Arc<SpinLock<CSpace>>,
    StageFlavor,
);

struct BackgroundJob {
    supervisor: TaskHandle,
    stages: Vec<TaskHandle>,
    control: JobControl,
    report: Arc<SpinLock<Option<JobReport>>>,
}

impl BackgroundJob {
    fn request_cancel(&self) {
        self.control.fail(Status::Cancelled);
        for stage in &self.stages {
            let _ = stage.cancel();
        }
        let _ = self.supervisor.cancel();
    }
}

#[derive(Clone)]
struct FunctionDef {
    params: Vec<String>,
    body: Script,
}

#[derive(Clone)]
pub struct StageReport {
    /// Pipeline-local stage ordinal. Executor task identity is supervisor-only
    /// and never enters shell-facing observability.
    pub stage: usize,
    pub status: Status,
    pub detail: TerminalDetail,
}

impl core::fmt::Debug for StageReport {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StageReport")
            .field("stage", &self.stage)
            .field("status", &self.status)
            .field("detail", &self.detail)
            .finish()
    }
}
#[derive(Clone, Debug)]
pub struct JobReport {
    pub id: u64,
    pub status: Status,
    pub stages: Vec<StageReport>,
    pub output: String,
    pub peak_pipe_depth: usize,
}

type VshFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

struct BlockOutcome {
    reports: Vec<JobReport>,
    status: Status,
}

impl BlockOutcome {
    fn success() -> Self {
        Self {
            reports: Vec::new(),
            status: Status::Success,
        }
    }

    fn append(mut self, next: Self) -> Self {
        self.reports.extend(next.reports);
        self.status = next.status;
        self
    }
}

pub struct Session {
    identity: Arc<SessionIdentity>,
    cspace: Arc<SpinLock<CSpace>>,
    commands: BTreeMap<String, Cap>,
    capabilities: BTreeMap<String, Cap>,
    values: BTreeMap<String, String>,
    functions: BTreeMap<String, FunctionDef>,
    console: Arc<OutputSink>,
    next_job: AtomicU64,
    revoke_next_job: Option<Cap>,
    cancel_next_job: bool,
    jobs: BTreeMap<u64, BackgroundJob>,
    external_cancel: Option<Arc<CancellationSignal>>,
    managed_cleanup: Option<ManagedInvocationCleanup>,
    function_depth: usize,
    substitution_depth: usize,
    script_depth: usize,
    active_script_caps: Option<BTreeSet<String>>,
    ssh_exec_policy_commands: BTreeSet<String>,
    profile: SessionProfile,
}

/// Unforgeable in-process identity for one Session value. Prepared work is
/// bound to this object as well as its CSpace so two SSH sessions sharing a
/// supervisor-provided CSpace cannot reuse each other's installed policy.
struct SessionIdentity;

#[derive(Clone, Copy)]
struct ManagedInvocationCleanup {
    lease: ManagedComponentStartLease,
}

impl ManagedInvocationCleanup {
    fn matches(self, other: Self) -> bool {
        self.lease.matches_exact(other.lease)
    }
}

/// Parent-side RAII for the interval in which the exact detach lease is live.
/// Dropping an execution future hands ownership to SYSTEM before attempting
/// to disarm the parent ledger, so ordinary future cancellation has the same
/// no-gap guarantee as permanent raw-fault detach.
struct ManagedForegroundGuard {
    lease: ManagedComponentStartLease,
    armed: bool,
}

impl ManagedForegroundGuard {
    const fn new(lease: ManagedComponentStartLease) -> Self {
        Self { lease, armed: true }
    }

    fn release(&mut self) {
        self.armed = false;
    }

    fn complete(&mut self) {
        if self.armed {
            disarm_managed_reaper_foreground(self.lease);
            self.armed = false;
        }
    }

    fn handoff(&mut self) {
        if self.armed {
            // A nested execution future dropped from an otherwise live parent
            // must synchronously publish Cancelled ownership. During teardown
            // of the whole parent task, however, the scheduler running slot is
            // already detached: leave the exact TaskDetach lease armed so the
            // executor can report the final Exited/Cancelled/Faulted reason
            // after every destructor (including a faulting later destructor).
            if self.lease.parent.is_current_running_exact() {
                handoff_managed_reaper(self.lease);
            }
            self.armed = false;
        }
    }
}

impl Drop for ManagedForegroundGuard {
    fn drop(&mut self) {
        self.handoff();
    }
}

/// Commands and syntax made available when constructing a shell session.
///
/// `SshExec` is intentionally not an interactive shell with features removed
/// after parsing. It starts with only three command capabilities and also
/// validates every execution at the `Session` boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionProfile {
    Interactive,
    SshExec,
}

impl Session {
    pub fn new() -> Self {
        Self::with_profile(SessionProfile::Interactive)
    }

    pub fn with_profile(profile: SessionProfile) -> Self {
        Self::with_cspace_profile(Arc::new(SpinLock::new(CSpace::new("vsh"))), profile)
    }

    pub fn with_cspace(cspace: Arc<SpinLock<CSpace>>) -> Self {
        Self::with_cspace_profile(cspace, SessionProfile::Interactive)
    }

    /// Build a session with an explicit command/syntax profile. The SSH
    /// component should pass its per-connection CSpace with `SshExec` rather
    /// than deriving an interactive session and deleting names afterward.
    pub fn with_cspace_profile(cspace: Arc<SpinLock<CSpace>>, profile: SessionProfile) -> Self {
        let console = OutputSink::new();
        let console_cap = cspace.lock().mint(
            console.clone(),
            Rights::WRITE.union(Rights::GRANT).union(Rights::REVOKE),
        );
        let mut capabilities = BTreeMap::new();
        capabilities.insert("console".to_string(), console_cap);
        let mut session = Self {
            identity: Arc::new(SessionIdentity),
            cspace,
            commands: BTreeMap::new(),
            capabilities,
            values: BTreeMap::new(),
            functions: BTreeMap::new(),
            console,
            next_job: AtomicU64::new(1),
            revoke_next_job: None,
            cancel_next_job: false,
            jobs: BTreeMap::new(),
            external_cancel: None,
            managed_cleanup: None,
            function_depth: 0,
            substitution_depth: 0,
            script_depth: 0,
            active_script_caps: None,
            ssh_exec_policy_commands: BTreeSet::new(),
            profile,
        };
        session.install("echo", Applet::Echo, 0, MAX_ARGS, StreamMode::Closed, true);
        session.install("true", Applet::True, 0, 0, StreamMode::Closed, false);
        session.install("false", Applet::False, 0, 0, StreamMode::Closed, false);
        if profile == SessionProfile::Interactive {
            session.install("wc", Applet::Wc, 0, 0, StreamMode::Required, false);
            session.install("deny", Applet::Deny, 0, 0, StreamMode::Closed, false);
            session.install("fault", Applet::Fault, 0, 0, StreamMode::Closed, false);
            session.install("spin", Applet::Spin, 0, 0, StreamMode::Closed, false);
        }
        session
    }

    /// Sorted command names visible to this session's interactive terminal.
    /// The list is derived only from installed command capabilities, built-in
    /// special forms, and functions defined in this session.
    pub fn completion_candidates(&self) -> Vec<String> {
        let mut candidates = BTreeSet::new();
        candidates.extend(self.commands.keys().cloned());
        candidates.extend(
            ["let", "jobs", "wait", "cancel", "run-script"]
                .into_iter()
                .map(String::from),
        );
        candidates.extend(self.functions.keys().cloned());
        candidates.into_iter().collect()
    }
    fn install(
        &mut self,
        name: &str,
        applet: Applet,
        min_args: usize,
        max_args: usize,
        stdin: StreamMode,
        early: bool,
    ) {
        let command = Arc::new(Command {
            manifest: CommandManifest {
                name: name.to_string(),
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

    /// Install an image-policy-provided Component as a session-local command.
    /// The manifest is moved into immutable command state; the runner is a
    /// trusted adapter around an already admitted artifact and cannot be
    /// selected or replaced by shell text.
    pub fn install_component_command(
        &mut self,
        runner: Arc<dyn ComponentCommandRunner>,
    ) -> Result<(), Diagnostic> {
        let source_manifest = runner.manifest();
        if self.profile == SessionProfile::SshExec {
            return Err(Diagnostic::new(
                0,
                source_manifest.name.len(),
                "component commands are outside the SSH exec profile",
            ));
        }
        let manifest = Self::snapshot_component_manifest(source_manifest)?;
        self.install_component_command_inner(manifest, runner)
    }

    /// Install one exact image-policy-pinned Component command into this SSH
    /// exec session. Ordinary [`Self::install_component_command`] remains
    /// closed for `SshExec`; only trusted setup holding a full independent
    /// policy witness can make the pinned name visible to this session.
    pub fn install_ssh_exec_component_command(
        &mut self,
        policy: &SshExecComponentPolicy,
        runner: Arc<dyn ComponentCommandRunner>,
    ) -> Result<(), Diagnostic> {
        let source_manifest = runner.manifest();
        if self.profile != SessionProfile::SshExec {
            return Err(Diagnostic::new(
                0,
                source_manifest.name.len(),
                "SSH component policy requires an SSH exec session",
            ));
        }
        if source_manifest.world == VIBE_STREAM_FILTER_WORLD {
            return Err(Diagnostic::new(
                0,
                source_manifest.name.len(),
                "stream components require the managed SSH lifecycle",
            ));
        }
        if !policy.admits_manifest(source_manifest) {
            return Err(Diagnostic::new(
                0,
                source_manifest.name.len(),
                "component runner does not match SSH image policy",
            ));
        }
        // Copy exactly the manifest that passed the independent image-policy
        // comparison. A stateful runner must not get a second manifest query
        // between authorization and immutable command installation.
        let manifest = Self::snapshot_component_manifest(source_manifest)?;
        let name = manifest.name.clone();
        self.install_component_command_inner(manifest, runner)?;
        self.ssh_exec_policy_commands.insert(name);
        Ok(())
    }

    /// Install the narrow managed stream-Component path selected by explicit
    /// image and SSH-session policy.
    ///
    /// Unlike [`Self::install_ssh_exec_component_command`], this accepts only
    /// a globally stable trusted lifecycle service and installs the distinct
    /// [`Applet::ManagedComponent`] variant. An ordinary runner can therefore
    /// never masquerade as a registry-managed invocation. The current managed
    /// ABI has zero shell arguments and exactly one Required stdin reader plus
    /// one Required stdout writer. Those transport caps are not ambient
    /// requirements: installation verifies them in this session's exact
    /// CSpace, and atomic stage preparation attenuates them to only `RECV` and
    /// `SEND` respectively. The two lifecycle-only terminal authorities are
    /// independently attenuated to `INVOKE`; the pump never receives them.
    ///
    /// # Safety
    ///
    /// The caller must be the trusted SSH platform installation hook. In the
    /// same accepted-session transaction, immediately before this call, it
    /// must have revalidated an exact `AuthorizedProfile`: profile id and
    /// generation, nonzero policy incarnation, command name, and artifact
    /// digest. It must also independently match the complete manifest against
    /// the image-admitted pin. Interactive, onboarding, and default sessions
    /// must never call this function, even if they can construct an `SshExec`
    /// Session value. `lifecycle` must satisfy every invariant of the unsafe
    /// [`ManagedComponentLifecycle`] contract.
    pub unsafe fn install_ssh_exec_managed_component_io(
        &mut self,
        policy: &SshExecComponentPolicy,
        lifecycle: &'static dyn ManagedComponentLifecycle,
        io: SshExecComponentIoInstall,
    ) -> Result<(), Diagnostic> {
        if self.profile != SessionProfile::SshExec {
            return Err(Diagnostic::new(
                0,
                0,
                "managed SSH component policy requires an SSH exec session",
            ));
        }
        let source_manifest = lifecycle.manifest();
        if !policy.admits_manifest(source_manifest) {
            return Err(Diagnostic::new(
                0,
                source_manifest.name.len(),
                "managed component lifecycle does not match SSH image policy",
            ));
        }
        if source_manifest.min_args != 0
            || source_manifest.max_args != 0
            || source_manifest.world != VIBE_STREAM_FILTER_WORLD
            || source_manifest.stdin != StreamMode::Required
            || source_manifest.stdout != StreamMode::Required
            || source_manifest.stderr == StreamMode::Required
            || !source_manifest.requirements.is_empty()
        {
            return Err(Diagnostic::new(
                0,
                source_manifest.name.len(),
                "managed SSH component contract is not the exact stream world",
            ));
        }

        // Query the lifecycle manifest exactly once. Copy the same value that
        // passed the independent policy comparison; execution will compare a
        // fresh read before `start` and fail closed if trusted setup mutated.
        let manifest = Self::snapshot_component_manifest(source_manifest)?;
        let name = manifest.name.clone();
        self.install_managed_component_command_inner(manifest, lifecycle, io.component)?;
        self.ssh_exec_policy_commands.insert(name);
        Ok(())
    }

    fn snapshot_component_manifest(
        source_manifest: &ComponentCommandManifest,
    ) -> Result<ComponentCommandManifest, Diagnostic> {
        source_manifest.validate(Span {
            start: 0,
            end: source_manifest.name.len(),
        })?;
        let mut requirements = Vec::new();
        requirements
            .try_reserve_exact(source_manifest.requirements.len())
            .map_err(|_| Diagnostic::new(0, 0, "component manifest allocation failed"))?;
        for requirement in &source_manifest.requirements {
            requirements.push(ComponentAuthorityRequirement::try_from_borrowed(
                &requirement.label,
                &requirement.interface,
                &requirement.resource,
                &requirement.resource_kind,
                requirement.rights,
            )?);
        }
        ComponentCommandManifest::try_from_borrowed(
            &source_manifest.name,
            source_manifest.abi,
            source_manifest.artifact,
            &source_manifest.world,
            &source_manifest.entrypoint,
            source_manifest.min_args,
            source_manifest.max_args,
            source_manifest.stdin,
            source_manifest.stdout,
            source_manifest.stderr,
            source_manifest.memory_bytes,
            source_manifest.total_fuel,
            source_manifest.poll_quantum,
            source_manifest.resource_limit,
            requirements,
        )
    }

    fn install_component_command_inner(
        &mut self,
        manifest: ComponentCommandManifest,
        runner: Arc<dyn ComponentCommandRunner>,
    ) -> Result<(), Diagnostic> {
        manifest.validate(Span {
            start: 0,
            end: manifest.name.len(),
        })?;
        if self.commands.contains_key(&manifest.name)
            || self.functions.contains_key(&manifest.name)
            || is_special_form(&manifest.name)
        {
            return Err(Diagnostic::new(
                0,
                manifest.name.len(),
                "component command name is already registered",
            ));
        }
        if self.commands.len() >= 128 {
            return Err(Diagnostic::new(
                0,
                manifest.name.len(),
                "visible command limit exceeded",
            ));
        }
        let name = manifest.name.clone();
        let general = manifest.command_manifest();
        let manifest = Arc::new(manifest);
        let command = Arc::new(Command {
            manifest: general,
            applet: Applet::Component { manifest, runner },
        });
        let cap = self.cspace.lock().mint(
            command,
            Rights::INVOKE.union(Rights::GRANT).union(Rights::REVOKE),
        );
        self.commands.insert(name, cap);
        Ok(())
    }

    fn install_managed_component_command_inner(
        &mut self,
        manifest: ComponentCommandManifest,
        lifecycle: &'static dyn ManagedComponentLifecycle,
        io: ManagedComponentIo,
    ) -> Result<(), Diagnostic> {
        manifest.validate(Span {
            start: 0,
            end: manifest.name.len(),
        })?;
        if self.commands.contains_key(&manifest.name)
            || self.functions.contains_key(&manifest.name)
            || is_special_form(&manifest.name)
        {
            return Err(Diagnostic::new(
                0,
                manifest.name.len(),
                "component command name is already registered",
            ));
        }
        if self.commands.len() >= 128 {
            return Err(Diagnostic::new(
                0,
                manifest.name.len(),
                "visible command limit exceeded",
            ));
        }
        let io = {
            let (stdin, stdout, stdin_supervisor, stdout_supervisor) = io.into_parts();
            if stdin.same_stream_as(&stdout)
                || !stdin_supervisor.same_stream_as_reader(&stdin)
                || stdin_supervisor.same_stream_as_writer(&stdout)
                || !stdout_supervisor.same_stream_as_writer(&stdout)
                || stdout_supervisor.same_stream_as_reader(&stdin)
            {
                return Err(Diagnostic::new(
                    0,
                    manifest.name.len(),
                    "managed component stdin and stdout must be distinct",
                ));
            }
            let mut cspace = self.cspace.lock();
            let stdin = cspace.mint(
                stdin,
                Rights::RECV.union(Rights::GRANT).union(Rights::REVOKE),
            );
            let stdout = cspace.mint(
                stdout,
                Rights::SEND.union(Rights::GRANT).union(Rights::REVOKE),
            );
            let stdin_supervisor = cspace.mint(
                stdin_supervisor,
                Rights::INVOKE.union(Rights::GRANT).union(Rights::REVOKE),
            );
            let stdout_supervisor = cspace.mint(
                stdout_supervisor,
                Rights::INVOKE.union(Rights::GRANT).union(Rights::REVOKE),
            );
            ManagedComponentIoSource {
                space: cspace.identity(),
                incarnation: cspace.incarnation(),
                stdin,
                stdout,
                stdin_supervisor,
                stdout_supervisor,
            }
        };
        let name = manifest.name.clone();
        let general = manifest.command_manifest();
        let manifest = Arc::new(manifest);
        let command = Arc::new(Command {
            manifest: general,
            applet: Applet::ManagedComponent {
                manifest,
                lifecycle,
                io,
            },
        });
        let cap = self.cspace.lock().mint(
            command,
            Rights::INVOKE.union(Rights::GRANT).union(Rights::REVOKE),
        );
        self.commands.insert(name, cap);
        Ok(())
    }

    /// Number of live entries in this session's local CSpace. This exposes no
    /// handle, slot, generation, or object identity and is suitable for
    /// admission/cleanup observability.
    pub fn local_authority_count(&self) -> usize {
        self.cspace.lock().list().len()
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
        // A restricted session's allowlist covers both the visible names and
        // the audited applets behind them. In particular, trusted setup code
        // must not be able to replace `echo` with a wider host callback while
        // retaining an allowlisted spelling.
        if self.profile == SessionProfile::SshExec {
            return;
        }
        self.install(
            name,
            Applet::Host {
                command,
                observability: is_observability_command(name),
            },
            min_args,
            max_args,
            StreamMode::Closed,
            false,
        );
    }

    pub fn install_async_host_command(
        &mut self,
        name: &'static str,
        min_args: usize,
        max_args: usize,
        command: fn(Vec<String>) -> crate::AsyncCommandFuture,
    ) {
        if self.profile == SessionProfile::SshExec {
            return;
        }
        self.install(
            name,
            Applet::AsyncHost {
                command,
                observability: is_observability_command(name),
            },
            min_args,
            max_args,
            StreamMode::Closed,
            false,
        );
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
        self.cspace
            .lock()
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

    /// Supervisor-only installation of one immutable, already parsed script.
    /// Shell text can hold only the resulting READ capability; it cannot
    /// replace the source or authority manifest in place.
    pub fn install_script(
        &mut self,
        label: &str,
        source: &str,
        manifest: ScriptManifest,
    ) -> Result<Cap, Diagnostic> {
        if !valid_name(label) || self.capabilities.len() >= 256 {
            return Err(Diagnostic::new(0, label.len(), "script binding rejected"));
        }
        let artifact = ScriptArtifact::new(source, manifest)?;
        let cap = self.cspace.lock().mint(
            artifact,
            Rights::READ.union(Rights::GRANT).union(Rights::REVOKE),
        );
        self.capabilities.insert(label.to_string(), cap);
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
        let Some(cap) = self
            .capabilities
            .get(name)
            .or_else(|| self.commands.get(name))
            .copied()
        else {
            return false;
        };
        self.revoke_next_job = Some(cap);
        true
    }
    /// Acceptance hook for the same supervisor path used by foreground Ctrl-C.
    pub fn cancel_next_job_for_test(&mut self) {
        self.cancel_next_job = true;
    }

    /// Cancel and join every background Job owned by this session.
    ///
    /// This is idempotent. Connection-oriented frontends should await it before
    /// releasing their transport so no stage or Job supervisor can outlive the
    /// session that admitted it.
    pub async fn shutdown(&mut self) {
        self.request_shutdown();
        self.finish_managed_cleanup().await;
        let jobs = core::mem::take(&mut self.jobs);
        for (_, job) in jobs {
            for stage in &job.stages {
                let _ = stage.join().await;
            }
            let _ = job.supervisor.join().await;
        }
    }

    fn request_shutdown(&mut self) {
        if let Some(cancel) = self.external_cancel.take() {
            cancel.cancel();
        }
        if let Some(cleanup) = self.managed_cleanup {
            handoff_managed_reaper(cleanup.lease);
        }
        for job in self.jobs.values() {
            job.request_cancel();
        }
    }

    async fn finish_managed_cleanup(&mut self) {
        let Some(cleanup) = self.managed_cleanup else {
            return;
        };
        handoff_managed_reaper(cleanup.lease);
        let mut listener = managed_reaper_completion_listener(cleanup.lease);
        loop {
            match managed_reaper_status(cleanup.lease) {
                ManagedReaperStatus::Acknowledged(_) | ManagedReaperStatus::CleanRetired => {
                    self.clear_managed_cleanup(cleanup);
                    return;
                }
                ManagedReaperStatus::Quarantined(_) | ManagedReaperStatus::IdentityLost => {
                    // Shutdown has no exact proof that the child tombstone was
                    // acknowledged. Returning would silently authorize the
                    // caller to release transport around an ambiguous live
                    // instance, so fail-stop while the fixed slot remains
                    // conservatively retained.
                    panic!("managed component cleanup was not acknowledged");
                }
                ManagedReaperStatus::Waiting => {}
            }
            if let Some(wait) = listener.take() {
                let _ = wait.await;
            } else {
                exec::yield_now().await;
            }
        }
    }

    fn clear_managed_cleanup(&mut self, expected: ManagedInvocationCleanup) {
        if self
            .managed_cleanup
            .is_some_and(|current| current.matches(expected))
        {
            self.managed_cleanup = None;
        }
    }

    pub async fn execute(&mut self, source: &str) -> Result<Vec<JobReport>, Diagnostic> {
        if self.profile == SessionProfile::SshExec {
            let _ = validate_ssh_exec_with_policy(source, |name| {
                self.ssh_exec_policy_commands.contains(name)
            })?;
        }
        let script = parse(source)?;
        Ok(self.execute_block(&script, true).await?.reports)
    }

    pub async fn execute_cancellable(
        &mut self,
        source: &str,
        cancel: Arc<CancellationSignal>,
    ) -> Result<Vec<JobReport>, Diagnostic> {
        self.external_cancel = Some(cancel);
        let result = self.execute(source).await;
        self.external_cancel = None;
        result
    }

    /// Validate and execute exactly one foreground command from the SSH
    /// profile. Execution deliberately continues through `execute_cancellable`
    /// so disconnect and supervisor cancellation use the ordinary Job teardown
    /// path.
    pub async fn execute_ssh_cancellable(
        &mut self,
        source: &str,
        cancel: Arc<CancellationSignal>,
    ) -> Result<Vec<JobReport>, Diagnostic> {
        if self.profile != SessionProfile::SshExec {
            return Err(Diagnostic::new(
                0,
                source.len(),
                "session does not use the SSH exec profile",
            ));
        }
        let _ = validate_ssh_exec_with_policy(source, |name| {
            self.ssh_exec_policy_commands.contains(name)
        })?;
        self.execute_cancellable(source, cancel).await
    }

    fn execute_block<'a>(
        &'a mut self,
        script: &'a Script,
        allow_background: bool,
    ) -> VshFuture<'a, Result<BlockOutcome, Diagnostic>> {
        Box::pin(async move {
            let mut outcome = BlockOutcome::success();
            for statement in &script.statements {
                let next = match statement {
                    Statement::Command(item) => {
                        if item.background && !allow_background {
                            return Err(Diagnostic::new(
                                item.command.first.span.start,
                                item.command.first.span.end,
                                "background job is not allowed in this scope",
                            ));
                        }
                        if let Some(special) = self.special_form(item).await? {
                            special
                        } else {
                            self.execute_and_or(&item.command, item.background).await?
                        }
                    }
                    Statement::If {
                        condition,
                        then_branch,
                        else_branch,
                        ..
                    } => {
                        let mut condition_outcome = self.execute_and_or(condition, false).await?;
                        let status = condition_outcome.status;
                        suppress_control_condition_statuses(&mut condition_outcome.reports);
                        if severe(status) {
                            condition_outcome
                        } else if status.succeeded() {
                            condition_outcome.append(self.execute_block(then_branch, false).await?)
                        } else if let Some(else_branch) = else_branch {
                            condition_outcome.append(self.execute_block(else_branch, false).await?)
                        } else {
                            condition_outcome.status = Status::Success;
                            condition_outcome
                        }
                    }
                    Statement::While {
                        condition, body, ..
                    } => {
                        let mut loop_outcome = BlockOutcome::success();
                        let mut completed_iterations = 0usize;
                        loop {
                            if completed_iterations >= MAX_LOOP_ITERATIONS {
                                loop_outcome.status = Status::BudgetExceeded;
                                loop_outcome
                                    .reports
                                    .push(control_report(Status::BudgetExceeded));
                                break;
                            }
                            let mut condition_outcome =
                                self.execute_and_or(condition, false).await?;
                            let condition_status = condition_outcome.status;
                            suppress_control_condition_statuses(&mut condition_outcome.reports);
                            loop_outcome.reports.extend(condition_outcome.reports);
                            if severe(condition_status) {
                                loop_outcome.status = condition_status;
                                break;
                            }
                            if !condition_status.succeeded() {
                                if completed_iterations == 0 {
                                    loop_outcome.status = Status::Success;
                                }
                                break;
                            }
                            let body_outcome = self.execute_block(body, false).await?;
                            loop_outcome.status = body_outcome.status;
                            loop_outcome.reports.extend(body_outcome.reports);
                            completed_iterations += 1;
                            exec::yield_now().await;
                            if severe(loop_outcome.status) {
                                break;
                            }
                        }
                        loop_outcome
                    }
                    Statement::Function {
                        name,
                        params,
                        body,
                        span,
                    } => {
                        if is_special_form(name) || self.commands.contains_key(name) {
                            return Err(Diagnostic::new(
                                span.start,
                                span.end,
                                "function cannot shadow a command or special form",
                            ));
                        }
                        if !self.functions.contains_key(name)
                            && self.functions.len() >= MAX_FUNCTIONS
                        {
                            return Err(Diagnostic::new(
                                span.start,
                                span.end,
                                "function limit exceeded",
                            ));
                        }
                        self.functions.insert(
                            name.clone(),
                            FunctionDef {
                                params: params.clone(),
                                body: body.clone(),
                            },
                        );
                        BlockOutcome::success()
                    }
                };
                outcome.reports.extend(next.reports);
                outcome.status = next.status;
            }
            Ok(outcome)
        })
    }

    async fn execute_and_or(
        &mut self,
        command: &AndOrAst,
        background: bool,
    ) -> Result<BlockOutcome, Diagnostic> {
        if background && !command.rest.is_empty() {
            return Err(Diagnostic::new(
                command.first.span.start,
                command.first.span.end,
                "background conditional lists are not supported",
            ));
        }
        let mut outcome = self
            .run_pipeline_or_function(&command.first, background)
            .await?;
        let mut status = outcome.status;
        for (condition, pipeline) in &command.rest {
            let run = match condition {
                Condition::And => status.succeeded(),
                Condition::Or => !status.succeeded(),
            };
            if run {
                let next = self.run_pipeline_or_function(pipeline, false).await?;
                status = next.status;
                outcome = outcome.append(next);
            }
        }
        outcome.status = status;
        Ok(outcome)
    }

    async fn run_pipeline_or_function(
        &mut self,
        pipeline: &PipelineAst,
        background: bool,
    ) -> Result<BlockOutcome, Diagnostic> {
        if pipeline.commands.len() == 1 {
            if let Some(name) = literal_word(&pipeline.commands[0].name) {
                if self.functions.contains_key(name) {
                    if background {
                        return Err(Diagnostic::new(
                            pipeline.span.start,
                            pipeline.span.end,
                            "function call must be foreground",
                        ));
                    }
                    return self.run_function(name, &pipeline.commands[0]).await;
                }
            }
        } else if pipeline.commands.iter().any(|command| {
            literal_word(&command.name).is_some_and(|name| self.functions.contains_key(name))
        }) {
            return Err(Diagnostic::new(
                pipeline.span.start,
                pipeline.span.end,
                "functions cannot be pipeline stages",
            ));
        }
        let report = self.run_pipeline(pipeline, background).await?.unwrap();
        Ok(BlockOutcome {
            status: report.status,
            reports: vec![report],
        })
    }

    fn run_function<'a>(
        &'a mut self,
        name: &'a str,
        command: &'a CommandAst,
    ) -> VshFuture<'a, Result<BlockOutcome, Diagnostic>> {
        Box::pin(async move {
            if self.function_depth >= MAX_FUNCTION_CALL_DEPTH {
                return Ok(BlockOutcome {
                    status: Status::BudgetExceeded,
                    reports: vec![control_report(Status::BudgetExceeded)],
                });
            }
            if !command.redirects.is_empty() {
                return Err(Diagnostic::new(
                    command.span.start,
                    command.span.end,
                    "function call redirection is not supported",
                ));
            }
            let definition = self.functions.get(name).cloned().unwrap();
            if command.args.len() != definition.params.len() {
                return Err(Diagnostic::new(
                    command.span.start,
                    command.span.end,
                    "function argument count mismatch",
                ));
            }
            let mut arguments = Vec::new();
            for argument in &command.args {
                let Argument::Word(word) = argument else {
                    let span = match argument {
                        Argument::Capability { span, .. } => *span,
                        _ => unreachable!(),
                    };
                    return Err(Diagnostic::new(
                        span.start,
                        span.end,
                        "function arguments are values, not capabilities",
                    ));
                };
                arguments.push(self.expand_word(word).await?);
            }

            let saved_values = self.values.clone();
            let saved_functions = self.functions.clone();
            for (param, value) in definition.params.iter().zip(arguments) {
                self.set_value(param, &value)?;
            }
            self.function_depth += 1;
            let result = self.execute_block(&definition.body, false).await;
            self.function_depth -= 1;
            self.values = saved_values;
            self.functions = saved_functions;
            result
        })
    }

    async fn special_form(&mut self, item: &ListItem) -> Result<Option<BlockOutcome>, Diagnostic> {
        if !item.command.rest.is_empty() || item.command.first.commands.len() != 1 {
            return Ok(None);
        }
        let command = &item.command.first.commands[0];
        let Some(name) = literal_word(&command.name) else {
            return Ok(None);
        };
        if !is_special_form(name) {
            return Ok(None);
        }
        if item.background {
            return Err(Diagnostic::new(
                command.span.start,
                command.span.end,
                "special form must be foreground",
            ));
        }
        if !command.redirects.is_empty() {
            return Err(Diagnostic::new(
                command.span.start,
                command.span.end,
                "special form cannot redirect",
            ));
        }
        if name == "run-script" {
            let [Argument::Capability { name: label, span }] = command.args.as_slice() else {
                return Err(Diagnostic::new(
                    command.span.start,
                    command.span.end,
                    "usage: run-script @SCRIPT",
                ));
            };
            if self
                .active_script_caps
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(label))
            {
                return Err(Diagnostic::new(
                    span.start,
                    span.end,
                    "script capability is outside the authority manifest",
                ));
            }
            let cap = self.capabilities.get(label).copied().ok_or_else(|| {
                Diagnostic::new(span.start, span.end, "unknown script capability")
            })?;
            let artifact = self
                .cspace
                .lock()
                .lookup_as::<ScriptArtifact>(cap, Rights::READ)
                .map_err(|_| {
                    Diagnostic::new(span.start, span.end, "script capability is not readable")
                })?;
            return Ok(Some(self.execute_artifact(artifact, *span).await?));
        }
        let mut args = Vec::new();
        for arg in &command.args {
            match arg {
                Argument::Word(word) => args.push(self.expand_word(word).await?),
                Argument::Capability { span, .. } => {
                    return Err(Diagnostic::new(
                        span.start,
                        span.end,
                        "special form requires value arguments",
                    ));
                }
            }
        }
        match name {
            "let" => {
                if args.len() != 2 {
                    return Err(Diagnostic::new(
                        command.span.start,
                        command.span.end,
                        "usage: let NAME VALUE",
                    ));
                }
                self.set_value(&args[0], &args[1])?;
                Ok(Some(BlockOutcome::success()))
            }
            "jobs" => {
                if !args.is_empty() {
                    return Err(Diagnostic::new(
                        command.span.start,
                        command.span.end,
                        "usage: jobs",
                    ));
                }
                let mut output = String::new();
                for (id, job) in &self.jobs {
                    let state = if !job.supervisor.is_published() {
                        "prepared"
                    } else if job.supervisor.try_exit().is_some() {
                        "done"
                    } else {
                        "running"
                    };
                    output.push_str(&format!("%{id} {state}\n"));
                }
                Ok(Some(BlockOutcome {
                    status: Status::Success,
                    reports: vec![JobReport {
                        id: 0,
                        status: Status::Success,
                        stages: Vec::new(),
                        output,
                        peak_pipe_depth: 0,
                    }],
                }))
            }
            "wait" => {
                let id = parse_job_id(&args, command.span)?;
                let job = self.jobs.remove(&id).ok_or_else(|| {
                    Diagnostic::new(command.span.start, command.span.end, "unknown job")
                })?;
                let _ = job.supervisor.join().await;
                let report = job.report.lock().take().ok_or_else(|| {
                    Diagnostic::new(
                        command.span.start,
                        command.span.end,
                        "job report unavailable",
                    )
                })?;
                Ok(Some(BlockOutcome {
                    status: report.status,
                    reports: vec![report],
                }))
            }
            "cancel" => {
                let id = parse_job_id(&args, command.span)?;
                let job = self.jobs.get(&id).ok_or_else(|| {
                    Diagnostic::new(command.span.start, command.span.end, "unknown job")
                })?;
                job.control.fail(Status::Cancelled);
                for stage in &job.stages {
                    let _ = stage.cancel();
                }
                Ok(Some(BlockOutcome::success()))
            }
            _ => unreachable!(),
        }
    }

    fn execute_artifact<'a>(
        &'a mut self,
        artifact: Arc<ScriptArtifact>,
        span: Span,
    ) -> VshFuture<'a, Result<BlockOutcome, Diagnostic>> {
        Box::pin(async move {
            if self.script_depth >= MAX_SCRIPT_CALL_DEPTH {
                return Ok(BlockOutcome {
                    status: Status::BudgetExceeded,
                    reports: vec![control_report(Status::BudgetExceeded)],
                });
            }
            let mut allowed = BTreeSet::new();
            for requirement in &artifact.manifest.requirements {
                if self
                    .active_script_caps
                    .as_ref()
                    .is_some_and(|parent| !parent.contains(&requirement.label))
                {
                    return Err(Diagnostic::new(
                        span.start,
                        span.end,
                        "nested script authority exceeds caller manifest",
                    ));
                }
                let cap = self
                    .capabilities
                    .get(&requirement.label)
                    .copied()
                    .ok_or_else(|| {
                        Diagnostic::new(
                            span.start,
                            span.end,
                            "script authority requirement is unavailable",
                        )
                    })?;
                let object = self
                    .cspace
                    .lock()
                    .lookup(cap, requirement.rights)
                    .map_err(|_| {
                        Diagnostic::new(
                            span.start,
                            span.end,
                            "script authority requirement is denied",
                        )
                    })?;
                if object.kind() != requirement.resource_kind {
                    return Err(Diagnostic::new(
                        span.start,
                        span.end,
                        "script authority requirement has wrong resource kind",
                    ));
                }
                allowed.insert(requirement.label.clone());
            }

            let saved_values = core::mem::take(&mut self.values);
            let saved_functions = core::mem::take(&mut self.functions);
            let saved_allowed = self.active_script_caps.replace(allowed);
            self.script_depth += 1;
            let result = self.execute_block(&artifact.script, false).await;
            self.script_depth -= 1;
            self.values = saved_values;
            self.functions = saved_functions;
            self.active_script_caps = saved_allowed;
            result
        })
    }

    fn expand_word<'a>(&'a mut self, word: &'a Word) -> VshFuture<'a, Result<String, Diagnostic>> {
        Box::pin(async move {
            let mut out = String::new();
            for part in &word.parts {
                match part {
                    WordPart::Literal(value) => out.push_str(value),
                    WordPart::Value(name) => {
                        out.push_str(self.values.get(name).map(String::as_str).unwrap_or(""));
                    }
                    WordPart::Command { source, span } => {
                        out.push_str(&self.command_substitution(source, *span).await?);
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
        })
    }

    fn command_substitution<'a>(
        &'a mut self,
        source: &'a str,
        span: Span,
    ) -> VshFuture<'a, Result<String, Diagnostic>> {
        Box::pin(async move {
            if self.substitution_depth >= MAX_COMMAND_SUBSTITUTION_DEPTH {
                return Err(Diagnostic::new(
                    span.start,
                    span.end,
                    "command substitution nesting limit exceeded",
                ));
            }
            let script = parse(source).map_err(|_| {
                Diagnostic::new(span.start, span.end, "invalid command substitution")
            })?;
            let saved_values = self.values.clone();
            let saved_functions = self.functions.clone();
            self.substitution_depth += 1;
            let result = self.execute_block(&script, false).await;
            self.substitution_depth -= 1;
            self.values = saved_values;
            self.functions = saved_functions;
            let outcome = result?;
            if !outcome.status.succeeded() {
                return Err(Diagnostic::new(
                    span.start,
                    span.end,
                    "command substitution failed",
                ));
            }
            let mut output = String::new();
            for report in outcome.reports {
                if output
                    .len()
                    .checked_add(report.output.len())
                    .is_none_or(|bytes| bytes > MAX_CAPTURED_OUTPUT)
                {
                    return Err(Diagnostic::new(
                        span.start,
                        span.end,
                        "command substitution output exceeds 64 KiB",
                    ));
                }
                output.push_str(&report.output);
            }
            while output.ends_with('\n') {
                output.pop();
            }
            Ok(output)
        })
    }

    /// Resolve and validate the complete literal pipeline without awaiting,
    /// allocating candidate execution state, or invoking a runner. In
    /// particular, no argument expansion or command substitution happens here.
    pub fn preflight_pipeline(&self, ast: &PipelineAst) -> Result<PipelinePreflight, Diagnostic> {
        let mut stages = Vec::new();
        let mut component_preflights = Vec::new();
        stages.try_reserve_exact(ast.commands.len()).map_err(|_| {
            Diagnostic::new(ast.span.start, ast.span.end, "pipeline allocation failed")
        })?;

        for (index, command_ast) in ast.commands.iter().enumerate() {
            let command_name = self.preflight_command_name(&command_ast.name)?;
            let command_source = self.commands.get(&command_name).copied().ok_or_else(|| {
                Diagnostic::new(
                    command_ast.name.span.start,
                    command_ast.name.span.end,
                    "unknown command",
                )
            })?;
            let (command, command_rights) = {
                let cspace = self.cspace.lock();
                let rights = cspace.rights_of(command_source).map_err(|_| {
                    Diagnostic::new(
                        command_ast.name.span.start,
                        command_ast.name.span.end,
                        "command is not invokable",
                    )
                })?;
                let command = cspace
                    .lookup_as::<Command>(command_source, Rights::INVOKE)
                    .map_err(|_| {
                        Diagnostic::new(
                            command_ast.name.span.start,
                            command_ast.name.span.end,
                            "command is not invokable",
                        )
                    })?;
                (command, rights)
            };
            if !command_rights.contains(Rights::GRANT) {
                return Err(Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "missing GRANT on command",
                ));
            }
            let manifest = command.manifest.clone();
            validate_command_manifest(&command_name, &manifest, command_ast.span)?;
            if command_ast.args.len() < manifest.min_args
                || command_ast.args.len() > manifest.max_args
            {
                return Err(Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "command argument count rejected by manifest",
                ));
            }
            for argument in &command_ast.args {
                if let Argument::Capability { span, .. } = argument {
                    return Err(Diagnostic::new(
                        span.start,
                        span.end,
                        "command accepts value arguments only",
                    ));
                }
            }

            let has_stdin_redirect = command_ast
                .redirects
                .iter()
                .any(|redirect| redirect.kind == RedirectKind::Stdin);
            let managed_io_source = match &command.applet {
                Applet::ManagedComponent { io, .. } => Some(*io),
                _ => None,
            };
            let stdin_present = index > 0 || has_stdin_redirect || managed_io_source.is_some();
            if manifest.stdin == StreamMode::Required && !stdin_present {
                return Err(Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "command requires stdin",
                ));
            }
            if manifest.stdin == StreamMode::Closed && stdin_present {
                return Err(Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "command requires closed stdin",
                ));
            }

            // Candidate construction installs inherited defaults before
            // applying redirects, so validate those exact grants as well.
            if managed_io_source.is_none() {
                if index + 1 == ast.commands.len() {
                    self.preflight_console(command_ast.span, "default stdout cannot be delegated")?;
                }
                self.preflight_console(command_ast.span, "default stderr cannot be delegated")?;
            }
            for redirect in &command_ast.redirects {
                self.preflight_redirect(redirect)?;
            }

            let (component, managed_component, managed_io) = match &command.applet {
                Applet::Component { manifest, runner } => {
                    manifest.validate(command_ast.span)?;
                    if runner.manifest() != manifest.as_ref() {
                        return Err(Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "component runner manifest changed after installation",
                        ));
                    }
                    for requirement in manifest.requirements() {
                        self.preflight_component_authority(requirement, command_ast.span)?;
                    }
                    component_preflights.push((command_ast.span, manifest.clone(), runner.clone()));
                    (Some(manifest.clone()), false, None)
                }
                Applet::ManagedComponent {
                    manifest,
                    lifecycle,
                    io,
                } => {
                    manifest.validate(command_ast.span)?;
                    if ast.commands.len() != 1 {
                        return Err(Diagnostic::new(
                            ast.span.start,
                            ast.span.end,
                            "managed component must be the only pipeline stage",
                        ));
                    }
                    if !command_ast.redirects.is_empty() {
                        return Err(Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "managed component redirection is not allowed",
                        ));
                    }
                    if literal_word(&command_ast.name) != Some(manifest.name())
                        || command_ast.args.iter().any(|argument| match argument {
                            Argument::Word(word) => !word
                                .parts
                                .iter()
                                .all(|part| matches!(part, WordPart::Literal(_))),
                            Argument::Capability { .. } => true,
                        })
                    {
                        return Err(Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "managed component substitution is not allowed",
                        ));
                    }
                    if lifecycle.manifest() != manifest.as_ref() {
                        return Err(Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "managed component manifest changed after installation",
                        ));
                    }
                    if manifest.min_args != 0
                        || manifest.max_args != 0
                        || manifest.world != VIBE_STREAM_FILTER_WORLD
                        || manifest.stdin != StreamMode::Required
                        || manifest.stdout != StreamMode::Required
                        || manifest.stderr == StreamMode::Required
                        || !manifest.requirements.is_empty()
                    {
                        return Err(Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "managed SSH component contract is not the exact stream world",
                        ));
                    }
                    let cspace = self.cspace.lock();
                    if cspace.identity() != io.space || cspace.incarnation() != io.incarnation {
                        return Err(Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "managed component IO belongs to another CSpace incarnation",
                        ));
                    }
                    validate_managed_component_io_source(
                        &cspace,
                        io.stdin,
                        io.stdout,
                        io.stdin_supervisor,
                        io.stdout_supervisor,
                        command_ast.span,
                    )?;
                    (Some(manifest.clone()), true, Some(*io))
                }
                _ => (None, false, None),
            };
            stages.push(PreflightStage {
                command: command_ast.clone(),
                command_name,
                command_source,
                manifest,
                component,
                managed_component,
                managed_io,
            });
        }

        if stages.iter().any(|stage| stage.component.is_some()) {
            for stage in &stages {
                self.preflight_component_pipeline_substitutions(&stage.command)?;
            }
        }

        // Trusted adapter hooks run only after every shell-controlled check has
        // succeeded, so an unauthorized later stage cannot even enter an
        // earlier component's adapter preflight.
        for (span, manifest, runner) in component_preflights {
            runner
                .preflight(&manifest)
                .map_err(|terminal| component_preflight_diagnostic(span, terminal))?;
        }
        Ok(PipelinePreflight {
            owner_identity: self.identity.clone(),
            stages,
        })
    }

    fn preflight_command_name(&self, word: &Word) -> Result<String, Diagnostic> {
        let mut name = String::new();
        for part in &word.parts {
            match part {
                WordPart::Literal(value) => name.push_str(value),
                WordPart::Value(value) => {
                    name.push_str(self.values.get(value).map(String::as_str).unwrap_or(""));
                }
                WordPart::Command { span, .. } => {
                    return Err(Diagnostic::new(
                        span.start,
                        span.end,
                        "command substitution cannot select a pipeline command",
                    ));
                }
            }
            if name.len() > MAX_BINDING_BYTES {
                return Err(Diagnostic::new(
                    word.span.start,
                    word.span.end,
                    "expanded command name exceeds 4 KiB",
                ));
            }
        }
        Ok(name)
    }

    fn preflight_component_pipeline_substitutions(
        &self,
        command: &CommandAst,
    ) -> Result<(), Diagnostic> {
        for argument in &command.args {
            if let Argument::Word(word) = argument {
                self.preflight_component_word(word, 0)?;
            }
        }
        Ok(())
    }

    fn preflight_component_word(&self, word: &Word, depth: usize) -> Result<(), Diagnostic> {
        for part in &word.parts {
            if let WordPart::Command { source, span } = part {
                if depth >= MAX_COMMAND_SUBSTITUTION_DEPTH {
                    return Err(Diagnostic::new(
                        span.start,
                        span.end,
                        "command substitution nesting limit exceeded",
                    ));
                }
                let script = parse(source).map_err(|_| {
                    Diagnostic::new(span.start, span.end, "invalid command substitution")
                })?;
                self.preflight_pure_substitution_script(&script, depth + 1, *span)?;
            }
        }
        Ok(())
    }

    fn preflight_pure_substitution_script(
        &self,
        script: &Script,
        depth: usize,
        outer_span: Span,
    ) -> Result<(), Diagnostic> {
        for statement in &script.statements {
            match statement {
                Statement::Command(item) => {
                    if item.background {
                        return Err(Diagnostic::new(
                            outer_span.start,
                            outer_span.end,
                            "component pipeline substitution cannot start a background job",
                        ));
                    }
                    self.preflight_pure_substitution_and_or(&item.command, depth, outer_span)?;
                }
                Statement::If {
                    condition,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    self.preflight_pure_substitution_and_or(condition, depth, outer_span)?;
                    self.preflight_pure_substitution_script(then_branch, depth, outer_span)?;
                    if let Some(else_branch) = else_branch {
                        self.preflight_pure_substitution_script(else_branch, depth, outer_span)?;
                    }
                }
                Statement::While {
                    condition, body, ..
                } => {
                    self.preflight_pure_substitution_and_or(condition, depth, outer_span)?;
                    self.preflight_pure_substitution_script(body, depth, outer_span)?;
                }
                Statement::Function { body, .. } => {
                    self.preflight_pure_substitution_script(body, depth, outer_span)?;
                }
            }
        }
        Ok(())
    }

    fn preflight_pure_substitution_and_or(
        &self,
        command: &AndOrAst,
        depth: usize,
        outer_span: Span,
    ) -> Result<(), Diagnostic> {
        self.preflight_pure_substitution_pipeline(&command.first, depth, outer_span)?;
        for (_, pipeline) in &command.rest {
            self.preflight_pure_substitution_pipeline(pipeline, depth, outer_span)?;
        }
        Ok(())
    }

    fn preflight_pure_substitution_pipeline(
        &self,
        pipeline: &PipelineAst,
        depth: usize,
        outer_span: Span,
    ) -> Result<(), Diagnostic> {
        for command in &pipeline.commands {
            if !command.redirects.is_empty() {
                return Err(Diagnostic::new(
                    outer_span.start,
                    outer_span.end,
                    "component pipeline substitution cannot redirect authority",
                ));
            }
            let Some(name) = literal_word(&command.name) else {
                return Err(Diagnostic::new(
                    outer_span.start,
                    outer_span.end,
                    "component pipeline substitution command must be literal",
                ));
            };
            if is_special_form(name) {
                if name != "let" {
                    return Err(Diagnostic::new(
                        outer_span.start,
                        outer_span.end,
                        "component pipeline substitution cannot control jobs or scripts",
                    ));
                }
            } else {
                let cap = self.commands.get(name).copied().ok_or_else(|| {
                    Diagnostic::new(
                        outer_span.start,
                        outer_span.end,
                        "unknown command substitution command",
                    )
                })?;
                let command_resource = self
                    .cspace
                    .lock()
                    .lookup_as::<Command>(cap, Rights::INVOKE)
                    .map_err(|_| {
                        Diagnostic::new(
                            outer_span.start,
                            outer_span.end,
                            "command substitution command is not invokable",
                        )
                    })?;
                if matches!(
                    command_resource.applet,
                    Applet::Host { .. }
                        | Applet::AsyncHost { .. }
                        | Applet::Component { .. }
                        | Applet::ManagedComponent { .. }
                ) {
                    return Err(Diagnostic::new(
                        outer_span.start,
                        outer_span.end,
                        "component pipeline substitution must be side-effect-free",
                    ));
                }
            }
            for argument in &command.args {
                match argument {
                    Argument::Word(word) => self.preflight_component_word(word, depth)?,
                    Argument::Capability { .. } => {
                        return Err(Diagnostic::new(
                            outer_span.start,
                            outer_span.end,
                            "component pipeline substitution cannot use authority",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn preflight_console(&self, span: Span, message: &'static str) -> Result<(), Diagnostic> {
        let console = self
            .capabilities
            .get("console")
            .copied()
            .ok_or_else(|| Diagnostic::new(span.start, span.end, message))?;
        let cspace = self.cspace.lock();
        let rights = cspace
            .rights_of(console)
            .map_err(|_| Diagnostic::new(span.start, span.end, message))?;
        if !rights.contains(Rights::WRITE.union(Rights::GRANT))
            || cspace
                .lookup(console, Rights::WRITE)
                .map_or(true, |object| object.kind() != "byte-sink")
        {
            return Err(Diagnostic::new(span.start, span.end, message));
        }
        Ok(())
    }

    fn preflight_redirect(&self, redirect: &Redirect) -> Result<(), Diagnostic> {
        if self
            .active_script_caps
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&redirect.target))
        {
            return Err(Diagnostic::new(
                redirect.span.start,
                redirect.span.end,
                "capability is outside the script authority manifest",
            ));
        }
        let source = self
            .capabilities
            .get(&redirect.target)
            .copied()
            .ok_or_else(|| {
                Diagnostic::new(redirect.span.start, redirect.span.end, "unknown capability")
            })?;
        let (rights, object) = {
            let cspace = self.cspace.lock();
            let need = if redirect.kind == RedirectKind::Stdin {
                Rights::RECV
            } else {
                Rights::WRITE
            };
            let rights = cspace.rights_of(source).map_err(|_| {
                Diagnostic::new(
                    redirect.span.start,
                    redirect.span.end,
                    if redirect.kind == RedirectKind::Stdin {
                        "input capability lacks required rights"
                    } else {
                        "output capability lacks required rights"
                    },
                )
            })?;
            let object = cspace.lookup(source, need).map_err(|_| {
                Diagnostic::new(
                    redirect.span.start,
                    redirect.span.end,
                    if redirect.kind == RedirectKind::Stdin {
                        "input capability lacks required rights"
                    } else {
                        "output capability lacks required rights"
                    },
                )
            })?;
            (rights, object)
        };
        let expected = if redirect.kind == RedirectKind::Stdin {
            "byte-stream"
        } else {
            "byte-sink"
        };
        if object.kind() != expected {
            return Err(Diagnostic::new(
                redirect.span.start,
                redirect.span.end,
                if redirect.kind == RedirectKind::Stdin {
                    "input capability has wrong resource kind"
                } else {
                    "output capability has wrong resource kind"
                },
            ));
        }
        if !rights.contains(Rights::GRANT) {
            return Err(Diagnostic::new(
                redirect.span.start,
                redirect.span.end,
                if redirect.kind == RedirectKind::Stdin {
                    "input capability cannot be delegated"
                } else {
                    "output capability cannot be delegated"
                },
            ));
        }
        Ok(())
    }

    fn preflight_component_authority(
        &self,
        requirement: &ComponentAuthorityRequirement,
        span: Span,
    ) -> Result<(), Diagnostic> {
        if self
            .active_script_caps
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(requirement.label()))
        {
            return Err(Diagnostic::new(
                span.start,
                span.end,
                "component authority is outside the script manifest",
            ));
        }
        let source = self
            .capabilities
            .get(requirement.label())
            .copied()
            .ok_or_else(|| {
                Diagnostic::new(span.start, span.end, "component authority is unavailable")
            })?;
        let cspace = self.cspace.lock();
        let rights = cspace
            .rights_of(source)
            .map_err(|_| Diagnostic::new(span.start, span.end, "component authority is denied"))?;
        if !rights.contains(requirement.rights().union(Rights::GRANT)) {
            return Err(Diagnostic::new(
                span.start,
                span.end,
                "component authority is denied",
            ));
        }
        let object = cspace
            .lookup(source, requirement.rights())
            .map_err(|_| Diagnostic::new(span.start, span.end, "component authority is denied"))?;
        if object.kind() != requirement.resource_kind() {
            return Err(Diagnostic::new(
                span.start,
                span.end,
                "component authority has wrong resource kind",
            ));
        }
        Ok(())
    }

    /// Allocate and populate every unpublished candidate only after synchronous
    /// preflight has completed. All live authority is revalidated before the
    /// first argument expansion or command substitution.
    pub async fn prepare_pipeline(
        &mut self,
        preflight: PipelinePreflight,
    ) -> Result<PreparedPipeline, Diagnostic> {
        let PipelinePreflight {
            owner_identity,
            stages: preflight_stages,
        } = preflight;
        if !Arc::ptr_eq(&owner_identity, &self.identity) {
            return Err(Diagnostic::new(
                0,
                0,
                "pipeline preflight belongs to another session",
            ));
        }
        let id = self.next_job.fetch_add(1, Ordering::Relaxed);
        let mut admission = CSpace::new("vsh-admission");
        let mut pipes = Vec::new();
        let mut roots = Vec::new();
        for _ in 1..preflight_stages.len() {
            let pipe = ByteStream::new();
            let root = admission.mint(
                pipe.clone(),
                Rights::SEND
                    .union(Rights::RECV)
                    .union(Rights::GRANT)
                    .union(Rights::REVOKE),
            );
            pipes.push(pipe);
            roots.push(root);
        }

        let mut stages = Vec::new();
        stages
            .try_reserve_exact(preflight_stages.len())
            .map_err(|_| Diagnostic::new(0, 0, "pipeline candidate allocation failed"))?;
        for (index, preflight_stage) in preflight_stages.iter().enumerate() {
            let command_ast = &preflight_stage.command;
            let mut stage = CSpace::new(&format!("vsh-job-{id}-stage-{index}"));
            let command = cap::grant(
                &self.cspace.lock(),
                preflight_stage.command_source,
                Rights::INVOKE,
                &mut stage,
            )
            .map_err(|_| {
                Diagnostic::new(
                    command_ast.span.start,
                    command_ast.span.end,
                    "missing GRANT on command",
                )
            })?;
            let managed_io = if let Some(source) = preflight_stage.managed_io {
                let mut owner = self.cspace.lock();
                if owner.identity() != source.space || owner.incarnation() != source.incarnation {
                    return Err(Diagnostic::new(
                        command_ast.span.start,
                        command_ast.span.end,
                        "managed component IO belongs to another CSpace incarnation",
                    ));
                }
                let ValidatedManagedComponentIo {
                    stdin: source_reader,
                    stdout: source_writer,
                    stdin_supervisor: source_stdin_supervisor,
                    stdout_supervisor: source_stdout_supervisor,
                } = validate_managed_component_io_source(
                    &owner,
                    source.stdin,
                    source.stdout,
                    source.stdin_supervisor,
                    source.stdout_supervisor,
                    command_ast.span,
                )?;
                // This is the one-shot move linearization point. Stage caps
                // are fresh exact roots, rather than derivations: revoking
                // the Session roots below therefore cannot invalidate the
                // sole prepared invocation. Holding the same owner lock from
                // lookup through all four revocations prevents a second
                // preflight copy from acquiring any endpoint or supervisor.
                let reader_cap = stage.mint(source_reader.clone(), Rights::RECV);
                let writer_cap = stage.mint(source_writer.clone(), Rights::SEND);
                let stdin_supervisor_cap =
                    stage.mint(source_stdin_supervisor.clone(), Rights::INVOKE);
                let stdout_supervisor_cap =
                    stage.mint(source_stdout_supervisor.clone(), Rights::INVOKE);
                if stage.rights_of(reader_cap) != Ok(Rights::RECV)
                    || stage.rights_of(writer_cap) != Ok(Rights::SEND)
                    || stage.rights_of(stdin_supervisor_cap) != Ok(Rights::INVOKE)
                    || stage.rights_of(stdout_supervisor_cap) != Ok(Rights::INVOKE)
                {
                    return Err(Diagnostic::new(
                        command_ast.span.start,
                        command_ast.span.end,
                        "managed component IO attenuation is not exact",
                    ));
                }
                let reader = stage
                    .lookup_as::<ByteStreamReader>(reader_cap, Rights::RECV)
                    .map_err(|_| {
                        Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "managed component stdin binding changed during admission",
                        )
                    })?;
                let writer = stage
                    .lookup_as::<ByteStreamWriter>(writer_cap, Rights::SEND)
                    .map_err(|_| {
                        Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "managed component stdout binding changed during admission",
                        )
                    })?;
                let stdin_supervisor = stage
                    .lookup_as::<ByteStreamSupervisor>(stdin_supervisor_cap, Rights::INVOKE)
                    .map_err(|_| {
                        Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "managed component stdin terminal binding changed during admission",
                        )
                    })?;
                let stdout_supervisor = stage
                    .lookup_as::<ByteStreamSupervisor>(stdout_supervisor_cap, Rights::INVOKE)
                    .map_err(|_| {
                        Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "managed component stdout terminal binding changed during admission",
                        )
                    })?;
                if !Arc::ptr_eq(&reader, &source_reader)
                    || !Arc::ptr_eq(&writer, &source_writer)
                    || !Arc::ptr_eq(&stdin_supervisor, &source_stdin_supervisor)
                    || !Arc::ptr_eq(&stdout_supervisor, &source_stdout_supervisor)
                    || reader.same_stream_as(&writer)
                    || Arc::ptr_eq(&stdin_supervisor, &stdout_supervisor)
                    || !stdin_supervisor.same_stream_as_reader(&reader)
                    || stdin_supervisor.same_stream_as_writer(&writer)
                    || !stdout_supervisor.same_stream_as_writer(&writer)
                    || stdout_supervisor.same_stream_as_reader(&reader)
                {
                    return Err(Diagnostic::new(
                        command_ast.span.start,
                        command_ast.span.end,
                        "managed component IO object identity changed during admission",
                    ));
                }
                let mut exact_source_move = true;
                for source_cap in [
                    source.stdin,
                    source.stdout,
                    source.stdin_supervisor,
                    source.stdout_supervisor,
                ] {
                    if owner.revoke(source_cap) != Ok(1) {
                        exact_source_move = false;
                    }
                }
                drop(owner);
                if !exact_source_move {
                    let io = ManagedComponentIo::new(
                        reader,
                        writer,
                        stdin_supervisor,
                        stdout_supervisor,
                    );
                    let _ = io.finalize_unpublished(ComponentTerminal::RunnerFault);
                    stage.revoke_all();
                    return Err(Diagnostic::new(
                        command_ast.span.start,
                        command_ast.span.end,
                        "managed component IO one-shot transfer failed",
                    ));
                }
                Some((
                    ManagedComponentIo {
                        stdin: reader,
                        stdout: writer,
                        stdin_supervisor,
                        stdout_supervisor,
                    },
                    reader_cap,
                    writer_cap,
                    stdin_supervisor_cap,
                    stdout_supervisor_cap,
                ))
            } else {
                None
            };
            let mut stdin = if managed_io.is_some() {
                LocalIo::Closed
            } else if index > 0 {
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
            let mut stdout = if managed_io.is_some() {
                LocalIo::Closed
            } else if index + 1 < preflight_stages.len() {
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
                LocalIo::Sink(
                    cap::grant(&self.cspace.lock(), console, Rights::WRITE, &mut stage).map_err(
                        |_| {
                            Diagnostic::new(
                                command_ast.span.start,
                                command_ast.span.end,
                                "default stdout cannot be delegated",
                            )
                        },
                    )?,
                )
            };
            let mut stderr = if managed_io.is_some() {
                LocalIo::Closed
            } else {
                let console = self.capabilities["console"];
                LocalIo::Sink(
                    cap::grant(&self.cspace.lock(), console, Rights::WRITE, &mut stage).map_err(
                        |_| {
                            Diagnostic::new(
                                command_ast.span.start,
                                command_ast.span.end,
                                "default stderr cannot be delegated",
                            )
                        },
                    )?,
                )
            };
            for redirect in &command_ast.redirects {
                let source = self.capabilities[&redirect.target];
                match redirect.kind {
                    RedirectKind::Stdin => {
                        stdin = LocalIo::Stream(
                            cap::grant(&self.cspace.lock(), source, Rights::RECV, &mut stage)
                                .map_err(|_| {
                                    Diagnostic::new(
                                        redirect.span.start,
                                        redirect.span.end,
                                        "input capability cannot be delegated",
                                    )
                                })?,
                        );
                    }
                    RedirectKind::Stdout | RedirectKind::Stderr => {
                        let local = LocalIo::Sink(
                            cap::grant(&self.cspace.lock(), source, Rights::WRITE, &mut stage)
                                .map_err(|_| {
                                    Diagnostic::new(
                                        redirect.span.start,
                                        redirect.span.end,
                                        "output capability cannot be delegated",
                                    )
                                })?,
                        );
                        if redirect.kind == RedirectKind::Stdout {
                            stdout = local;
                        } else {
                            stderr = local;
                        }
                    }
                }
            }
            let mut component_authorities = Vec::new();
            if let Some(manifest) = &preflight_stage.component {
                component_authorities
                    .try_reserve_exact(manifest.requirements().len())
                    .map_err(|_| {
                        Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "component authority allocation failed",
                        )
                    })?;
                for requirement in manifest.requirements() {
                    let source = self.capabilities[requirement.label()];
                    let cap = cap::grant(
                        &self.cspace.lock(),
                        source,
                        requirement.rights(),
                        &mut stage,
                    )
                    .map_err(|_| {
                        Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "component authority cannot be delegated",
                        )
                    })?;
                    component_authorities.push(PreparedComponentAuthority {
                        label: requirement.label.clone(),
                        resource_kind: requirement.resource_kind.clone(),
                        rights: requirement.rights,
                        cap,
                    });
                }
            }
            stages.push(PreparedStage {
                cspace: Arc::new(SpinLock::new(stage)),
                command,
                args: Vec::new(),
                stdin,
                stdout,
                _stderr: stderr,
                component_authorities,
                is_component: preflight_stage.component.is_some(),
                is_managed_component: preflight_stage.managed_component,
                managed_io,
                result: Arc::new(SpinLock::new(None)),
            });
        }

        // Candidate authority and topology are now complete. Expansion may
        // await and may run a separately preflighted command substitution, but
        // it can no longer discover a bad later command or redirect.
        for (preflight_stage, stage) in preflight_stages.iter().zip(&mut stages) {
            let mut args = Vec::new();
            let mut expanded_bytes = 0usize;
            for argument in &preflight_stage.command.args {
                let Argument::Word(word) = argument else {
                    unreachable!("capability arguments were rejected by preflight")
                };
                let value = self.expand_word(word).await?;
                expanded_bytes = expanded_bytes.checked_add(value.len()).ok_or_else(|| {
                    Diagnostic::new(
                        word.span.start,
                        word.span.end,
                        "expanded argument size overflow",
                    )
                })?;
                args.push(value);
            }
            if expanded_bytes > MAX_EXPANDED_BYTES {
                return Err(Diagnostic::new(
                    preflight_stage.command.span.start,
                    preflight_stage.command.span.end,
                    "expanded arguments exceed 16 KiB",
                ));
            }
            stage.args = args;
        }
        Ok(PreparedPipeline {
            owner_identity: self.identity.clone(),
            owner: self.cspace.clone(),
            id,
            admission,
            pipes,
            stages,
        })
    }

    async fn run_pipeline(
        &mut self,
        ast: &PipelineAst,
        background: bool,
    ) -> Result<Option<JobReport>, Diagnostic> {
        let preflight = self.preflight_pipeline(ast)?;
        let prepared = self.prepare_pipeline(preflight).await?;
        Ok(Some(prepared.commit(self, background).await?))
    }
}

impl PreparedPipeline {
    /// Atomically publish all prepared stage tasks. This method performs no
    /// name resolution, manifest validation, expansion, or runner preflight.
    pub async fn commit(
        self,
        session: &mut Session,
        background: bool,
    ) -> Result<JobReport, Diagnostic> {
        let Self {
            owner_identity,
            owner,
            id,
            admission,
            pipes,
            stages,
        } = self;
        if !Arc::ptr_eq(&owner_identity, &session.identity) || !Arc::ptr_eq(&owner, &session.cspace)
        {
            return Err(Diagnostic::new(
                0,
                0,
                "prepared pipeline belongs to another session",
            ));
        }
        let job = JobControl {
            live: Arc::new(AtomicBool::new(true)),
            completed: CancellationSignal::new(),
            pipes: pipes.clone(),
        };
        let managed_stages = stages
            .iter()
            .filter(|stage| stage.is_managed_component)
            .count();
        if managed_stages != 0 {
            if session.profile != SessionProfile::SshExec {
                return Err(Diagnostic::new(
                    0,
                    0,
                    "managed component requires an SSH exec session",
                ));
            }
            if managed_stages != 1 || stages.len() != 1 {
                return Err(Diagnostic::new(
                    0,
                    0,
                    "managed component must be the only pipeline stage",
                ));
            }
            if background {
                return Err(Diagnostic::new(
                    0,
                    0,
                    "managed component must run in the foreground",
                ));
            }
            return commit_managed_component(session, id, admission, stages, job).await;
        }
        if heap::current_domain().arena.is_tracked() {
            // Existing kernel VSH/SSH supervisors run in audited raw-reclaim
            // arenas. Ordinary child commands inherit that exact domain and
            // are hart-pinned: while this parent is polling, sequential spawn
            // cannot run a child, and any intervening allocation fault causes
            // the established whole-domain teardown to detach every sibling.
            //
            // WASM Component children require the separate C4.8 generational
            // instance registry and CSpace identity gate. Until that lifecycle
            // is installed, keep this production path explicitly closed.
            if stages.iter().any(|stage| stage.is_component) {
                return Err(Diagnostic::new(
                    0,
                    0,
                    "component lifecycle registry is not installed",
                ));
            }
            return commit_tracked_pipeline(session, id, admission, pipes, stages, job, background)
                .await;
        }
        let mut prepared_running = Vec::new();
        prepared_running
            .try_reserve_exact(stages.len())
            .map_err(|_| Diagnostic::new(0, 0, "stage publication allocation failed"))?;
        let mut task_batch = exec::PreparedTaskBatch::new();
        let mut stage_reports = Vec::new();
        stage_reports
            .try_reserve_exact(stages.len())
            .map_err(|_| Diagnostic::new(0, 0, "stage report allocation failed"))?;
        let auxiliary_tasks =
            usize::from(!background && session.external_cancel.is_some()) + usize::from(background);
        task_batch
            .try_reserve(stages.len().saturating_add(auxiliary_tasks))
            .map_err(|_| Diagnostic::new(0, 0, "stage publication allocation failed"))?;
        for stage in stages {
            let result = stage.result.clone();
            let cspace = stage.cspace.clone();
            let flavor = if stage.is_component {
                StageFlavor::Component
            } else {
                StageFlavor::Command
            };
            let control = job.clone();
            task_batch.prepare("vsh-stage", async move {
                let exit = run_stage(&stage, &control).await;
                *stage.result.lock() = Some(exit.clone());
                close_stage_outputs(&stage, exit.status);
                if severe(exit.status) {
                    control.fail(exit.status);
                }
            });
            prepared_running.push((result, cspace, flavor));
        }
        let stage_count = prepared_running.len();
        let mut running: Vec<RunningStage> = Vec::new();
        running
            .try_reserve_exact(stage_count)
            .map_err(|_| Diagnostic::new(0, 0, "stage publication allocation failed"))?;
        for (handle, (result, cspace, flavor)) in task_batch
            .prepared_handles()
            .iter()
            .take(stage_count)
            .cloned()
            .zip(prepared_running)
        {
            running.push((handle, result, cspace, flavor));
        }

        // Parent revocation and injected cancellation are committed before a
        // stage can become runnable. Every stage checks `job.live` on its first
        // poll, so cancellation needs no post-publication handle walk.
        if let Some(cap) = session.revoke_next_job.take() {
            let _ = session.cspace.lock().revoke(cap);
        }
        if core::mem::take(&mut session.cancel_next_job) {
            job.fail(Status::Cancelled);
            for (handle, _, _, _) in &running {
                // Pre-publication cancellation is intentionally inert at the
                // executor layer; `job.live` is the first-poll cancellation
                // gate that preserves the stage's typed Component identity.
                debug_assert_eq!(handle.cancel(), exec::CancelOutcome::NotPublished);
            }
        }

        // Background Jobs have their own cancellation domain. A Ctrl-C token
        // belongs only to the foreground request that is currently awaiting.
        if !background {
            if let Some(cancel) = session.external_cancel.clone() {
                let control = job.clone();
                let handles: Vec<_> = running
                    .iter()
                    .map(|(handle, _, _, _)| handle.clone())
                    .collect();
                task_batch.prepare("vsh-ctrl-c", async move {
                    watch_foreground_cancel(cancel, control, handles).await;
                });
            }
        }

        if background {
            let mut acknowledgement = String::new();
            use core::fmt::Write as _;
            write!(&mut acknowledgement, "[%{id}]\n")
                .map_err(|_| Diagnostic::new(0, 0, "job acknowledgement allocation failed"))?;
            let admitted_report = JobReport {
                id,
                status: Status::Success,
                stages: Vec::new(),
                output: acknowledgement,
                peak_pipe_depth: 0,
            };
            let report = Arc::new(SpinLock::new(None));
            let report_task = report.clone();
            let handles = running
                .iter()
                .map(|(handle, _, _, _)| handle.clone())
                .collect();
            let control = job.clone();
            let console = session.console.clone();
            task_batch.prepare("vsh-job-supervisor", async move {
                *report_task.lock() = Some(
                    finish_job(id, running, admission, job, pipes, console, stage_reports).await,
                );
            });
            let supervisor = task_batch
                .prepared_handles()
                .get(stage_count)
                .expect("the background supervisor was prepared")
                .clone();
            let replaced = session.jobs.insert(
                id,
                BackgroundJob {
                    supervisor,
                    stages: handles,
                    control,
                    report,
                },
            );
            assert!(replaced.is_none(), "fresh background Job id collided");
            if let Err(error) = task_batch.publish() {
                session.jobs.remove(&id);
                return Err(Diagnostic::new(
                    0,
                    0,
                    match error {
                        exec::PreparedTaskBatchError::Empty => "empty stage publication batch",
                        exec::PreparedTaskBatchError::AlreadyPublished => {
                            "stage publication repeated"
                        }
                        exec::PreparedTaskBatchError::Capacity => {
                            "stage publication capacity failed"
                        }
                        exec::PreparedTaskBatchError::ExclusiveBindingRequired => {
                            "component stage publication requires lifecycle binding"
                        }
                        exec::PreparedTaskBatchError::ExclusiveBindingRejected => {
                            "component lifecycle binding was rejected"
                        }
                        exec::PreparedTaskBatchError::DuplicateReclaimableArena => {
                            "component stages share one exclusive arena"
                        }
                        exec::PreparedTaskBatchError::ReclaimableDomainMismatch => {
                            "component arena owner mismatch"
                        }
                        exec::PreparedTaskBatchError::ReclaimableWrongHome => {
                            "component task home hart mismatch"
                        }
                        exec::PreparedTaskBatchError::ReclaimableDomainUnavailable => {
                            "component arena is unavailable"
                        }
                        exec::PreparedTaskBatchError::ReclaimableCapacity => {
                            "component lifecycle capacity failed"
                        }
                    },
                ));
            }
            return Ok(admitted_report);
        }

        // Foreground stages and the optional Ctrl-C watcher become runnable in
        // one executor transaction. No allocation or authority mutation occurs
        // after this point before we start awaiting the already-owned handles.
        task_batch
            .publish()
            .map_err(|_| Diagnostic::new(0, 0, "stage publication failed"))?;
        Ok(finish_job(
            id,
            running,
            admission,
            job,
            pipes,
            session.console.clone(),
            stage_reports,
        )
        .await)
    }
}

/// Execute the managed SSH Component adapter in the calling VSH task. The
/// lifecycle service owns and schedules the actual Component child; this
/// adapter retains only its static service reference and opaque token while it
/// waits for a copy-only completion scalar.
async fn commit_managed_component(
    session: &mut Session,
    id: u64,
    mut admission: CSpace,
    mut stages: Vec<PreparedStage>,
    job: JobControl,
) -> Result<JobReport, Diagnostic> {
    debug_assert_eq!(session.profile, SessionProfile::SshExec);
    debug_assert_eq!(stages.len(), 1);
    debug_assert!(stages[0].is_managed_component);
    debug_assert!(job.pipes.is_empty());

    if let Some(cap) = session.revoke_next_job.take() {
        let _ = session.cspace.lock().revoke(cap);
    }
    if core::mem::take(&mut session.cancel_next_job) {
        job.fail(Status::Cancelled);
    }
    let external_cancel = session.external_cancel.clone();
    let mut stage = stages.pop().expect("managed stage gate required one stage");
    if external_cancel
        .as_ref()
        .is_some_and(|cancel| cancel.is_cancelled())
    {
        job.fail(Status::Cancelled);
    }
    let prepared = if session.managed_cleanup.is_some() {
        let terminal = stage.finalize_unpublished_managed_io(ComponentTerminal::RunnerFault);
        stage.cspace.lock().revoke_all();
        Err(terminal)
    } else if job.live.load(Ordering::Acquire) {
        prepare_managed_component_start(stage)
    } else {
        let terminal = stage.finalize_unpublished_managed_io(ComponentTerminal::Cancelled);
        stage.cspace.lock().revoke_all();
        Err(terminal)
    };
    // No admission capability is needed after the exact managed start
    // envelope has been extracted. In particular, neither CSpace survives
    // across the lifecycle await below.
    admission.revoke_all();
    let exit = match prepared {
        Ok(prepared) => {
            run_prepared_managed_component(session, prepared, &job, external_cancel.as_ref())
                .await?
        }
        Err(terminal) => managed_component_exit(terminal),
    };
    if severe(exit.status) {
        job.fail(exit.status);
    }
    job.finish();

    Ok(JobReport {
        id,
        status: exit.status,
        stages: vec![StageReport {
            stage: 0,
            status: exit.status,
            detail: exit.detail,
        }],
        output: session.console.take_string(),
        peak_pipe_depth: 0,
    })
}

struct PreparedManagedComponentStart {
    lifecycle: &'static dyn ManagedComponentLifecycle,
    io: ManagedComponentIo,
}

fn prepare_managed_component_start(
    mut stage: PreparedStage,
) -> Result<PreparedManagedComponentStart, ComponentTerminal> {
    let (io, stdin_cap, stdout_cap, stdin_supervisor_cap, stdout_supervisor_cap) = stage
        .managed_io
        .take()
        .ok_or(ComponentTerminal::BackendFault)?;
    let preflight = (|| {
        let command = stage
            .cspace
            .lock()
            .lookup_as::<Command>(stage.command, Rights::INVOKE)
            .map_err(|_| ComponentTerminal::Denied)?;
        let lifecycle = match &command.applet {
            Applet::ManagedComponent {
                manifest,
                lifecycle,
                ..
            } if lifecycle.manifest() == manifest.as_ref() => *lifecycle,
            _ => return Err(ComponentTerminal::BackendFault),
        };
        let (
            observed_stdin,
            observed_stdout,
            observed_stdin_supervisor,
            observed_stdout_supervisor,
        ) = {
            let cspace = stage.cspace.lock();
            if cspace.rights_of(stdin_cap) != Ok(Rights::RECV)
                || cspace.rights_of(stdout_cap) != Ok(Rights::SEND)
                || cspace.rights_of(stdin_supervisor_cap) != Ok(Rights::INVOKE)
                || cspace.rights_of(stdout_supervisor_cap) != Ok(Rights::INVOKE)
            {
                return Err(ComponentTerminal::Denied);
            }
            let stdin = cspace
                .lookup_as::<ByteStreamReader>(stdin_cap, Rights::RECV)
                .map_err(|_| ComponentTerminal::Denied)?;
            let stdout = cspace
                .lookup_as::<ByteStreamWriter>(stdout_cap, Rights::SEND)
                .map_err(|_| ComponentTerminal::Denied)?;
            let stdin_supervisor = cspace
                .lookup_as::<ByteStreamSupervisor>(stdin_supervisor_cap, Rights::INVOKE)
                .map_err(|_| ComponentTerminal::Denied)?;
            let stdout_supervisor = cspace
                .lookup_as::<ByteStreamSupervisor>(stdout_supervisor_cap, Rights::INVOKE)
                .map_err(|_| ComponentTerminal::Denied)?;
            (stdin, stdout, stdin_supervisor, stdout_supervisor)
        };
        if !Arc::ptr_eq(&observed_stdin, &io.stdin)
            || !Arc::ptr_eq(&observed_stdout, &io.stdout)
            || !Arc::ptr_eq(&observed_stdin_supervisor, &io.stdin_supervisor)
            || !Arc::ptr_eq(&observed_stdout_supervisor, &io.stdout_supervisor)
            || observed_stdin.same_stream_as(&observed_stdout)
            || Arc::ptr_eq(&observed_stdin_supervisor, &observed_stdout_supervisor)
            || !observed_stdin_supervisor.same_stream_as_reader(&observed_stdin)
            || observed_stdin_supervisor.same_stream_as_writer(&observed_stdout)
            || !observed_stdout_supervisor.same_stream_as_writer(&observed_stdout)
            || observed_stdout_supervisor.same_stream_as_reader(&observed_stdin)
        {
            return Err(ComponentTerminal::BackendFault);
        }
        drop(command);
        Ok(lifecycle)
    })();
    let lifecycle = match preflight {
        Ok(lifecycle) => lifecycle,
        Err(terminal) => {
            let terminal = io.finalize_unpublished(terminal);
            stage.cspace.lock().revoke_all();
            return Err(terminal);
        }
    };
    // The Session roots were consumed by the one-shot prepare transaction.
    // Revoke the four temporary stage roots before `start` can publish and
    // wake a child on another hart; the non-cloneable envelope is then the
    // only VSH-held ownership and moves directly into the registry call.
    stage.cspace.lock().revoke_all();
    drop(stage);
    Ok(PreparedManagedComponentStart { lifecycle, io })
}

async fn run_prepared_managed_component(
    session: &mut Session,
    prepared: PreparedManagedComponentStart,
    job: &JobControl,
    external_cancel: Option<&Arc<CancellationSignal>>,
) -> Result<StageExit, Diagnostic> {
    enum PrestartWait {
        Installed,
        Cancelled,
        Lost,
    }

    enum ManagedWake {
        Completion(Result<(), OneShotWaitError>),
        CompletionScalar,
        Cancelled(Result<(), OneShotWaitError>),
    }

    let PreparedManagedComponentStart { lifecycle, io } = prepared;
    // The complete endpoint envelope moves into the fixed SYSTEM registry
    // before the first await. Across Armed, the parent retains no endpoint or
    // reference-counted cleanup object.
    let lease = match prepare_managed_reaper(lifecycle, io).await {
        Ok(lease) => lease,
        Err(ManagedPrepareFailure::Terminal(terminal)) => {
            return Ok(managed_component_exit(terminal));
        }
        Err(ManagedPrepareFailure::Lost) => {
            return Err(Diagnostic::new(
                0,
                0,
                "managed component reaper preparation was quarantined",
            ));
        }
    };
    let mut foreground = ManagedForegroundGuard::new(lease);
    let Some(listener) = managed_reaper_completion_listener(lease) else {
        let outcome = lease.abort_before_child_publication(ComponentTerminal::RunnerFault);
        foreground.complete();
        return match outcome {
            ManagedComponentStartAbort::CleanAborted => {
                Ok(managed_component_exit(ComponentTerminal::RunnerFault))
            }
            ManagedComponentStartAbort::Quarantined => Err(Diagnostic::new(
                0,
                0,
                "managed component prestart identity was lost",
            )),
        };
    };
    let mut completion = Box::pin(listener);
    let mut cancellation = external_cancel.map(|cancel| Box::pin(cancel.cancelled()));

    // Both possible parent wake registrations are installed while no child is
    // live. `prepare_managed_reaper` pre-reserved their TaskStatus ledger
    // capacity, so a post-publication RegistrationFailed cannot open an orphan
    // window. This poll returns synchronously once both futures are Pending.
    let prestart = poll_fn(|context| {
        match completion.as_mut().poll(context) {
            Poll::Pending => {}
            Poll::Ready(_) => return Poll::Ready(PrestartWait::Lost),
        }
        if let Some(wait) = cancellation.as_mut() {
            match wait.as_mut().poll(context) {
                Poll::Pending => {}
                Poll::Ready(Ok(())) => return Poll::Ready(PrestartWait::Cancelled),
                Poll::Ready(Err(_)) => return Poll::Ready(PrestartWait::Lost),
            }
        }
        Poll::Ready(PrestartWait::Installed)
    })
    .await;
    let prestart_terminal = match prestart {
        PrestartWait::Installed if job.live.load(Ordering::Acquire) => None,
        PrestartWait::Installed | PrestartWait::Cancelled => {
            job.fail(Status::Cancelled);
            Some(ComponentTerminal::Cancelled)
        }
        PrestartWait::Lost => Some(ComponentTerminal::RunnerFault),
    };
    if let Some(terminal) = prestart_terminal {
        let outcome = lease.abort_before_child_publication(terminal);
        foreground.complete();
        return match outcome {
            ManagedComponentStartAbort::CleanAborted => Ok(managed_component_exit(terminal)),
            ManagedComponentStartAbort::Quarantined => Err(Diagnostic::new(
                0,
                0,
                "managed component prestart identity was lost",
            )),
        };
    }

    let token = match lifecycle.start(lease) {
        Ok(token) => token,
        Err(terminal) => {
            // A conforming lifecycle used the same exact lease to distinguish
            // unpublished abort from ambiguous partial publication. Repeating
            // this operation is idempotent and can only make the result more
            // conservative.
            let outcome = lease.abort_before_child_publication(terminal);
            foreground.complete();
            return match outcome {
                ManagedComponentStartAbort::CleanAborted => Ok(managed_component_exit(terminal)),
                ManagedComponentStartAbort::Quarantined => Err(Diagnostic::new(
                    0,
                    0,
                    "managed component partial start was quarantined",
                )),
            };
        }
    };
    let cleanup = ManagedInvocationCleanup { lease };
    session.managed_cleanup = Some(cleanup);
    if !lease.is_active_for(token) && managed_reaper_completion(lease).is_none() {
        lease.quarantine_partial_start();
    }

    let mut completion_registration_lost = false;
    loop {
        if let Some(observed) = managed_reaper_completion(lease) {
            foreground.complete();
            session.clear_managed_cleanup(cleanup);
            return match observed {
                ManagedReaperCompletion::Terminal(terminal) => Ok(managed_component_exit(terminal)),
                ManagedReaperCompletion::Lost => Err(Diagnostic::new(
                    0,
                    0,
                    "managed component lifecycle identity was lost",
                )),
            };
        }

        if !job.live.load(Ordering::Acquire) {
            request_managed_reaper_cancel(lease);
        }
        if completion_registration_lost {
            // The sole SYSTEM reaper remains authoritative. Keep the exact
            // detach lease armed and wait for its stable scalar instead of
            // guessing a Component terminal from a broken parent listener.
            exec::yield_now().await;
            continue;
        }

        let wake = poll_fn(|context| {
            if managed_reaper_completion(lease).is_some() {
                return Poll::Ready(ManagedWake::CompletionScalar);
            }
            if let Poll::Ready(result) = completion.as_mut().poll(context) {
                return Poll::Ready(ManagedWake::Completion(result));
            }
            if let Some(cancel) = cancellation.as_mut() {
                return cancel.as_mut().poll(context).map(ManagedWake::Cancelled);
            }
            Poll::Pending
        })
        .await;
        match wake {
            ManagedWake::CompletionScalar => {}
            ManagedWake::Completion(Ok(())) => {
                // The completion scalar was stored before this exact edge.
            }
            ManagedWake::Completion(Err(_)) => {
                request_managed_reaper_cancel(lease);
                completion_registration_lost = true;
            }
            ManagedWake::Cancelled(Ok(())) => {
                cancellation = None;
                job.fail(Status::Cancelled);
                request_managed_reaper_cancel(lease);
            }
            ManagedWake::Cancelled(Err(_)) => {
                cancellation = None;
                request_managed_reaper_cancel(lease);
            }
        }
    }
}

const fn managed_component_exit(terminal: ComponentTerminal) -> StageExit {
    StageExit {
        status: terminal.status(),
        detail: TerminalDetail::Component(terminal),
    }
}

/// Commit the existing kernel's tracked-arena builtin-command path without
/// exporting any child state outside that arena. Children are non-stealable
/// and inherit the parent's exact domain, so none can run until this parent
/// yields after all control state and background registration are complete.
/// A fault at any intermediate allocation invokes the executor's established
/// whole-domain sibling teardown rather than returning a partial commit.
async fn commit_tracked_pipeline(
    session: &mut Session,
    id: u64,
    admission: CSpace,
    pipes: Vec<Arc<ByteStream>>,
    stages: Vec<PreparedStage>,
    job: JobControl,
    background: bool,
) -> Result<JobReport, Diagnostic> {
    debug_assert!(heap::current_domain().arena.is_tracked());
    debug_assert!(stages.iter().all(|stage| !stage.is_component));

    let mut running: Vec<RunningStage> = Vec::new();
    running
        .try_reserve_exact(stages.len())
        .map_err(|_| Diagnostic::new(0, 0, "stage publication allocation failed"))?;
    let mut stage_reports = Vec::new();
    stage_reports
        .try_reserve_exact(stages.len())
        .map_err(|_| Diagnostic::new(0, 0, "stage report allocation failed"))?;

    if let Some(cap) = session.revoke_next_job.take() {
        let _ = session.cspace.lock().revoke(cap);
    }
    if core::mem::take(&mut session.cancel_next_job) {
        job.fail(Status::Cancelled);
    }

    for stage in stages {
        let result = stage.result.clone();
        let cspace = stage.cspace.clone();
        let control = job.clone();
        let handle = exec::spawn_tracked("vsh-stage", async move {
            let exit = run_stage(&stage, &control).await;
            *stage.result.lock() = Some(exit.clone());
            close_stage_outputs(&stage, exit.status);
            if severe(exit.status) {
                control.fail(exit.status);
            }
        });
        running.push((handle, result, cspace, StageFlavor::Command));
    }

    if !background {
        if let Some(cancel) = session.external_cancel.clone() {
            let control = job.clone();
            let handles: Vec<_> = running
                .iter()
                .map(|(handle, _, _, _)| handle.clone())
                .collect();
            exec::spawn_tracked("vsh-ctrl-c", async move {
                watch_foreground_cancel(cancel, control, handles).await;
            });
        }
    }

    if background {
        let mut acknowledgement = String::new();
        use core::fmt::Write as _;
        write!(&mut acknowledgement, "[%{id}]\n")
            .map_err(|_| Diagnostic::new(0, 0, "job acknowledgement allocation failed"))?;
        let admitted_report = JobReport {
            id,
            status: Status::Success,
            stages: Vec::new(),
            output: acknowledgement,
            peak_pipe_depth: 0,
        };
        let report = Arc::new(SpinLock::new(None));
        let report_task = report.clone();
        let handles = running
            .iter()
            .map(|(handle, _, _, _)| handle.clone())
            .collect();
        let control = job.clone();
        let console = session.console.clone();
        let supervisor = exec::spawn_tracked("vsh-job-supervisor", async move {
            *report_task.lock() =
                Some(finish_job(id, running, admission, job, pipes, console, stage_reports).await);
        });
        let replaced = session.jobs.insert(
            id,
            BackgroundJob {
                supervisor,
                stages: handles,
                control,
                report,
            },
        );
        assert!(replaced.is_none(), "fresh background Job id collided");
        return Ok(admitted_report);
    }

    Ok(finish_job(
        id,
        running,
        admission,
        job,
        pipes,
        session.console.clone(),
        stage_reports,
    )
    .await)
}

fn literal_word(word: &Word) -> Option<&str> {
    let [WordPart::Literal(value)] = word.parts.as_slice() else {
        return None;
    };
    Some(value)
}

fn is_special_form(name: &str) -> bool {
    matches!(name, "let" | "jobs" | "wait" | "cancel" | "run-script")
}

fn control_report(status: Status) -> JobReport {
    JobReport {
        id: 0,
        status,
        stages: Vec::new(),
        output: String::new(),
        peak_pipe_depth: 0,
    }
}

fn suppress_control_condition_statuses(reports: &mut [JobReport]) {
    for report in reports {
        if !severe(report.status) {
            report.status = Status::Success;
        }
    }
}

fn collect_script_requirements(
    script: &Script,
) -> Result<BTreeMap<String, (String, Rights)>, Diagnostic> {
    let mut requirements = BTreeMap::new();
    collect_block_requirements(script, &mut requirements, 0)?;
    Ok(requirements)
}

fn collect_block_requirements(
    script: &Script,
    requirements: &mut BTreeMap<String, (String, Rights)>,
    substitution_depth: usize,
) -> Result<(), Diagnostic> {
    for statement in &script.statements {
        match statement {
            Statement::Command(item) => {
                collect_and_or_requirements(&item.command, requirements, substitution_depth)?;
            }
            Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                collect_and_or_requirements(condition, requirements, substitution_depth)?;
                collect_block_requirements(then_branch, requirements, substitution_depth)?;
                if let Some(else_branch) = else_branch {
                    collect_block_requirements(else_branch, requirements, substitution_depth)?;
                }
            }
            Statement::While {
                condition, body, ..
            } => {
                collect_and_or_requirements(condition, requirements, substitution_depth)?;
                collect_block_requirements(body, requirements, substitution_depth)?;
            }
            Statement::Function { body, .. } => {
                collect_block_requirements(body, requirements, substitution_depth)?;
            }
        }
    }
    Ok(())
}

fn collect_and_or_requirements(
    command: &AndOrAst,
    requirements: &mut BTreeMap<String, (String, Rights)>,
    substitution_depth: usize,
) -> Result<(), Diagnostic> {
    collect_pipeline_requirements(&command.first, requirements, substitution_depth)?;
    for (_, pipeline) in &command.rest {
        collect_pipeline_requirements(pipeline, requirements, substitution_depth)?;
    }
    Ok(())
}

fn collect_pipeline_requirements(
    pipeline: &PipelineAst,
    requirements: &mut BTreeMap<String, (String, Rights)>,
    substitution_depth: usize,
) -> Result<(), Diagnostic> {
    for command in &pipeline.commands {
        collect_word_requirements(&command.name, requirements, substitution_depth)?;
        let command_name = literal_word(&command.name);
        for argument in &command.args {
            match argument {
                Argument::Word(word) => {
                    collect_word_requirements(word, requirements, substitution_depth)?;
                }
                Argument::Capability { name, span } if command_name == Some("run-script") => {
                    merge_script_requirement(
                        requirements,
                        name,
                        "script-artifact",
                        Rights::READ,
                        *span,
                    )?;
                }
                Argument::Capability { span, .. } => {
                    return Err(Diagnostic::new(
                        span.start,
                        span.end,
                        "script capability argument has no manifest contract",
                    ));
                }
            }
        }
        for redirect in &command.redirects {
            let (kind, rights) = match redirect.kind {
                RedirectKind::Stdin => ("byte-stream", Rights::RECV),
                RedirectKind::Stdout | RedirectKind::Stderr => ("byte-sink", Rights::WRITE),
            };
            merge_script_requirement(requirements, &redirect.target, kind, rights, redirect.span)?;
        }
    }
    Ok(())
}

fn collect_word_requirements(
    word: &Word,
    requirements: &mut BTreeMap<String, (String, Rights)>,
    substitution_depth: usize,
) -> Result<(), Diagnostic> {
    for part in &word.parts {
        if let WordPart::Command { source, span } = part {
            if substitution_depth >= MAX_COMMAND_SUBSTITUTION_DEPTH {
                return Err(Diagnostic::new(
                    span.start,
                    span.end,
                    "command substitution nesting limit exceeded",
                ));
            }
            let nested = parse(source).map_err(|_| {
                Diagnostic::new(span.start, span.end, "invalid command substitution")
            })?;
            collect_block_requirements(&nested, requirements, substitution_depth + 1)?;
        }
    }
    Ok(())
}

fn merge_script_requirement(
    requirements: &mut BTreeMap<String, (String, Rights)>,
    label: &str,
    resource_kind: &str,
    rights: Rights,
    span: Span,
) -> Result<(), Diagnostic> {
    match requirements.get_mut(label) {
        Some((kind, held)) if kind == resource_kind => {
            *held = held.union(rights);
        }
        Some(_) => {
            return Err(Diagnostic::new(
                span.start,
                span.end,
                "one script capability is used as incompatible resource kinds",
            ));
        }
        None => {
            requirements.insert(label.to_string(), (resource_kind.to_string(), rights));
        }
    }
    Ok(())
}

fn parse_job_id(args: &[String], span: Span) -> Result<u64, Diagnostic> {
    if args.len() != 1 || !args[0].starts_with('%') {
        return Err(Diagnostic::new(span.start, span.end, "job id must be %N"));
    }
    args[0][1..]
        .parse()
        .map_err(|_| Diagnostic::new(span.start, span.end, "invalid job id"))
}

async fn finish_job(
    id: u64,
    running: Vec<RunningStage>,
    mut admission: CSpace,
    job: JobControl,
    pipes: Vec<Arc<ByteStream>>,
    console: Arc<OutputSink>,
    mut stage_reports: Vec<StageReport>,
) -> JobReport {
    for (stage_index, (handle, result, cspace, flavor)) in running.iter().enumerate() {
        let exit = handle.join().await;
        let stage_exit = if exit.state() == TaskState::Faulted {
            StageExit {
                status: Status::Faulted,
                detail: match flavor {
                    StageFlavor::Command => TerminalDetail::Command(Status::Faulted),
                    StageFlavor::Component => {
                        TerminalDetail::Component(ComponentTerminal::RunnerFault)
                    }
                },
            }
        } else if exit.state() == TaskState::Cancelled {
            StageExit {
                status: Status::Cancelled,
                detail: match flavor {
                    StageFlavor::Command => TerminalDetail::Command(Status::Cancelled),
                    StageFlavor::Component => {
                        TerminalDetail::Component(ComponentTerminal::Cancelled)
                    }
                },
            }
        } else {
            result.lock().clone().unwrap_or(StageExit {
                status: Status::Faulted,
                detail: match flavor {
                    StageFlavor::Command => TerminalDetail::Command(Status::Faulted),
                    StageFlavor::Component => {
                        TerminalDetail::Component(ComponentTerminal::RunnerFault)
                    }
                },
            })
        };
        stage_reports.push(StageReport {
            stage: stage_index,
            status: stage_exit.status,
            detail: stage_exit.detail,
        });
        if severe(stage_exit.status) {
            job.fail(stage_exit.status);
        }
        cspace.lock().revoke_all();
    }
    admission.revoke_all();
    job.finish();
    JobReport {
        id,
        status: aggregate(&stage_reports),
        stages: stage_reports,
        output: console.take_string(),
        peak_pipe_depth: pipes.iter().map(|p| p.peak_depth()).max().unwrap_or(0),
    }
}

fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.first().copied().is_some_and(is_name_start) && b[1..].iter().copied().all(is_name_continue)
}

fn valid_component_manifest_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn try_component_string(value: &str) -> Result<String, Diagnostic> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| Diagnostic::new(0, 0, "component manifest allocation failed"))?;
    owned.push_str(value);
    Ok(owned)
}

fn is_observability_command(name: &str) -> bool {
    matches!(name, "ps" | "caps" | "mem")
}

/// Fail closed when an observability adapter attempts to serialize an opaque
/// capability/resource identity or an address. Numeric counters and budgets
/// remain valid; the forbidden prefixes are the stable renderings used by the
/// kernel's opaque identity types.
pub fn validate_observability_output(output: &str) -> Result<(), Status> {
    const FORBIDDEN: &[&str] = &[
        "cap:",
        "component:",
        "task:",
        "cspace:",
        "slot:",
        "generation:",
        "object-id:",
        "object_id:",
        "pointer:",
        "address:",
        "0x",
    ];
    let lower = output.to_ascii_lowercase();
    if FORBIDDEN.iter().any(|marker| lower.contains(marker)) {
        Err(Status::BackendFault)
    } else {
        Ok(())
    }
}

fn validate_command_manifest(
    resolved_name: &str,
    manifest: &CommandManifest,
    span: Span,
) -> Result<(), Diagnostic> {
    if manifest.abi == 0
        || manifest.name != resolved_name
        || manifest.min_args > manifest.max_args
        || manifest.max_args > MAX_ARGS
        || manifest.memory_bytes == 0
        || manifest.memory_bytes > MAX_STAGE_MEMORY
        || manifest.operation_budget == 0
    {
        return Err(Diagnostic::new(
            span.start,
            span.end,
            "invalid command manifest",
        ));
    }
    Ok(())
}

fn component_preflight_diagnostic(span: Span, terminal: ComponentTerminal) -> Diagnostic {
    let message = match terminal {
        ComponentTerminal::Usage => "component runner rejected command use",
        ComponentTerminal::Denied => "component runner preflight denied",
        ComponentTerminal::Unavailable => "component runner is unavailable",
        ComponentTerminal::BackendFault => "component runner backend fault",
        ComponentTerminal::BudgetExceeded => "component runner budget rejected",
        ComponentTerminal::Cancelled => "component runner preflight cancelled",
        ComponentTerminal::RunnerFault => "component runner preflight faulted",
        ComponentTerminal::Trapped(_) => "component runner preflight trapped",
        ComponentTerminal::Returned(_) => "component runner preflight returned failure",
        ComponentTerminal::Success => "component runner preflight returned invalid success",
    };
    Diagnostic::new(span.start, span.end, message)
}

fn severe(status: Status) -> bool {
    matches!(
        status,
        Status::Faulted
            | Status::BackendFault
            | Status::BudgetExceeded
            | Status::Denied
            | Status::Cancelled
    )
}
fn rank(status: Status) -> u8 {
    match status {
        Status::Faulted => 5,
        Status::BackendFault => 4,
        Status::BudgetExceeded => 3,
        Status::Denied => 2,
        Status::Cancelled => 1,
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

async fn run_stage(stage: &PreparedStage, job: &JobControl) -> StageExit {
    let command = match stage
        .cspace
        .lock()
        .lookup_as::<Command>(stage.command, Rights::INVOKE)
    {
        Ok(c) => c,
        Err(_) => return command_exit(Status::Denied),
    };
    if !job.live.load(Ordering::Acquire) {
        return match &command.applet {
            Applet::Component { .. } | Applet::ManagedComponent { .. } => StageExit {
                status: Status::Cancelled,
                detail: TerminalDetail::Component(ComponentTerminal::Cancelled),
            },
            _ => command_exit(Status::Cancelled),
        };
    }
    let status = match &command.applet {
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
                    Err(status) => return command_exit(status),
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
        Applet::True => Status::Success,
        Applet::False => Status::Returned(1),
        Applet::Deny => Status::Denied,
        Applet::Fault => Status::Faulted,
        Applet::Spin => {
            while job.live.load(Ordering::Acquire) {
                exec::yield_now().await;
            }
            Status::Cancelled
        }
        Applet::Host {
            command,
            observability,
        } => match command(&stage.args) {
            Ok(output) if *observability && validate_observability_output(&output).is_err() => {
                Status::BackendFault
            }
            Ok(output) if output.is_empty() => Status::Success,
            Ok(output) => write_all(&stage.cspace, &stage.stdout, output.into_bytes(), job).await,
            Err(status) => status,
        },
        Applet::AsyncHost {
            command,
            observability,
        } => match command(stage.args.clone()).await {
            Ok(output) if *observability && validate_observability_output(&output).is_err() => {
                Status::BackendFault
            }
            Ok(output) if output.is_empty() => Status::Success,
            Ok(output) => write_all(&stage.cspace, &stage.stdout, output.into_bytes(), job).await,
            Err(status) => status,
        },
        Applet::Component { manifest, runner } => {
            return run_component_stage(stage, job, manifest.clone(), runner.clone()).await;
        }
        Applet::ManagedComponent { .. } => {
            // Managed invocations must take the dedicated direct adapter path,
            // which never owns or cancels the lifecycle's child task handle.
            return managed_component_exit(ComponentTerminal::BackendFault);
        }
    };
    command_exit(status)
}

const fn command_exit(status: Status) -> StageExit {
    StageExit {
        status,
        detail: TerminalDetail::Command(status),
    }
}

async fn run_component_stage(
    stage: &PreparedStage,
    job: &JobControl,
    manifest: Arc<ComponentCommandManifest>,
    runner: Arc<dyn ComponentCommandRunner>,
) -> StageExit {
    if runner.manifest() != manifest.as_ref() {
        return StageExit {
            status: Status::BackendFault,
            detail: TerminalDetail::Component(ComponentTerminal::BackendFault),
        };
    }
    let input = match collect_component_input(&stage.cspace, &stage.stdin, job).await {
        Ok(input) => input,
        Err(status) => return command_exit(status),
    };
    if !job.live.load(Ordering::Acquire) {
        return StageExit {
            status: Status::Cancelled,
            detail: TerminalDetail::Component(ComponentTerminal::Cancelled),
        };
    }
    let prepared = PreparedComponentStage {
        manifest,
        arguments: stage.args.clone(),
        input,
        cspace: stage.cspace.clone(),
        authorities: stage.component_authorities.clone(),
        cancellation: ComponentCancellation {
            live: job.live.clone(),
        },
    };
    let result = runner.run(prepared).await;
    let (mut terminal, output) = result.into_parts();
    if output.len() > MAX_CAPTURED_OUTPUT {
        terminal = ComponentTerminal::BudgetExceeded;
    } else if matches!(
        terminal,
        ComponentTerminal::Success | ComponentTerminal::Returned(_)
    ) && !output.is_empty()
    {
        let write = write_all(&stage.cspace, &stage.stdout, output, job).await;
        if write != Status::Success {
            terminal = match write {
                Status::Usage => ComponentTerminal::Usage,
                Status::Denied => ComponentTerminal::Denied,
                Status::Unavailable => ComponentTerminal::Unavailable,
                Status::BackendFault => ComponentTerminal::BackendFault,
                Status::BudgetExceeded => ComponentTerminal::BudgetExceeded,
                Status::Cancelled => ComponentTerminal::Cancelled,
                _ => ComponentTerminal::RunnerFault,
            };
        }
    }
    StageExit {
        status: terminal.status(),
        detail: TerminalDetail::Component(terminal),
    }
}

async fn collect_component_input(
    space: &Arc<SpinLock<CSpace>>,
    io: &LocalIo,
    job: &JobControl,
) -> Result<Vec<u8>, Status> {
    let mut input = Vec::new();
    loop {
        match read_chunk(space, io).await? {
            Some(chunk) => {
                let next = input
                    .len()
                    .checked_add(chunk.len())
                    .ok_or(Status::BudgetExceeded)?;
                if next > MAX_CAPTURED_OUTPUT {
                    return Err(Status::BudgetExceeded);
                }
                input
                    .try_reserve_exact(chunk.len())
                    .map_err(|_| Status::BudgetExceeded)?;
                input.extend_from_slice(&chunk);
            }
            None => return Ok(input),
        }
        if !job.live.load(Ordering::Acquire) {
            return Err(Status::Cancelled);
        }
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

fn close_stage_outputs(stage: &PreparedStage, status: Status) {
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

impl Drop for Session {
    fn drop(&mut self) {
        // Drop cannot await the Job supervisors, but requesting cancellation
        // ensures their retained handles observe terminal stage state and can
        // finish their ordinary cleanup path when the executor next runs.
        self.request_shutdown();
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}
