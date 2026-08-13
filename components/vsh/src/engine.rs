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
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use vibeos_core::cap::{self, CSpace, Cap, CapError, Resource, Revocable, Rights};
use vibeos_core::exec::{self, TaskHandle, TaskState, WaitQueue};
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

    fn admits(&self, manifest: &ComponentCommandManifest) -> bool {
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
            Self::Denied => Status::Denied,
            Self::Unavailable => Status::Unavailable,
            Self::BackendFault => Status::BackendFault,
            Self::BudgetExceeded => Status::BudgetExceeded,
            Self::Cancelled => Status::Cancelled,
            Self::RunnerFault => Status::Faulted,
            Self::Trapped(_) => Status::Faulted,
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

struct PreflightStage {
    command: CommandAst,
    command_name: String,
    command_source: Cap,
    manifest: CommandManifest,
    component: Option<Arc<ComponentCommandManifest>>,
}

/// Synchronous, inert result of validating every stage in one pipeline.
/// It owns the syntax and immutable manifest snapshots but no candidate task,
/// stream, CSpace, or live object pointer that can perform an operation.
pub struct PipelinePreflight {
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
    result: Arc<SpinLock<Option<StageExit>>>,
}

/// Fully admitted but unpublished pipeline candidates. Construction may await
/// bounded value expansion, but no stage task or runner is started until
/// [`PreparedPipeline::commit`].
pub struct PreparedPipeline {
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
    external_cancel: Option<Arc<AtomicBool>>,
    function_depth: usize,
    substitution_depth: usize,
    script_depth: usize,
    active_script_caps: Option<BTreeSet<String>>,
    ssh_exec_policy_commands: BTreeSet<String>,
    profile: SessionProfile,
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
        if !policy.admits(source_manifest) {
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
        let Some(cap) = self.capabilities.get(name).copied() else {
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
            cancel.store(true, Ordering::Release);
        }
        for job in self.jobs.values() {
            job.request_cancel();
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
        cancel: Arc<AtomicBool>,
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
        cancel: Arc<AtomicBool>,
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
            let stdin_present = index > 0 || has_stdin_redirect;
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
            if index + 1 == ast.commands.len() {
                self.preflight_console(command_ast.span, "default stdout cannot be delegated")?;
            }
            self.preflight_console(command_ast.span, "default stderr cannot be delegated")?;
            for redirect in &command_ast.redirects {
                self.preflight_redirect(redirect)?;
            }

            let component = match &command.applet {
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
                    Some(manifest.clone())
                }
                _ => None,
            };
            stages.push(PreflightStage {
                command: command_ast.clone(),
                command_name,
                command_source,
                manifest,
                component,
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
        Ok(PipelinePreflight { stages })
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
                    Applet::Host { .. } | Applet::AsyncHost { .. } | Applet::Component { .. }
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
        let id = self.next_job.fetch_add(1, Ordering::Relaxed);
        let preflight_stages = preflight.stages;
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
            let mut stdin = if index > 0 {
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
            let mut stdout = if index + 1 < preflight_stages.len() {
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
            let console = self.capabilities["console"];
            let mut stderr = LocalIo::Sink(
                cap::grant(&self.cspace.lock(), console, Rights::WRITE, &mut stage).map_err(
                    |_| {
                        Diagnostic::new(
                            command_ast.span.start,
                            command_ast.span.end,
                            "default stderr cannot be delegated",
                        )
                    },
                )?,
            );
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
            owner,
            id,
            admission,
            pipes,
            stages,
        } = self;
        if !Arc::ptr_eq(&owner, &session.cspace) {
            return Err(Diagnostic::new(
                0,
                0,
                "prepared pipeline belongs to another session",
            ));
        }
        let job = JobControl {
            live: Arc::new(AtomicBool::new(true)),
            pipes: pipes.clone(),
        };
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
                    while control.live.load(Ordering::Acquire) && !cancel.load(Ordering::Acquire) {
                        exec::yield_now().await;
                    }
                    if cancel.load(Ordering::Acquire) {
                        control.fail(Status::Cancelled);
                        for handle in &handles {
                            let _ = handle.cancel();
                        }
                    }
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
                while control.live.load(Ordering::Acquire) && !cancel.load(Ordering::Acquire) {
                    exec::yield_now().await;
                }
                if cancel.load(Ordering::Acquire) {
                    control.fail(Status::Cancelled);
                    for handle in &handles {
                        let _ = handle.cancel();
                    }
                }
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
    job.live.store(false, Ordering::Release);
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
            Applet::Component { .. } => StageExit {
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
