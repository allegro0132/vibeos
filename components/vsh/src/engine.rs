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
    if !matches!(name, "echo" | "true" | "false") {
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
    Ok(())
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
    True,
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
struct PlannedStage {
    cspace: Arc<SpinLock<CSpace>>,
    command: Cap,
    args: Vec<String>,
    stdin: LocalIo,
    stdout: LocalIo,
    _stderr: LocalIo,
    result: Arc<SpinLock<Option<Status>>>,
}
type RunningStage = (
    TaskHandle,
    Arc<SpinLock<Option<Status>>>,
    Arc<SpinLock<CSpace>>,
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
    }
}

#[derive(Clone)]
struct FunctionDef {
    params: Vec<String>,
    body: Script,
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
        // A restricted session's allowlist covers both the visible names and
        // the audited applets behind them. In particular, trusted setup code
        // must not be able to replace `echo` with a wider host callback while
        // retaining an allowlisted spelling.
        if self.profile == SessionProfile::SshExec {
            return;
        }
        self.install(
            name,
            Applet::Host(command),
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
            validate_ssh_exec(source)?;
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
        validate_ssh_exec(source)?;
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
                    ))
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
                    let state = if job.supervisor.try_exit().is_some() {
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

    async fn run_pipeline(
        &mut self,
        ast: &PipelineAst,
        background: bool,
    ) -> Result<Option<JobReport>, Diagnostic> {
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
            let command_name = self.expand_word(&command_ast.name).await?;
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
                        let value = self.expand_word(word).await?;
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
            let command = cap::grant(
                &self.cspace.lock(),
                command_source,
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
            let mut stdin = stdin;
            let mut stdout = stdout;
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
                        Diagnostic::new(
                            redirect.span.start,
                            redirect.span.end,
                            "unknown capability",
                        )
                    })?;
                match redirect.kind {
                    RedirectKind::Stdin => {
                        let object =
                            self.cspace
                                .lock()
                                .lookup(source, Rights::RECV)
                                .map_err(|_| {
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
                        let object =
                            self.cspace
                                .lock()
                                .lookup(source, Rights::WRITE)
                                .map_err(|_| {
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
        if let Some(cap) = self.revoke_next_job.take() {
            let _ = self.cspace.lock().revoke(cap);
        }
        if core::mem::take(&mut self.cancel_next_job) {
            job.fail(Status::Cancelled);
            for (handle, _, _) in &running {
                let _ = handle.cancel();
            }
        }
        if let Some(cancel) = self.external_cancel.clone() {
            let control = job.clone();
            let handles: Vec<_> = running
                .iter()
                .map(|(handle, _, _)| handle.clone())
                .collect();
            exec::spawn("vsh-ctrl-c", async move {
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
        if background {
            let report = Arc::new(SpinLock::new(None));
            let report_task = report.clone();
            let handles = running
                .iter()
                .map(|(handle, _, _)| handle.clone())
                .collect();
            let control = job.clone();
            let console = self.console.clone();
            let supervisor = exec::spawn_tracked("vsh-job-supervisor", async move {
                *report_task.lock() =
                    Some(finish_job(id, running, admission, job, pipes, console).await);
            });
            self.jobs.insert(
                id,
                BackgroundJob {
                    supervisor,
                    stages: handles,
                    control,
                    report,
                },
            );
            return Ok(Some(JobReport {
                id,
                status: Status::Success,
                stages: Vec::new(),
                output: format!("[%{id}]\n"),
                peak_pipe_depth: 0,
            }));
        }
        Ok(Some(
            finish_job(id, running, admission, job, pipes, self.console.clone()).await,
        ))
    }
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
) -> JobReport {
    let mut stage_reports = Vec::new();
    for (handle, result, cspace) in &running {
        let exit = handle.join().await;
        let status = if exit.state() == TaskState::Faulted {
            Status::Faulted
        } else if exit.state() == TaskState::Cancelled {
            Status::Cancelled
        } else {
            (*result.lock()).unwrap_or(Status::Faulted)
        };
        stage_reports.push(StageReport {
            task: handle.id(),
            status,
        });
        if severe(status) {
            job.fail(status);
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
