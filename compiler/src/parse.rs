//! Recursive-descent parser with precedence climbing.

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ast::*;
use crate::lex::{Tok, Token};

pub struct Parser {
    toks: Vec<Token>,
    pos: usize,
    depth: u32,
}

/// Deepest nesting of parentheses, blocks, and `if`s the parser will descend
/// through.
///
/// This is a kernel-safety limit, not a style rule. `rustc edit` feeds arbitrary
/// console input to a recursive-descent parser running on a 256 KiB kernel stack
/// with no guard page, so unbounded nesting is a way to corrupt memory from the
/// shell prompt. 64 is far past anything a person writes and far short of
/// anything that threatens the stack.
const MAX_DEPTH: u32 = 64;

type PResult<T> = Result<T, String>;

impl Parser {
    pub fn new(toks: Vec<Token>) -> Self {
        Self { toks, pos: 0, depth: 0 }
    }

    fn descend(&mut self) -> PResult<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(format!("line {}: expression nests more than {} deep", self.line(), MAX_DEPTH));
        }
        Ok(())
    }

    fn ascend(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn peek(&self) -> &Tok {
        &self.toks[self.pos].tok
    }

    fn line(&self) -> u32 {
        self.toks[self.pos].line
    }

    fn bump(&mut self) -> Tok {
        let t = self.toks[self.pos].tok.clone();
        if self.pos + 1 < self.toks.len() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, p: &str) -> bool {
        if matches!(self.peek(), Tok::Punct(q) if *q == p) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, p: &str) -> PResult<()> {
        if self.eat(p) {
            Ok(())
        } else {
            Err(format!("line {}: expected `{}`, found {}", self.line(), p, self.describe()))
        }
    }

    fn describe(&self) -> String {
        match self.peek() {
            Tok::Eof => "end of input".to_string(),
            Tok::Ident(s) => format!("`{}`", s),
            Tok::Int(v) => format!("`{}`", v),
            Tok::Str(_) => "a string literal".to_string(),
            Tok::Macro(m) => format!("`{}!`", m),
            Tok::Punct(p) => format!("`{}`", p),
            // Keywords must render as they are written, not as their Debug name:
            // "found `Fn`" is not a token the user typed.
            Tok::Fn => "`fn`".to_string(),
            Tok::Let => "`let`".to_string(),
            Tok::Mut => "`mut`".to_string(),
            Tok::If => "`if`".to_string(),
            Tok::Else => "`else`".to_string(),
            Tok::While => "`while`".to_string(),
            Tok::Return => "`return`".to_string(),
            Tok::I64 => "`i64`".to_string(),
            Tok::Bool => "`bool`".to_string(),
            Tok::True => "`true`".to_string(),
            Tok::False => "`false`".to_string(),
        }
    }

    // Note: `bump` deliberately does not advance past `Eof`, so nothing here may
    // undo a bump by decrementing `pos` -- at end of input that walks backwards
    // onto the previous token and blames it for the error. Peek, then commit.
    fn ident(&mut self) -> PResult<String> {
        let Tok::Ident(s) = self.peek().clone() else {
            return Err(format!(
                "line {}: expected an identifier, found {}",
                self.line(),
                self.describe()
            ));
        };
        self.bump();
        Ok(s)
    }

    pub fn program(&mut self) -> PResult<Program> {
        let mut funcs = Vec::new();
        while !matches!(self.peek(), Tok::Eof) {
            funcs.push(self.func()?);
        }
        if !funcs.iter().any(|f| f.name == "main") {
            return Err("no `main` function found".to_string());
        }
        Ok(Program { funcs })
    }

    fn func(&mut self) -> PResult<Func> {
        let line = self.line();
        if !matches!(self.peek(), Tok::Fn) {
            return Err(format!("line {}: expected `fn`, found {}", line, self.describe()));
        }
        self.bump();
        let name = self.ident()?;
        self.expect("(")?;
        let mut params = Vec::new();
        while !self.eat(")") {
            if !params.is_empty() {
                self.expect(",")?;
                if self.eat(")") {
                    break;
                }
            }
            let p = self.ident()?;
            self.expect(":")?;
            let t = self.ty()?;
            params.push((p, t));
        }
        let ret = if self.eat("->") { self.ty()? } else { Ty::Unit };
        let body = self.block()?;
        Ok(Func { name, params, ret, body, line })
    }

    fn ty(&mut self) -> PResult<Ty> {
        match self.peek() {
            Tok::I64 => {
                self.bump();
                Ok(Ty::I64)
            }
            Tok::Bool => {
                self.bump();
                Ok(Ty::Bool)
            }
            _ => Err(format!(
                "line {}: expected a type (`i64` or `bool`), found {}",
                self.line(),
                self.describe()
            )),
        }
    }

    fn block(&mut self) -> PResult<Block> {
        self.descend()?;
        let out = self.block_inner();
        self.ascend();
        out
    }

    fn block_inner(&mut self) -> PResult<Block> {
        self.expect("{")?;
        let mut stmts = Vec::new();
        let mut tail = None;

        loop {
            if self.eat("}") {
                break;
            }
            if matches!(self.peek(), Tok::Eof) {
                return Err(format!("line {}: unclosed block", self.line()));
            }

            let line = self.line();
            match self.peek().clone() {
                Tok::Let => {
                    self.bump();
                    let mutable = matches!(self.peek(), Tok::Mut) && {
                        self.bump();
                        true
                    };
                    let name = self.ident()?;
                    let declared = if self.eat(":") { Some(self.ty()?) } else { None };
                    self.expect("=")?;
                    let init = self.expr()?;
                    self.expect(";")?;
                    stmts.push(Stmt::Let { name, mutable, declared, init, line });
                }
                Tok::Return => {
                    self.bump();
                    let value = if matches!(self.peek(), Tok::Punct(";")) {
                        None
                    } else {
                        Some(self.expr()?)
                    };
                    self.expect(";")?;
                    stmts.push(Stmt::Return(value));
                }
                Tok::While => {
                    self.bump();
                    let cond = self.expr()?;
                    let body = self.block()?;
                    stmts.push(Stmt::While(cond, body, line));
                }
                Tok::Macro(m) if m == "println" || m == "print" => {
                    self.bump();
                    let parts = self.print_args()?;
                    self.expect(";")?;
                    stmts.push(Stmt::Print { parts, newline: m == "println" });
                }
                Tok::Macro(m) => {
                    return Err(format!("line {}: unsupported macro `{}!`", line, m))
                }
                // `ident = expr;` is an assignment; anything else starting with
                // an identifier is an expression.
                Tok::Ident(name)
                    if matches!(self.toks[self.pos + 1].tok, Tok::Punct("=")) =>
                {
                    self.bump();
                    self.bump();
                    let value = self.expr()?;
                    self.expect(";")?;
                    stmts.push(Stmt::Assign { name, value, line });
                }
                _ => {
                    let e = self.expr()?;
                    if self.eat(";") {
                        stmts.push(Stmt::Expr(e));
                    } else if matches!(e, Expr::If(..))
                        && !matches!(self.peek(), Tok::Punct("}"))
                    {
                        // As in real Rust: a block-like expression in statement
                        // position takes no semicolon. Without this, an `if`
                        // parses only as a block's final expression, so any `if`
                        // followed by more statements is a syntax error.
                        stmts.push(Stmt::Expr(e));
                    } else {
                        self.expect("}")?;
                        tail = Some(Box::new(e));
                        break;
                    }
                }
            }
        }

        Ok(Block { stmts, tail })
    }

    /// `println!("a {} b", x)` -> alternating literal / value parts.
    fn print_args(&mut self) -> PResult<Vec<PrintPart>> {
        self.expect("(")?;
        if self.eat(")") {
            return Ok(Vec::new());
        }
        let line = self.line();
        let fmt = match self.bump() {
            Tok::Str(s) => s,
            _ => {
                return Err(format!(
                    "line {}: the first argument to print must be a string literal",
                    line
                ))
            }
        };

        let mut args = Vec::new();
        while self.eat(",") {
            if matches!(self.peek(), Tok::Punct(")")) {
                break;
            }
            args.push(self.expr()?);
        }
        self.expect(")")?;

        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut used = 0usize;
        let mut chars = fmt.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '{' if chars.peek() == Some(&'{') => {
                    chars.next();
                    lit.push('{');
                }
                '}' if chars.peek() == Some(&'}') => {
                    chars.next();
                    lit.push('}');
                }
                '{' => {
                    if chars.next() != Some('}') {
                        return Err(format!(
                            "line {}: only the empty format specifier `{{}}` is supported",
                            line
                        ));
                    }
                    if used >= args.len() {
                        return Err(format!(
                            "line {}: format string wants at least {} argument(s), {} given",
                            line,
                            used + 1,
                            args.len()
                        ));
                    }
                    if !lit.is_empty() {
                        parts.push(PrintPart::Str(core::mem::take(&mut lit)));
                    }
                    // The checker fills the real type in.
                    parts.push(PrintPart::Val(args[used].clone(), Ty::I64));
                    used += 1;
                }
                c => lit.push(c),
            }
        }
        if used != args.len() {
            return Err(format!(
                "line {}: {} argument(s) given but the format string uses {}",
                line,
                args.len(),
                used
            ));
        }
        if !lit.is_empty() {
            parts.push(PrintPart::Str(lit));
        }
        Ok(parts)
    }

    fn expr(&mut self) -> PResult<Expr> {
        self.descend()?;
        let out = self.bin_expr(0);
        self.ascend();
        out
    }

    fn bin_expr(&mut self, min_prec: u8) -> PResult<Expr> {
        let mut lhs = self.unary()?;
        loop {
            let Tok::Punct(p) = self.peek() else { break };
            let Some((op, prec)) = binop(p) else { break };
            if prec < min_prec {
                break;
            }
            let line = self.line();
            self.bump();
            let rhs = self.bin_expr(prec + 1)?;
            lhs = Expr::Bin(op, Box::new(lhs), Box::new(rhs), line);
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> PResult<Expr> {
        if self.eat("-") {
            return Ok(Expr::Neg(Box::new(self.unary()?)));
        }
        if self.eat("!") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> PResult<Expr> {
        let line = self.line();
        match self.peek().clone() {
            Tok::Int(v) => {
                self.bump();
                Ok(Expr::Int(v))
            }
            Tok::True => {
                self.bump();
                Ok(Expr::Bool(true))
            }
            Tok::False => {
                self.bump();
                Ok(Expr::Bool(false))
            }
            Tok::If => {
                self.bump();
                let cond = self.expr()?;
                let then = self.block()?;
                let els = if matches!(self.peek(), Tok::Else) {
                    self.bump();
                    // `else if` chains desugar into a block holding one if.
                    if matches!(self.peek(), Tok::If) {
                        let nested = self.primary()?;
                        Some(Block { stmts: Vec::new(), tail: Some(Box::new(nested)) })
                    } else {
                        Some(self.block()?)
                    }
                } else {
                    None
                };
                Ok(Expr::If(Box::new(cond), then, els, line))
            }
            Tok::Ident(name) => {
                self.bump();
                if self.eat("(") {
                    let mut args = Vec::new();
                    while !self.eat(")") {
                        if !args.is_empty() {
                            self.expect(",")?;
                            if self.eat(")") {
                                break;
                            }
                        }
                        args.push(self.expr()?);
                    }
                    Ok(Expr::Call(name, args, line))
                } else {
                    Ok(Expr::Var(name, line))
                }
            }
            Tok::Punct("(") => {
                self.bump();
                let e = self.expr()?;
                self.expect(")")?;
                Ok(e)
            }
            _ => Err(format!("line {}: expected an expression, found {}", line, self.describe())),
        }
    }
}

fn binop(p: &str) -> Option<(BinOp, u8)> {
    Some(match p {
        "||" => (BinOp::Or, 1),
        "&&" => (BinOp::And, 2),
        "==" => (BinOp::Eq, 3),
        "!=" => (BinOp::Ne, 3),
        "<" => (BinOp::Lt, 4),
        "<=" => (BinOp::Le, 4),
        ">" => (BinOp::Gt, 4),
        ">=" => (BinOp::Ge, 4),
        "+" => (BinOp::Add, 5),
        "-" => (BinOp::Sub, 5),
        "*" => (BinOp::Mul, 6),
        "/" => (BinOp::Div, 6),
        "%" => (BinOp::Rem, 6),
        _ => return None,
    })
}
