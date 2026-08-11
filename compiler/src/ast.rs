//! AST for the Rust subset. Everything is `i64`; string literals exist only as
//! arguments to `print!`/`println!`.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// The subset's types. `i64` was load-bearing for everything in v0.1 —
/// conditions included — which is exactly where it stopped being a subset of
/// Rust, since Rust has no truthiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    I64,
    Bool,
    Unit,
    /// `[i64; N]`. Arrays live in the capability-granted region, not the frame,
    /// and are the only reason generated code touches memory it does not own
    /// outright — see `codegen`'s region register contract.
    Array(u32),
}

impl core::fmt::Display for Ty {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Ty::I64 => "i64",
            Ty::Bool => "bool",
            Ty::Unit => "()",
            Ty::Array(n) => return write!(f, "[i64; {}]", n),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Clone, Debug)]
pub enum Expr {
    Int(i64),
    Bool(bool),
    Var(String, u32),
    Neg(Box<Expr>),
    /// `!` on a `bool`: logical negation.
    Not(Box<Expr>),
    /// `!` on an `i64`: bitwise complement. The parser cannot tell these apart,
    /// so it always emits `Not` and the type checker rewrites.
    BitNot(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>, u32),
    Call(String, Vec<Expr>, u32),
    /// `a[i]` — always bounds-checked.
    Index(String, Box<Expr>, u32),
    /// `[value; N]`, the only way to make an array.
    ArrayRepeat(Box<Expr>, u32, u32),
    If(Box<Expr>, Block, Option<Block>, u32),
}

#[derive(Clone, Debug)]
pub enum PrintPart {
    Str(String),
    /// The type is a placeholder until the checker fills it in; code generation
    /// needs it because a `bool` prints `true`/`false`, not `1`/`0`.
    Val(Expr, Ty),
}

#[derive(Clone, Debug)]
pub enum Stmt {
    Let {
        name: String,
        mutable: bool,
        declared: Option<Ty>,
        init: Expr,
        line: u32,
    },
    Assign {
        name: String,
        value: Expr,
        line: u32,
    },
    /// `a[i] = value`.
    IndexAssign {
        name: String,
        index: Expr,
        value: Expr,
        line: u32,
    },
    Expr(Expr),
    While(Expr, Block, u32),
    Return(Option<Expr>),
    Print {
        parts: Vec<PrintPart>,
        newline: bool,
    },
}

/// A block evaluates to its trailing expression, or to `0` if it has none.
#[derive(Clone, Debug)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub tail: Option<Box<Expr>>,
}

#[derive(Clone, Debug)]
pub struct Func {
    pub name: String,
    pub params: Vec<(String, Ty)>,
    pub ret: Ty,
    pub body: Block,
    pub line: u32,
}

#[derive(Clone, Debug)]
pub struct Program {
    pub funcs: Vec<Func>,
}
