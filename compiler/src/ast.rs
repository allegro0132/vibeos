//! AST for the Rust subset. Everything is `i64`; string literals exist only as
//! arguments to `print!`/`println!`.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

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
    Var(String, u32),
    Neg(Box<Expr>),
    Not(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>, u32),
    If(Box<Expr>, Block, Option<Block>),
}

#[derive(Clone, Debug)]
pub enum PrintPart {
    Str(String),
    Val(Expr),
}

#[derive(Clone, Debug)]
pub enum Stmt {
    Let { name: String, mutable: bool, init: Expr },
    Assign { name: String, value: Expr, line: u32 },
    Expr(Expr),
    While(Expr, Block),
    Return(Option<Expr>),
    Print { parts: Vec<PrintPart>, newline: bool },
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
    pub params: Vec<String>,
    pub body: Block,
    pub line: u32,
}

#[derive(Clone, Debug)]
pub struct Program {
    pub funcs: Vec<Func>,
}
