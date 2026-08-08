//! Type checking, and the annotation code generation needs.
//!
//! v0.1 had no types: `i64` stood in for everything, including conditions. That
//! is precisely where the subset stopped being a subset — Rust has no
//! truthiness, so `if 1` is a type error there and was accepted here. Since
//! real rustc is the differential oracle, every such disagreement is a hole in
//! the only strong check the code generator has.
//!
//! The pass both validates and rewrites: `!` on an `i64` becomes `BitNot`, and
//! each printed value is tagged with its type, because a `bool` prints
//! `true`/`false` rather than `1`/`0`.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ast::*;

type TResult<T> = Result<T, String>;

struct Signature {
    params: Vec<Ty>,
    ret: Ty,
}

struct Checker {
    sigs: BTreeMap<String, Signature>,
    scope: Vec<(String, Ty, bool)>,
    ret: Ty,
}

/// Validate a program and return it annotated for code generation.
pub fn check(prog: &Program) -> TResult<Program> {
    let mut sigs = BTreeMap::new();
    for f in &prog.funcs {
        if sigs
            .insert(
                f.name.clone(),
                Signature { params: f.params.iter().map(|(_, t)| *t).collect(), ret: f.ret },
            )
            .is_some()
        {
            return Err(format!("line {}: function `{}` is defined twice", f.line, f.name));
        }
    }

    let main = sigs.get("main").ok_or_else(|| "no `main` function found".to_string())?;
    if !main.params.is_empty() {
        return Err("`main` must take no arguments".to_string());
    }

    let mut funcs = Vec::new();
    for f in &prog.funcs {
        let mut c = Checker {
            sigs: BTreeMap::new(),
            scope: f.params.iter().map(|(n, t)| (n.clone(), *t, false)).collect(),
            ret: f.ret,
        };
        // Cheaper than cloning signatures per function.
        core::mem::swap(&mut c.sigs, &mut sigs);
        let body = c.block(&f.body, Some(f.ret), f.line)?;
        core::mem::swap(&mut c.sigs, &mut sigs);
        funcs.push(Func { body, ..f.clone() });
    }
    Ok(Program { funcs })
}

impl Checker {
    fn lookup(&self, name: &str) -> Option<(Ty, bool)> {
        self.scope.iter().rev().find(|(n, _, _)| n == name).map(|(_, t, m)| (*t, *m))
    }

    /// Check a block. `expect` is the type its value must have, when it has one.
    fn block(&mut self, b: &Block, expect: Option<Ty>, line: u32) -> TResult<Block> {
        let mark = self.scope.len();
        let mut stmts = Vec::new();
        for st in &b.stmts {
            stmts.push(self.stmt(st)?);
        }

        let tail = match &b.tail {
            Some(e) => {
                let (e, t) = self.expr(e)?;
                if let Some(want) = expect {
                    self.unify(want, t, line, "block value")?;
                }
                Some(alloc::boxed::Box::new(e))
            }
            None => {
                if let Some(want) = expect {
                    if want != Ty::Unit && !always_returns(b) {
                        return Err(format!(
                            "line {}: expected this block to have type `{}`, but it has no value",
                            line, want
                        ));
                    }
                }
                None
            }
        };

        self.scope.truncate(mark);
        Ok(Block { stmts, tail })
    }

    fn stmt(&mut self, st: &Stmt) -> TResult<Stmt> {
        Ok(match st {
            Stmt::Let { name, mutable, declared, init, line } => {
                let (init, t) = self.expr(init)?;
                if let Some(d) = declared {
                    // A `let` is the one place an array type may be written, so
                    // it compares directly rather than going through `unify`,
                    // which rejects arrays as values everywhere else.
                    match (d, t) {
                        (Ty::Array(want), Ty::Array(got)) if *want != got => {
                            return Err(format!(
                                "line {}: mismatched types: `{}` is `[i64; {}]` but its initializer has {} element(s)",
                                line, name, want, got
                            ))
                        }
                        (Ty::Array(_), Ty::Array(_)) => {}
                        _ => self.unify(*d, t, *line, &format!("initializer for `{}`", name))?,
                    }
                }
                if t == Ty::Unit {
                    return Err(format!("line {}: `{}` cannot have type `()`", line, name));
                }
                if matches!(t, Ty::Array(_)) && !*mutable {
                    // An immutable array can never be written, and there is no
                    // initializer syntax other than repeat, so it would be a
                    // constant nobody can use.
                    return Err(format!(
                        "line {}: `{}` is an array and must be declared `let mut`",
                        line, name
                    ));
                }
                self.scope.push((name.clone(), t, *mutable));
                Stmt::Let { name: name.clone(), mutable: *mutable, declared: *declared, init, line: *line }
            }
            Stmt::Assign { name, value, line } => {
                let Some((want, mutable)) = self.lookup(name) else {
                    return Err(format!("line {}: cannot find value `{}` in this scope", line, name));
                };
                if !mutable {
                    return Err(format!(
                        "line {}: cannot assign twice to immutable variable `{}` (declare it `let mut`)",
                        line, name
                    ));
                }
                let (value, t) = self.expr(value)?;
                self.unify(want, t, *line, &format!("assignment to `{}`", name))?;
                Stmt::Assign { name: name.clone(), value, line: *line }
            }
            Stmt::IndexAssign { name, index, value, line } => {
                let Some((t, mutable)) = self.lookup(name) else {
                    return Err(format!("line {}: cannot find value `{}` in this scope", line, name));
                };
                let Ty::Array(_) = t else {
                    return Err(format!(
                        "line {}: cannot index into `{}`, which has type `{}`",
                        line, name, t
                    ));
                };
                if !mutable {
                    return Err(format!(
                        "line {}: cannot assign to an element of immutable `{}` (declare it `let mut`)",
                        line, name
                    ));
                }
                let (index, ti) = self.expr(index)?;
                self.unify(Ty::I64, ti, *line, "array index")?;
                let (value, tv) = self.expr(value)?;
                self.unify(Ty::I64, tv, *line, &format!("element assigned to `{}`", name))?;
                Stmt::IndexAssign { name: name.clone(), index, value, line: *line }
            }
            Stmt::Expr(e) => Stmt::Expr(self.expr(e)?.0),
            Stmt::While(cond, body, line) => {
                let (cond, t) = self.expr(cond)?;
                self.unify(Ty::Bool, t, *line, "`while` condition")?;
                Stmt::While(cond, self.block(body, Some(Ty::Unit), *line)?, *line)
            }
            Stmt::Return(value) => {
                let want = self.ret;
                match value {
                    Some(e) => {
                        let (e, t) = self.expr(e)?;
                        self.unify(want, t, 0, "`return` value")?;
                        Stmt::Return(Some(e))
                    }
                    None => {
                        self.unify(want, Ty::Unit, 0, "`return` with no value")?;
                        Stmt::Return(None)
                    }
                }
            }
            Stmt::Print { parts, newline } => {
                let mut out = Vec::new();
                for p in parts {
                    out.push(match p {
                        PrintPart::Str(s) => PrintPart::Str(s.clone()),
                        PrintPart::Val(e, _) => {
                            let (e, t) = self.expr(e)?;
                            match t {
                                Ty::Unit => {
                                    return Err("`()` cannot be formatted with `{}`".to_string())
                                }
                                Ty::Array(_) => {
                                    return Err(format!(
                                        "`{}` cannot be formatted with `{{}}`; print elements instead",
                                        t
                                    ))
                                }
                                _ => {}
                            }
                            PrintPart::Val(e, t)
                        }
                    });
                }
                Stmt::Print { parts: out, newline: *newline }
            }
        })
    }

    fn expr(&mut self, e: &Expr) -> TResult<(Expr, Ty)> {
        Ok(match e {
            Expr::Int(v) => (Expr::Int(*v), Ty::I64),
            Expr::Bool(b) => (Expr::Bool(*b), Ty::Bool),
            Expr::Var(name, line) => {
                let Some((t, _)) = self.lookup(name) else {
                    return Err(format!("line {}: cannot find value `{}` in this scope", line, name));
                };
                (Expr::Var(name.clone(), *line), t)
            }
            Expr::Neg(a) => {
                let (a, t) = self.expr(a)?;
                self.unify(Ty::I64, t, 0, "operand of unary `-`")?;
                if let Expr::Int(v) = a {
                    match v.checked_neg() {
                        Some(n) => return Ok((Expr::Int(n), Ty::I64)),
                        None => {
                            return Err(
                                "this arithmetic operation will overflow: `-i64::MIN`".to_string()
                            )
                        }
                    }
                }
                (Expr::Neg(alloc::boxed::Box::new(a)), Ty::I64)
            }
            // The parser cannot tell the two `!`s apart; the operand type does.
            Expr::Not(a) | Expr::BitNot(a) => {
                let (a, t) = self.expr(a)?;
                let a = alloc::boxed::Box::new(a);
                match t {
                    Ty::Bool => (Expr::Not(a), Ty::Bool),
                    Ty::I64 => (Expr::BitNot(a), Ty::I64),
                    other => return Err(format!("cannot apply `!` to `{}`", other)),
                }
            }
            Expr::Bin(op, a, b, line) => {
                let line = *line;
                let (a, ta) = self.expr(a)?;
                let (b, tb) = self.expr(b)?;
                let (want, out) = match op {
                    BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Rem => {
                        (Ty::I64, Ty::I64)
                    }
                    BinOp::And | BinOp::Or => (Ty::Bool, Ty::Bool),
                    BinOp::Eq | BinOp::Ne => {
                        // Equality works on both, as long as both sides agree.
                        self.unify(ta, tb, line, &format!("operands of `{}`", op_name(*op)))?;
                        if ta == Ty::Unit {
                            return Err("cannot compare values of type `()`".to_string());
                        }
                        (ta, Ty::Bool)
                    }
                    BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => (Ty::I64, Ty::Bool),
                };
                self.unify(want, ta, line, &format!("left operand of `{}`", op_name(*op)))?;
                self.unify(want, tb, line, &format!("right operand of `{}`", op_name(*op)))?;
                // Fold constants here rather than emitting code for them. Real
                // rustc reports literal arithmetic that overflows as an error
                // rather than a runtime panic, and so does this.
                if let (Expr::Int(x), Expr::Int(y)) = (&a, &b) {
                    if let Some(folded) = fold(*op, *x, *y, line)? {
                        return Ok((folded, out));
                    }
                }
                (
                    Expr::Bin(*op, alloc::boxed::Box::new(a), alloc::boxed::Box::new(b), line),
                    out,
                )
            }
            Expr::Call(name, args, line) => {
                let Some(sig) = self.sigs.get(name) else {
                    return Err(format!("line {}: cannot find function `{}`", line, name));
                };
                let (want, ret) = (sig.params.clone(), sig.ret);
                if want.len() != args.len() {
                    return Err(format!(
                        "line {}: `{}` takes {} argument(s) but {} were supplied",
                        line,
                        name,
                        want.len(),
                        args.len()
                    ));
                }
                let mut out = Vec::new();
                for (arg, w) in args.iter().zip(&want) {
                    let (arg, t) = self.expr(arg)?;
                    self.unify(*w, t, *line, &format!("argument to `{}`", name))?;
                    out.push(arg);
                }
                (Expr::Call(name.clone(), out, *line), ret)
            }
            Expr::Index(name, idx, line) => {
                let Some((t, _)) = self.lookup(name) else {
                    return Err(format!("line {}: cannot find value `{}` in this scope", line, name));
                };
                let Ty::Array(_) = t else {
                    return Err(format!(
                        "line {}: cannot index into `{}`, which has type `{}`",
                        line, name, t
                    ));
                };
                let (idx, ti) = self.expr(idx)?;
                self.unify(Ty::I64, ti, *line, "array index")?;
                (Expr::Index(name.clone(), alloc::boxed::Box::new(idx), *line), Ty::I64)
            }
            Expr::ArrayRepeat(v, n, line) => {
                let (v, tv) = self.expr(v)?;
                self.unify(Ty::I64, tv, *line, "array element")?;
                (
                    Expr::ArrayRepeat(alloc::boxed::Box::new(v), *n, *line),
                    Ty::Array(*n),
                )
            }
            Expr::If(cond, then, els, line) => {
                let line = *line;
                let (cond, t) = self.expr(cond)?;
                self.unify(Ty::Bool, t, line, "`if` condition")?;
                match els {
                    Some(e) => {
                        // Both arms must agree; infer from `then`.
                        let then_c = self.block(then, None, line)?;
                        let ty = self.block_ty(&then_c);
                        let else_c = self.block(e, Some(ty), line)?;
                        (
                            Expr::If(alloc::boxed::Box::new(cond), then_c, Some(else_c), line),
                            ty,
                        )
                    }
                    None => {
                        let then_c = self.block(then, Some(Ty::Unit), line)?;
                        (Expr::If(alloc::boxed::Box::new(cond), then_c, None, line), Ty::Unit)
                    }
                }
            }
        })
    }

    /// The type of an already-checked block: its tail's type, or `()`.
    fn block_ty(&mut self, b: &Block) -> Ty {
        match &b.tail {
            Some(e) => self.expr(e).map(|(_, t)| t).unwrap_or(Ty::Unit),
            None => Ty::Unit,
        }
    }

    fn unify(&self, want: Ty, got: Ty, line: u32, what: &str) -> TResult<()> {
        if want == got {
            if matches!(want, Ty::Array(_)) {
                let where_ = if line > 0 { format!("line {}: ", line) } else { String::new() };
                return Err(format!(
                    "{}arrays cannot be passed, returned or assigned as values yet; \
                     index them instead",
                    where_
                ));
            }
            return Ok(());
        }
        let where_ = if line > 0 { format!("line {}: ", line) } else { String::new() };
        Err(format!("{}mismatched types: {} expects `{}`, found `{}`", where_, what, want, got))
    }
}

/// Whether every path out of a block is a `return`, in which case the block
/// needs no value of its own.
fn always_returns(b: &Block) -> bool {
    b.stmts.iter().any(|s| matches!(s, Stmt::Return(_)))
}

fn op_name(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Rem => "%",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Le => "<=",
        BinOp::Gt => ">",
        BinOp::Ge => ">=",
        BinOp::And => "&&",
        BinOp::Or => "||",
    }
}

/// Fold an operation on two literals. `None` means "not a foldable operator".
fn fold(op: BinOp, x: i64, y: i64, line: u32) -> TResult<Option<Expr>> {
    let overflow = |what: &str| {
        Err(format!(
            "line {}: this arithmetic operation will overflow: `{} {} {}`",
            line, x, what, y
        ))
    };
    Ok(Some(match op {
        BinOp::Add => Expr::Int(x.checked_add(y).ok_or_else(|| overflow("+").unwrap_err())?),
        BinOp::Sub => Expr::Int(x.checked_sub(y).ok_or_else(|| overflow("-").unwrap_err())?),
        BinOp::Mul => Expr::Int(x.checked_mul(y).ok_or_else(|| overflow("*").unwrap_err())?),
        BinOp::Div => match x.checked_div(y) {
            Some(v) => Expr::Int(v),
            None if y == 0 => {
                return Err(format!(
                    "line {}: this operation will panic at runtime: attempt to divide by zero",
                    line
                ))
            }
            None => return overflow("/"),
        },
        BinOp::Rem => match x.checked_rem(y) {
            Some(v) => Expr::Int(v),
            None if y == 0 => {
                return Err(format!(
                    "line {}: this operation will panic at runtime: attempt to calculate the remainder by zero",
                    line
                ))
            }
            None => return overflow("%"),
        },
        BinOp::Eq => Expr::Bool(x == y),
        BinOp::Ne => Expr::Bool(x != y),
        BinOp::Lt => Expr::Bool(x < y),
        BinOp::Le => Expr::Bool(x <= y),
        BinOp::Gt => Expr::Bool(x > y),
        BinOp::Ge => Expr::Bool(x >= y),
        BinOp::And | BinOp::Or => return Ok(None),
    }))
}
