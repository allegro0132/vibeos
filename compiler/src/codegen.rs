//! RV64 machine-code generator.
//!
//! Straight AST -> native code, no IR and no register allocator: values live on
//! the machine stack and only `t0`/`t1` are ever live between instructions. That
//! costs performance and buys something better for a v0.1 — the emitter is small
//! enough to be obviously correct, and nothing has to be spilled across calls.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ast::*;

// Registers.
const ZERO: u32 = 0;
const RA: u32 = 1;
const SP: u32 = 2;
const S0: u32 = 8;
const T0: u32 = 5;
const T1: u32 = 6;
const A0: u32 = 10;

/// Every stack slot is 16 bytes so `sp` is always 16-byte aligned, which is
/// what the RISC-V C ABI requires at a call boundary.
const SLOT: i32 = 16;

// --- instruction encoders ---

fn r(f7: u32, rs2: u32, rs1: u32, f3: u32, rd: u32, op: u32) -> u32 {
    (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
}
fn i(imm: i32, rs1: u32, f3: u32, rd: u32, op: u32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
}
fn s(imm: i32, rs2: u32, rs1: u32, f3: u32, op: u32) -> u32 {
    let im = imm as u32 & 0xfff;
    ((im >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((im & 0x1f) << 7) | op
}
fn b(imm: i32, rs2: u32, rs1: u32, f3: u32) -> u32 {
    let im = imm as u32;
    (((im >> 12) & 1) << 31)
        | (((im >> 5) & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (f3 << 12)
        | (((im >> 1) & 0xf) << 8)
        | (((im >> 11) & 1) << 7)
        | 0x63
}
fn j(imm: i32, rd: u32) -> u32 {
    let im = imm as u32;
    (((im >> 20) & 1) << 31)
        | (((im >> 1) & 0x3ff) << 21)
        | (((im >> 11) & 1) << 20)
        | (((im >> 12) & 0xff) << 12)
        | (rd << 7)
        | 0x6f
}

fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    i(imm, rs1, 0, rd, 0x13)
}
fn ld(rd: u32, rs1: u32, off: i32) -> u32 {
    i(off, rs1, 3, rd, 0x03)
}
fn sd(rs2: u32, rs1: u32, off: i32) -> u32 {
    s(off, rs2, rs1, 3, 0x23)
}

struct Scope {
    name: String,
    slot: u32,
    mutable: bool,
}

pub struct Codegen {
    code: Vec<u32>,
    /// Absolute address the code buffer will live at.
    code_base: u64,
    /// Resolved on pass 2; all zero on pass 1.
    fn_addrs: BTreeMap<String, u64>,
    fn_arity: BTreeMap<String, usize>,
    str_addr: BTreeMap<String, u64>,
    rt_print_str: u64,
    rt_print_int: u64,
    scope: Vec<Scope>,
    next_slot: u32,
    ret_patches: Vec<usize>,
}

pub struct Runtime {
    pub print_str: u64,
    pub print_int: u64,
}

type CResult<T> = Result<T, String>;

impl Codegen {
    fn emit(&mut self, word: u32) {
        self.code.push(word);
    }

    fn here(&self) -> usize {
        self.code.len()
    }

    /// Materialize an arbitrary 64-bit constant. Fixed at 11 instructions so
    /// that code size does not change between pass 1 and pass 2.
    fn li64(&mut self, rd: u32, v: u64) {
        self.emit(addi(rd, ZERO, ((v >> 55) & 0x1ff) as i32));
        for k in (0..5).rev() {
            self.emit(i(11, rd, 1, rd, 0x13)); // slli rd, rd, 11
            self.emit(addi(rd, rd, ((v >> (11 * k)) & 0x7ff) as i32));
        }
    }

    fn push(&mut self, reg: u32) {
        self.emit(addi(SP, SP, -SLOT));
        self.emit(sd(reg, SP, 0));
    }

    fn pop(&mut self, reg: u32) {
        self.emit(ld(reg, SP, 0));
        self.emit(addi(SP, SP, SLOT));
    }

    /// `jal zero, 0` placeholder; returns its index for later patching.
    fn jump_placeholder(&mut self) -> usize {
        let at = self.here();
        self.emit(j(0, ZERO));
        at
    }

    /// Pop a condition and jump to a patch target when it is false (zero).
    fn jump_if_false(&mut self) -> usize {
        self.pop(T0);
        self.emit(b(8, ZERO, T0, 1)); // bne t0, zero, +8  (skip the jump)
        self.jump_placeholder()
    }

    fn patch_to_here(&mut self, at: usize) {
        let target = self.here();
        let off = ((target - at) * 4) as i32;
        self.code[at] = j(off, ZERO);
    }

    fn patch_to(&mut self, at: usize, target: usize) {
        let off = (target as i64 - at as i64) as i32 * 4;
        self.code[at] = j(off, ZERO);
    }

    fn call_abs(&mut self, addr: u64) {
        self.li64(T0, addr);
        self.emit(i(0, T0, 0, RA, 0x67)); // jalr ra, t0, 0
    }

    fn lookup(&self, name: &str) -> Option<&Scope> {
        self.scope.iter().rev().find(|s| s.name == name)
    }
}

/// Count every `let` in a function so the frame can be sized up front.
fn count_lets(block: &Block) -> u32 {
    fn expr_lets(e: &Expr) -> u32 {
        match e {
            Expr::Neg(a) | Expr::Not(a) => expr_lets(a),
            Expr::Bin(_, a, b) => expr_lets(a) + expr_lets(b),
            Expr::Call(_, args, _) => args.iter().map(expr_lets).sum(),
            Expr::If(c, t, e) => {
                expr_lets(c) + count_lets(t) + e.as_ref().map_or(0, count_lets)
            }
            _ => 0,
        }
    }
    let mut n = 0;
    for st in &block.stmts {
        n += match st {
            Stmt::Let { init, .. } => 1 + expr_lets(init),
            Stmt::Assign { value, .. } => expr_lets(value),
            Stmt::Expr(e) => expr_lets(e),
            Stmt::While(c, b) => expr_lets(c) + count_lets(b),
            Stmt::Return(Some(e)) => expr_lets(e),
            Stmt::Return(None) => 0,
            Stmt::Print { parts, .. } => parts
                .iter()
                .map(|p| match p {
                    PrintPart::Val(e) => expr_lets(e),
                    PrintPart::Str(_) => 0,
                })
                .sum(),
        };
    }
    n + block.tail.as_ref().map_or(0, |e| expr_lets(e))
}

/// Collect every string literal the program prints, in first-use order.
pub fn collect_strings(prog: &Program, newline_marker: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |s: &str, out: &mut Vec<String>| {
        if !out.iter().any(|e| e == s) {
            out.push(s.to_string());
        }
    };
    fn walk(block: &Block, out: &mut Vec<String>, add: &mut impl FnMut(&str, &mut Vec<String>)) {
        for st in &block.stmts {
            match st {
                Stmt::While(_, b) => walk(b, out, add),
                Stmt::Print { parts, .. } => {
                    for p in parts {
                        if let PrintPart::Str(s) = p {
                            add(s, out);
                        }
                    }
                }
                _ => {}
            }
            // `if` blocks can hide prints inside expressions.
            for e in stmt_exprs(st) {
                walk_expr(e, out, add);
            }
        }
        if let Some(t) = &block.tail {
            walk_expr(t, out, add);
        }
    }
    fn stmt_exprs(st: &Stmt) -> Vec<&Expr> {
        match st {
            Stmt::Let { init, .. } => alloc::vec![init],
            Stmt::Assign { value, .. } => alloc::vec![value],
            Stmt::Expr(e) => alloc::vec![e],
            Stmt::While(c, _) => alloc::vec![c],
            Stmt::Return(Some(e)) => alloc::vec![e],
            Stmt::Print { parts, .. } => parts
                .iter()
                .filter_map(|p| match p {
                    PrintPart::Val(e) => Some(e),
                    PrintPart::Str(_) => None,
                })
                .collect(),
            Stmt::Return(None) => Vec::new(),
        }
    }
    fn walk_expr(e: &Expr, out: &mut Vec<String>, add: &mut impl FnMut(&str, &mut Vec<String>)) {
        match e {
            Expr::Neg(a) | Expr::Not(a) => walk_expr(a, out, add),
            Expr::Bin(_, a, b) => {
                walk_expr(a, out, add);
                walk_expr(b, out, add);
            }
            Expr::Call(_, args, _) => args.iter().for_each(|a| walk_expr(a, out, add)),
            Expr::If(c, t, els) => {
                walk_expr(c, out, add);
                walk(t, out, add);
                if let Some(e) = els {
                    walk(e, out, add);
                }
            }
            _ => {}
        }
    }
    for f in &prog.funcs {
        walk(&f.body, &mut out, &mut add);
    }
    add(newline_marker, &mut out);
    out
}

/// Compile to machine code. Runs twice: pass 1 discovers function addresses,
/// pass 2 emits calls to them. Instruction sizes never depend on the addresses,
/// so the two passes always agree on layout.
pub fn compile(
    prog: &Program,
    code_base: u64,
    str_addr: BTreeMap<String, u64>,
    rt: &Runtime,
) -> CResult<Vec<u32>> {
    let mut fn_arity = BTreeMap::new();
    for f in &prog.funcs {
        if fn_arity.insert(f.name.clone(), f.params.len()).is_some() {
            return Err(format!("line {}: function `{}` is defined twice", f.line, f.name));
        }
    }
    if fn_arity["main"] != 0 {
        return Err("`main` must take no arguments".to_string());
    }

    let mut addrs = BTreeMap::new();
    let mut code = Vec::new();
    for pass in 0..2 {
        let mut cg = Codegen {
            code: Vec::new(),
            code_base,
            fn_addrs: addrs.clone(),
            fn_arity: fn_arity.clone(),
            str_addr: str_addr.clone(),
            rt_print_str: rt.print_str,
            rt_print_int: rt.print_int,
            scope: Vec::new(),
            next_slot: 0,
            ret_patches: Vec::new(),
        };

        // `main` goes first so the entry point is the buffer's first instruction.
        let mut order: Vec<&Func> = prog.funcs.iter().filter(|f| f.name == "main").collect();
        order.extend(prog.funcs.iter().filter(|f| f.name != "main"));

        let mut found = BTreeMap::new();
        for f in order {
            found.insert(f.name.clone(), code_base + (cg.here() * 4) as u64);
            cg.func(f)?;
        }
        addrs = found;
        code = cg.code;
        let _ = pass;
    }
    Ok(code)
}

impl Codegen {
    fn func(&mut self, f: &Func) -> CResult<()> {
        let nlocals = f.params.len() as u32 + count_lets(&f.body);
        // 2 saved registers + locals, rounded up to a 16-byte multiple.
        let frame = (16 + 8 * nlocals as i32 + 15) & !15;
        if frame > 2032 {
            return Err(format!(
                "line {}: `{}` needs {} locals; at most 252 are supported",
                f.line, f.name, nlocals
            ));
        }

        self.scope.clear();
        self.next_slot = 0;
        self.ret_patches.clear();

        self.emit(addi(SP, SP, -frame));
        self.emit(sd(RA, SP, 0));
        self.emit(sd(S0, SP, 8));
        self.emit(addi(S0, SP, 0));

        // Spill incoming arguments into their frame slots.
        for (n, p) in f.params.iter().enumerate() {
            if n >= 8 {
                return Err(format!("line {}: at most 8 parameters are supported", f.line));
            }
            let slot = self.next_slot;
            self.next_slot += 1;
            self.scope.push(Scope { name: p.clone(), slot, mutable: false });
            let off = 16 + 8 * slot as i32;
            self.emit(sd(A0 + n as u32, S0, off));
        }

        self.block(&f.body)?;
        self.pop(A0); // every block leaves exactly one value on the stack

        let epilogue = self.here();
        for at in core::mem::take(&mut self.ret_patches) {
            self.patch_to(at, epilogue);
        }
        self.emit(addi(SP, S0, 0));
        self.emit(ld(RA, SP, 0));
        self.emit(ld(S0, SP, 8));
        self.emit(addi(SP, SP, frame));
        self.emit(i(0, RA, 0, ZERO, 0x67)); // jalr zero, ra, 0  == ret
        Ok(())
    }

    /// Compiles a block, leaving exactly one value on the stack.
    fn block(&mut self, blk: &Block) -> CResult<()> {
        let mark = self.scope.len();
        for st in &blk.stmts {
            self.stmt(st)?;
        }
        match &blk.tail {
            Some(e) => self.expr(e)?,
            None => {
                self.emit(addi(T0, ZERO, 0));
                self.push(T0);
            }
        }
        self.scope.truncate(mark);
        Ok(())
    }

    fn stmt(&mut self, st: &Stmt) -> CResult<()> {
        match st {
            Stmt::Let { name, mutable, init, .. } => {
                self.expr(init)?;
                self.pop(T0);
                let slot = self.next_slot;
                self.next_slot += 1;
                self.emit(sd(T0, S0, 16 + 8 * slot as i32));
                self.scope.push(Scope { name: name.clone(), slot, mutable: *mutable });
            }
            Stmt::Assign { name, value, line } => {
                let Some(v) = self.lookup(name) else {
                    return Err(format!("line {}: cannot find value `{}` in this scope", line, name));
                };
                if !v.mutable {
                    return Err(format!(
                        "line {}: cannot assign twice to immutable variable `{}` (declare it `let mut`)",
                        line, name
                    ));
                }
                let off = 16 + 8 * v.slot as i32;
                self.expr(value)?;
                self.pop(T0);
                self.emit(sd(T0, S0, off));
            }
            Stmt::Expr(e) => {
                self.expr(e)?;
                self.pop(T0); // discard
            }
            Stmt::While(cond, body) => {
                let top = self.here();
                self.expr(cond)?;
                let exit = self.jump_if_false();
                self.block(body)?;
                self.pop(T0); // discard the block's value
                let back = self.jump_placeholder();
                self.patch_to(back, top);
                self.patch_to_here(exit);
            }
            Stmt::Return(value) => {
                match value {
                    Some(e) => {
                        self.expr(e)?;
                        self.pop(A0);
                    }
                    None => self.emit(addi(A0, ZERO, 0)),
                }
                let at = self.jump_placeholder();
                self.ret_patches.push(at);
            }
            Stmt::Print { parts, newline } => {
                for p in parts {
                    match p {
                        PrintPart::Str(s) => self.call_print_str(s)?,
                        PrintPart::Val(e) => {
                            self.expr(e)?;
                            self.pop(A0);
                            let f = self.rt_print_int;
                            self.call_abs(f);
                        }
                    }
                }
                if *newline {
                    self.call_print_str("\n")?;
                }
            }
        }
        Ok(())
    }

    fn call_print_str(&mut self, s: &str) -> CResult<()> {
        let addr = *self
            .str_addr
            .get(s)
            .ok_or_else(|| format!("internal error: string literal {:?} was not interned", s))?;
        self.li64(A0, addr);
        self.li64(A0 + 1, s.len() as u64);
        let f = self.rt_print_str;
        self.call_abs(f);
        Ok(())
    }

    /// Compiles an expression, leaving exactly one value on the stack.
    fn expr(&mut self, e: &Expr) -> CResult<()> {
        match e {
            Expr::Int(v) => {
                self.li64(T0, *v as u64);
                self.push(T0);
            }
            Expr::Var(name, line) => {
                let Some(v) = self.lookup(name) else {
                    return Err(format!("line {}: cannot find value `{}` in this scope", line, name));
                };
                let off = 16 + 8 * v.slot as i32;
                self.emit(ld(T0, S0, off));
                self.push(T0);
            }
            Expr::Neg(a) => {
                self.expr(a)?;
                self.pop(T0);
                self.emit(r(0x20, T0, ZERO, 0, T0, 0x33)); // sub t0, zero, t0
                self.push(T0);
            }
            Expr::Not(a) => {
                self.expr(a)?;
                self.pop(T0);
                self.emit(i(1, T0, 3, T0, 0x13)); // sltiu t0, t0, 1
                self.push(T0);
            }
            Expr::Bin(BinOp::And, a, b) | Expr::Bin(BinOp::Or, a, b) => {
                let is_and = matches!(e, Expr::Bin(BinOp::And, _, _));
                self.expr(a)?;
                let short = self.short_circuit(is_and);
                self.expr(b)?;
                self.pop(T0);
                self.emit(r(0, T0, ZERO, 3, T0, 0x33)); // sltu t0, zero, t0 -> 0 or 1
                self.push(T0);
                let end = self.jump_placeholder();
                self.patch_to_here(short);
                self.emit(addi(T0, ZERO, if is_and { 0 } else { 1 }));
                self.push(T0);
                self.patch_to_here(end);
            }
            Expr::Bin(op, a, bb) => {
                self.expr(a)?;
                self.expr(bb)?;
                self.pop(T1);
                self.pop(T0);
                self.arith(*op)?;
                self.push(T0);
            }
            Expr::Call(name, args, line) => {
                let Some(&arity) = self.fn_arity.get(name) else {
                    return Err(format!("line {}: cannot find function `{}`", line, name));
                };
                if arity != args.len() {
                    return Err(format!(
                        "line {}: `{}` takes {} argument(s) but {} were supplied",
                        line,
                        name,
                        arity,
                        args.len()
                    ));
                }
                for a in args {
                    self.expr(a)?;
                }
                for n in (0..args.len()).rev() {
                    self.pop(A0 + n as u32);
                }
                let addr = self.fn_addrs.get(name).copied().unwrap_or(self.code_base);
                self.call_abs(addr);
                self.push(A0);
            }
            Expr::If(cond, then, els) => {
                self.expr(cond)?;
                let to_else = self.jump_if_false();
                self.block(then)?;
                let to_end = self.jump_placeholder();
                self.patch_to_here(to_else);
                match els {
                    Some(b) => self.block(b)?,
                    None => {
                        self.emit(addi(T0, ZERO, 0));
                        self.push(T0);
                    }
                }
                self.patch_to_here(to_end);
            }
        }
        Ok(())
    }

    /// Pops nothing; consumes the condition already on the stack and returns a
    /// patch site taken when the operator short-circuits.
    fn short_circuit(&mut self, is_and: bool) -> usize {
        self.pop(T0);
        // `and` bails when false, `or` bails when true.
        self.emit(b(8, ZERO, T0, if is_and { 1 } else { 0 }));
        self.jump_placeholder()
    }

    /// Combines `t0` (lhs) and `t1` (rhs), leaving the result in `t0`.
    fn arith(&mut self, op: BinOp) -> CResult<()> {
        match op {
            BinOp::Add => self.emit(r(0, T1, T0, 0, T0, 0x33)),
            BinOp::Sub => self.emit(r(0x20, T1, T0, 0, T0, 0x33)),
            BinOp::Mul => self.emit(r(1, T1, T0, 0, T0, 0x33)),
            BinOp::Div => self.emit(r(1, T1, T0, 4, T0, 0x33)),
            BinOp::Rem => self.emit(r(1, T1, T0, 6, T0, 0x33)),
            BinOp::Lt => self.emit(r(0, T1, T0, 2, T0, 0x33)), // slt t0, t0, t1
            BinOp::Gt => self.emit(r(0, T0, T1, 2, T0, 0x33)), // slt t0, t1, t0
            BinOp::Ge => {
                self.emit(r(0, T1, T0, 2, T0, 0x33));
                self.emit(i(1, T0, 4, T0, 0x13)); // xori t0, t0, 1
            }
            BinOp::Le => {
                self.emit(r(0, T0, T1, 2, T0, 0x33));
                self.emit(i(1, T0, 4, T0, 0x13));
            }
            BinOp::Eq => {
                self.emit(r(0x20, T1, T0, 0, T0, 0x33)); // sub
                self.emit(i(1, T0, 3, T0, 0x13)); // sltiu t0, t0, 1
            }
            BinOp::Ne => {
                self.emit(r(0x20, T1, T0, 0, T0, 0x33));
                self.emit(r(0, T0, ZERO, 3, T0, 0x33)); // sltu t0, zero, t0
            }
            BinOp::And | BinOp::Or => unreachable!("short-circuited above"),
        }
        Ok(())
    }
}
