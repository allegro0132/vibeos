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
/// Lowest permitted `sp`, established by the trampoline. Callee-saved, so the
/// runtime hooks preserve it and generated code never writes it.
const S1: u32 = 9;
/// Remaining fuel, likewise.
const S2: u32 = 18;
/// Base of the capability-granted memory region, likewise.
///
/// Arrays are the only reason generated code touches memory outside its frame.
/// Keeping the base in a reserved callee-saved register — rather than letting a
/// program compute an address — is what preserves the confinement argument: an
/// element access is `s3 + index*8` with a bounds check against `s4`, so a
/// program still cannot name an address of its own choosing.
const S3: u32 = 19;
/// Length of that region, in elements.
const S4: u32 = 20;
const T0: u32 = 5;
const T1: u32 = 6;
const T2: u32 = 7;
const T3: u32 = 28;
const T4: u32 = 29;
/// The region cursor: the only non-frame base register a memory access may use.
const T5: u32 = 30;
const A0: u32 = 10;

// Branch funct3 values.
const BEQ: u32 = 0;
const BNE: u32 = 1;
const BGE: u32 = 5;
const BLTU: u32 = 6;
const BGEU: u32 = 7;

/// Abort reasons, shared with `kernel::trampoline::abort`.
pub mod abort {
    pub const STACK_OVERFLOW: u8 = 1;
    pub const DIVIDE_BY_ZERO: u8 = 2;
    pub const REMAINDER_BY_ZERO: u8 = 3;
    pub const OUT_OF_FUEL: u8 = 4;
    pub const ARITHMETIC_OVERFLOW: u8 = 5;
    pub const DIVIDE_OVERFLOW: u8 = 6;
    pub const INDEX_OUT_OF_BOUNDS: u8 = 7;
    pub const OUT_OF_MEMORY: u8 = 8;
}

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
fn mv(rd: u32, rs: u32) -> u32 {
    addi(rd, rs, 0)
}
fn xor(rd: u32, rs1: u32, rs2: u32) -> u32 {
    r(0, rs2, rs1, 4, rd, 0x33)
}
fn and(rd: u32, rs1: u32, rs2: u32) -> u32 {
    r(0, rs2, rs1, 7, rd, 0x33)
}
/// `srai rd, rs1, shamt` — RV64 sets bit 10 of the immediate.
fn srai(rd: u32, rs1: u32, shamt: u32) -> u32 {
    i((0x400 | shamt) as i32, rs1, 5, rd, 0x13)
}
/// Materialize `i64::MIN` in two instructions, for the overflow checks.
fn li_min(rd: u32) -> [u32; 2] {
    [addi(rd, ZERO, 1), i(63, rd, 1, rd, 0x13)]
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
    /// `(base, len)` in elements, for an array. Arrays live in the granted
    /// region rather than the frame, and both numbers are compile-time
    /// constants, so no frame slot holds a pointer a program could tamper with.
    array: Option<(u32, u32)>,
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
    rt_print_bool: u64,
    rt_abort: u64,
    scope: Vec<Scope>,
    next_slot: u32,
    /// Next free element index in the region. Allocation is a compile-time bump
    /// with a single runtime check, because every array length is a constant.
    next_region: u32,
    ret_patches: Vec<usize>,
    /// `jal` sites waiting to be pointed at a shared abort stub. Emitting one
    /// stub per reason keeps each check site to two instructions instead of the
    /// thirteen an inline call would cost.
    abort_patches: Vec<(usize, u8)>,
}

pub struct Runtime {
    pub print_str: u64,
    pub print_int: u64,
    pub print_bool: u64,
    pub abort: u64,
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

    /// Materialize a small constant in one instruction where possible. Lengths
    /// and bases are program constants, so this stays layout-stable across the
    /// two passes.
    fn li_small(&mut self, rd: u32, v: i64) {
        if (-2048..2048).contains(&v) {
            self.emit(addi(rd, ZERO, v as i32));
        } else {
            self.li64(rd, v as u64);
        }
    }

    /// Resolve an array binding to its `(base, len)` in the region.
    fn array_of(&self, name: &str, line: u32) -> CResult<(u32, u32)> {
        match self.lookup(name).and_then(|s| s.array) {
            Some(pair) => Ok(pair),
            None => Err(format!("line {}: `{}` is not an array", line, name)),
        }
    }

    /// Bounds-check the index in `t0` and leave the element address in `t5`.
    ///
    /// This is the *only* place generated code computes a memory address that
    /// is not frame-relative, and it always emits the check with the address in
    /// one piece — which is what makes the invariant auditable: every write to
    /// `t5` is an `add t5, s3, _` preceded by this exact guard.
    ///
    /// The comparison is unsigned, so a negative index becomes a huge value and
    /// fails the same check. Rust indexes with `usize`; the subset has only
    /// `i64`, and this is how it keeps the same guarantee.
    fn element_address(&mut self, base: u32, len: u32) {
        self.li_small(T4, len as i64);
        self.guard(b(8, T4, T0, BLTU), abort::INDEX_OUT_OF_BOUNDS);
        if base != 0 {
            self.li_small(T4, base as i64);
            self.emit(r(0, T4, T0, 0, T0, 0x33)); // add t0, t0, t4
        }
        self.emit(i(3, T0, 1, T0, 0x13)); // slli t0, t0, 3
        self.emit(r(0, T0, S3, 0, T5, 0x33)); // add t5, s3, t0
    }

    /// `[value; len]`: store `t2` into every element, as Rust does for a `Copy`
    /// element type.
    fn fill_array(&mut self, base: u32, len: u32) {
        self.li_small(T3, 0);
        let top = self.here();
        self.li_small(T4, len as i64);
        // Exit when the cursor reaches the length.
        self.emit(b(8, T4, T3, BLTU)); // continue while t3 < t4
        let done = self.jump_placeholder();

        self.emit(mv(T0, T3));
        self.element_address(base, len);
        self.emit(sd(T2, T5, 0));
        self.emit(addi(T3, T3, 1));
        let back = self.jump_placeholder();
        self.patch_to(back, top);
        self.patch_to_here(done);
    }

    /// Emit `guard` (a branch that skips the abort when the check passes),
    /// followed by a jump to the shared stub for `reason`.
    fn guard(&mut self, guard: u32, reason: u8) {
        self.emit(guard);
        let at = self.jump_placeholder();
        self.abort_patches.push((at, reason));
    }

    /// One stub per distinct reason, emitted after every function.
    fn emit_abort_stubs(&mut self) {
        let mut reasons: Vec<u8> = self.abort_patches.iter().map(|(_, r)| *r).collect();
        reasons.sort_unstable();
        reasons.dedup();

        let mut stub_of: Vec<(u8, usize)> = Vec::new();
        for reason in reasons {
            stub_of.push((reason, self.here()));
            self.emit(addi(A0, ZERO, reason as i32));
            let target = self.rt_abort;
            self.call_abs(target);
            // `rt_abort` diverges; if it ever returned, spinning here is far
            // better than resuming a program that failed a safety check.
            // `jal zero, 0` branches to itself.
            self.emit(j(0, ZERO));
        }

        for (at, reason) in core::mem::take(&mut self.abort_patches) {
            let target = stub_of.iter().find(|(r, _)| *r == reason).map(|(_, t)| *t);
            if let Some(t) = target {
                self.patch_to(at, t);
            }
        }
    }
}

/// True when a function contains no call and no loop, and therefore executes a
/// bounded number of instructions no matter its arguments.
fn is_leaf(block: &Block) -> bool {
    fn expr_leaf(e: &Expr) -> bool {
        match e {
            Expr::Call(..) => false,
            Expr::ArrayRepeat(..) => false,
            Expr::Index(_, i, _) => expr_leaf(i),
            Expr::Neg(a) | Expr::Not(a) | Expr::BitNot(a) => expr_leaf(a),
            Expr::Bin(_, a, b, _) => expr_leaf(a) && expr_leaf(b),
            Expr::If(c, t, e, _) => {
                expr_leaf(c) && is_leaf(t) && e.as_ref().map_or(true, is_leaf)
            }
            _ => true,
        }
    }
    block.stmts.iter().all(|st| match st {
        Stmt::While(..) => false,
        // An array initializer emits a fill loop.
        Stmt::Let { init: Expr::ArrayRepeat(..), .. } => false,
        Stmt::IndexAssign { index, value, .. } => expr_leaf(index) && expr_leaf(value),
        // A print is a call into the runtime; charge for it.
        Stmt::Print { .. } => false,
        Stmt::Let { init, .. } => expr_leaf(init),
        Stmt::Assign { value, .. } => expr_leaf(value),
        Stmt::Expr(e) => expr_leaf(e),
        Stmt::Return(Some(e)) => expr_leaf(e),
        Stmt::Return(None) => true,
    }) && block.tail.as_ref().map_or(true, |e| expr_leaf(e))
}

/// Count every `let` in a function so the frame can be sized up front.
fn count_lets(block: &Block) -> u32 {
    fn expr_lets(e: &Expr) -> u32 {
        match e {
            Expr::Neg(a) | Expr::Not(a) | Expr::BitNot(a) => expr_lets(a),
            Expr::Bin(_, a, b, _) => expr_lets(a) + expr_lets(b),
            Expr::Call(_, args, _) => args.iter().map(expr_lets).sum(),
            Expr::Index(_, i, _) => expr_lets(i),
            Expr::ArrayRepeat(v, _, _) => expr_lets(v),
            Expr::If(c, t, e, _) => {
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
            Stmt::IndexAssign { index, value, .. } => expr_lets(index) + expr_lets(value),
            Stmt::Expr(e) => expr_lets(e),
            Stmt::While(c, b, _) => expr_lets(c) + count_lets(b),
            Stmt::Return(Some(e)) => expr_lets(e),
            Stmt::Return(None) => 0,
            Stmt::Print { parts, .. } => parts
                .iter()
                .map(|p| match p {
                    PrintPart::Val(e, _) => expr_lets(e),
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
                Stmt::While(_, b, _) => walk(b, out, add),
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
            Stmt::IndexAssign { index, value, .. } => alloc::vec![index, value],
            Stmt::Expr(e) => alloc::vec![e],
            Stmt::While(c, _, _) => alloc::vec![c],
            Stmt::Return(Some(e)) => alloc::vec![e],
            Stmt::Print { parts, .. } => parts
                .iter()
                .filter_map(|p| match p {
                    PrintPart::Val(e, _) => Some(e),
                    PrintPart::Str(_) => None,
                })
                .collect(),
            Stmt::Return(None) => Vec::new(),
        }
    }
    fn walk_expr(e: &Expr, out: &mut Vec<String>, add: &mut impl FnMut(&str, &mut Vec<String>)) {
        match e {
            Expr::Neg(a) | Expr::Not(a) | Expr::BitNot(a) => walk_expr(a, out, add),
            Expr::Bin(_, a, b, _) => {
                walk_expr(a, out, add);
                walk_expr(b, out, add);
            }
            Expr::Call(_, args, _) => args.iter().for_each(|a| walk_expr(a, out, add)),
            Expr::Index(_, i, _) => walk_expr(i, out, add),
            Expr::ArrayRepeat(v, _, _) => walk_expr(v, out, add),
            Expr::If(c, t, els, _) => {
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
    // Names, arities and types were already validated by `types::check`.
    let mut fn_arity = BTreeMap::new();
    for f in &prog.funcs {
        fn_arity.insert(f.name.clone(), f.params.len());
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
            rt_print_bool: rt.print_bool,
            rt_abort: rt.abort,
            scope: Vec::new(),
            next_slot: 0,
            next_region: 0,
            ret_patches: Vec::new(),
            abort_patches: Vec::new(),
        };

        // `main` goes first so the entry point is the buffer's first instruction.
        let mut order: Vec<&Func> = prog.funcs.iter().filter(|f| f.name == "main").collect();
        order.extend(prog.funcs.iter().filter(|f| f.name != "main"));

        let mut found = BTreeMap::new();
        for f in order {
            found.insert(f.name.clone(), code_base + (cg.here() * 4) as u64);
            cg.func(f)?;
        }
        cg.emit_abort_stubs();
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

        // Stack probe. The frame is already claimed, so this catches the
        // overflow before anything writes through it.
        self.guard(b(8, S1, SP, BGEU), abort::STACK_OVERFLOW);

        // Fuel. Charged per call so that unbounded recursion runs out even when
        // it contains no loop. A function that makes no call and contains no
        // loop cannot fail to terminate, so it is not charged.
        if !is_leaf(&f.body) {
            self.emit(addi(S2, S2, -1));
            self.guard(b(8, ZERO, S2, BGE), abort::OUT_OF_FUEL);
        }

        self.emit(sd(RA, SP, 0));
        self.emit(sd(S0, SP, 8));
        self.emit(addi(S0, SP, 0));

        // Spill incoming arguments into their frame slots.
        for (n, (p, _)) in f.params.iter().enumerate() {
            if n >= 8 {
                return Err(format!("line {}: at most 8 parameters are supported", f.line));
            }
            let slot = self.next_slot;
            self.next_slot += 1;
            self.scope.push(Scope { name: p.clone(), slot, mutable: false, array: None });
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
            Stmt::Let { name, mutable, init: Expr::ArrayRepeat(value, n, _), .. } => {
                let base = self.next_region;
                let len = *n;
                self.next_region = self.next_region.saturating_add(len);

                // One runtime check per array: does the granted region actually
                // reach this far? Everything else about the layout is decided
                // here, at compile time.
                self.li_small(T4, (base + len) as i64);
                self.guard(b(8, T4, S4, BGEU), abort::OUT_OF_MEMORY);

                self.expr(value)?;
                self.pop(T2);
                self.fill_array(base, len);

                let slot = self.next_slot;
                self.next_slot += 1;
                self.scope.push(Scope {
                    name: name.clone(),
                    slot,
                    mutable: *mutable,
                    array: Some((base, len)),
                });
            }
            Stmt::Let { name, mutable, init, .. } => {
                self.expr(init)?;
                self.pop(T0);
                let slot = self.next_slot;
                self.next_slot += 1;
                self.emit(sd(T0, S0, 16 + 8 * slot as i32));
                self.scope.push(Scope {
                    name: name.clone(),
                    slot,
                    mutable: *mutable,
                    array: None,
                });
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
            Stmt::IndexAssign { name, index, value, line } => {
                let (base, len) = self.array_of(name, *line)?;
                self.expr(index)?;
                self.expr(value)?;
                self.pop(T2); // value
                self.pop(T0); // index
                self.element_address(base, len);
                self.emit(sd(T2, T5, 0));
            }
            Stmt::Expr(e) => {
                self.expr(e)?;
                self.pop(T0); // discard
            }
            Stmt::While(cond, body, _) => {
                let top = self.here();
                // Charge each iteration, so `while true {}` terminates.
                self.emit(addi(S2, S2, -1));
                self.guard(b(8, ZERO, S2, BGE), abort::OUT_OF_FUEL);
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
                        PrintPart::Val(e, ty) => {
                            self.expr(e)?;
                            self.pop(A0);
                            // `bool` renders as true/false, matching Rust.
                            let f = match ty {
                                Ty::Bool => self.rt_print_bool,
                                _ => self.rt_print_int,
                            };
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
            Expr::Bool(v) => {
                self.emit(addi(T0, ZERO, i32::from(*v)));
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
                // -i64::MIN overflows; real Rust panics.
                for w in li_min(T2) {
                    self.emit(w);
                }
                self.guard(b(8, T2, T0, BNE), abort::ARITHMETIC_OVERFLOW);
                self.emit(r(0x20, T0, ZERO, 0, T0, 0x33)); // sub t0, zero, t0
                self.push(T0);
            }
            // `!` on a bool. Values are already 0 or 1, so this is exact.
            Expr::Not(a) => {
                self.expr(a)?;
                self.pop(T0);
                self.emit(i(1, T0, 3, T0, 0x13)); // sltiu t0, t0, 1
                self.push(T0);
            }
            // `!` on an integer is bitwise complement, as in Rust.
            Expr::BitNot(a) => {
                self.expr(a)?;
                self.pop(T0);
                self.emit(i(-1, T0, 4, T0, 0x13)); // xori t0, t0, -1
                self.push(T0);
            }
            Expr::Bin(BinOp::And, a, b, _) | Expr::Bin(BinOp::Or, a, b, _) => {
                let is_and = matches!(e, Expr::Bin(BinOp::And, ..));
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
            Expr::Bin(op, a, bb, _) => {
                if matches!(op, BinOp::Div | BinOp::Rem) {
                    if let Expr::Int(0) = **bb {
                        return Err(format!(
                            "this operation will panic at runtime: attempt to {} by zero",
                            if *op == BinOp::Div { "divide" } else { "calculate the remainder" }
                        ));
                    }
                }
                self.expr(a)?;
                self.expr(bb)?;
                self.pop(T1);
                self.pop(T0);
                // A positive literal divisor is neither zero nor -1, so both
                // division guards are provably dead and are not emitted.
                let divisor_is_safe = matches!(**bb, Expr::Int(v) if v > 0);
                self.arith(*op, divisor_is_safe)?;
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
            Expr::Index(name, idx, line) => {
                let (base, len) = self.array_of(name, *line)?;
                self.expr(idx)?;
                self.pop(T0);
                self.element_address(base, len);
                self.emit(ld(T0, T5, 0));
                self.push(T0);
            }
            Expr::ArrayRepeat(..) => {
                return Err(
                    "an array literal may only initialise a `let` binding".to_string()
                )
            }
            Expr::If(cond, then, els, _) => {
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
    ///
    /// Arithmetic is checked. Real Rust panics on overflow and on division by
    /// zero, and a subset that silently wraps is not a subset — it is a
    /// different language that happens to parse the same.
    fn arith(&mut self, op: BinOp, divisor_is_safe: bool) -> CResult<()> {
        match op {
            // r = a + b overflows iff a and b share a sign that r does not,
            // i.e. (r^a) & (r^b) has its sign bit set.
            BinOp::Add => {
                self.emit(r(0, T1, T0, 0, T2, 0x33)); // add t2, t0, t1
                self.emit(xor(T3, T2, T0));
                self.emit(xor(T4, T2, T1));
                self.emit(and(T3, T3, T4));
                self.guard(b(8, ZERO, T3, BGE), abort::ARITHMETIC_OVERFLOW);
                self.emit(mv(T0, T2));
            }
            // r = a - b overflows iff a and b differ in sign and r differs
            // from a: (a^b) & (a^r).
            BinOp::Sub => {
                self.emit(r(0x20, T1, T0, 0, T2, 0x33)); // sub t2, t0, t1
                self.emit(xor(T3, T0, T1));
                self.emit(xor(T4, T0, T2));
                self.emit(and(T3, T3, T4));
                self.guard(b(8, ZERO, T3, BGE), abort::ARITHMETIC_OVERFLOW);
                self.emit(mv(T0, T2));
            }
            // The full product fits in 128 bits; it fits in 64 exactly when the
            // high half is the sign extension of the low half.
            BinOp::Mul => {
                self.emit(r(1, T1, T0, 0, T2, 0x33)); // mul  t2, t0, t1
                self.emit(r(1, T1, T0, 1, T3, 0x33)); // mulh t3, t0, t1
                self.emit(srai(T4, T2, 63));
                self.guard(b(8, T4, T3, BEQ), abort::ARITHMETIC_OVERFLOW);
                self.emit(mv(T0, T2));
            }
            BinOp::Div | BinOp::Rem => {
                let is_div = op == BinOp::Div;
                if !divisor_is_safe {
                    let zero_reason = if is_div {
                        abort::DIVIDE_BY_ZERO
                    } else {
                        abort::REMAINDER_BY_ZERO
                    };
                    self.guard(b(8, ZERO, T1, BNE), zero_reason);

                    // i64::MIN / -1 is the one other case RISC-V answers and
                    // Rust refuses. Only pay for the MIN comparison when b == -1.
                    self.emit(addi(T2, ZERO, -1));
                    self.emit(b(20, T2, T1, BNE)); // b != -1 -> skip the check
                    for w in li_min(T2) {
                        self.emit(w);
                    }
                    self.guard(b(8, T2, T0, BNE), abort::DIVIDE_OVERFLOW);
                }

                let f3 = if is_div { 4 } else { 6 };
                self.emit(r(1, T1, T0, f3, T0, 0x33));
            }
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
