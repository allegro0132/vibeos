//! Experimental bounded RV64IM lowering of validated Wasmi instructions.
//! This crate produces code, never publishes or executes it. The embedding must
//! enforce W^X, validate entry offsets, and supply the exact live frame layout.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::vec::Vec;
pub use wasmi_ir::{Op, Slot};

/// Trusted native-call ABI. All fields are RV64 words, regardless of build host.
/// Entry arguments are `(context_address, code_address + entries[resume] * 4)`.
/// The entry preserves the RISC-V C ABI and writes fuel/resume/reason on return.
#[repr(C)]
#[derive(Debug, Default)]
pub struct Context {
    pub slots: u64,
    pub memory: u64,
    pub memory_len: u64,
    pub fuel: u64,
    pub resume: u64,
    /// 0: interpret at resume; 1: insufficient fuel; 2: memory out of bounds.
    pub reason: u64,
}

const _: () = {
    assert!(core::mem::size_of::<Context>() == 48);
    assert!(core::mem::offset_of!(Context, slots) == 0);
    assert!(core::mem::offset_of!(Context, fuel) == 24);
    assert!(core::mem::offset_of!(Context, resume) == 32);
    assert!(core::mem::offset_of!(Context, reason) == 40);
};

#[derive(Debug, PartialEq, Eq)]
pub enum CompileError {
    Empty,
    Limit,
    Slot,
    Branch,
}

pub struct Code {
    pub words: Vec<u32>,
    /// Word offsets of original instructions. Never derive this from guest data.
    pub entries: Vec<usize>,
    pub lowered: usize,
    /// Native entry is useful; false entries are interpreter-only exit stubs.
    pub supported: Vec<bool>,
}

const ZERO: u32 = 0;
const RA: u32 = 1;
const T0: u32 = 5;
const T1: u32 = 6;
const T2: u32 = 7;
const CTX: u32 = 10;
const ENTRY: u32 = 11;
const SLOTS: u32 = 12;
const MEMORY: u32 = 13;
const FUEL: u32 = 14;
const MEMORY_LEN: u32 = 15;
// Caller-saved registers unused by instruction lowering and the entry ABI.
const FRAME_REGS: [u32; 6] = [16, 17, 28, 29, 30, 31];

fn i(imm: i32, rs: u32, f3: u32, rd: u32, op: u32) -> u32 {
    ((imm as u32 & 4095) << 20) | (rs << 15) | (f3 << 12) | (rd << 7) | op
}
fn r(f7: u32, rhs: u32, lhs: u32, f3: u32, rd: u32, op: u32) -> u32 {
    (f7 << 25) | (rhs << 20) | (lhs << 15) | (f3 << 12) | (rd << 7) | op
}
fn store(offset: i32, value: u32, base: u32) -> u32 {
    store_sized(offset, value, base, 3)
}
fn store_sized(offset: i32, value: u32, base: u32, f3: u32) -> u32 {
    let n = offset as u32 & 4095;
    ((n >> 5) << 25) | (value << 20) | (base << 15) | (f3 << 12) | ((n & 31) << 7) | 0x23
}
fn branch(offset: i32, rhs: u32, lhs: u32, f3: u32) -> u32 {
    let n = offset as u32;
    ((n >> 12 & 1) << 31)
        | ((n >> 5 & 63) << 25)
        | (rhs << 20)
        | (lhs << 15)
        | (f3 << 12)
        | ((n >> 1 & 15) << 8)
        | ((n >> 11 & 1) << 7)
        | 0x63
}
fn jump(offset: i32) -> u32 {
    let n = offset as u32;
    ((n >> 20 & 1) << 31) | ((n >> 1 & 1023) << 21) | ((n >> 11 & 1) << 20) | (n & 0xff000) | 0x6f
}

struct Emitter {
    code: Code,
    fixups: Vec<(usize, usize)>,
    exits: Vec<usize>,
    cached: Vec<Slot>,
    uses: Vec<u32>,
    slots: usize,
    constants: usize,
    limit: usize,
}
impl Emitter {
    fn emit(&mut self, word: u32) -> Result<(), CompileError> {
        if self.code.words.len() >= self.limit {
            return Err(CompileError::Limit);
        }
        self.code.words.push(word);
        Ok(())
    }
    fn imm(&mut self, reg: u32, value: i32) -> Result<(), CompileError> {
        if (-2048..2048).contains(&value) {
            return self.emit(i(value, ZERO, 0, reg, 0x13));
        }
        let hi = (i64::from(value) + 2048) >> 12;
        self.emit(((hi as u32 & 0xfffff) << 12) | (reg << 7) | 0x37)?;
        self.emit(i(value.wrapping_sub((hi << 12) as i32), reg, 0, reg, 0x1b))
    }
    fn slot_address(&mut self, slot: Slot, write: bool) -> Result<(u32, i32), CompileError> {
        let n = i32::from(i16::from(slot));
        if n < -(self.constants as i32) || n >= self.slots as i32 || (write && n < 0) {
            return Err(CompileError::Slot);
        }
        let offset = n * 8;
        if (-2048..2048).contains(&offset) {
            return Ok((SLOTS, offset));
        }
        self.imm(T2, offset)?;
        self.emit(r(0, T2, SLOTS, 0, T2, 0x33))?;
        Ok((T2, 0))
    }
    fn load(&mut self, slot: Slot, reg: u32, word: bool) -> Result<(), CompileError> {
        if let Some(count) = self.uses.get_mut(i16::from(slot) as usize) {
            *count += 1;
        }
        if let Some(index) = self.cached.iter().position(|&value| value == slot) {
            return self.emit(i(
                0,
                FRAME_REGS[index],
                0,
                reg,
                if word { 0x1b } else { 0x13 },
            ));
        }
        let (base, offset) = self.slot_address(slot, false)?;
        self.emit(i(offset, base, if word { 2 } else { 3 }, reg, 3))
    }
    fn save(&mut self, slot: Slot, word: bool) -> Result<(), CompileError> {
        // Wasmi represents i32 writes as zero-extended u64 values.
        if word {
            self.emit(i(32, T0, 1, T0, 0x13))?;
            self.emit(i(32, T0, 5, T0, 0x13))?;
        }
        if let Some(count) = self.uses.get_mut(i16::from(slot) as usize) {
            *count += 1;
        }
        if let Some(index) = self.cached.iter().position(|&value| value == slot) {
            return self.emit(i(0, T0, 0, FRAME_REGS[index], 0x13));
        }
        let (base, offset) = self.slot_address(slot, true)?;
        self.emit(store(offset, T0, base))
    }
    fn exit(&mut self, pc: usize, reason: i32) -> Result<(), CompileError> {
        self.imm(T0, pc as i32)?;
        self.emit(store(32, T0, CTX))?;
        self.imm(T0, reason)?;
        self.emit(store(40, T0, CTX))?;
        self.exits.push(self.code.words.len());
        self.emit(0)
    }
    fn memory_guard(&mut self, pc: usize, lhs: u32, rhs: u32) -> Result<(), CompileError> {
        let at = self.code.words.len();
        self.emit(0)?;
        self.exit(pc, 2)?;
        self.code.words[at] = branch(((self.code.words.len() - at) * 4) as i32, rhs, lhs, 7);
        Ok(())
    }
    /// T0 becomes a host pointer only after the entire guest access is checked.
    fn memory_address(
        &mut self,
        pc: usize,
        ptr: Slot,
        offset: wasmi_ir::Offset16,
        width: usize,
    ) -> Result<(), CompileError> {
        self.load(ptr, T0, false)?;
        // Check the exclusive end in two comparisons. Since offset is u16
        // and width is at most eight, their sum cannot overflow. An end below
        // that sum means pointer addition wrapped; end <= len then proves the
        // entire nonempty range, including zero-length memories, is valid.
        let end_offset = u64::from(wasmi_ir::Offset64::from(offset)) + width as u64;
        self.imm(T2, end_offset as i32)?;
        self.emit(r(0, T2, T0, 0, T0, 0x33))?;
        self.memory_guard(pc, T0, T2)?;
        self.memory_guard(pc, MEMORY_LEN, T0)?;
        self.emit(i(-(width as i32), T0, 0, T0, 0x13))?;
        self.emit(r(0, MEMORY, T0, 0, T0, 0x33))
    }
    fn memory_load(
        &mut self,
        pc: usize,
        result: Slot,
        ptr: Slot,
        offset: wasmi_ir::Offset16,
        width: usize,
        signed: bool,
        word: bool,
    ) -> Result<(), CompileError> {
        self.memory_address(pc, ptr, offset, width)?;
        // Test the actual host address: the embedding need not align memory.
        // Bounds were checked before either path can touch guest memory.
        let aligned = if width > 1 {
            self.emit(i((width - 1) as i32, T0, 7, T2, 0x13))?;
            let branch_at = self.code.words.len();
            self.emit(0)?;
            let f3 = match (width, signed) {
                (2, true) => 1,
                (2, false) => 5,
                (4, true) => 2,
                (4, false) => 6,
                (8, _) => 3,
                _ => unreachable!(),
            };
            self.emit(i(0, T0, f3, T1, 3))?;
            let done = self.code.words.len();
            self.emit(0)?;
            self.code.words[branch_at] = branch(
                ((self.code.words.len() - branch_at) * 4) as i32,
                ZERO,
                T2,
                1,
            );
            Some(done)
        } else {
            None
        };
        self.imm(T1, 0)?;
        // Byte accesses do not assume hardware support for misaligned loads.
        for byte in 0..width {
            self.emit(i(
                byte as i32,
                T0,
                if signed && byte + 1 == width { 0 } else { 4 },
                T2,
                3,
            ))?;
            if byte > 0 {
                self.emit(i((byte * 8) as i32, T2, 1, T2, 0x13))?;
            }
            self.emit(r(0, T2, T1, 6, T1, 0x33))?;
        }
        if let Some(done) = aligned {
            self.code.words[done] = jump(((self.code.words.len() - done) * 4) as i32);
        }
        self.emit(i(0, T1, 0, T0, 0x13))?;
        self.save(result, word)
    }
    fn memory_store(
        &mut self,
        pc: usize,
        ptr: Slot,
        offset: wasmi_ir::Offset16,
        value: Slot,
        width: usize,
    ) -> Result<(), CompileError> {
        self.memory_address(pc, ptr, offset, width)?;
        self.load(value, T1, false)?;
        let aligned = if width > 1 {
            self.emit(i((width - 1) as i32, T0, 7, T2, 0x13))?;
            let branch_at = self.code.words.len();
            self.emit(0)?;
            self.emit(store_sized(0, T1, T0, width.trailing_zeros()))?;
            let done = self.code.words.len();
            self.emit(0)?;
            self.code.words[branch_at] = branch(
                ((self.code.words.len() - branch_at) * 4) as i32,
                ZERO,
                T2,
                1,
            );
            Some(done)
        } else {
            None
        };
        // All bounds are checked before the first byte becomes observable.
        for byte in 0..width {
            self.emit(store_sized(byte as i32, T1, T0, 0))?;
            if byte + 1 < width {
                self.emit(i(8, T1, 5, T1, 0x13))?;
            }
        }
        if let Some(done) = aligned {
            self.code.words[done] = jump(((self.code.words.len() - done) * 4) as i32);
        }
        Ok(())
    }
    fn target(&self, ops: &[Op], pc: usize, offset: i32) -> Result<Option<usize>, CompileError> {
        let target = (pc as i64) + i64::from(offset);
        if target < 0 || target >= ops.len() as i64 {
            return Err(CompileError::Branch);
        }
        // Until CFG verification is integrated, backward native branches must
        // land directly on a positive fuel check. Other branches fall back.
        if target <= pc as i64
            && !matches!(ops[target as usize], Op::ConsumeFuel { block_fuel } if block_fuel.to_u64() > 0)
        {
            return Ok(None);
        }
        Ok(Some(target as usize))
    }
    fn jump_to(&mut self, target: usize) -> Result<(), CompileError> {
        self.fixups.push((self.code.words.len(), target));
        self.emit(0)
    }
}

/// Compile the exact validated IR and frame layout. Unsupported instructions
/// produce an exit to the interpreter at the same original instruction index.
/// `slots` excludes constants, which occupy negative frame indices.
/// The embedding must supply non-SIMD, eight-byte Wasmi slots and keep the
/// entire constant/local frame alive and immovable throughout the native call.
pub fn compile(
    ops: &[Op],
    slots: u16,
    constants: u16,
    max_words: usize,
) -> Result<Code, CompileError> {
    let (fallback, uses) = compile_impl(ops, slots, constants, max_words, &[])?;
    let mut ranked: Vec<_> = uses
        .into_iter()
        .enumerate()
        .filter(|(_, count)| *count > 0)
        .collect();
    ranked.sort_unstable_by_key(|&(slot, count)| (core::cmp::Reverse(count), slot));
    let cached: Vec<_> = ranked
        .into_iter()
        .take(FRAME_REGS.len())
        .map(|(slot, _)| Slot::from(slot as i16))
        .collect();
    if cached.is_empty() {
        return Ok(fallback);
    }
    // Preserve bounded interpretation fallback when the cached variant does
    // not fit the caller's code budget.
    match compile_impl(ops, slots, constants, max_words, &cached) {
        Ok((code, _)) => Ok(code),
        Err(CompileError::Limit) => Ok(fallback),
        Err(error) => Err(error),
    }
}

fn compile_impl(
    ops: &[Op],
    slots: u16,
    constants: u16,
    max_words: usize,
    cached: &[Slot],
) -> Result<(Code, Vec<u32>), CompileError> {
    if ops.is_empty() {
        return Err(CompileError::Empty);
    }
    // Bound work and ensure all local JAL relocations fit their signed range.
    if ops.len() > 32768 || slots > 32768 || constants > 32768 || max_words > 131072 {
        return Err(CompileError::Limit);
    }
    let mut e = Emitter {
        code: Code {
            words: Vec::new(),
            entries: Vec::new(),
            lowered: 0,
            supported: Vec::new(),
        },
        fixups: Vec::new(),
        exits: Vec::new(),
        cached: cached.to_vec(),
        uses: if cached.is_empty() {
            alloc::vec![0; slots as usize]
        } else {
            Vec::new()
        },
        slots: slots as usize,
        constants: constants as usize,
        limit: max_words,
    };
    e.emit(i(0, CTX, 3, SLOTS, 3))?;
    e.emit(i(8, CTX, 3, MEMORY, 3))?;
    e.emit(i(16, CTX, 3, MEMORY_LEN, 3))?;
    e.emit(i(24, CTX, 3, FUEL, 3))?;
    for (index, &slot) in cached.iter().enumerate() {
        let (base, offset) = e.slot_address(slot, false)?;
        e.emit(i(offset, base, 3, FRAME_REGS[index], 3))?;
    }
    e.emit(i(0, ENTRY, 0, ZERO, 0x67))?;
    for (pc, op) in ops.iter().enumerate() {
        e.code.entries.push(e.code.words.len());
        e.code.supported.push(false);
        match *op {
            Op::Load32Offset16 {
                result,
                ptr,
                offset,
            }
            | Op::Load64Offset16 {
                result,
                ptr,
                offset,
            }
            | Op::I32Load8sOffset16 {
                result,
                ptr,
                offset,
            }
            | Op::I32Load8uOffset16 {
                result,
                ptr,
                offset,
            }
            | Op::I32Load16sOffset16 {
                result,
                ptr,
                offset,
            }
            | Op::I32Load16uOffset16 {
                result,
                ptr,
                offset,
            }
            | Op::I64Load8sOffset16 {
                result,
                ptr,
                offset,
            }
            | Op::I64Load8uOffset16 {
                result,
                ptr,
                offset,
            }
            | Op::I64Load16sOffset16 {
                result,
                ptr,
                offset,
            }
            | Op::I64Load16uOffset16 {
                result,
                ptr,
                offset,
            }
            | Op::I64Load32sOffset16 {
                result,
                ptr,
                offset,
            }
            | Op::I64Load32uOffset16 {
                result,
                ptr,
                offset,
            } => {
                let (width, signed, word) = match op {
                    Op::Load32Offset16 { .. } => (4, false, true),
                    Op::Load64Offset16 { .. } => (8, false, false),
                    Op::I32Load8sOffset16 { .. } => (1, true, true),
                    Op::I32Load8uOffset16 { .. } => (1, false, true),
                    Op::I32Load16sOffset16 { .. } => (2, true, true),
                    Op::I32Load16uOffset16 { .. } => (2, false, true),
                    Op::I64Load8sOffset16 { .. } => (1, true, false),
                    Op::I64Load8uOffset16 { .. } => (1, false, false),
                    Op::I64Load16sOffset16 { .. } => (2, true, false),
                    Op::I64Load16uOffset16 { .. } => (2, false, false),
                    Op::I64Load32sOffset16 { .. } => (4, true, false),
                    _ => (4, false, false),
                };
                e.memory_load(pc, result, ptr, offset, width, signed, word)?;
            }
            Op::Store32Offset16 { ptr, offset, value }
            | Op::Store64Offset16 { ptr, offset, value }
            | Op::I32Store8Offset16 { ptr, offset, value }
            | Op::I32Store16Offset16 { ptr, offset, value }
            | Op::I64Store8Offset16 { ptr, offset, value }
            | Op::I64Store16Offset16 { ptr, offset, value }
            | Op::I64Store32Offset16 { ptr, offset, value } => {
                let width = match op {
                    Op::Store64Offset16 { .. } => 8,
                    Op::I32Store8Offset16 { .. } | Op::I64Store8Offset16 { .. } => 1,
                    Op::I32Store16Offset16 { .. } | Op::I64Store16Offset16 { .. } => 2,
                    _ => 4,
                };
                e.memory_store(pc, ptr, offset, value, width)?;
            }
            Op::ConsumeFuel { block_fuel } => {
                // Cost is u32, whereas LUI/ADDIW create a signed value.
                e.imm(T0, block_fuel.to_u64() as i32)?;
                e.emit(i(32, T0, 1, T0, 0x13))?;
                e.emit(i(32, T0, 5, T0, 0x13))?;
                let skip = e.code.words.len();
                e.emit(0)?;
                e.exit(pc, 1)?;
                e.code.words[skip] = branch(((e.code.words.len() - skip) * 4) as i32, T0, FUEL, 7);
                // exit's temporary writes only execute on the return path.
                e.emit(r(0x20, T0, FUEL, 0, FUEL, 0x33))?;
            }
            Op::BranchTable0 { index, len_targets } => {
                let count = len_targets as usize;
                if count == 0 || count >= ops.len() - pc {
                    return Err(CompileError::Branch);
                }
                e.load(index, T0, true)?;
                // Equality tests naturally send all out-of-range u32 indices
                // to the last (default) target, including sign-extended values.
                for target in 0..count - 1 {
                    e.imm(T1, target as i32)?;
                    e.emit(branch(8, T1, T0, 1))?;
                    e.jump_to(pc + 1 + target)?;
                }
                e.jump_to(pc + count)?;
            }
            Op::SelectI32EqImm16 { result, lhs, rhs } => {
                let Some(Op::Slot2 { slots: [yes, no] }) = ops.get(pc + 1) else {
                    return Err(CompileError::Branch);
                };
                if pc + 2 >= ops.len() {
                    return Err(CompileError::Branch);
                }
                e.load(lhs, T0, true)?;
                e.imm(T1, i32::from(rhs))?;
                let otherwise = e.code.words.len();
                e.emit(0)?;
                e.load(*yes, T0, false)?;
                e.save(result, false)?;
                e.jump_to(pc + 2)?;
                e.code.words[otherwise] =
                    branch(((e.code.words.len() - otherwise) * 4) as i32, T1, T0, 1);
                e.load(*no, T0, false)?;
                e.save(result, false)?;
                e.jump_to(pc + 2)?;
            }
            Op::CopyImm32 { result, value } => {
                e.imm(T0, u32::from(value) as i32)?;
                e.save(result, true)?;
            }
            Op::I32ShlBy { result, lhs, rhs }
            | Op::I32ShrUBy { result, lhs, rhs }
            | Op::I32ShrSBy { result, lhs, rhs } => {
                e.load(lhs, T0, true)?;
                let shift = i32::from(rhs);
                let (f3, upper) = match op {
                    Op::I32ShlBy { .. } => (1, 0),
                    Op::I32ShrSBy { .. } => (5, 0x400),
                    _ => (5, 0),
                };
                e.emit(i(shift | upper, T0, f3, T0, 0x1b))?;
                e.save(result, true)?;
            }
            Op::I32LtS { result, lhs, rhs } | Op::I32LtU { result, lhs, rhs } => {
                e.load(lhs, T0, true)?;
                e.load(rhs, T1, true)?;
                e.emit(r(
                    0,
                    T1,
                    T0,
                    if matches!(op, Op::I32LtS { .. }) {
                        2
                    } else {
                        3
                    },
                    T0,
                    0x33,
                ))?;
                e.save(result, true)?;
            }
            Op::I32Extend16S { result, input } => {
                e.load(input, T0, true)?;
                e.emit(i(48, T0, 1, T0, 0x13))?;
                e.emit(i(0x400 | 48, T0, 5, T0, 0x13))?;
                e.save(result, true)?;
            }
            Op::BranchI32Eq { lhs, rhs, offset }
            | Op::BranchI32Ne { lhs, rhs, offset }
            | Op::BranchI32LtS { lhs, rhs, offset }
            | Op::BranchI32LeS { lhs, rhs, offset }
            | Op::BranchI32LtU { lhs, rhs, offset }
            | Op::BranchI32LeU { lhs, rhs, offset } => {
                if let Some(target) = e.target(ops, pc, i32::from(offset.to_i16()))? {
                    e.load(lhs, T0, true)?;
                    e.load(rhs, T1, true)?;
                    let (f3, left, right) = match op {
                        Op::BranchI32Eq { .. } => (1, T0, T1),
                        Op::BranchI32Ne { .. } => (0, T0, T1),
                        Op::BranchI32LtS { .. } => (5, T0, T1),
                        Op::BranchI32LeS { .. } => (4, T1, T0),
                        Op::BranchI32LtU { .. } => (7, T0, T1),
                        _ => (6, T1, T0),
                    };
                    e.emit(branch(8, right, left, f3))?;
                    e.jump_to(target)?;
                } else {
                    e.exit(pc, 0)?;
                    continue;
                }
            }
            Op::BranchI32LtUImm16Rhs { lhs, rhs, offset }
            | Op::BranchI32LeUImm16Rhs { lhs, rhs, offset } => {
                if let Some(target) = e.target(ops, pc, i32::from(offset.to_i16()))? {
                    e.load(lhs, T0, true)?;
                    e.imm(T1, u32::from(rhs) as i32)?;
                    if matches!(op, Op::BranchI32LtUImm16Rhs { .. }) {
                        e.emit(branch(8, T1, T0, 7))?;
                    } else {
                        e.emit(branch(8, T0, T1, 6))?;
                    }
                    e.jump_to(target)?;
                } else {
                    e.exit(pc, 0)?;
                    continue;
                }
            }
            Op::BranchI32LtSImm16Rhs { lhs, rhs, offset }
            | Op::BranchI32LeSImm16Rhs { lhs, rhs, offset } => {
                if let Some(target) = e.target(ops, pc, i32::from(offset.to_i16()))? {
                    e.load(lhs, T0, true)?;
                    e.imm(T1, i32::from(rhs))?;
                    if matches!(op, Op::BranchI32LtSImm16Rhs { .. }) {
                        e.emit(branch(8, T1, T0, 5))?;
                    } else {
                        e.emit(branch(8, T0, T1, 4))?;
                    }
                    e.jump_to(target)?;
                } else {
                    e.exit(pc, 0)?;
                    continue;
                }
            }
            Op::BranchI32LtSImm16Lhs { lhs, rhs, offset }
            | Op::BranchI32LeSImm16Lhs { lhs, rhs, offset } => {
                if let Some(target) = e.target(ops, pc, i32::from(offset.to_i16()))? {
                    e.imm(T0, i32::from(lhs))?;
                    e.load(rhs, T1, true)?;
                    if matches!(op, Op::BranchI32LtSImm16Lhs { .. }) {
                        e.emit(branch(8, T1, T0, 5))?;
                    } else {
                        e.emit(branch(8, T0, T1, 4))?;
                    }
                    e.jump_to(target)?;
                } else {
                    e.exit(pc, 0)?;
                    continue;
                }
            }
            Op::BranchI32LtUImm16Lhs { lhs, rhs, offset }
            | Op::BranchI32LeUImm16Lhs { lhs, rhs, offset } => {
                if let Some(target) = e.target(ops, pc, i32::from(offset.to_i16()))? {
                    e.imm(T0, u32::from(lhs) as i32)?;
                    e.load(rhs, T1, true)?;
                    if matches!(op, Op::BranchI32LtUImm16Lhs { .. }) {
                        e.emit(branch(8, T1, T0, 7))?;
                    } else {
                        e.emit(branch(8, T0, T1, 6))?;
                    }
                    e.jump_to(target)?;
                } else {
                    e.exit(pc, 0)?;
                    continue;
                }
            }
            Op::Copy2 { results, values } => {
                // Read both values before either result, including swapped or
                // overlapping frame slots. T1 survives save's T2 scratch use.
                e.load(values[1], T1, false)?;
                e.load(values[0], T0, false)?;
                let result = results.span().head();
                e.save(result, false)?;
                e.emit(i(0, T1, 0, T0, 0x13))?;
                e.save(result.next(), false)?;
            }
            Op::Copy { result, value } => {
                e.load(value, T0, false)?;
                e.save(result, false)?;
            }
            Op::I32Add { result, lhs, rhs }
            | Op::I32Sub { result, lhs, rhs }
            | Op::I32Mul { result, lhs, rhs }
            | Op::I32BitAnd { result, lhs, rhs }
            | Op::I32BitOr { result, lhs, rhs }
            | Op::I32BitXor { result, lhs, rhs } => {
                e.load(lhs, T0, true)?;
                e.load(rhs, T1, true)?;
                let (f7, f3, opcode) = match op {
                    Op::I32Sub { .. } => (32, 0, 0x3b),
                    Op::I32Mul { .. } => (1, 0, 0x3b),
                    Op::I32BitAnd { .. } => (0, 7, 0x33),
                    Op::I32BitOr { .. } => (0, 6, 0x33),
                    Op::I32BitXor { .. } => (0, 4, 0x33),
                    _ => (0, 0, 0x3b),
                };
                e.emit(r(f7, T1, T0, f3, T0, opcode))?;
                e.save(result, true)?;
            }
            Op::I32AddImm16 { result, lhs, rhs }
            | Op::I32MulImm16 { result, lhs, rhs }
            | Op::I32BitAndImm16 { result, lhs, rhs }
            | Op::I32BitOrImm16 { result, lhs, rhs }
            | Op::I32BitXorImm16 { result, lhs, rhs } => {
                e.load(lhs, T0, true)?;
                e.imm(T1, i32::from(rhs))?;
                let (f7, f3, opcode) = match op {
                    Op::I32MulImm16 { .. } => (1, 0, 0x3b),
                    Op::I32BitAndImm16 { .. } => (0, 7, 0x33),
                    Op::I32BitOrImm16 { .. } => (0, 6, 0x33),
                    Op::I32BitXorImm16 { .. } => (0, 4, 0x33),
                    _ => (0, 0, 0x3b),
                };
                e.emit(r(f7, T1, T0, f3, T0, opcode))?;
                e.save(result, true)?;
            }
            Op::Branch { offset } => {
                if let Some(target) = e.target(ops, pc, offset.to_i32())? {
                    e.jump_to(target)?;
                } else {
                    e.exit(pc, 0)?;
                    continue;
                }
            }
            Op::BranchI32EqImm16 { lhs, rhs, offset }
            | Op::BranchI32NeImm16 { lhs, rhs, offset } => {
                if let Some(target) = e.target(ops, pc, i32::from(offset.to_i16()))? {
                    e.load(lhs, T0, true)?;
                    e.imm(T1, i32::from(rhs))?;
                    e.emit(branch(
                        8,
                        T1,
                        T0,
                        if matches!(op, Op::BranchI32EqImm16 { .. }) {
                            1
                        } else {
                            0
                        },
                    ))?;
                    e.jump_to(target)?;
                } else {
                    e.exit(pc, 0)?;
                    continue;
                }
            }
            _ => {
                e.exit(pc, 0)?;
                continue;
            }
        }
        e.code.lowered += 1;
        e.code.supported[pc] = true;
    }
    // Valid Wasmi functions terminate, but do not allow a malformed caller's
    // final fallthrough to execute beyond the emitted buffer.
    e.exit(ops.len(), 0)?;
    let epilogue = e.code.words.len();
    for (index, &slot) in cached.iter().enumerate() {
        let (base, offset) = e.slot_address(slot, true)?;
        e.emit(store(offset, FRAME_REGS[index], base))?;
    }
    e.emit(store(24, FUEL, CTX))?;
    e.emit(i(0, RA, 0, ZERO, 0x67))?;
    for &at in &e.exits {
        e.code.words[at] = jump(((epilogue - at) * 4) as i32);
    }
    for &(at, target) in &e.fixups {
        let offset = (e.code.entries[target] as i64 - at as i64) * 4;
        if !(-1048576..1048576).contains(&offset) {
            return Err(CompileError::Limit);
        }
        e.code.words[at] = jump(offset as i32);
    }
    Ok((e.code, e.uses))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_block_eliminates_repeated_frame_memory_accesses() {
        let mut ops = alloc::vec![Op::consume_fuel(10u32)];
        for _ in 0..20 {
            ops.push(Op::copy(Slot::from(1i16), Slot::from(0i16)));
            ops.push(Op::copy(Slot::from(0i16), Slot::from(1i16)));
        }
        ops.push(Op::Return);
        let (uncached, _) = compile_impl(&ops, 2, 0, 4096, &[]).unwrap();
        let cached = compile(&ops, 2, 0, 4096).unwrap();
        let frame_accesses = |code: &Code| {
            code.words
                .iter()
                .filter(|&&word| matches!(word & 0x7f, 3 | 0x23) && (word >> 15 & 31) == SLOTS)
                .count()
        };
        assert_eq!(frame_accesses(&uncached), 80);
        assert_eq!(frame_accesses(&cached), 4); // two entry loads + two exit stores
                                                // An optimization fallback must still respect every caller budget.
        for budget in 1..cached.words.len() {
            if let Ok(code) = compile(&ops, 2, 0, budget) {
                assert!(code.words.len() <= budget);
            }
        }
    }
}
