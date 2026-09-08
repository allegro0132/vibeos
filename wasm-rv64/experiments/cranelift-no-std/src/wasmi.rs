//! Bounded first lowering of validated Wasmi IR. Not a kernel backend yet.
use alloc::vec::Vec;
use cranelift_codegen::{
    ir::{
        condcodes::IntCC,
        types::{I32, I64},
        AbiParam, InstBuilder, MemFlagsData, Signature, UserFuncName,
    },
    isa::CallConv,
    Context,
};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use vibeos_wasm_rv64::{Op, Slot};

/// Entry ABI: `(Context*, original_instruction_index)`. The existing six-word
/// context is written back before every exit; its frame is exclusively borrowed.
/// Constants and larger functions deliberately await later lowering work.
pub fn compile(ops: &[Op], slots: u16) -> Result<Vec<u8>, &'static str> {
    if ops.len() > 256 || slots > 16 {
        return Err("prototype structural limit");
    }
    let reference =
        vibeos_wasm_rv64::compile(ops, slots, 0, 131072).map_err(|_| "invalid input")?;
    let isa = crate::riscv64_backend();
    let mut context = Context::new();
    context.func.name = UserFuncName::testcase("wasmi_integer");
    context.func.signature = Signature::new(CallConv::SystemV);
    context
        .func
        .signature
        .params
        .extend([AbiParam::new(I64), AbiParam::new(I64)]);
    let mut frontend = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut context.func, &mut frontend);
        let entry = b.create_block();
        let exit = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.append_block_param(exit, I64);
        b.append_block_param(exit, I64);
        let blocks: Vec<_> = (0..ops.len() + 1).map(|_| b.create_block()).collect();
        let vars: Vec<_> = (0..slots).map(|_| b.declare_var(I64)).collect();
        let fuel = b.declare_var(I64);
        b.switch_to_block(entry);
        let ctx = b.block_params(entry)[0];
        let resume = b.block_params(entry)[1];
        let flags = MemFlagsData::trusted();
        let frame = b.ins().load(I64, flags, ctx, 0);
        let initial = b.ins().load(I64, flags, ctx, 24);
        b.def_var(fuel, initial);
        for (n, &var) in vars.iter().enumerate() {
            let value = b.ins().load(I64, flags, frame, (n * 8) as i32);
            b.def_var(var, value);
        }
        // A branch chain avoids generated jump-table reads from execute-only pages.
        for (pc, &block) in blocks.iter().take(ops.len()).enumerate() {
            let next = b.create_block();
            let test = b.ins().icmp_imm_s(IntCC::Equal, resume, pc as i64);
            b.ins().brif(test, block, &[], next, &[]);
            b.switch_to_block(next);
        }
        b.ins().jump(blocks[ops.len()], &[]);
        let get = |slot: Slot| -> Result<usize, &'static str> {
            let n = i16::from(slot);
            if n < 0 || n >= slots as i16 {
                Err("frame slot")
            } else {
                Ok(n as usize)
            }
        };
        for (pc, op) in ops.iter().enumerate() {
            b.switch_to_block(blocks[pc]);
            let exit_to = |b: &mut FunctionBuilder<'_>, reason: i64| {
                let p = b.ins().iconst(I64, pc as i64);
                let r = b.ins().iconst(I64, reason);
                b.ins().jump(exit, &[p.into(), r.into()]);
            };
            match *op {
                Op::ConsumeFuel { block_fuel } if block_fuel.to_u64() <= i32::MAX as u64 => {
                    let next = b.create_block();
                    let out = b.create_block();
                    let available = b.use_var(fuel);
                    let enough = b.ins().icmp_imm_u(
                        IntCC::UnsignedGreaterThanOrEqual,
                        available,
                        block_fuel.to_u64() as i64,
                    );
                    b.ins().brif(enough, next, &[], out, &[]);
                    b.switch_to_block(out);
                    exit_to(&mut b, 1);
                    b.switch_to_block(next);
                    let left = b.ins().iadd_imm_s(available, -(block_fuel.to_u64() as i64));
                    b.def_var(fuel, left);
                    b.ins().jump(blocks[pc + 1], &[]);
                }
                Op::Copy { result, value } => {
                    let v = b.use_var(vars[get(value)?]);
                    b.def_var(vars[get(result)?], v);
                    b.ins().jump(blocks[pc + 1], &[]);
                }
                Op::CopyImm32 { result, value } if u32::from(value) <= i32::MAX as u32 => {
                    let v = b.ins().iconst(I64, u32::from(value) as i64);
                    b.def_var(vars[get(result)?], v);
                    b.ins().jump(blocks[pc + 1], &[]);
                }
                Op::I32Add { result, lhs, rhs }
                | Op::I32Sub { result, lhs, rhs }
                | Op::I32Mul { result, lhs, rhs }
                | Op::I32BitXor { result, lhs, rhs } => {
                    let lhs = b.use_var(vars[get(lhs)?]);
                    let rhs = b.use_var(vars[get(rhs)?]);
                    let lhs = b.ins().ireduce(I32, lhs);
                    let rhs = b.ins().ireduce(I32, rhs);
                    let v = match op {
                        Op::I32Add { .. } => b.ins().iadd(lhs, rhs),
                        Op::I32Sub { .. } => b.ins().isub(lhs, rhs),
                        Op::I32Mul { .. } => b.ins().imul(lhs, rhs),
                        _ => b.ins().bxor(lhs, rhs),
                    };
                    let v = b.ins().uextend(I64, v);
                    b.def_var(vars[get(result)?], v);
                    b.ins().jump(blocks[pc + 1], &[]);
                }
                Op::Branch { offset } if reference.supported[pc] => {
                    let target = (pc as i64 + offset.to_i32() as i64) as usize;
                    b.ins().jump(blocks[target], &[]);
                }
                Op::BranchI32NeImm16 { lhs, rhs, offset } if reference.supported[pc] => {
                    let value = b.use_var(vars[get(lhs)?]);
                    let value = b.ins().ireduce(I32, value);
                    let different =
                        b.ins()
                            .icmp_imm_s(IntCC::NotEqual, value, i32::from(rhs) as i64);
                    let target = (pc as i64 + offset.to_i16() as i64) as usize;
                    b.ins()
                        .brif(different, blocks[target], &[], blocks[pc + 1], &[]);
                }
                _ => exit_to(&mut b, 0),
            }
        }
        b.switch_to_block(blocks[ops.len()]);
        let invalid = b.ins().iconst(I64, ops.len() as i64);
        let reason = b.ins().iconst(I64, 0);
        b.ins().jump(exit, &[invalid.into(), reason.into()]);
        b.switch_to_block(exit);
        for (n, &var) in vars.iter().enumerate() {
            let value = b.use_var(var);
            b.ins().store(flags, value, frame, (n * 8) as i32);
        }
        let left = b.use_var(fuel);
        b.ins().store(flags, left, ctx, 24);
        let p = b.block_params(exit)[0];
        let r = b.block_params(exit)[1];
        b.ins().store(flags, p, ctx, 32);
        b.ins().store(flags, r, ctx, 40);
        b.ins().return_(&[]);
        b.seal_all_blocks();
        b.finalize(isa.frontend_config());
    }
    let code = context
        .compile(isa.as_ref(), &mut Default::default())
        .map_err(|_| "code generation")?;
    if !code.buffer.relocs().is_empty()
        || !code.buffer.traps().is_empty()
        || code.code_buffer().len() > 65536
    {
        return Err("prototype code boundary");
    }
    Ok(code.code_buffer().to_vec())
}
