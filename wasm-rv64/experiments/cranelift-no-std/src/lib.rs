#![no_std]
extern crate alloc;
use alloc::vec::Vec;
use cranelift_codegen::{
    ir::{condcodes::IntCC, types::I64, AbiParam, InstBuilder, Signature, UserFuncName},
    isa::CallConv,
    settings::{self, Configurable},
    Context,
};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};

pub fn riscv64_backend() -> cranelift_codegen::isa::OwnedTargetIsa {
    let mut builder = cranelift_codegen::isa::lookup_by_name("riscv64").unwrap();
    // Upstream requires G at ISA construction, even for integer-only IR.
    // Generated code must therefore be audited before any IMAC integration.
    builder.set("has_zca", "false").unwrap();
    let mut flags = settings::builder();
    flags.set("opt_level", "speed").unwrap();
    flags.set("enable_probestack", "false").unwrap();
    builder.finish(settings::Flags::new(flags)).unwrap()
}

/// Pure integer loop, plus a wide constant to expose inline-pool requirements.
/// Returns code bytes. No code is executed here.
pub fn compile_probe(external_literal: bool) -> Vec<u8> {
    let isa = riscv64_backend();
    let mut context = Context::new();
    context.func.name = UserFuncName::testcase("integer_loop");
    context.func.signature = Signature::new(CallConv::SystemV);
    for _ in 0..if external_literal { 4 } else { 3 } {
        context.func.signature.params.push(AbiParam::new(I64));
    }
    context.func.signature.returns.push(AbiParam::new(I64));
    let mut frontend = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut context.func, &mut frontend);
        let entry = b.create_block();
        let header = b.create_block();
        let body = b.create_block();
        let done = b.create_block();
        b.append_block_params_for_function_params(entry);
        let x = b.declare_var(I64);
        let count = b.declare_var(I64);
        b.switch_to_block(entry);
        let args = b.block_params(entry).to_vec();
        b.def_var(x, args[0]);
        b.def_var(count, args[2]);
        b.ins().jump(header, &[]);
        b.switch_to_block(header);
        let n = b.use_var(count);
        let zero = b.ins().icmp_imm_s(IntCC::Equal, n, 0);
        b.ins().brif(zero, done, &[], body, &[]);
        b.switch_to_block(body);
        let v = b.use_var(x);
        let v = b.ins().imul_imm_s(v, 1664525);
        let v = b.ins().iadd_imm_s(v, 1013904223);
        let v = b.ins().bxor(v, args[1]);
        b.def_var(x, v);
        let n = b.ins().iadd_imm_s(n, -1);
        b.def_var(count, n);
        b.ins().jump(header, &[]);
        b.switch_to_block(done);
        let v = b.use_var(x);
        let wide = if external_literal {
            let flags = cranelift_codegen::ir::MemFlagsData::trusted().with_readonly();
            b.ins().load(I64, flags, args[3], 0)
        } else {
            b.ins().iconst(I64, 0xfedcba9876543210u64 as i64)
        };
        let v = b.ins().bxor(v, wide);
        b.ins().return_(&[v]);
        b.seal_all_blocks();
        b.finalize(isa.frontend_config());
    }
    let code = context
        .compile(isa.as_ref(), &mut Default::default())
        .unwrap();
    assert!(
        code.buffer.relocs().is_empty(),
        "probe must have no external relocations"
    );
    assert!(
        code.buffer.traps().is_empty(),
        "probe must not rely on hardware traps"
    );
    code.code_buffer().to_vec()
}

pub mod wasmi;
