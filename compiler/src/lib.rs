//! The VibeOS Rust-subset compiler: lexer, parser, and RV64 code generator.
//!
//! Deliberately free of any dependency on the kernel. It emits `Vec<u32>` and
//! knows nothing about how that gets executed, which is what lets the whole
//! front end and back end be tested on the host.
//!
//! This crate is security-critical. Generated code runs in the kernel's address
//! space with no MMU, so a wrong frame offset here is a privilege escalation,
//! not a wrong answer. Test it accordingly.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod ast;
pub mod codegen;
pub mod lex;
pub mod parse;

pub mod samples;

use alloc::string::String;
use alloc::vec::Vec;

/// Everything a compiled program needs in memory before it can run.
pub struct Image {
    /// String literals. Generated code holds absolute pointers into this, so it
    /// must outlive execution.
    pub data: Vec<u8>,
    pub code: Vec<u32>,
    pub funcs: usize,
}

/// Addresses of the runtime hooks generated code is allowed to call. These are
/// the program's *entire* interface to the outside world.
pub struct Runtime {
    pub print_str: u64,
    pub print_int: u64,
}

/// Compile source to machine code laid out for `code_base`.
///
/// `place_data` receives the assembled string table and returns the address it
/// will live at; the caller owns that buffer's lifetime.
pub fn compile_at(
    src: &str,
    data_base: u64,
    code_base: u64,
    rt: &Runtime,
) -> Result<Image, String> {
    let toks = lex::lex(src)?;
    let prog = parse::Parser::new(toks).program()?;

    let literals = codegen::collect_strings(&prog, "\n");
    let mut data = Vec::new();
    let mut str_addr = alloc::collections::BTreeMap::new();
    for s in &literals {
        str_addr.insert(s.clone(), data_base + data.len() as u64);
        data.extend_from_slice(s.as_bytes());
    }

    let rt = codegen::Runtime { print_str: rt.print_str, print_int: rt.print_int };
    let code = codegen::compile(&prog, code_base, str_addr, &rt)?;
    Ok(Image { data, code, funcs: prog.funcs.len() })
}

/// Measure how long the emitted code will be, without committing to an address.
///
/// Sound because instruction sizes never depend on addresses — see
/// `codegen::li64`, which is deliberately a fixed 11 instructions.
pub fn code_len(src: &str) -> Result<usize, String> {
    let rt = Runtime { print_str: 0, print_int: 0 };
    Ok(compile_at(src, 0, 0, &rt)?.code.len())
}
