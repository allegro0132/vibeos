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
pub mod image;
pub mod lex;
pub mod parse;
pub mod types;

pub mod samples;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub use image::{
    ImageMetadata, RelocatableImage, Relocation, RelocationKind, RelocationTarget,
    RuntimeBinding, RuntimeImport, COMPILER_ABI_VERSION, IMAGE_FORMAT_VERSION,
    IMAGE_HEADER_LEN, IMAGE_MAGIC, MAX_ENCODED_IMAGE_BYTES, RUNTIME_ABI_VERSION,
    TARGET_ABI_RV64IM_LP64_V1,
};

/// Everything a compiled program needs in memory before it can run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    /// String literals. Generated code holds absolute pointers into this, so it
    /// must outlive execution.
    pub data: Vec<u8>,
    pub code: Vec<u32>,
    pub funcs: usize,
}

/// Addresses of the runtime hooks generated code is allowed to call. These are
/// the program's *entire* interface to the outside world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Runtime {
    pub print_str: u64,
    pub print_int: u64,
    /// Prints `true`/`false`, as Rust's `Display for bool` does.
    pub print_bool: u64,
    /// Called with an abort reason when an emitted safety check fails. Must not
    /// return; the kernel implements it as a longjmp out of the program.
    pub abort: u64,
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
    compile_relocatable(src)?.link_with_runtime(data_base, code_base, rt)
}

/// Compile a deterministic, address-independent executable suitable for
/// capability-addressed persistence.  Linking is a separate, checked step once
/// the loader knows the data/code addresses and runtime import table.
pub fn compile_relocatable(src: &str) -> Result<RelocatableImage, String> {
    let source_len = u32::try_from(src.len())
        .map_err(|_| "source length exceeds the executable ABI".to_string())?;
    let toks = lex::lex(src)?;
    let prog = parse::Parser::new(toks).program()?;
    // Validates, and annotates what code generation needs.
    let prog = types::check(&prog)?;

    let literals = codegen::collect_strings(&prog, "\n");
    let mut data = Vec::new();
    let mut str_offsets = alloc::collections::BTreeMap::new();
    for s in &literals {
        let offset = u64::try_from(data.len())
            .map_err(|_| "string table length exceeds the executable ABI".to_string())?;
        str_offsets.insert(s.clone(), offset);
        data.extend_from_slice(s.as_bytes());
    }

    let funcs = u32::try_from(prog.funcs.len())
        .map_err(|_| "function count exceeds the executable ABI".to_string())?;
    let (code_template, relocations) = codegen::compile_relocatable(&prog, str_offsets)?;
    RelocatableImage::from_parts(
        funcs,
        source_len,
        image::crc32c(src.as_bytes()),
        data,
        code_template,
        relocations,
    )
}

/// Measure how long the emitted code will be, without committing to an address.
///
/// Sound because instruction sizes never depend on addresses — see
/// `codegen::li64`, which is deliberately a fixed 11 instructions.
pub fn code_len(src: &str) -> Result<usize, String> {
    Ok(compile_relocatable(src)?.code_template().len())
}
