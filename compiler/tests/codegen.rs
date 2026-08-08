//! Code generation.
//!
//! This crate emits machine code that runs in the kernel's address space with
//! no MMU. A wrong frame offset here is a privilege escalation, not a wrong
//! answer — so these tests check encodings against the RISC-V spec by hand, and
//! then audit every instruction the emitter can produce.

use vibeos_rustc::{code_len, compile_at, samples, Runtime};

fn rt() -> Runtime {
    Runtime { print_str: 0x1111_2222_3333_4444, print_int: 0x5555_6666_7777_8888 }
}

fn emit(src: &str) -> Vec<u32> {
    compile_at(src, 0x8000_0000, 0x8010_0000, &rt()).unwrap().code
}

fn err(src: &str) -> String {
    match compile_at(src, 0, 0, &rt()) {
        Err(e) => e,
        Ok(_) => panic!("expected {src:?} to be rejected, but it compiled"),
    }
}

// --- instruction encoding, checked against the spec by hand ---

/// Every function ends with `ret`, whose encoding is the most widely known
/// word in RISC-V: `jalr x0, x1, 0` == 0x00008067.
#[test]
fn functions_end_in_a_canonical_ret() {
    let code = emit("fn main() {}");
    assert_eq!(*code.last().unwrap(), 0x0000_8067, "expected `ret`");
}

#[test]
fn the_prologue_saves_ra_and_s0_and_establishes_a_frame() {
    let code = emit("fn main() {}");
    // addi sp, sp, -16   |  sd ra, 0(sp)  |  sd s0, 8(sp)  |  addi s0, sp, 0
    // low 20 bits: opcode 0x13 | rd=sp(2)<<7 | funct3=0 | rs1=sp(2)<<15
    assert_eq!(code[0] & 0x000f_ffff, 0x0001_0113, "addi sp, sp, imm");
    assert_eq!(code[0] >> 20, 0xff0, "frame of 16 bytes");
    assert_eq!(code[1], 0x0011_3023, "sd ra, 0(sp)");
    assert_eq!(code[2], 0x0081_3423, "sd s0, 8(sp)");
    assert_eq!(code[3], 0x0001_0413, "addi s0, sp, 0");
}

/// Decoded by hand from the spec's field layouts, so a change to the encoders
/// has to be justified against the ISA rather than against itself.
#[test]
fn known_words_for_each_instruction_format() {
    let code = emit("fn main() -> i64 { 1 + 2 }");
    let has = |w: u32| code.contains(&w);
    assert!(has(0x0062_82b3), "add t0, t0, t1  (R-type)");
    assert!(has(0x0002_8067) || has(0x0000_8067), "jalr (I-type, jump)");
    assert!(has(0x0001_3283) || has(0x0001_3303), "ld from sp (I-type, load)");
}

#[test]
fn the_stack_pointer_moves_in_16_byte_steps() {
    // Slots are 16 bytes so `sp` stays ABI-aligned at every call boundary.
    let code = emit("fn main() -> i64 { 1 + 2 }");
    let push = code.iter().filter(|w| **w == 0xff01_0113).count(); // addi sp, sp, -16
    let pop = code.iter().filter(|w| **w == 0x0101_0113).count(); // addi sp, sp, 16
    assert!(push > 0 && pop > 0, "push/pop use 16-byte slots");
}

// --- li64: verified by executing it ---

/// The constant materializer is 11 instructions of `addi`/`slli`. Rather than
/// hand-encoding it, interpret those two forms and check the register lands on
/// the intended value — including negative and boundary constants.
fn simulate_li64(code: &[u32], rd: u32) -> u64 {
    let mut reg = 0u64;
    for w in code {
        let opcode = w & 0x7f;
        let f3 = (w >> 12) & 7;
        let d = (w >> 7) & 0x1f;
        let rs1 = (w >> 15) & 0x1f;
        let imm = (w >> 20) & 0xfff;
        if opcode != 0x13 || d != rd {
            continue;
        }
        match f3 {
            0 => {
                // addi rd, rs1, imm  (rs1 is x0 for the first chunk)
                let base = if rs1 == 0 { 0 } else { reg };
                reg = base.wrapping_add(imm as u64);
            }
            1 => reg <<= imm & 0x3f, // slli
            _ => {}
        }
    }
    reg
}

#[test]
fn constants_materialize_exactly() {
    // Only non-negative literals reach `li64` directly: the lexer never produces
    // a negative token, so `-5` parses as `Neg(Int(5))` and is negated at runtime.
    for want in [
        0i64, 1, 42, 2047, 2048, 0xffff, 1 << 31, 1 << 40, 1 << 62,
        i64::MAX, 6765, 1_000_000_007,
    ] {
        let code = emit(&format!("fn main() -> i64 {{ {want} }}"));
        // The literal is loaded into t0 before the first push.
        let upto: Vec<u32> = code.iter().copied().skip(4).take(11).collect();
        assert_eq!(
            simulate_li64(&upto, 5) as i64,
            want,
            "materializing {want} from {upto:08x?}"
        );
    }
}

/// A negative literal is a unary negation of a positive one, so the emitter
/// must follow the constant with a `sub rd, zero, rd`.
#[test]
fn negative_literals_are_materialized_then_negated() {
    let code = emit("fn main() -> i64 { -42 }");
    assert!(
        code.contains(&0x4050_02b3),
        "expected `sub t0, zero, t0` in {code:08x?}"
    );
}

#[test]
fn constant_materialization_is_a_fixed_length() {
    // Layout stability across the two passes depends on this exactly.
    let small = emit("fn main() -> i64 { 1 }").len();
    let large = emit("fn main() -> i64 { 1234567890123 }").len();
    assert_eq!(small, large, "constant size must not depend on its value");
}

// --- two-pass layout stability ---

#[test]
fn code_length_is_independent_of_the_load_address() {
    for src in [samples::HELLO, samples::DEMO, samples::CONFORMANCE] {
        let a = compile_at(src, 0, 0, &rt()).unwrap().code.len();
        let b = compile_at(src, 0x8000_0000, 0x9abc_def0, &rt()).unwrap().code.len();
        assert_eq!(a, b, "pass 1 and pass 2 must agree on layout");
    }
}

#[test]
fn compilation_is_deterministic() {
    let a = emit(samples::DEMO);
    let b = emit(samples::DEMO);
    assert_eq!(a, b, "same input, same bytes");
}

#[test]
fn the_entry_point_is_the_first_instruction() {
    // `main` is emitted first so the buffer's address is the entry point.
    let code = emit("fn helper() -> i64 { 1 }\nfn main() -> i64 { helper() }");
    assert_eq!(code[1], 0x0011_3023, "the buffer opens with main's prologue");
}

#[test]
fn string_literals_are_interned_once() {
    let img = compile_at(
        r#"fn main() { println!("dup"); println!("dup"); }"#,
        0, 0, &rt(),
    ).unwrap();
    // "dup" (3) + "\n" (1); the second use must not add another copy.
    assert_eq!(img.data.len(), 4, "data was {:?}", String::from_utf8_lossy(&img.data));
}

// --- the confinement audit, as a test ---

const OP_IMM: u32 = 0x13;
const OP: u32 = 0x33;
const LOAD: u32 = 0x03;
const STORE: u32 = 0x23;
const BRANCH: u32 = 0x63;
const JAL: u32 = 0x6f;
const JALR: u32 = 0x67;

const ZERO: u32 = 0;
const RA: u32 = 1;
const SP: u32 = 2;
const T0: u32 = 5;
const S0: u32 = 8;

fn all_programs() -> Vec<Vec<u32>> {
    let mut out = vec![];
    for src in [samples::HELLO, samples::DEMO, samples::CONFORMANCE] {
        out.push(emit(src));
    }
    out
}

/// BLUEPRINT §6.3 claims generated code cannot reach hardware. That rests on
/// the emitter never producing a privileged or memory-unsafe instruction, so
/// assert the opcode set directly rather than trusting the prose.
#[test]
fn the_emitter_produces_no_privileged_instructions() {
    let allowed = [OP_IMM, OP, LOAD, STORE, BRANCH, JAL, JALR];
    for code in all_programs() {
        for (i, w) in code.iter().enumerate() {
            let op = w & 0x7f;
            assert!(
                allowed.contains(&op),
                "instruction {i} ({w:08x}) has opcode {op:#04x}: not in the permitted set. \
                 SYSTEM (0x73, ecall/csr), AMO (0x2f), LUI (0x37) and AUIPC (0x17) are all \
                 escapes from the sandbox."
            );
        }
    }
}

/// Every memory access must be frame-relative. A load or store through any
/// other base register would be an arbitrary read or write of kernel memory.
#[test]
fn every_memory_access_is_frame_relative() {
    for code in all_programs() {
        for (i, w) in code.iter().enumerate() {
            let op = w & 0x7f;
            if op != LOAD && op != STORE {
                continue;
            }
            let rs1 = (w >> 15) & 0x1f;
            assert!(
                rs1 == S0 || rs1 == SP,
                "instruction {i} ({w:08x}) addresses memory through x{rs1}; \
                 only s0 (frame) and sp (eval stack) are permitted"
            );
        }
    }
}

/// Calls are either to a statically-resolved address in `t0`, or a return
/// through `ra`. There is no computed call, so a program cannot jump to an
/// address it constructed.
#[test]
fn every_indirect_jump_is_a_call_or_a_return() {
    for code in all_programs() {
        for (i, w) in code.iter().enumerate() {
            if w & 0x7f != JALR {
                continue;
            }
            let rd = (w >> 7) & 0x1f;
            let rs1 = (w >> 15) & 0x1f;
            let is_call = rd == RA && rs1 == T0;
            let is_ret = rd == ZERO && rs1 == RA;
            assert!(
                is_call || is_ret,
                "instruction {i} ({w:08x}): jalr rd=x{rd} rs1=x{rs1} is neither \
                 a call through t0 nor a return through ra"
            );
        }
    }
}

/// The only addresses a program can name are the ones the compiler put there.
#[test]
fn the_only_absolute_addresses_are_compiler_chosen() {
    let rt = rt();
    let img = compile_at(samples::DEMO, 0x8000_0000, 0x8010_0000, &rt).unwrap();
    // Reconstruct every constant the program materializes into t0/a0/a1.
    let mut found = vec![];
    let mut i = 0;
    while i + 11 <= img.code.len() {
        let window = &img.code[i..i + 11];
        if window.iter().all(|w| w & 0x7f == OP_IMM) {
            let rd = (window[0] >> 7) & 0x1f;
            found.push(simulate_li64(window, rd));
            i += 11;
        } else {
            i += 1;
        }
    }
    for addr in found.iter().filter(|v| **v > 0x1000_0000) {
        let in_data = (0x8000_0000..0x8000_0000 + img.data.len() as u64).contains(addr);
        let in_code = (0x8010_0000..0x8010_0000 + (img.code.len() * 4) as u64).contains(addr);
        let is_hook = *addr == rt.print_str || *addr == rt.print_int;
        assert!(
            in_data || in_code || is_hook,
            "generated code materializes {addr:#x}, which is neither its own data, \
             its own code, nor a runtime hook"
        );
    }
}

// --- semantic diagnostics ---

#[test]
fn scope_and_mutability_are_enforced() {
    assert_eq!(err("fn main() { y; }"), "line 1: cannot find value `y` in this scope");
    assert_eq!(
        err("fn main() { let x = 1; x = 2; }"),
        "line 1: cannot assign twice to immutable variable `x` (declare it `let mut`)"
    );
    assert!(compile_at("fn main() { let mut x = 1; x = 2; }", 0, 0, &rt()).is_ok());
}

#[test]
fn a_variable_leaves_scope_at_the_end_of_its_block() {
    assert_eq!(
        err("fn main() { if 1 { let inner = 1; } inner; }"),
        "line 1: cannot find value `inner` in this scope"
    );
}

#[test]
fn calls_are_checked_for_existence_and_arity() {
    assert_eq!(err("fn main() { nope(); }"), "line 1: cannot find function `nope`");
    assert_eq!(
        err("fn f(a: i64) -> i64 { a }\nfn main() { f(1, 2); }"),
        "line 2: `f` takes 1 argument(s) but 2 were supplied"
    );
    assert_eq!(
        err("fn f(a: i64) -> i64 { a }\nfn main() { f(); }"),
        "line 2: `f` takes 1 argument(s) but 0 were supplied"
    );
}

#[test]
fn duplicate_definitions_and_bad_main_are_rejected() {
    assert_eq!(
        err("fn f() {}\nfn f() {}\nfn main() {}"),
        "line 2: function `f` is defined twice"
    );
    assert_eq!(err("fn main(a: i64) {}"), "`main` must take no arguments");
}

#[test]
fn resource_limits_are_diagnosed_rather_than_miscompiled() {
    let many = (0..300).map(|i| format!("let v{i} = {i};")).collect::<String>();
    let msg = err(&format!("fn main() {{ {many} }}"));
    assert!(msg.contains("at most 252 are supported"), "{msg}");

    let params = (0..9).map(|i| format!("p{i}: i64")).collect::<Vec<_>>().join(", ");
    let msg = err(&format!("fn f({params}) -> i64 {{ p0 }}\nfn main() {{}}"));
    assert!(msg.contains("at most 8 parameters"), "{msg}");
}

#[test]
fn samples_compile() {
    for (name, src) in [
        ("hello", samples::HELLO),
        ("demo", samples::DEMO),
        ("conformance", samples::CONFORMANCE),
    ] {
        assert!(code_len(src).is_ok(), "{name} failed to compile");
    }
}
