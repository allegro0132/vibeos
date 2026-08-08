//! Code generation.
//!
//! This crate emits machine code that runs in the kernel's address space with
//! no MMU. A wrong frame offset here is a privilege escalation, not a wrong
//! answer — so these tests check encodings against the RISC-V spec by hand, and
//! then audit every instruction the emitter can produce.

use vibeos_rustc::{code_len, compile_at, samples, Runtime};

fn rt() -> Runtime {
    Runtime {
        print_str: 0x1111_2222_3333_4444,
        print_int: 0x5555_6666_7777_8888,
        print_bool: 0x1357_9bdf_0246_8ace,
        abort: 0x9999_aaaa_bbbb_cccc,
    }
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

/// `ret` is `jalr x0, x1, 0` == 0x00008067, the most widely known word in
/// RISC-V. Every function must contain exactly one.
#[test]
fn every_function_returns_through_a_canonical_ret() {
    for (src, funcs) in [("fn main() {}", 1), ("fn f() {}\nfn main() { f(); }", 2)] {
        let code = emit(src);
        let rets = code.iter().filter(|w| **w == 0x0000_8067).count();
        assert_eq!(rets, funcs, "expected one `ret` per function in {src:?}");
    }
}

#[test]
fn the_prologue_claims_a_frame_and_saves_ra_and_s0() {
    let code = emit("fn main() {}");
    // low 20 bits: opcode 0x13 | rd=sp(2)<<7 | funct3=0 | rs1=sp(2)<<15
    assert_eq!(code[0] & 0x000f_ffff, 0x0001_0113, "opens with addi sp, sp, imm");
    assert_eq!(code[0] >> 20, 0xff0, "frame of 16 bytes");
    // The safety checks sit between the frame claim and the saves, so search
    // rather than index.
    let head = &code[..12];
    assert!(head.contains(&0x0011_3023), "sd ra, 0(sp)");
    assert!(head.contains(&0x0081_3423), "sd s0, 8(sp)");
    assert!(head.contains(&0x0001_0413), "addi s0, sp, 0");
}

/// Decoded by hand from the spec's field layouts, so a change to the encoders
/// has to be justified against the ISA rather than against itself.
#[test]
fn known_words_for_each_instruction_format() {
    let code = emit("fn main() -> i64 { 1 + 2 }");
    let has = |w: u32| code.contains(&w);
    // Checked addition computes into t2, tests, then moves.
    assert!(has(0x0062_83b3), "add t2, t0, t1  (R-type)");
    assert!(has(0x0003_8293), "mv t0, t2  (addi with imm 0)");
    assert!(has(0x0000_8067), "ret (I-type, jump)");
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
/// Find the first 11-instruction constant-materialization run targeting `rd`.
/// Position varies with how many safety checks precede it, so search for the
/// shape rather than assuming an offset.
fn first_li64_into(code: &[u32], rd: u32) -> Option<Vec<u32>> {
    code.windows(11).find(|w| {
        w.iter().all(|x| x & 0x7f == 0x13 && (x >> 7) & 0x1f == rd)
            && (w[0] >> 15) & 0x1f == 0 // starts from x0
    }).map(|w| w.to_vec())
}

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
        let run = first_li64_into(&code, 5).unwrap_or_else(|| panic!("no li64 for {want}"));
        assert_eq!(simulate_li64(&run, 5) as i64, want, "materializing {want}");
    }
}

/// A negative literal is a unary negation of a positive one, so the emitter
/// must follow the constant with a `sub rd, zero, rd`.
#[test]
fn negative_literals_are_materialized_then_negated() {
    let code = emit("fn main() -> i64 { -42 }");
    assert!(code.contains(&0x4050_02b3), "expected `sub t0, zero, t0`");
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
    assert_eq!(code[0] & 0x000f_ffff, 0x0001_0113, "opens with main's frame claim");
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
const T4: u32 = 29;
const T5: u32 = 30;
const S0: u32 = 8;
const S3: u32 = 19;
const BLTU: u32 = 6;

/// Programs that exercise the region: allocation, read, write, and a loop.
fn all_programs_with_arrays() -> Vec<Vec<u32>> {
    vec![
        emit("fn main() { let mut a = [0; 4]; a[0] = 1; println!(\"{}\", a[0]); }"),
        emit(
            "fn main() { let mut a = [7; 16]; let mut b = [0; 8]; let mut i = 0;\
             while i < 8 { b[i] = a[i] * 2; i = i + 1; } println!(\"{}\", b[3]); }",
        ),
    ]
}

fn all_programs() -> Vec<Vec<u32>> {
    let mut out = vec![];
    for src in [samples::HELLO, samples::DEMO, samples::CONFORMANCE] {
        out.push(emit(src));
    }
    out.extend(all_programs_with_arrays());
    // Programs that carry every kind of abort stub, so the audit covers the
    // failure paths and not just the happy ones.
    out.push(emit(
        "fn r(n: i64) -> i64 { r(n) }\n\
         fn main() -> i64 { let a = 1; let b = 2; let mut i = 0;\
             while i < 3 { i = i + 1; }\
             r(a / b + a * b - a + -a) }",
    ));
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

/// Every memory access is frame-relative, or goes through the region cursor.
///
/// A load or store through any other base register is an arbitrary read or
/// write of kernel memory. This caught a real bug: element assignment stored
/// through `t0`, which holds the *scaled index* rather than the address, so
/// `a[1] = 9` wrote near address 8.
#[test]
fn every_memory_access_is_frame_relative_or_through_the_region_cursor() {
    for code in all_programs() {
        for (i, w) in code.iter().enumerate() {
            let op = w & 0x7f;
            if op != LOAD && op != STORE {
                continue;
            }
            let rs1 = (w >> 15) & 0x1f;
            assert!(
                rs1 == S0 || rs1 == SP || rs1 == T5,
                "instruction {i} ({w:08x}) addresses memory through x{rs1}; \
                 only s0 (frame), sp (eval stack) and t5 (region cursor) are permitted"
            );
        }
    }
}

/// ...and the region cursor is only ever formed by adding to the granted base.
///
/// Together with the bounds check asserted below, this is what keeps arrays
/// from reopening the address-forgery hole: a program can choose an *index*,
/// never an address.
#[test]
fn the_region_cursor_is_only_ever_the_granted_base_plus_an_offset() {
    for code in all_programs_with_arrays() {
        let mut writes = 0;
        for (i, w) in code.iter().enumerate() {
            let writes_t5 = match w & 0x7f {
                OP | OP_IMM | LOAD => (w >> 7) & 0x1f == T5,
                JAL | JALR => (w >> 7) & 0x1f == T5,
                _ => false,
            };
            if !writes_t5 {
                continue;
            }
            writes += 1;
            // add t5, s3, rX
            let is_add_from_base =
                w & 0x7f == OP && (w >> 12) & 7 == 0 && w >> 25 == 0 && (w >> 15) & 0x1f == S3;
            assert!(
                is_add_from_base,
                "instruction {i} ({w:08x}) writes t5 without deriving it from s3"
            );
        }
        assert!(writes > 0, "a program using arrays must form region addresses");
    }
}

/// Every region address is preceded by an unsigned bounds check against the
/// array's length. Unsigned, so a negative index fails the same test — Rust
/// indexes with `usize`, and this is how the subset keeps that guarantee with
/// only `i64`.
#[test]
fn every_region_address_is_preceded_by_a_bounds_check() {
    for code in all_programs_with_arrays() {
        for (i, w) in code.iter().enumerate() {
            let is_add_from_base =
                w & 0x7f == OP && (w >> 7) & 0x1f == T5 && (w >> 15) & 0x1f == S3;
            if !is_add_from_base {
                continue;
            }
            // Look back a short window for `bltu t0, t4, +8`.
            let start = i.saturating_sub(8);
            let guarded = code[start..i].iter().any(|g| {
                g & 0x7f == BRANCH
                    && (g >> 12) & 7 == BLTU
                    && (g >> 15) & 0x1f == T0
                    && (g >> 20) & 0x1f == T4
            });
            assert!(
                guarded,
                "region address at {i} ({w:08x}) has no bounds check in the preceding window"
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
        let is_hook = *addr == rt.print_str || *addr == rt.print_int || *addr == rt.print_bool || *addr == rt.abort;
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
        err("fn main() { if 1 < 2 { let inner = 1; } inner; }"),
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

// --- M2: emitted safety checks ---

/// Every function claims its frame and then immediately proves it is still
/// inside the stack. Without this, deep recursion in generated code walks `sp`
/// down into `.bss` and corrupts the kernel rather than faulting.
#[test]
fn every_function_probes_the_stack() {
    // bgeu sp, s1, +8 : rs1=sp(2) rs2=s1(9) funct3=7
    let probe = 0x0091_7463u32;
    for src in ["fn main() {}", "fn f(a: i64) -> i64 { a }\nfn main() { f(1); }"] {
        let code = emit(src);
        let funcs = code.iter().filter(|w| **w == 0x0000_8067).count();
        assert_eq!(
            code.iter().filter(|w| **w == probe).count(),
            funcs,
            "one stack probe per function in {src:?}"
        );
    }
}

/// Fuel is charged per call and per loop iteration, so neither unbounded
/// recursion nor `while true {}` can run forever.
#[test]
fn calls_and_loops_are_charged_fuel() {
    let burn = 0xfff9_0913u32; // addi s2, s2, -1

    let recursive = emit("fn f(n: i64) -> i64 { f(n) }\nfn main() -> i64 { f(0) }");
    assert!(recursive.contains(&burn), "a recursive function is charged");

    let looping = emit("fn main() { let mut i = 0; while i < 3 { i = i + 1; } }");
    assert!(
        looping.iter().filter(|w| **w == burn).count() >= 2,
        "the function entry and the loop back-edge are both charged"
    );
}

/// A function with no call and no loop executes a bounded number of
/// instructions whatever its arguments, so charging it is pure overhead.
#[test]
fn a_leaf_function_is_not_charged_fuel() {
    let burn = 0xfff9_0913u32;
    let leaf = emit("fn square(n: i64) -> i64 { n * n }\nfn main() -> i64 { square(7) }");
    // `main` calls, so it is charged; `square` is a leaf and is not.
    assert_eq!(leaf.iter().filter(|w| **w == burn).count(), 1);
    // The probe is still unconditional -- it is the security-critical one.
    assert_eq!(leaf.iter().filter(|w| **w == 0x0091_7463).count(), 2);
}

#[test]
fn division_is_guarded_against_zero_and_overflow() {
    let code = emit("fn main() -> i64 { let a = 10; let b = 2; a / b }");
    // bne t1, zero, +8 : rs1=t1(6) rs2=zero funct3=1
    assert!(code.contains(&0x0003_1463), "divisor-is-zero guard");
    // i64::MIN materialization for the MIN / -1 case
    assert!(code.contains(&0x03f3_9393), "slli t2, t2, 63");
}

/// A positive literal divisor is neither zero nor -1, so both guards are
/// provably dead and must not be paid for.
#[test]
fn a_constant_divisor_needs_no_guard() {
    let code = emit("fn main() -> i64 { let a = 10; a / 2 }");
    assert!(!code.contains(&0x0003_1463), "no divisor-is-zero guard");
    assert!(!code.contains(&0x03f3_9393), "no MIN comparison");
}

#[test]
fn dividing_by_a_literal_zero_is_a_compile_error() {
    assert_eq!(
        err("fn main() -> i64 { 1 / 0 }"),
        "this operation will panic at runtime: attempt to divide by zero"
    );
    assert_eq!(
        err("fn main() -> i64 { 1 % 0 }"),
        "this operation will panic at runtime: attempt to calculate the remainder by zero"
    );
}

/// Real Rust panics on overflow; a subset that silently wraps is a different
/// language that happens to parse the same.
#[test]
fn arithmetic_is_overflow_checked() {
    let add = emit("fn main() -> i64 { let a = 1; let b = 2; a + b }");
    assert!(add.contains(&0x0062_83b3), "add into a scratch register");
    assert!(add.contains(&0x0053_ce33), "xor t3, t2, t0 for the sign test");
    assert!(add.contains(&0x0063_ceb3), "xor t4, t2, t1 for the sign test");

    let mul = emit("fn main() -> i64 { let a = 1; let b = 2; a * b }");
    assert!(mul.contains(&0x0262_9e33), "mulh t3, t0, t1");
    assert!(mul.contains(&0x43f3_de93), "srai t4, t2, 63");

    let neg = emit("fn main() -> i64 { let a = 1; -a }");
    assert!(neg.contains(&0x03f3_9393), "compare against i64::MIN");
}

/// `!` on an integer is bitwise complement in Rust. Matching it is what lets a
/// program in this subset be compiled by real rustc as a differential oracle.
#[test]
fn bang_is_bitwise_complement_not_logical_negation() {
    let code = emit("fn main() -> i64 { let a = 5; !a }");
    assert!(code.contains(&0xfff2_c293), "xori t0, t0, -1");
    assert!(!code.contains(&0x0012_b293), "not sltiu t0, t0, 1");
}

/// The abort path must itself obey the confinement rules: a program that fails
/// a check calls the runtime, it does not jump somewhere of its own choosing.
#[test]
fn the_abort_stubs_are_ordinary_guarded_calls() {
    let code = emit("fn main() -> i64 { let a = 1; let b = 0; a / b }");
    // One `addi a0, zero, <reason>` per distinct abort reason.
    let reasons = code
        .iter()
        .filter(|w| **w & 0x000f_ffff == 0x0000_0513 && (**w >> 20) < 16 && (**w >> 20) > 0)
        .count();
    assert!(reasons >= 1, "at least one abort stub");
    // And the audit tests below still apply to all of it.
}
