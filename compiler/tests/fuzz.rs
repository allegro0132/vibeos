//! Robustness. The front end must never panic — on any input at all.
//!
//! A panic here is not a cosmetic bug. `rustc edit` feeds arbitrary console
//! input straight into the parser, and a panic in a `no_std` kernel with
//! `panic = "abort"` takes the machine down. Every malformed program must come
//! back as `Err`.
//!
//! Not `cargo-fuzz`, which needs a nightly sanitizer runtime and a separate
//! build: this is a deterministic generator that runs in CI on every push, at a
//! cost of a few milliseconds.

use vibeos_rustc::{compile_at, Runtime};

fn rt() -> Runtime {
    Runtime { print_str: 0, print_int: 0, abort: 0 }
}

/// Must return, whatever it is handed.
fn survives(src: &str) {
    let _ = compile_at(src, 0x8000_0000, 0x8010_0000, &rt());
}

/// Deterministic pseudo-randomness: a test that finds a different bug every run
/// is a test whose failures nobody can reproduce.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[(self.next() % xs.len() as u64) as usize]
    }
}

const TOKENS: &[&str] = &[
    "fn", "main", "(", ")", "{", "}", ";", ",", ":", "i64", "->", "let", "mut", "=", "if",
    "else", "while", "return", "println!", "print!", "\"{}\"", "\"a\"", "1", "0", "-", "+",
    "*", "/", "%", "<", ">", "==", "!=", "<=", ">=", "&&", "||", "!", "x", "f", "//c\n",
    "\\", "\"", "{", "@", "\n", " ", "999999999999999999999", "_", "{{", "}}", "{:?}",
];

#[test]
fn random_token_soup_never_panics() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for _ in 0..20_000 {
        let len = (rng.next() % 24) as usize;
        let mut src = String::new();
        for _ in 0..len {
            src.push_str(rng.pick(TOKENS));
            src.push(' ');
        }
        survives(&src);
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for _ in 0..5_000 {
        let len = (rng.next() % 64) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (rng.next() % 128) as u8).collect();
        if let Ok(s) = std::str::from_utf8(&bytes) {
            survives(s);
        }
    }
}

/// Truncating a valid program anywhere is the most common way a real user
/// produces broken input, and the case that exposed the `Eof` backtracking bug.
#[test]
fn every_prefix_of_a_valid_program_is_handled() {
    for src in [
        vibeos_rustc::samples::HELLO,
        vibeos_rustc::samples::DEMO,
        vibeos_rustc::samples::CONFORMANCE,
    ] {
        for n in 0..=src.len() {
            if src.is_char_boundary(n) {
                survives(&src[..n]);
            }
        }
    }
}

/// ...and so is deleting one character from the middle.
#[test]
fn every_single_character_deletion_is_handled() {
    let src = vibeos_rustc::samples::DEMO;
    for n in 0..src.len() {
        if !src.is_char_boundary(n) {
            continue;
        }
        let mut m = String::with_capacity(src.len());
        m.push_str(&src[..n]);
        m.push_str(&src[n + src[n..].chars().next().unwrap().len_utf8()..]);
        survives(&m);
    }
}

/// Deep nesting is the classic way to blow a recursive-descent parser's stack.
/// The kernel has 256 KiB and no guard page, and `rustc edit` accepts arbitrary
/// console input -- so this must be *rejected*, not merely survived. A host test
/// would pass either way on an 8 MB stack, which is exactly why the limit is
/// asserted rather than assumed.
#[test]
fn deeply_nested_input_is_rejected_rather_than_recursed() {
    let shallow = format!("fn main() {{ let x = {}1{}; }}", "(".repeat(8), ")".repeat(8));
    assert!(
        compile_at(&shallow, 0, 0, &rt()).is_ok(),
        "ordinary nesting still works"
    );

    for depth in [256usize, 1024, 100_000] {
        let src = format!(
            "fn main() {{ let x = {}1{}; }}",
            "(".repeat(depth),
            ")".repeat(depth)
        );
        let err = compile_at(&src, 0, 0, &rt())
            .err()
            .unwrap_or_else(|| panic!("{depth}-deep nesting was accepted"));
        assert!(err.contains("nests more than"), "unexpected error: {err}");
    }

    let ifs = format!(
        "fn main() {{ let x = {} 1 {}; }}",
        "if 1 < 2 { ".repeat(512),
        "} else { 0 }".repeat(512)
    );
    assert!(compile_at(&ifs, 0, 0, &rt()).is_err(), "deep if-chains rejected");
}

/// Unbalanced delimiters in every combination, the shape most likely to walk
/// the token cursor off the end.
#[test]
fn unbalanced_delimiters_are_rejected_cleanly() {
    for open in ["(", "{", "\"", "//"] {
        for n in 0..8 {
            survives(&format!("fn main() {{ {} }}", open.repeat(n)));
            survives(&format!("fn f({} ", open.repeat(n)));
            survives(&open.repeat(n));
        }
    }
}

/// Numbers at and beyond the edges of i64.
#[test]
fn extreme_literals_are_handled() {
    for lit in [
        "0", "9223372036854775807", "9223372036854775808", "18446744073709551616",
        "99999999999999999999999999999999", "0000000000000000001", "1_______0",
    ] {
        survives(&format!("fn main() -> i64 {{ {lit} }}"));
    }
}
