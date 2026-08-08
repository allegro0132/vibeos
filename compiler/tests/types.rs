//! The type checker.
//!
//! Its real job is not catching user mistakes — it is making the subset a
//! genuine subset of Rust. v0.1 accepted `if 1`, which Rust rejects, and every
//! such disagreement is a hole in the differential oracle that is the code
//! generator's strongest check.

use vibeos_rustc::{compile_at, Runtime};

fn rt() -> Runtime {
    Runtime { print_str: 1, print_int: 2, print_bool: 3, abort: 4 }
}

fn check(src: &str) -> Result<(), String> {
    compile_at(src, 0x8000_0000, 0x8010_0000, &rt()).map(|_| ())
}

fn err(src: &str) -> String {
    check(src).expect_err("expected a type error")
}

fn ok(src: &str) {
    check(src).unwrap_or_else(|e| panic!("expected {src:?} to type-check, got: {e}"));
}

// --- conditions are bool, as in Rust ---

#[test]
fn a_condition_must_be_a_bool() {
    assert_eq!(
        err("fn main() { if 1 { } }"),
        "line 1: mismatched types: `if` condition expects `bool`, found `i64`"
    );
    assert_eq!(
        err("fn main() { while 1 { } }"),
        "line 1: mismatched types: `while` condition expects `bool`, found `i64`"
    );
    ok("fn main() { if 1 < 2 { } }");
    ok("fn main() { if true { } }");
    ok("fn main() { let mut i = 0; while i < 3 { i = i + 1; } }");
}

#[test]
fn arithmetic_rejects_bools_and_logic_rejects_integers() {
    assert_eq!(
        err("fn main() { let x = true + 1; }"),
        "line 1: mismatched types: left operand of `+` expects `i64`, found `bool`"
    );
    assert_eq!(
        err("fn main() { let x = 1 && 2; }"),
        "line 1: mismatched types: left operand of `&&` expects `bool`, found `i64`"
    );
    ok("fn main() { let x = 1 < 2 && 3 < 4; }");
}

#[test]
fn comparison_yields_bool_and_ordering_needs_integers() {
    ok("fn main() { let b: bool = 1 < 2; }");
    assert_eq!(
        err("fn main() { let x: i64 = 1 < 2; }"),
        "line 1: mismatched types: initializer for `x` expects `i64`, found `bool`"
    );
    assert_eq!(
        err("fn main() { let x = true < false; }"),
        "line 1: mismatched types: left operand of `<` expects `i64`, found `bool`"
    );
}

/// Equality is the one operator that works on both, as long as the sides agree.
#[test]
fn equality_is_homogeneous() {
    ok("fn main() { let a = 1 == 2; }");
    ok("fn main() { let b = true == false; }");
    assert_eq!(
        err("fn main() { let c = 1 == true; }"),
        "line 1: mismatched types: operands of `==` expects `i64`, found `bool`"
    );
}

// --- annotations and inference ---

#[test]
fn a_declared_type_is_enforced() {
    ok("fn main() { let x: i64 = 1; }");
    ok("fn main() { let b: bool = true; }");
    assert_eq!(
        err("fn main() { let b: bool = 1; }"),
        "line 1: mismatched types: initializer for `b` expects `bool`, found `i64`"
    );
}

#[test]
fn assignment_must_keep_the_type() {
    assert_eq!(
        err("fn main() { let mut x = 1; x = true; }"),
        "line 1: mismatched types: assignment to `x` expects `i64`, found `bool`"
    );
    ok("fn main() { let mut b = true; b = 1 < 2; }");
}

// --- functions ---

#[test]
fn arguments_and_returns_are_checked_by_type_not_just_arity() {
    assert_eq!(
        err("fn f(a: i64) -> i64 { a }\nfn main() { f(true); }"),
        "line 2: mismatched types: argument to `f` expects `i64`, found `bool`"
    );
    assert_eq!(
        err("fn f() -> bool { 1 }\nfn main() { }"),
        "line 1: mismatched types: block value expects `bool`, found `i64`"
    );
    ok("fn f(a: i64, b: bool) -> bool { if b { a > 0 } else { false } }\nfn main() { f(1, true); }");
}

#[test]
fn a_function_with_no_return_type_returns_unit() {
    ok("fn f() { }\nfn main() { f(); }");
    assert_eq!(
        err("fn f() { 1 }\nfn main() { }"),
        "line 1: mismatched types: block value expects `()`, found `i64`"
    );
}

#[test]
fn return_must_match_the_signature() {
    assert_eq!(
        err("fn f() -> i64 { return true; }\nfn main() { }"),
        "mismatched types: `return` value expects `i64`, found `bool`"
    );
    ok("fn f() -> i64 { return 1; }\nfn main() { }");
    ok("fn f(a: i64) -> i64 { if a > 0 { return 1; } 0 }\nfn main() { }");
}

// --- if as an expression ---

#[test]
fn both_arms_of_an_if_expression_must_agree() {
    ok("fn main() { let x = if 1 < 2 { 1 } else { 2 }; }");
    ok("fn main() { let b = if 1 < 2 { true } else { false }; }");
    assert_eq!(
        err("fn main() { let x = if 1 < 2 { 1 } else { true }; }"),
        "line 1: mismatched types: block value expects `i64`, found `bool`"
    );
}

#[test]
fn an_if_without_else_has_no_value() {
    assert_eq!(
        err("fn main() { let x = if 1 < 2 { 1 }; }"),
        "line 1: mismatched types: block value expects `()`, found `i64`"
    );
    ok("fn main() { if 1 < 2 { } }");
}

// --- the two flavours of `!` ---

#[test]
fn bang_dispatches_on_the_operand_type() {
    // Logical on bool, bitwise on i64 — exactly as Rust does.
    ok("fn main() { let a: bool = !true; }");
    ok("fn main() { let b: i64 = !5; }");
    assert_eq!(
        err("fn main() { let a: i64 = !true; }"),
        "line 1: mismatched types: initializer for `a` expects `i64`, found `bool`"
    );
}

// --- unit ---

#[test]
fn unit_cannot_be_stored_compared_or_printed() {
    assert_eq!(err("fn f() { }\nfn main() { let x = f(); }"), "line 2: `x` cannot have type `()`");
    assert_eq!(
        err("fn f() { }\nfn main() { println!(\"{}\", f()); }"),
        "`()` cannot be formatted with `{}`"
    );
    assert_eq!(
        err("fn f() { }\nfn main() { let b = f() == f(); }"),
        "cannot compare values of type `()`"
    );
}

// --- program shape ---

#[test]
fn program_level_rules_are_still_enforced() {
    assert_eq!(err("fn f() { }"), "no `main` function found");
    assert_eq!(err("fn main(a: i64) { }"), "`main` must take no arguments");
    assert_eq!(
        err("fn f() { }\nfn f() { }\nfn main() { }"),
        "line 2: function `f` is defined twice"
    );
}

#[test]
fn the_samples_type_check() {
    for src in [
        vibeos_rustc::samples::HELLO,
        vibeos_rustc::samples::DEMO,
        vibeos_rustc::samples::CONFORMANCE,
    ] {
        ok(src);
    }
}
