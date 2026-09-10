//! Structural admission tests for the wasi-threads contract. Kept out of
//! `validate.rs` because the Wasmtime backend includes that file by path and
//! has neither this crate's `WasiLimits::default` nor the `wat` dev-dependency.

use crate::profile::DECLARATIONS as BASE;
use crate::validate::*;
use crate::{WasiError, WasiLimits};
use alloc::{format, string::{String, ToString}};
/// Build a wasi-threads module from its parts: the memory declaration
/// (imported or defined, placed after the imports), the spawn import, and
/// the per-thread entry export.
fn module(memory: &str, imported: bool, spawn: bool, thread_start: bool) -> String {
    let spawn = if spawn {
        r#"(import "wasi" "thread-spawn" (func $spawn (param i32) (result i32)))"#
    } else {
        ""
    };
    let (import, define) = if imported {
        (format!(r#"(import "env" "memory" {memory})"#), String::new())
    } else {
        (String::new(), memory.to_string())
    };
    let start = if thread_start { r#"(func (export "wasi_thread_start") (param i32 i32))"# } else { "" };
    format!(
        r#"(module {import} {spawn} {define} (export "memory" (memory 0))
        (func (export "_start")
            (drop (memory.atomic.wait32 (i32.const 0) (i32.const 1) (i64.const 0)))
            (drop (memory.atomic.notify (i32.const 0) (i32.const 1)))
            (drop (i32.atomic.rmw.add (i32.const 0) (i32.const 1))))
        {start})"#
    )
}
fn limits(threads: bool) -> WasiLimits {
    WasiLimits { threads, ..WasiLimits::default() }
}
fn check(source: &str, threads: bool) -> Result<(), WasiError> {
    inspect(&wat::parse_str(source).unwrap(), limits(threads))
}
#[test]
fn threads_contract_is_gated() {
    let threaded = module("(memory 1 4 shared)", true, true, true);
    assert_eq!(check(&threaded, false), Err(WasiError::Import));
    assert_eq!(check(&threaded, true), Ok(()));
}
#[test]
fn core_start_requires_the_complete_threads_contract() {
    let threaded = module("(memory 1 4 shared)", true, true, true)
        .replace("(export \"memory\"", "(func $init (i32.atomic.store (i32.const 0) (i32.const 7))) (start $init) (export \"memory\"");
    assert_eq!(check(&threaded, true), Ok(()));
    assert_eq!(check(&threaded, false), Err(WasiError::Import));
    let single = r#"(module (memory (export "memory") 1)
        (func $init) (start $init) (func (export "_start")))"#;
    assert_eq!(check(single, false), Err(WasiError::Contract));
    assert_eq!(check(single, true), Err(WasiError::Contract));
    assert_eq!(check(&threaded.replace("(export \"wasi_thread_start\")", ""), true), Err(WasiError::Contract));
}
#[test]
fn threads_contract_requires_every_half() {
    assert_eq!(check(&module("(memory 1 4 shared)", true, true, false), true), Err(WasiError::Contract));
    assert_eq!(check(&module("(memory 1 4 shared)", true, false, true), true), Err(WasiError::Contract));
    assert_eq!(check(&module("(memory 1 4)", false, true, true), true), Err(WasiError::Contract));
}
#[test]
fn shared_memory_must_be_imported_and_bounded() {
    assert_eq!(check(&module("(memory 1 4 shared)", false, true, true), true), Err(WasiError::Unsupported));
    let oversized = format!("(memory 1 {} shared)", WasiLimits::default().memory_bytes / 65536 + 1);
    assert_eq!(check(&module(&oversized, true, true, true), true), Err(WasiError::Limit));
    assert_eq!(check(&module("(memory 1 4)", true, true, true), true), Err(WasiError::Unsupported));
    // An unbounded shared memory is malformed at the encoding level.
    assert!(check(&module("(memory 1 4)", true, true, true).replace("(memory 1 4)", "(memory 1 shared)"), true).is_err());
}
#[test]
fn atomics_need_the_threads_profile() {
    let single = r#"(module (memory (export "memory") 1)
        (func (export "_start") (drop (i32.atomic.rmw.add (i32.const 0) (i32.const 1)))))"#;
    assert_eq!(check(single, false), Err(WasiError::Unsupported));
    assert_eq!(check(single, true), Ok(()));
}
#[test]
fn command_declaration_ceiling_is_enforced() {
    let mut wat = String::from("(module (memory (export \"memory\") 1) (func (export \"_start\"))");
    for _ in 1..BASE.max_functions {
        wat.push_str("(func)");
    }
    assert_eq!(check(&(wat.clone() + ")"), false), Ok(()));
    assert_eq!(check(&(wat + "(func))"), false), Err(WasiError::Limit));
    let over_table = format!("(module (memory (export \"memory\") 1) (table {} funcref) (func (export \"_start\")))", BASE.max_table_elements + 1);
    assert_eq!(check(&over_table, false), Err(WasiError::Limit));
}
