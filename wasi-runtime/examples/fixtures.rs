//! Deterministic adversarial modules for the real SSH/QEMU gate.
fn main() {
    let out = std::env::args().nth(1).expect("output directory");
    std::fs::create_dir_all(&out).unwrap();
    let fixtures = [
        (
            "loop",
            r#"(module (memory (export "memory") 1) (func (export "_start") (loop $l br $l)))"#,
        ),
        (
            "memory",
            r#"(module (memory (export "memory") 1) (func (export "_start") i32.const 1000 memory.grow drop))"#,
        ),
        (
            "trap",
            r#"(module (memory (export "memory") 1) (func (export "_start") unreachable))"#,
        ),
        (
            "unknown",
            r#"(module (import "env" "unknown" (func)) (memory (export "memory") 1) (func (export "_start")))"#,
        ),
        (
            "bounds",
            r#"(module (import "wasi_snapshot_preview1" "fd_write" (func $w (param i32 i32 i32 i32)(result i32)))
        (memory (export "memory") 1) (data(i32.const 0) "\ff\ff\ff\ff\01\00\00\00")
        (func (export "_start") i32.const 1 i32.const 0 i32.const 1 i32.const 16 call $w i32.const 21 i32.ne if unreachable end))"#,
        ),
        (
            "output",
            r#"(module (import "wasi_snapshot_preview1" "fd_write" (func $w (param i32 i32 i32 i32)(result i32)))
        (memory (export "memory") 1) (data(i32.const 0) "\20\00\00\00\00\04\00\00")
        (func (export "_start") (loop $l i32.const 1 i32.const 0 i32.const 1 i32.const 16 call $w drop br $l)))"#,
        ),
    ];
    for (name, source) in fixtures {
        std::fs::write(
            format!("{out}/{name}.wasm"),
            wat::parse_str(source).unwrap(),
        )
        .unwrap();
    }
}
