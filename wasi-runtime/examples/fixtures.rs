//! Deterministic adversarial modules for the real SSH/QEMU gate.
fn main() {
    let out = std::env::args().nth(1).expect("output directory");
    std::fs::create_dir_all(&out).unwrap();
    let fixtures = [
        ("stdio-pipes", include_str!("../../tests/wasi/stdio-pipes.wat")),
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
    for (name, source) in threads_fixtures() {
        std::fs::write(format!("{out}/{name}.wasm"), wat::parse_str(source).unwrap()).unwrap();
    }

    // Constant bulk copies must compile on RV64GC without introducing V
    // instructions. Check both overlap directions, unaligned addresses and
    // bytes outside the destination against a host memmove oracle.
    let mut data = String::new();
    let mut body = String::new();
    let mut oracle = 1024;
    for length in [0, 1, 7, 8, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128] {
        for (src, dst) in [(1, 3), (3, 1), (1, 257)] {
            let mut expected: Vec<u8> = (0..512).map(|i| (i * 37 + 11) as u8).collect();
            body += "i32.const 0 local.set $i (loop $init
                local.get $i local.get $i i32.const 37 i32.mul i32.const 11 i32.add i32.store8
                local.get $i i32.const 1 i32.add local.tee $i i32.const 512 i32.lt_u br_if $init)\n";
            body += &format!("i32.const {dst} i32.const {src} i32.const {length} memory.copy\n");
            expected.copy_within(src..src + length, dst);
            let bytes: String = expected.iter().map(|byte| format!("\\{byte:02x}")).collect();
            data += &format!("(data (i32.const {oracle}) \"{bytes}\")\n");
            body += &format!("i32.const 0 local.set $i (loop $check
                local.get $i i32.load8_u local.get $i i32.const {oracle} i32.add i32.load8_u
                i32.ne if unreachable end
                local.get $i i32.const 1 i32.add local.tee $i i32.const 512 i32.lt_u br_if $check)\n");
            oracle += 512;
        }
    }
    let copy = format!("(module (memory (export \"memory\") 1) {data}
        (func (export \"_start\") (local $i i32) {body}))");
    std::fs::write(format!("{out}/copy.wasm"), wat::parse_str(copy).unwrap()).unwrap();
}

/// wasi-threads fixtures: an imported bounded shared memory, `wasi::thread-spawn`,
/// and `wasi_thread_start`. Workers publish through atomics and notify; the
/// main thread waits, verifies, and exits 0 on success or 1 on a wrong value.
fn threads_fixtures() -> Vec<(&'static str, String)> {
    let header = r#"(import "env" "memory" (memory 1 4 shared))
        (import "wasi" "thread-spawn" (func $spawn (param i32) (result i32)))
        (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
        (export "memory" (memory 0))"#;
    // Wait until the i32 at $addr equals $value, using wait/notify.
    let wait_for = |addr: u32, value: u32| format!(
        "(block $done (loop $w
            (br_if $done (i32.eq (i32.atomic.load (i32.const {addr})) (i32.const {value})))
            (drop (memory.atomic.wait32 (i32.const {addr}) (i32.atomic.load (i32.const {addr})) (i64.const -1)))
            (br $w)))");
    let spawn_n = |n: u32| format!(
        "(local $i i32) (loop $s
            (if (i32.lt_s (call $spawn (local.get $i)) (i32.const 1)) (then unreachable))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br_if $s (i32.lt_u (local.get $i) (i32.const {n}))))");
    let finish = "(drop (i32.atomic.rmw.add (i32.const 4) (i32.const 1)))
        (drop (memory.atomic.notify (i32.const 4) (i32.const -1)))";
    vec![
        ("threads-counter", format!("(module {header}
            (func (export \"_start\") {} {} 
                (if (i32.ne (i32.atomic.load (i32.const 0)) (i32.const 3000)) (then (call $exit (i32.const 1)))))
            (func (export \"wasi_thread_start\") (param $tid i32) (param $arg i32) (local $n i32)
                (loop $l (drop (i32.atomic.rmw.add (i32.const 0) (i32.const 1)))
                    (local.set $n (i32.add (local.get $n) (i32.const 1)))
                    (br_if $l (i32.lt_u (local.get $n) (i32.const 1000))))
                {finish}))", spawn_n(3), wait_for(4, 3))),
        ("threads-atomics", format!("(module {header}
            (func (export \"_start\")
                (if (i32.ne (i32.atomic.rmw.cmpxchg (i32.const 16) (i32.const 0) (i32.const 7)) (i32.const 0)) (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.atomic.rmw.cmpxchg (i32.const 16) (i32.const 0) (i32.const 9)) (i32.const 7)) (then (call $exit (i32.const 1))))
                (if (i64.ne (i64.atomic.rmw.xchg (i32.const 24) (i64.const 0x1122334455667788)) (i64.const 0)) (then (call $exit (i32.const 1))))
                (if (i64.ne (i64.atomic.load (i32.const 24)) (i64.const 0x1122334455667788)) (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.atomic.rmw8.add_u (i32.const 32) (i32.const 250)) (i32.const 0)) (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.atomic.rmw8.add_u (i32.const 32) (i32.const 10)) (i32.const 250)) (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.atomic.load8_u (i32.const 32)) (i32.const 4)) (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.atomic.rmw16.sub_u (i32.const 40) (i32.const 1)) (i32.const 0)) (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.atomic.load16_u (i32.const 40)) (i32.const 65535)) (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.atomic.rmw.xor (i32.const 44) (i32.const 0xff)) (i32.const 0)) (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.atomic.rmw.and (i32.const 44) (i32.const 0x0f)) (i32.const 0xff)) (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.atomic.rmw.or (i32.const 44) (i32.const 0xf0)) (i32.const 0x0f)) (then (call $exit (i32.const 1))))
                (i32.atomic.store (i32.const 48) (i32.const 5)) (atomic.fence)
                (if (i32.ne (i32.atomic.load (i32.const 48)) (i32.const 5)) (then (call $exit (i32.const 1))))
                (if (i32.ne (memory.atomic.notify (i32.const 48) (i32.const 1)) (i32.const 0)) (then (call $exit (i32.const 1))))
                (if (i32.ne (memory.atomic.wait32 (i32.const 48) (i32.const 6) (i64.const -1)) (i32.const 1)) (then (call $exit (i32.const 1)))))
            (func (export \"wasi_thread_start\") (param i32 i32)))")),
        ("threads-wait-timeout", format!("(module {header}
            (func (export \"_start\")
                (if (i32.ne (memory.atomic.wait32 (i32.const 0) (i32.const 0) (i64.const 1000000)) (i32.const 2)) (then (call $exit (i32.const 1))))
                (if (i32.ne (memory.atomic.wait64 (i32.const 8) (i64.const 0) (i64.const 1000000)) (i32.const 2)) (then (call $exit (i32.const 1)))))
            (func (export \"wasi_thread_start\") (param i32 i32)))")),
        ("threads-exit", format!("(module {header}
            (func (export \"_start\") {}
                (drop (memory.atomic.wait32 (i32.const 0) (i32.const 0) (i64.const -1))) (call $exit (i32.const 1)))
            (func (export \"wasi_thread_start\") (param i32 i32) (call $exit (i32.const 7))))", spawn_n(1))),
        ("threads-spawn-cap", format!("(module {header}
            (func (export \"_start\") (local $i i32) (local $r i32)
                (loop $s
                    (local.set $r (call $spawn (local.get $i)))
                    (if (i32.gt_s (local.get $r) (i32.const 0))
                        (then (drop (i32.atomic.rmw.add (i32.const 8) (i32.const 1))))
                        (else (if (i32.ne (local.get $r) (i32.const -6)) (then (call $exit (i32.const 1))))))
                    (local.set $i (i32.add (local.get $i) (i32.const 1)))
                    (br_if $s (i32.lt_u (local.get $i) (i32.const 16))))
                (block $done (loop $w
                    (br_if $done (i32.eq (i32.atomic.load (i32.const 4)) (i32.atomic.load (i32.const 8))))
                    (drop (memory.atomic.wait32 (i32.const 4) (i32.atomic.load (i32.const 4)) (i64.const -1)))
                    (br $w)))
                (call $exit (i32.atomic.load (i32.const 8))))
            (func (export \"wasi_thread_start\") (param i32 i32) {finish}))")),
        ("threads-grow", format!("(module {header}
            (func (export \"_start\") {} {}
                (if (i32.ne (memory.size) (i32.const 2)) (then (call $exit (i32.const 1))))
                (if (i32.ne (i32.atomic.load (i32.const 65536)) (i32.const 42)) (then (call $exit (i32.const 1)))))
            (func (export \"wasi_thread_start\") (param i32 i32)
                (if (i32.ne (memory.grow (i32.const 1)) (i32.const 1)) (then (call $exit (i32.const 1))))
                (i32.atomic.store (i32.const 65536) (i32.const 42)) {finish}))", spawn_n(1), wait_for(4, 1))),
        ("threads-fault", format!("(module {header}
            (func (export \"_start\") {}
                (drop (memory.atomic.wait32 (i32.const 0) (i32.const 0) (i64.const -1))) (call $exit (i32.const 1)))
            (func (export \"wasi_thread_start\") (param i32 i32) unreachable))", spawn_n(1))),
        ("threads-busy", format!("(module {header}
            (func (export \"_start\") {}
                (drop (memory.atomic.wait32 (i32.const 0) (i32.const 0) (i64.const -1))) (call $exit (i32.const 1)))
            (func (export \"wasi_thread_start\") (param i32 i32) (loop $l (br $l))))", spawn_n(3))),
        ("threads-defined-shared", format!("(module
            (import \"wasi\" \"thread-spawn\" (func $spawn (param i32) (result i32)))
            (memory (export \"memory\") 1 4 shared)
            (func (export \"_start\")) (func (export \"wasi_thread_start\") (param i32 i32)))")),
        ("threads-no-start", format!("(module {header} (func (export \"_start\")))")),
    ]
}
