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
