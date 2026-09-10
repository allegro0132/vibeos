(module
  (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $stat (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_filestat_get" (func $file (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start") (local $fd i32)
    (loop $next
      ;; Both metadata APIs must describe byte pipes, never TTY devices.
      (if (call $stat (local.get $fd) (i32.const 0)) (then unreachable))
      (if (i32.load8_u (i32.const 0)) (then unreachable))
      (if (call $file (local.get $fd) (i32.const 32)) (then unreachable))
      (if (i32.load8_u (i32.const 48)) (then unreachable))
      (local.set $fd (i32.add (local.get $fd) (i32.const 1)))
      (br_if $next (i32.lt_u (local.get $fd) (i32.const 3)))))
)
