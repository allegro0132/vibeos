(module
  (type $fd-write-type (func (param i32 i32 i32 i32) (result i32)))
  (type (func))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd-write (type $fd-write-type)))
  (memory 1 16)
  (export "memory" (memory 0))
  (export "_start" (func 1))
  (func (type 1)
    i32.const 1
    i32.const 0
    i32.const 0
    i32.const 0
    call $fd-write
    drop))
