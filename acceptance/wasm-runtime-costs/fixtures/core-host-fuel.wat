(module
  (import "vibe:bench/host@1.0.0" "echo"
    (func $echo (param i64) (result i64)))

  (func (export "host-roundtrip") (param i64) (result i64)
    local.get 0
    call $echo
    i64.const 1
    i64.add)

  (func (export "burn") (param i32) (result i32)
    (local $value i32)
    local.get 0
    local.set $value
    (block $done
      (loop $again
        local.get $value
        i32.eqz
        br_if $done
        local.get $value
        i32.const 1
        i32.sub
        local.set $value
        br $again))
    local.get $value))
