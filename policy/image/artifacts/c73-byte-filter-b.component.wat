(component
  (core module $guest
    (memory (export "memory") 1 1)
    (data (i32.const 0) "\00\40\00\00")

    (func (export "cabi_realloc")
      (param $old i32) (param $old-size i32) (param $align i32) (param $new-size i32)
      (result i32)
      (local $pointer i32)
      local.get $new-size
      i32.eqz
      if
        i32.const 0
        return
      end
      local.get $old
      if
        local.get $old
        return
      end
      i32.const 0
      i32.load
      local.get $align
      i32.const 1
      i32.sub
      i32.add
      local.get $align
      i32.const 1
      i32.sub
      i32.const -1
      i32.xor
      i32.and
      local.set $pointer
      i32.const 0
      local.get $pointer
      local.get $new-size
      i32.add
      i32.store
      local.get $pointer)

    ;; Operator fixture B deliberately has different immutable code while
    ;; preserving the exact same public WIT contract and bounded topology.
    (func (export "run") (param $input i32) (param $length i32) (result i32)
      (local $index i32)
      block $done
        loop $copy
          local.get $index
          local.get $length
          i32.ge_u
          br_if $done
          i32.const 4096
          local.get $index
          i32.add
          local.get $input
          local.get $index
          i32.add
          i32.load8_u
          i32.const 1
          i32.xor
          i32.store8
          local.get $index
          i32.const 1
          i32.add
          local.set $index
          br $copy
        end
      end
      i32.const 512
      i32.const 4096
      i32.store
      i32.const 516
      local.get $length
      i32.store
      i32.const 512)

    (func (export "cabi_post_run") (param i32)))

  (core instance $instance (instantiate $guest))
  (alias core export $instance "memory" (core memory $memory))
  (alias core export $instance "cabi_realloc" (core func $realloc))
  (alias core export $instance "run" (core func $run))
  (alias core export $instance "cabi_post_run" (core func $post-return))
  (type $bytes (list u8))
  (type $filter (func (param "input" $bytes) (result $bytes)))
  (func $lifted (type $filter)
    (canon lift (core func $run)
      (memory $memory)
      (realloc $realloc)
      (post-return $post-return)))
  (export "run" (func $lifted)))
