(component
  (core module $guest
    (memory (export "memory") 1 1)
    (data (i32.const 0) "\00\10\00\00")
    (func (export "cabi_realloc")
      (param $old i32) (param $old-size i32) (param $align i32) (param $new-size i32)
      (result i32)
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
      i32.const 4096)
    (func (export "run") (param $mode i32) (param $input i32) (param $length i32) (result i32)
      local.get $mode
      i32.const 1
      i32.eq
      if unreachable end
      local.get $mode
      i32.const 2
      i32.eq
      if
        loop $spin br $spin end
      end
      local.get $mode
      i32x4.splat
      i32x4.extract_lane 0
      drop
      i32.const 512)
    (func (export "cabi_post_run") (param i32)))
  (core instance $instance (instantiate $guest))
  (alias core export $instance "memory" (core memory $memory))
  (alias core export $instance "cabi_realloc" (core func $realloc))
  (alias core export $instance "run" (core func $run))
  (alias core export $instance "cabi_post_run" (core func $post-return))
  (type $bytes (list u8))
  (type $run-type (func (param "mode" u32) (param "input" $bytes) (result $bytes)))
  (func $lifted (type $run-type)
    (canon lift (core func $run)
      (memory $memory)
      (realloc $realloc)
      (post-return $post-return)))
  (export "run" (func $lifted)))
