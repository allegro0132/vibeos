(component
  (core module $memory-provider
    (memory (export "memory") 1 1)
    (data (i32.const 0) "\00\40\00\00")
    (func (export "realloc")
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
      local.get $pointer))
  (core instance $memory-instance (instantiate $memory-provider))
  (alias core export $memory-instance "memory" (core memory $provider-memory))
  (alias core export $memory-instance "realloc" (core func $realloc))

  (type $random-interface
    (instance
      (export "random-source" (type $random-source-in (sub resource)))
      (type $borrow-source-in (borrow $random-source-in))
      (type $error-private (enum "denied" "exhausted"))
      (export "random-error" (type $error-in (eq $error-private)))
      (type $fill-type
        (func
          (param "source" $borrow-source-in)
          (param "len" u32)
          (result (result (list u8) (error $error-in)))))
      (export "fill" (func (type $fill-type)))))
  (import "vibe:random/random@1.0.0"
    (instance $random (type $random-interface)))
  (alias export $random "random-source" (type $random-source))
  (alias export $random "random-error" (type $random-error))
  (alias export $random "fill" (func $fill))
  (type $borrow-source (borrow $random-source))
  (type $run-type
    (func
      (param "source" $borrow-source)
      (param "len" u32)
      (result (result (list u8) (error $random-error)))))

  (core func $lowered-fill
    (canon lower (func $fill)
      string-encoding=utf8
      (memory $provider-memory)
      (realloc $realloc)))
  (core instance $random-core
    (export "fill" (func $lowered-fill)))

  (core module $guest
    (type $fill-core (func (param i32 i32 i32)))
    (import "vibe:random/random@1.0.0" "fill" (func $fill (type $fill-core)))
    (import "env" "memory" (memory 1 1))
    (export "memory" (memory 0))
    (func (export "run") (param $source i32) (param $len i32) (result i32)
      local.get $source
      local.get $len
      i32.const 512
      call $fill
      i32.const 512)
    (func (export "cabi_post_run") (param $result-pointer i32)))
  (core instance $guest-instance
    (instantiate $guest
      (with "vibe:random/random@1.0.0" (instance $random-core))
      (with "env" (instance $memory-instance))))
  (alias core export $guest-instance "memory" (core memory $guest-memory))
  (alias core export $guest-instance "run" (core func $run))
  (alias core export $guest-instance "cabi_post_run" (core func $post-return))
  (func $lifted-run (type $run-type)
    (canon lift (core func $run)
      string-encoding=utf8
      (memory $guest-memory)
      (post-return $post-return)))
  (export "run" (func $lifted-run))
)
