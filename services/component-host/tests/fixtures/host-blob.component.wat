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
  (alias core export $memory-instance "memory" (core memory $memory))
  (alias core export $memory-instance "realloc" (core func $realloc))

  (type $blob-interface
    (instance
      (export "blob" (type $blob-in (sub resource)))
      (type $borrow-blob-in (borrow $blob-in))
      (type $error-private (enum "denied" "invalid" "failed"))
      (export "blob-error" (type $error-in (eq $error-private)))
      (type $len-type (func (param "blob" $borrow-blob-in) (result u64)))
      (type $read-type
        (func
          (param "blob" $borrow-blob-in)
          (param "offset" u64)
          (param "len" u32)
          (result (result (list u8) (error $error-in)))))
      (export "len" (func (type $len-type)))
      (export "read" (func (type $read-type)))))
  (import "vibe:blob/blob@1.0.0" (instance $blob-api (type $blob-interface)))
  (alias export $blob-api "blob" (type $blob))
  (alias export $blob-api "blob-error" (type $blob-error))
  (alias export $blob-api "len" (func $len))
  (alias export $blob-api "read" (func $read))
  (type $borrow-blob (borrow $blob))
  (type $run-len-type (func (param "blob" $borrow-blob) (result u64)))
  (type $run-read-type
    (func
      (param "blob" $borrow-blob)
      (param "offset" u64)
      (param "len" u32)
      (result (result (list u8) (error $blob-error)))))

  (core func $lowered-len (canon lower (func $len)))
  (core func $lowered-read
    (canon lower (func $read)
      string-encoding=utf8
      (memory $memory)
      (realloc $realloc)))
  (core instance $blob-core
    (export "len" (func $lowered-len))
    (export "read" (func $lowered-read)))

  (core module $guest
    (type $len-core (func (param i32) (result i64)))
    (type $read-core (func (param i32 i64 i32 i32)))
    (import "vibe:blob/blob@1.0.0" "len" (func $len (type $len-core)))
    (import "vibe:blob/blob@1.0.0" "read" (func $read (type $read-core)))
    (import "env" "memory" (memory 1 1))
    (export "memory" (memory 0))
    (func (export "run-len") (param $blob i32) (result i64)
      local.get $blob
      call $len)
    (func (export "run-read") (param $blob i32) (param $offset i64) (param $len i32)
      (result i32)
      local.get $blob
      local.get $offset
      local.get $len
      i32.const 512
      call $read
      i32.const 512)
    (func (export "cabi_post_run_read") (param i32)))
  (core instance $guest-instance
    (instantiate $guest
      (with "vibe:blob/blob@1.0.0" (instance $blob-core))
      (with "env" (instance $memory-instance))))
  (alias core export $guest-instance "run-len" (core func $run-len))
  (alias core export $guest-instance "run-read" (core func $run-read))
  (alias core export $guest-instance "memory" (core memory $guest-memory))
  (alias core export $guest-instance "cabi_post_run_read" (core func $post-run-read))
  (func $lifted-run-len (type $run-len-type) (canon lift (core func $run-len)))
  (func $lifted-run-read (type $run-read-type)
    (canon lift (core func $run-read)
      string-encoding=utf8
      (memory $guest-memory)
      (post-return $post-run-read)))
  (export "run-len" (func $lifted-run-len))
  (export "run-read" (func $lifted-run-read))
)
