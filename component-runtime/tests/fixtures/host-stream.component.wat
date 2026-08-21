(component
  ;; One executable C5.3 byte-stream filter. The allocator records its exact
  ;; live size and traps if either the runtime shrink or the guest free lies
  ;; about `old-size`; this catches a max-size allocation being published with
  ;; a shorter Canonical ABI list length.
  (core module $memory-provider
    (memory (export "memory") 1 1)
    ;; 0 bump; 4 allocs; 8 shrinks; 12 frees; 16 mismatch; 20 live pointer;
    ;; 24 live size; 28 last old size; 32 last new size; 36 run count.
    (data (i32.const 0) "\00\10\00\00")

    (func (export "cabi_realloc")
      (param $old-pointer i32)
      (param $old-size i32)
      (param $alignment i32)
      (param $new-size i32)
      (result i32)
      (local $pointer i32)
      i32.const 28
      local.get $old-size
      i32.store
      i32.const 32
      local.get $new-size
      i32.store

      local.get $new-size
      i32.eqz
      if
        i32.const 12
        i32.const 12
        i32.load
        i32.const 1
        i32.add
        i32.store
        local.get $old-pointer
        i32.const 20
        i32.load
        i32.ne
        local.get $old-size
        i32.const 24
        i32.load
        i32.ne
        i32.or
        if
          i32.const 16
          i32.const 1
          i32.store
          unreachable
        end
        i32.const 20
        i32.const 0
        i32.store
        i32.const 24
        i32.const 0
        i32.store
        i32.const 0
        return
      end

      local.get $old-pointer
      if
        i32.const 8
        i32.const 8
        i32.load
        i32.const 1
        i32.add
        i32.store
        local.get $old-pointer
        i32.const 20
        i32.load
        i32.ne
        local.get $old-size
        i32.const 24
        i32.load
        i32.ne
        i32.or
        local.get $new-size
        local.get $old-size
        i32.gt_u
        i32.or
        local.get $alignment
        i32.const 1
        i32.ne
        i32.or
        if
          i32.const 16
          i32.const 1
          i32.store
          unreachable
        end
        i32.const 24
        local.get $new-size
        i32.store
        local.get $old-pointer
        return
      end

      i32.const 4
      i32.const 4
      i32.load
      i32.const 1
      i32.add
      i32.store
      local.get $alignment
      i32.const 1
      i32.ne
      i32.const 20
      i32.load
      i32.eqz
      i32.eqz
      i32.or
      if
        i32.const 16
        i32.const 1
        i32.store
        unreachable
      end
      i32.const 0
      i32.load
      local.set $pointer
      i32.const 0
      local.get $pointer
      local.get $new-size
      i32.add
      i32.store
      i32.const 20
      local.get $pointer
      i32.store
      i32.const 24
      local.get $new-size
      i32.store
      local.get $pointer)
  )

  (core module $guest
    (import "env" "memory" (memory 1 1))
    (import "env" "cabi_realloc"
      (func $realloc (param i32 i32 i32 i32) (result i32)))
    (export "memory" (memory 0))
    (export "cabi_realloc" (func $realloc))
    (type $read-core (func (param i32 i32)))
    (type $write-core (func (param i32 i32 i32)))
    (type $close-core (func (param i32 i32)))
    (import "vibe:stream/streams@1.0.0" "read"
      (func $read (type $read-core)))
    (import "vibe:stream/streams@1.0.0" "write"
      (func $write (type $write-core)))
    (import "vibe:stream/streams@1.0.0" "close-reader"
      (func $close-reader (type $close-core)))
    (import "vibe:stream/streams@1.0.0" "close-writer"
      (func $close-writer (type $close-core)))

    (func (export "run") (param $input i32) (param $output i32)
      (local $pointer i32)
      (local $length i32)
      i32.const 36
      i32.const 36
      i32.load
      i32.const 1
      i32.add
      i32.store
      local.get $input
      i32.const 64
      call $read
      i32.const 64
      i32.load
      local.set $pointer
      i32.const 68
      i32.load
      local.set $length
      local.get $output
      local.get $pointer
      local.get $length
      call $write
      local.get $pointer
      local.get $length
      i32.const 1
      i32.const 0
      call $realloc
      drop
      local.get $input
      i32.const 0
      call $close-reader
      local.get $output
      i32.const 0
      call $close-writer)
  )

  (type $streams-interface
    (instance
      (export "reader" (type $reader-in (sub resource)))
      (export "writer" (type $writer-in (sub resource)))
      (type $close-reason-private
        (enum "normal" "failure" "cancelled" "denied" "unavailable"
          "exhausted" "invalid" "backend-fault"))
      (export "close-reason"
        (type $close-reason-in (eq $close-reason-private)))
      (type $borrow-reader-in (borrow $reader-in))
      (type $borrow-writer-in (borrow $writer-in))
      (type $read-type
        (func (param "input" $borrow-reader-in) (result (list u8))))
      (type $write-type
        (func (param "output" $borrow-writer-in) (param "bytes" (list u8))))
      (type $close-reader-type
        (func
          (param "input" $borrow-reader-in)
          (param "reason" $close-reason-in)))
      (type $close-writer-type
        (func
          (param "output" $borrow-writer-in)
          (param "reason" $close-reason-in)))
      (export "read" (func (type $read-type)))
      (export "write" (func (type $write-type)))
      (export "close-reader" (func (type $close-reader-type)))
      (export "close-writer" (func (type $close-writer-type)))))
  (import "vibe:stream/streams@1.0.0"
    (instance $streams (type $streams-interface)))
  (alias export $streams "reader" (type $reader))
  (alias export $streams "writer" (type $writer))
  (alias export $streams "close-reason" (type $close-reason))
  (alias export $streams "read" (func $read))
  (alias export $streams "write" (func $write))
  (alias export $streams "close-reader" (func $close-reader))
  (alias export $streams "close-writer" (func $close-writer))

  (core instance $memory-instance (instantiate $memory-provider))
  (alias core export $memory-instance "memory" (core memory $memory))
  (alias core export $memory-instance "cabi_realloc" (core func $realloc))
  (core func $lowered-read
    (canon lower (func $read) (memory $memory) (realloc $realloc)))
  (core func $lowered-write
    (canon lower (func $write) (memory $memory)))
  (core func $lowered-close-reader (canon lower (func $close-reader)))
  (core func $lowered-close-writer (canon lower (func $close-writer)))
  (core instance $env
    (export "memory" (memory $memory))
    (export "cabi_realloc" (func $realloc)))
  (core instance $stream-core
    (export "read" (func $lowered-read))
    (export "write" (func $lowered-write))
    (export "close-reader" (func $lowered-close-reader))
    (export "close-writer" (func $lowered-close-writer)))
  (core instance $guest-instance
    (instantiate $guest
      (with "env" (instance $env))
      (with "vibe:stream/streams@1.0.0" (instance $stream-core))))
  (alias core export $guest-instance "memory" (core memory $run-memory))
  (alias core export $guest-instance "cabi_realloc" (core func $run-realloc))
  (alias core export $guest-instance "run" (core func $run))

  (type $borrow-reader (borrow $reader))
  (type $borrow-writer (borrow $writer))
  (type $run-type
    (func
      (param "input" $borrow-reader)
      (param "output" $borrow-writer)))
  (func $lifted-run (type $run-type)
    (canon lift (core func $run)
      (memory $run-memory)
      (realloc $run-realloc)))
  (export "run" (func $lifted-run))
)
