(component
  ;; The Canonical ABI memory used by stream/future copies must exist before
  ;; the canonical builtins that the guest imports. Keep this provider inert:
  ;; one fixed page, no functions, globals, data segments, or start section.
  (core module $memory-provider
    (memory (export "memory") 1 1))
  (core instance $memory-instance (instantiate $memory-provider))
  (alias core export $memory-instance "memory" (core memory $memory))

  (type $close-reason-private
    (enum
      "normal"
      "failure"
      "cancelled"
      "denied"
      "unavailable"
      "exhausted"
      "invalid"
      "backend-fault"))
  (import "close-reason" (type $close-reason (eq $close-reason-private)))
  (type $bytes-private (stream u8))
  (import "bytes" (type $bytes (eq $bytes-private)))
  (type $closed-private (future $close-reason))
  (import "closed" (type $closed (eq $closed-private)))
  (type $byte-stream-private
    (record
      (field "bytes" $bytes)
      (field "closed" $closed)))
  (import "byte-stream" (type $byte-stream (eq $byte-stream-private)))
  (type $run-type
    (func async
      (param "input" $byte-stream)
      (result $byte-stream)))

  ;; Keep this sequence ABI-stable. Admission locks every bridge, type, option,
  ;; and origin instance before the validation-only executor may instantiate it.
  (core func $task-return
    (canon task.return (result $byte-stream)))
  (core func $stream-new (canon stream.new $bytes))
  (core func $stream-read
    (canon stream.read $bytes async (memory $memory)))
  (core func $stream-write
    (canon stream.write $bytes async (memory $memory)))
  (core func $stream-drop-readable
    (canon stream.drop-readable $bytes))
  (core func $stream-drop-writable
    (canon stream.drop-writable $bytes))
  (core func $future-new (canon future.new $closed))
  (core func $future-read
    (canon future.read $closed async (memory $memory)))
  (core func $future-write
    (canon future.write $closed async (memory $memory)))
  (core func $future-drop-readable
    (canon future.drop-readable $closed))
  (core func $future-drop-writable
    (canon future.drop-writable $closed))
  (core func $waitable-set-new (canon waitable-set.new))
  (core func $waitable-set-drop (canon waitable-set.drop))
  (core func $waitable-join (canon waitable.join))
  (core instance $builtins
    (export "task-return" (func $task-return))
    (export "stream-new" (func $stream-new))
    (export "stream-read" (func $stream-read))
    (export "stream-write" (func $stream-write))
    (export "stream-drop-readable" (func $stream-drop-readable))
    (export "stream-drop-writable" (func $stream-drop-writable))
    (export "future-new" (func $future-new))
    (export "future-read" (func $future-read))
    (export "future-write" (func $future-write))
    (export "future-drop-readable" (func $future-drop-readable))
    (export "future-drop-writable" (func $future-drop-writable))
    (export "waitable-set-new" (func $waitable-set-new))
    (export "waitable-set-drop" (func $waitable-set-drop))
    (export "waitable-join" (func $waitable-join)))

  (core module $filter
    (import "env" "memory" (memory 1 1))
    (import "vibe:async" "task-return"
      (func $task-return (param i32 i32)))
    (import "vibe:async" "stream-new"
      (func $stream-new (result i64)))
    (import "vibe:async" "stream-read"
      (func $stream-read (param i32 i32 i32) (result i32)))
    (import "vibe:async" "stream-write"
      (func $stream-write (param i32 i32 i32) (result i32)))
    (import "vibe:async" "stream-drop-readable"
      (func $stream-drop-readable (param i32)))
    (import "vibe:async" "stream-drop-writable"
      (func $stream-drop-writable (param i32)))
    (import "vibe:async" "future-new"
      (func $future-new (result i64)))
    (import "vibe:async" "future-read"
      (func $future-read (param i32 i32) (result i32)))
    (import "vibe:async" "future-write"
      (func $future-write (param i32 i32) (result i32)))
    (import "vibe:async" "future-drop-readable"
      (func $future-drop-readable (param i32)))
    (import "vibe:async" "future-drop-writable"
      (func $future-drop-writable (param i32)))
    (import "vibe:async" "waitable-set-new"
      (func $waitable-set-new (result i32)))
    (import "vibe:async" "waitable-set-drop"
      (func $waitable-set-drop (param i32)))
    (import "vibe:async" "waitable-join"
      (func $waitable-join (param i32 i32)))

    ;; The pinned Core profile forbids mutable globals. Bytes 0..35 are the
    ;; guest-private state record; the fixed 1 KiB transfer buffer begins at
    ;; 1024. Neither region is exported as Component authority.
    (func $load-state (param $address i32) (result i32)
      local.get $address
      i32.load)
    (func $store-state (param $value i32) (param $address i32)
      local.get $address
      local.get $value
      i32.store)

    (func $wait-result (result i32)
      i32.const 24
      call $load-state
      i32.const 4
      i32.shl
      i32.const 2
      i32.or)

    (func $xor-buffer (param $length i32)
      (local $index i32)
      block $done
        loop $next
          local.get $index
          local.get $length
          i32.ge_u
          br_if $done
          i32.const 1024
          local.get $index
          i32.add
          i32.const 1024
          local.get $index
          i32.add
          i32.load8_u
          i32.const 32
          i32.xor
          i32.store8
          local.get $index
          i32.const 1
          i32.add
          local.set $index
          br $next
        end
      end)

    (func $begin-input-read (result i32)
      i32.const 0
      call $load-state
      i32.const 1024
      i32.const 1024
      call $stream-read
      i32.const -1
      i32.ne
      if
        unreachable
      end
      call $wait-result)

    (func $begin-output-write (result i32)
      i32.const 12
      call $load-state
      i32.const 1024
      i32.const 28
      call $load-state
      i32.add
      i32.const 32
      call $load-state
      call $stream-write
      i32.const -1
      i32.ne
      if
        unreachable
      end
      call $wait-result)

    (func $begin-input-close-read (result i32)
      i32.const 4
      call $load-state
      i32.const 32
      call $future-read
      i32.const -1
      i32.ne
      if
        unreachable
      end
      call $wait-result)

    (func $begin-output-close-write (result i32)
      i32.const 20
      call $load-state
      i32.const 32
      call $future-write
      i32.const -1
      i32.ne
      if
        unreachable
      end
      call $wait-result)

    (func (export "run")
      (param $input-bytes-param i32)
      (param $input-closed-param i32)
      (result i32)
      (local $pair i64)

      local.get $input-bytes-param
      i32.const 0
      call $store-state
      local.get $input-closed-param
      i32.const 4
      call $store-state
      i32.const 0
      i32.const 28
      call $store-state
      i32.const 0
      i32.const 32
      call $store-state

      call $waitable-set-new
      i32.const 24
      call $store-state
      i32.const 0
      call $load-state
      i32.const 24
      call $load-state
      call $waitable-join
      i32.const 4
      call $load-state
      i32.const 24
      call $load-state
      call $waitable-join

      call $stream-new
      local.set $pair
      local.get $pair
      i32.wrap_i64
      i32.const 8
      call $store-state
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const 12
      call $store-state
      i32.const 12
      call $load-state
      i32.const 24
      call $load-state
      call $waitable-join

      call $future-new
      local.set $pair
      local.get $pair
      i32.wrap_i64
      i32.const 16
      call $store-state
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const 20
      call $store-state
      i32.const 20
      call $load-state
      i32.const 24
      call $load-state
      call $waitable-join

      ;; Publish the output endpoints before the first write. This makes every
      ;; subsequent output copy a real HostPending transition.
      i32.const 8
      call $load-state
      i32.const 16
      call $load-state
      call $task-return
      call $begin-input-read)

    (func (export "callback")
      (param $event i32)
      (param $p1 i32)
      (param $p2 i32)
      (result i32)
      (local $progress i32)

      local.get $event
      i32.const 2
      i32.eq
      if (result i32)
        local.get $p1
        i32.const 0
        call $load-state
        i32.ne
        if unreachable end
        local.get $p2
        i32.const 15
        i32.and
        i32.eqz
        if (result i32)
          local.get $p2
          i32.const 4
          i32.shr_u
          local.tee $progress
          i32.eqz
          if unreachable end
          local.get $progress
          i32.const 1024
          i32.gt_u
          if unreachable end
          local.get $progress
          call $xor-buffer
          i32.const 0
          i32.const 28
          call $store-state
          local.get $progress
          i32.const 32
          call $store-state
          call $begin-output-write
        else
          local.get $p2
          i32.const 1
          i32.ne
          if unreachable end
          i32.const 0
          call $load-state
          call $stream-drop-readable
          call $begin-input-close-read
        end
      else
        local.get $event
        i32.const 3
        i32.eq
        if (result i32)
          local.get $p1
          i32.const 12
          call $load-state
          i32.ne
          if unreachable end
          local.get $p2
          i32.const 15
          i32.and
          if unreachable end
          local.get $p2
          i32.const 4
          i32.shr_u
          local.tee $progress
          i32.eqz
          if unreachable end
          local.get $progress
          i32.const 32
          call $load-state
          i32.gt_u
          if unreachable end
          i32.const 28
          call $load-state
          local.get $progress
          i32.add
          i32.const 28
          call $store-state
          i32.const 32
          call $load-state
          local.get $progress
          i32.sub
          i32.const 32
          call $store-state
          i32.const 32
          call $load-state
          if (result i32)
            call $begin-output-write
          else
            call $begin-input-read
          end
        else
          local.get $event
          i32.const 4
          i32.eq
          if (result i32)
            local.get $p1
            i32.const 4
            call $load-state
            i32.ne
            if unreachable end
            local.get $p2
            if unreachable end
            i32.const 32
            i32.load8_u
            i32.const 8
            i32.ge_u
            if unreachable end
            i32.const 4
            call $load-state
            call $future-drop-readable
            i32.const 12
            call $load-state
            call $stream-drop-writable
            call $begin-output-close-write
          else
            local.get $event
            i32.const 5
            i32.ne
            if unreachable end
            local.get $p1
            i32.const 20
            call $load-state
            i32.ne
            if unreachable end
            local.get $p2
            if unreachable end
            i32.const 20
            call $load-state
            call $future-drop-writable
            i32.const 24
            call $load-state
            call $waitable-set-drop
            i32.const 0
          end
        end
      end))

  (core instance $filter-instance
    (instantiate $filter
      (with "env" (instance $memory-instance))
      (with "vibe:async" (instance $builtins))))
  (alias core export $filter-instance "run" (core func $run))
  (alias core export $filter-instance "callback" (core func $callback))
  (func $lifted (type $run-type)
    (canon lift (core func $run)
      async
      (callback (core func $callback))))
  (export "run" (func $lifted)))
