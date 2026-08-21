(component
  (core module $memory-provider
    (memory (export "memory") 1 1))
  (core instance $memory-instance (instantiate $memory-provider))
  (alias core export $memory-instance "memory" (core memory $memory))

  (type $bytes (stream u8))
  (type $closed (future u32))
  (type $run-type (func async))

  (core func $task-return (canon task.return))
  (core func $stream-new (canon stream.new $bytes))
  (core func $stream-read
    (canon stream.read $bytes async (memory $memory)))
  (core func $stream-write
    (canon stream.write $bytes async (memory $memory)))
  (core func $stream-cancel-read (canon stream.cancel-read $bytes))
  (core func $stream-cancel-write (canon stream.cancel-write $bytes))
  (core func $stream-drop-readable (canon stream.drop-readable $bytes))
  (core func $stream-drop-writable (canon stream.drop-writable $bytes))
  (core func $future-new (canon future.new $closed))
  (core func $future-read
    (canon future.read $closed async (memory $memory)))
  (core func $future-write
    (canon future.write $closed async (memory $memory)))
  (core func $future-cancel-read (canon future.cancel-read $closed))
  (core func $future-cancel-write (canon future.cancel-write $closed))
  (core func $future-drop-readable (canon future.drop-readable $closed))
  (core func $future-drop-writable (canon future.drop-writable $closed))
  (core func $waitable-set-new (canon waitable-set.new))
  (core func $waitable-set-drop (canon waitable-set.drop))
  (core func $waitable-join (canon waitable.join))

  (core instance $async-builtins
    (export "task-return" (func $task-return))
    (export "stream-new" (func $stream-new))
    (export "stream-read" (func $stream-read))
    (export "stream-write" (func $stream-write))
    (export "stream-cancel-read" (func $stream-cancel-read))
    (export "stream-cancel-write" (func $stream-cancel-write))
    (export "stream-drop-readable" (func $stream-drop-readable))
    (export "stream-drop-writable" (func $stream-drop-writable))
    (export "future-new" (func $future-new))
    (export "future-read" (func $future-read))
    (export "future-write" (func $future-write))
    (export "future-cancel-read" (func $future-cancel-read))
    (export "future-cancel-write" (func $future-cancel-write))
    (export "future-drop-readable" (func $future-drop-readable))
    (export "future-drop-writable" (func $future-drop-writable))
    (export "waitable-set-new" (func $waitable-set-new))
    (export "waitable-set-drop" (func $waitable-set-drop))
    (export "waitable-join" (func $waitable-join)))

  (core module $guest
    (import "env" "memory" (memory 1 1))
    (import "vibe:async" "task-return" (func $task-return))
    (import "vibe:async" "stream-new"
      (func $stream-new (result i64)))
    (import "vibe:async" "stream-read"
      (func $stream-read (param i32 i32 i32) (result i32)))
    (import "vibe:async" "stream-write"
      (func $stream-write (param i32 i32 i32) (result i32)))
    (import "vibe:async" "stream-cancel-read"
      (func $stream-cancel-read (param i32) (result i32)))
    (import "vibe:async" "stream-cancel-write"
      (func $stream-cancel-write (param i32) (result i32)))
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
    (import "vibe:async" "future-cancel-read"
      (func $future-cancel-read (param i32) (result i32)))
    (import "vibe:async" "future-cancel-write"
      (func $future-cancel-write (param i32) (result i32)))
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

    ;; Resolve the task, then yield so result resolution and callback exit are
    ;; observably separate executor transitions.
    (func (export "run") (result i32)
      call $task-return
      i32.const 1)

    ;; Vibe callback ABI: event, p1, p2 -> packed callback result.
    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0))

  (core instance $guest-instance
    (instantiate $guest
      (with "env" (instance $memory-instance))
      (with "vibe:async" (instance $async-builtins))))
  (alias core export $guest-instance "run" (core func $run))
  (alias core export $guest-instance "callback" (core func $callback))

  (func $lifted (type $run-type)
    (canon lift (core func $run)
      async
      (callback (core func $callback))))
  (export "run" (func $lifted)))
