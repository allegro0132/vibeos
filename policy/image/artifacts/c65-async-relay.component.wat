(component
  (type $pipe-in-type
    (instance
      (type $in-close-reason-private
        (enum
          "normal"
          "failure"
          "cancelled"
          "denied"
          "unavailable"
          "exhausted"
          "invalid"
          "backend-fault"))
      (export "close-reason"
        (type $in-close-reason (eq $in-close-reason-private)))
      (type $in-bytes-private (stream u8))
      (export "bytes" (type $in-bytes (eq $in-bytes-private)))
      (type $in-closed-private (future $in-close-reason))
      (export "closed" (type $in-closed (eq $in-closed-private)))
      (type $in-byte-stream-private
        (record
          (field "bytes" $in-bytes)
          (field "closed" $in-closed)))
      (export "byte-stream"
        (type $in-byte-stream (eq $in-byte-stream-private)))
      (type $in-run-type
        (func async
          (param "input" $in-byte-stream)
          (result $in-byte-stream)))
      (export "run" (func (type $in-run-type)))))
  (import "test:c65-chain/pipe@1.0.0"
    (instance $pipe-in (type $pipe-in-type)))

  (type $out-close-reason
    (enum
      "normal"
      "failure"
      "cancelled"
      "denied"
      "unavailable"
      "exhausted"
      "invalid"
      "backend-fault"))
  (type $out-bytes (stream u8))
  (type $out-closed (future $out-close-reason))
  (type $out-byte-stream
    (record
      (field "bytes" $out-bytes)
      (field "closed" $out-closed)))
  (type $out-run-type
    (func async
      (param "input" $out-byte-stream)
      (result $out-byte-stream)))

  ;; This local implementation exists only to give the relay its own exact
  ;; validator provenance. Profile 1 async cannot execute it.
  (core func $task-return
    (canon task.return (result $out-byte-stream)))
  (core instance $builtins
    (export "task-return" (func $task-return)))
  (core module $relay
    (import "test:c65-validation" "task-return"
      (func $task-return (param i32 i32)))
    (func (export "run")
      (param $input-bytes i32)
      (param $input-closed i32)
      (result i32)
      local.get $input-bytes
      local.get $input-closed
      call $task-return
      i32.const 0)
    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0))
  (core instance $relay-instance
    (instantiate $relay
      (with "test:c65-validation" (instance $builtins))))
  (alias core export $relay-instance "run" (core func $run))
  (alias core export $relay-instance "callback" (core func $callback))
  (func $lifted-run (type $out-run-type)
    (canon lift (core func $run)
      async
      (callback (core func $callback))))
  (instance $pipe-out
    (export "close-reason" (type $out-close-reason))
    (export "bytes" (type $out-bytes))
    (export "closed" (type $out-closed))
    (export "byte-stream" (type $out-byte-stream))
    (export "run" (func $lifted-run)))
  (export "test:c65-chain/pipe@1.0.0" (instance $pipe-out)))
