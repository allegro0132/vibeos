(component
  (type $close-reason
    (enum
      "normal"
      "failure"
      "cancelled"
      "denied"
      "unavailable"
      "exhausted"
      "invalid"
      "backend-fault"))
  (type $bytes (stream u8))
  (type $closed (future $close-reason))
  (type $byte-stream
    (record
      (field "bytes" $bytes)
      (field "closed" $closed)))
  (type $run-type
    (func async
      (param "input" $byte-stream)
      (result $byte-stream)))

  ;; This bridge is validator input only. The image pin selects the
  ;; execution-disabled Profile 1 async identity, so neither function below
  ;; can become a guest entry point.
  (core func $task-return
    (canon task.return (result $byte-stream)))
  (core instance $builtins
    (export "task-return" (func $task-return)))
  (core module $source
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
  (core instance $source-instance
    (instantiate $source
      (with "test:c65-validation" (instance $builtins))))
  (alias core export $source-instance "run" (core func $run))
  (alias core export $source-instance "callback" (core func $callback))
  (func $lifted-run (type $run-type)
    (canon lift (core func $run)
      async
      (callback (core func $callback))))
  (instance $pipe
    (export "close-reason" (type $close-reason))
    (export "bytes" (type $bytes))
    (export "closed" (type $closed))
    (export "byte-stream" (type $byte-stream))
    (export "run" (func $lifted-run)))
  (export "test:c65-chain/pipe@1.0.0" (instance $pipe)))
