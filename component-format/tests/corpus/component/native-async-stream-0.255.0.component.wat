(component
  (core module $m
    (func (export "run") (param i32 i32) (result i32)
      i32.const 0)
    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0))
  (core instance $i (instantiate $m))
  (alias core export $i "run" (core func $run))
  (alias core export $i "callback" (core func $callback))

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
  (func $lifted (type $run-type)
    (canon lift (core func $run)
      async
      (callback (core func $callback))))
  (export "run" (func $lifted)))
