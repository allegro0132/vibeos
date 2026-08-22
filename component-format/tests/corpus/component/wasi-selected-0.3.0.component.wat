(component
  (type $clock-types-interface
    (instance
      (type $duration-private u64)
      (export "duration" (type $duration-in (eq $duration-private)))))
  (import "wasi:clocks/types@0.3.0"
    (instance $clock-types (type $clock-types-interface)))

  (type $monotonic-clock-interface
    (instance
      (type $duration-private u64)
      (export "duration" (type $duration-in (eq $duration-private)))
      (type $mark-private u64)
      (export "mark" (type $mark-in (eq $mark-private)))
      (type $now (func (result $mark-in)))
      (type $get-resolution (func (result $duration-in)))
      (type $wait-until (func async (param "when" $mark-in)))
      (type $wait-for (func async (param "how-long" $duration-in)))
      (export "now" (func (type $now)))
      (export "get-resolution" (func (type $get-resolution)))
      (export "wait-until" (func (type $wait-until)))
      (export "wait-for" (func (type $wait-for)))))
  (import "wasi:clocks/monotonic-clock@0.3.0"
    (instance $monotonic-clock (type $monotonic-clock-interface)))

  (type $random-interface
    (instance
      (type $get-random-bytes
        (func (param "max-len" u64) (result (list u8))))
      (type $get-random-u64 (func (result u64)))
      (export "get-random-bytes" (func (type $get-random-bytes)))
      (export "get-random-u64" (func (type $get-random-u64)))))
  (import "wasi:random/random@0.3.0"
    (instance $random (type $random-interface)))

  (type $cli-types-interface
    (instance
      (type $error-code-private
        (enum "io" "illegal-byte-sequence" "pipe"))
      (export "error-code" (type $error-code-in (eq $error-code-private)))))
  (import "wasi:cli/types@0.3.0"
    (instance $cli-types (type $cli-types-interface)))

  (type $stdin-interface
    (instance
      (type $error-code-private
        (enum "io" "illegal-byte-sequence" "pipe"))
      (export "error-code" (type $error-code-in (eq $error-code-private)))
      (type $bytes (stream u8))
      (type $completion (result (error $error-code-in)))
      (type $completed (future $completion))
      (type $read-result (tuple $bytes $completed))
      (type $read-via-stream (func (result $read-result)))
      (export "read-via-stream" (func (type $read-via-stream)))))
  (import "wasi:cli/stdin@0.3.0"
    (instance $stdin (type $stdin-interface)))

  (type $stdout-interface
    (instance
      (type $error-code-private
        (enum "io" "illegal-byte-sequence" "pipe"))
      (export "error-code" (type $error-code-in (eq $error-code-private)))
      (type $bytes (stream u8))
      (type $completion (result (error $error-code-in)))
      (type $completed (future $completion))
      (type $write-via-stream
        (func (param "data" $bytes) (result $completed)))
      (export "write-via-stream" (func (type $write-via-stream)))))
  (import "wasi:cli/stdout@0.3.0"
    (instance $stdout (type $stdout-interface)))

  (core module $guest
    (func (export "run") (result i32) i32.const 0)
    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0))
  (core instance $guest-instance (instantiate $guest))
  (alias core export $guest-instance "run" (core func $run-core))
  (alias core export $guest-instance "callback" (core func $callback))
  (type $run-result (result))
  (type $run-type (func async (result $run-result)))
  (func $run (type $run-type)
    (canon lift (core func $run-core) async
      (callback (core func $callback))))
  (instance $run-interface (export "run" (func $run)))
  (export "wasi:cli/run@0.3.0" (instance $run-interface))
)
