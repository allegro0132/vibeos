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

  (type $log-interface
    (instance
      (export "structured-log" (type $log-in (sub resource)))
      (type $borrow-log-in (borrow $log-in))
      (type $level-private (enum "trace" "debug" "info" "warn" "error"))
      (export "level" (type $level-in (eq $level-private)))
      (type $field-private (record (field "key" string) (field "value" string)))
      (export "field" (type $field-in (eq $field-private)))
      (type $fields-in (list $field-in))
      (type $event-private
        (record
          (field "level" $level-in)
          (field "target" string)
          (field "message" string)
          (field "fields" $fields-in)))
      (export "event" (type $event-in (eq $event-private)))
      (type $error-private (enum "denied" "invalid" "failed"))
      (export "log-error" (type $error-in (eq $error-private)))
      (type $write-type
        (func
          (param "log" $borrow-log-in)
          (param "event" $event-in)
          (result (result (error $error-in)))))
      (export "write" (func (type $write-type)))))
  (import "vibe:log/structured@1.0.0" (instance $log-api (type $log-interface)))
  (alias export $log-api "structured-log" (type $log))
  (alias export $log-api "level" (type $level))
  (alias export $log-api "field" (type $field))
  (alias export $log-api "event" (type $event))
  (alias export $log-api "log-error" (type $log-error))
  (alias export $log-api "write" (func $write))
  (type $borrow-log (borrow $log))
  (type $run-type
    (func
      (param "log" $borrow-log)
      (param "event" $event)
      (result (result (error $log-error)))))

  (core func $lowered-write
    (canon lower (func $write)
      string-encoding=utf8
      (memory $memory)
      (realloc $realloc)))
  (core instance $log-core (export "write" (func $lowered-write)))

  (core module $guest
    (type $write-core (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32)))
    (type $realloc-core (func (param i32 i32 i32 i32) (result i32)))
    (import "vibe:log/structured@1.0.0" "write" (func $write (type $write-core)))
    (import "env" "memory" (memory 1 1))
    (import "env" "realloc" (func $guest-realloc (type $realloc-core)))
    (export "memory" (memory 0))
    (export "realloc" (func $guest-realloc))
    (func (export "run")
      (param $log i32)
      (param $level i32)
      (param $target-pointer i32)
      (param $target-length i32)
      (param $message-pointer i32)
      (param $message-length i32)
      (param $fields-pointer i32)
      (param $fields-length i32)
      (result i32)
      local.get $log
      local.get $level
      local.get $target-pointer
      local.get $target-length
      local.get $message-pointer
      local.get $message-length
      local.get $fields-pointer
      local.get $fields-length
      i32.const 512
      call $write
      i32.const 512)
    (func (export "cabi_post_run") (param i32)))
  (core instance $guest-instance
    (instantiate $guest
      (with "vibe:log/structured@1.0.0" (instance $log-core))
      (with "env" (instance $memory-instance))))
  (alias core export $guest-instance "run" (core func $run))
  (alias core export $guest-instance "memory" (core memory $guest-memory))
  (alias core export $guest-instance "realloc" (core func $guest-realloc))
  (alias core export $guest-instance "cabi_post_run" (core func $post-run))
  (func $lifted-run (type $run-type)
    (canon lift (core func $run)
      string-encoding=utf8
      (memory $guest-memory)
      (realloc $guest-realloc)
      (post-return $post-run)))
  (export "run" (func $lifted-run))
)
