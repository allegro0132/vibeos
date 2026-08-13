(component
  ;; Instance 0 owns the lowered host import and exports a wrapper. Instance 1
  ;; imports that exact prior function and is the top-level active continuation.
  (core module $provider
    (type $now-type (func (param i32) (result i64)))
    (import "vibe:clock/monotonic@1.0.0" "now"
      (func $now (type $now-type)))
    (func (export "wrapped-now") (param $clock i32) (result i64)
      local.get $clock
      call $now))
  (core module $consumer
    (type $now-type (func (param i32) (result i64)))
    (import "provider" "wrapped-now" (func $now (type $now-type)))
    (func (export "run") (param $clock i32) (result i64)
      local.get $clock
      call $now))

  (type $clock-interface
    (instance
      (export "clock" (type (sub resource)))
      (type $borrow-clock (borrow 0))
      (type $now-type
        (func
          (param "clock" $borrow-clock)
          (result u64)))
      (export "now" (func (type $now-type)))))
  (import "vibe:clock/monotonic@1.0.0"
    (instance $clock (type $clock-interface)))
  (alias export $clock "clock" (type $clock-resource))
  (alias export $clock "now" (func $now))

  (core func $lowered-now (canon lower (func $now)))
  (core instance $clock-core
    (export "now" (func $lowered-now)))
  (core instance $provider-instance
    (instantiate $provider
      (with "vibe:clock/monotonic@1.0.0" (instance $clock-core))))
  (core instance $consumer-instance
    (instantiate $consumer
      (with "provider" (instance $provider-instance))))

  (alias core export $consumer-instance "run" (core func $run))
  (type $borrow-clock (borrow $clock-resource))
  (type $run-type
    (func
      (param "clock" $borrow-clock)
      (result u64)))
  (func $lifted-run (type $run-type) (canon lift (core func $run)))
  (export "clock" (type $clock-resource))
  (export "run" (func $lifted-run))
)
