(component
  ;; Scalar-only C3 fixture. Keeping the host edge free of memory/realloc
  ;; makes the authority/resource behavior independently executable before the
  ;; richer host Canonical ABI cases are enabled.
  (core module $guest
    (type $now-type (func (param i32) (result i64)))
    (import "vibe:clock/monotonic@1.0.0" "now"
      (func $now (type $now-type)))
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
  (core instance $guest-instance
    (instantiate $guest
      (with "vibe:clock/monotonic@1.0.0" (instance $clock-core))))

  (alias core export $guest-instance "run" (core func $run))
  (type $borrow-clock (borrow $clock-resource))
  (type $run-type
    (func
      (param "clock" $borrow-clock)
      (result u64)))
  (func $lifted-run (type $run-type) (canon lift (core func $run)))
  ;; Export the nominal resource type alongside every direct function that
  ;; mentions it. This gives exact-world normalization a stable type name and
  ;; prevents a same-shaped foreign resource from being substituted.
  (export "clock" (type $clock-resource))
  (export "run" (func $lifted-run))
)
