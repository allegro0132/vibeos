(component
  ;; This candidate has no imports, adapters, start section, or ambient
  ;; authority. The bounded memory exists solely for F4 lifecycle quota
  ;; accounting; the scalar export does not receive it as a Canonical ABI
  ;; option.
  (core module $guest
    (memory (export "memory") 1 2)

    ;; mode 0: deterministic successful scalar-float work.
    ;; mode 1: deterministic guest trap.
    ;; other: deterministic non-termination bounded by fuel/cancellation.
    (func (export "run")
      (param $mode i32)
      (param $left f32)
      (param $right f64)
      (result f64)
      local.get $mode
      i32.eqz
      if
        local.get $left
        f64.promote_f32
        local.get $right
        f64.add
        return
      end

      local.get $mode
      i32.const 1
      i32.eq
      if
        unreachable
      end

      loop $spin
        br $spin
      end
      unreachable))

  (core instance $guest-instance (instantiate $guest))
  (alias core export $guest-instance "run" (core func $run-core))

  (type $run-type
    (func
      (param "mode" u32)
      (param "left" f32)
      (param "right" f64)
      (result f64)))
  (func $run (type $run-type) (canon lift (core func $run-core)))
  (export "run" (func $run)))
