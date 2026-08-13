(component
  (core module $memory-provider
    (memory (export "memory") 1 1))
  (core module $guest
    (type $pair-type (func (param i32)))
    (import "vibe:test/pair@1.0.0" "get" (func $get (type $pair-type)))
    (func (export "run") (result i32)
      i32.const 64
      call $get
      i32.const 7))

  (type $pair (tuple u32 u32))
  (type $pair-interface
    (instance
      (type $get-type (func (result $pair)))
      (export "get" (func (type $get-type)))))
  (import "vibe:test/pair@1.0.0"
    (instance $pair-host (type $pair-interface)))
  (alias export $pair-host "get" (func $get))

  (core instance $memory-provider-instance (instantiate $memory-provider))
  (alias core export $memory-provider-instance "memory" (core memory $memory))
  (core func $lowered-get
    (canon lower (func $get) (memory $memory)))
  (core instance $pair-core
    (export "get" (func $lowered-get)))
  (core instance $guest-instance
    (instantiate $guest
      (with "vibe:test/pair@1.0.0" (instance $pair-core))))

  (alias core export $guest-instance "run" (core func $run))
  (type $run-type (func (result u32)))
  (func $lifted-run (type $run-type) (canon lift (core func $run)))
  (export "run" (func $lifted-run)))
