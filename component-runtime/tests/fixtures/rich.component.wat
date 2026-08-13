(component
  ;; Executable Core guest for the exported filter interface. Its memory also
  ;; contains small observability counters used by the synchronous runtime
  ;; tests: realloc calls at 4, transform calls at 8, the last flags word at
  ;; 12, the last borrowed-resource handle at 16, post-return calls at 20, and
  ;; successful argument frees at 28.
  (core module $guest
    (memory (export "memory") 1 1)

    ;; The bump pointer begins above all fixed result scratch regions.
    (data (i32.const 0) "\00\80\00\00")

    (func (export "cabi_realloc")
      (param $old-pointer i32)
      (param $old-size i32)
      (param $alignment i32)
      (param $new-size i32)
      (result i32)
      (local $pointer i32)

      i32.const 4
      i32.const 4
      i32.load
      i32.const 1
      i32.add
      i32.store

      local.get $new-size
      i32.eqz
      if
        i32.const 28
        i32.const 28
        i32.load
        i32.const 1
        i32.add
        i32.store
        i32.const 0
        return
      end

      ;; This fixture only needs the allocate form used while lowering the
      ;; UTF-8 string and byte list. Retain an existing pointer for the
      ;; reallocate form so the signature remains a valid canonical realloc.
      local.get $old-pointer
      if
        local.get $old-pointer
        return
      end

      i32.const 0
      i32.load
      local.get $alignment
      i32.const 1
      i32.sub
      i32.add
      local.get $alignment
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

      local.get $pointer)

    ;; Canonical signature for:
    ;;   transform: func(value: request, source: borrow<random-source>)
    ;;       -> response
    ;;
    ;; request flattens to six i32s. response flattens to five i32s, exceeding
    ;; MAX_FLAT_RESULTS=1, so this function returns one memory32 result pointer.
    (func (export "transform")
      (param $label-pointer i32)
      (param $label-length i32)
      (param $payload-pointer i32)
      (param $payload-length i32)
      (param $attributes i32)
      (param $source i32)
      (result i32)
      (local $index i32)
      (local $byte i32)

      i32.const 8
      i32.const 8
      i32.load
      i32.const 1
      i32.add
      i32.store
      i32.const 12
      local.get $attributes
      i32.store
      i32.const 16
      local.get $source
      i32.store

      ;; Keep the deterministic fixture's fixed output regions disjoint.
      local.get $label-length
      i32.const 4096
      i32.gt_u
      if
        unreachable
      end
      local.get $payload-length
      i32.const 4096
      i32.gt_u
      if
        unreachable
      end

      ;; Uppercase ASCII label bytes into [4096, 8192).
      block $label-done
        loop $label-loop
          local.get $index
          local.get $label-length
          i32.ge_u
          br_if $label-done

          local.get $label-pointer
          local.get $index
          i32.add
          i32.load8_u
          local.tee $byte
          i32.const 97
          i32.ge_u
          local.get $byte
          i32.const 122
          i32.le_u
          i32.and
          if
            local.get $byte
            i32.const 32
            i32.sub
            local.set $byte
          end

          i32.const 4096
          local.get $index
          i32.add
          local.get $byte
          i32.store8

          local.get $index
          i32.const 1
          i32.add
          local.set $index
          br $label-loop
        end
      end

      ;; XOR each payload byte with the deterministic fixture entropy.
      i32.const 0
      local.set $index
      block $payload-done
        loop $payload-loop
          local.get $index
          local.get $payload-length
          i32.ge_u
          br_if $payload-done

          i32.const 8192
          local.get $index
          i32.add
          local.get $payload-pointer
          local.get $index
          i32.add
          i32.load8_u
          i32.const 0x5a
          i32.xor
          i32.store8

          local.get $index
          i32.const 1
          i32.add
          local.set $index
          br $payload-loop
        end
      end

      ;; response::accepted((string, list<u8>)) at address 512:
      ;;   +0  u8 accepted discriminant
      ;;   +4  string pointer, +8 string length
      ;;   +12 list pointer, +16 list length
      i32.const 512
      i32.const 0
      i32.store8
      i32.const 516
      i32.const 4096
      i32.store
      i32.const 520
      local.get $label-length
      i32.store
      i32.const 524
      i32.const 8192
      i32.store
      i32.const 528
      local.get $payload-length
      i32.store
      i32.const 512)

    (func (export "cabi_post_transform") (param $result-pointer i32)
      i32.const 20
      i32.const 20
      i32.load
      i32.const 1
      i32.add
      i32.store
      i32.const 24
      local.get $result-pointer
      i32.store)
  )

  (core instance $guest-instance (instantiate $guest))
  (alias core export $guest-instance "memory" (core memory $memory))
  (alias core export $guest-instance "cabi_realloc" (core func $realloc))
  (alias core export $guest-instance "transform" (core func $transform))
  (alias core export $guest-instance "cabi_post_transform" (core func $post-return))

  ;; This is the exact import from
  ;; component-format/tests/corpus/wit/world.wit. C2 uses the imported
  ;; random-source type for an inert borrowed handle; C3 will bind the live
  ;; random interface authority.
  (type $random-interface
    (instance
      (export "random-source" (type $random-source-in (sub resource)))
      (type $borrow-random-source-in (borrow $random-source-in))
      (type $random-error-private (enum "denied" "exhausted"))
      (export "random-error" (type $random-error-in (eq $random-error-private)))
      (type $fill
        (func
          (param "source" $borrow-random-source-in)
          (param "len" u32)
          (result (result (list u8) (error $random-error-in)))))
      (export "fill" (func (type $fill)))))
  (import "vibe:fixture/random@1.0.0"
    (instance $random (type $random-interface)))
  (alias export $random "random-source" (type $random-source))
  (type $borrow-random-source (borrow $random-source))

  (type $flags-value (flags "urgent" "audited"))
  (type $error-code (enum "denied" "invalid" "exhausted"))
  (type $bytes (list u8))
  (type $request
    (record
      (field "label" string)
      (field "payload" $bytes)
      (field "attributes" $flags-value)))
  (type $accepted (tuple string $bytes))
  (type $response
    (variant
      (case "accepted" $accepted)
      (case "rejected" $error-code)))
  (type $transform-type
    (func
      (param "value" $request)
      (param "source" $borrow-random-source)
      (result $response)))

  (func $lifted-transform (type $transform-type)
    (canon lift (core func $transform)
      string-encoding=utf8
      (memory $memory)
      (realloc $realloc)
      (post-return $post-return)))

  ;; WIT interfaces are represented by structural component instances. The
  ;; runtime resolves this one bounded FromExports layer to the lifted func.
  (instance $filter
    (export "random-source" (type $random-source))
    (export "flags-value" (type $flags-value))
    (export "error-code" (type $error-code))
    (export "request" (type $request))
    (export "response" (type $response))
    (export "transform" (func $lifted-transform)))
  (export "vibe:fixture/filter@1.0.0" (instance $filter))
)
