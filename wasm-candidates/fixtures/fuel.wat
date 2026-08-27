(module
  (func (export "burn") (param i32) (result i32)
    (local i32)
    local.get 0
    local.set 1
    block $done
      loop $again
        local.get 1
        i32.eqz
        br_if $done
        local.get 1
        i32.const 1
        i32.sub
        local.set 1
        br $again
      end
    end
    local.get 1))
