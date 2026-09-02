(module
  (memory 1 1)
  (func (export "run") (param v128) (result v128)
    i32.const 0
    local.get 0
    v128.store
    i32.const 0
    v128.load))
