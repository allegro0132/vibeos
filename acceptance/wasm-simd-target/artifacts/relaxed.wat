(module
  (func (export "run") (param v128 v128 v128) (result v128)
    local.get 0
    local.get 1
    local.get 2
    f32x4.relaxed_madd))
