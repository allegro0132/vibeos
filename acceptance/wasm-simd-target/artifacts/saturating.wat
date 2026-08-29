(module
  (func (export "run") (param v128 v128) (result v128)
    local.get 0
    local.get 1
    i8x16.add_sat_u))
