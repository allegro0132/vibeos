(component
  (core module $m
    (func (export "add") (param i32 i32) (result i32)
      local.get 0 local.get 1 i32.add))
  (core instance $i (instantiate $m))
  (func $lifted (param "lhs" s32) (param "rhs" s32) (result s32)
    (canon lift (core func $i "add")))
  (core func $lowered (canon lower (func $lifted)))
  (export "add" (func $lifted)))
