(module
  (table 2 4 funcref)
  (func $f)
  (func (export "run") (result i32)
    i32.const 0
    ref.null func
    table.set
    ref.null func
    i32.const 1
    table.grow
    drop
    i32.const 0
    ref.null func
    i32.const 1
    table.fill
    table.size))
