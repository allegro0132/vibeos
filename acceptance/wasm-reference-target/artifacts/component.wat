(component
  (core module
    (table 2 funcref)
    (func $f)
    (elem (i32.const 0) $f)
    (func (export "run") (result i32)
      ref.null func
      ref.is_null
      ref.func $f
      ref.is_null
      i32.add
      i32.const 0
      table.get
      ref.is_null
      i32.add)))
