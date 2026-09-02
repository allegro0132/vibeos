(module
  (memory 1 256)
  (func (export "grow") (param i32) (result i32)
    local.get 0
    memory.grow))
