(module
  (import "imports" "logi32" (func $logi32 (param i32)))
  (func (export "log")
    i32.const 10
    i32.const 2
    call $add
    call $logi32
  )
  (func $add (param $x i32) (param $y i32) (result i32)
    get_local $x
    get_local $y
    i32.add
  )
)
