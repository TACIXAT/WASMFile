(module
  (import "imports" "trigger" (func $wh.trigger))
  (func (export "add") (result i32)
    i32.const 65534
    i32.const 2
    call $add
  )
  (func $add (param $x i32) (param $y i32) (result i32)
    get_local 0 
    get_local 1 
    call $wh.store.i32
    call $wh.trigger

    i32.const 0 ;; offset
    i32.load
    set_local 0 ;; value

    i32.const 4 ;; offset
    i32.load
    set_local 1 ;; value

    ;; original
    get_local $x
    get_local $y
    i32.add
  )
  (func $wh.store.i32 (param i32 i32)
    i32.const 0 ;; offset
    get_local 0 ;; value
    i32.store
    i32.const 4 ;; offset
    get_local 1 ;; value
    i32.store
  )
  (memory (export "wh_mem") 8)
)
