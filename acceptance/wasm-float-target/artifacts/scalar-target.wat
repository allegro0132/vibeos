(module
  ;; C8.8-F5 integer-bit target corpus.
  ;;
  ;; `runtime` constructs every float from the integer bit pattern supplied by
  ;; the caller. f32 inputs use the low 32 bits. Float results are returned as
  ;; raw bits (f32 zero-extended to i64); comparisons return 0/1; signed i32
  ;; truncations are sign-extended and unsigned i32 truncations zero-extended.
  ;; `fold` executes the same numbered operation with literal operands so the
  ;; candidate translator's constant-fold path is target-executed too.
  ;;
  ;; op  name                     runtime a / b                         fold literals => expected i64
  ;;  0  f32.add                  f32 bits / f32 bits                   1.5 + 0.5 => 0x0000000040000000
  ;;  1  f32.sub                  f32 bits / f32 bits                   1.5 - 0.5 => 0x000000003f800000
  ;;  2  f32.mul                  f32 bits / f32 bits                   1.5 * 0.5 => 0x000000003f400000
  ;;  3  f32.div                  f32 bits / f32 bits                   1.5 / 0.5 => 0x0000000040400000
  ;;  4  f32.min                  f32 bits / f32 bits                   min(1.5,0.5) => 0x000000003f000000
  ;;  5  f32.max                  f32 bits / f32 bits                   max(1.5,0.5) => 0x000000003fc00000
  ;;  6  f32.copysign             f32 bits / f32 sign                  copysign(1.5,-0.5) => 0x00000000bfc00000
  ;;  7  f64.add                  f64 bits / f64 bits                   1.5 + 0.5 => 0x4000000000000000
  ;;  8  f64.sub                  f64 bits / f64 bits                   1.5 - 0.5 => 0x3ff0000000000000
  ;;  9  f64.mul                  f64 bits / f64 bits                   1.5 * 0.5 => 0x3fe8000000000000
  ;; 10  f64.div                  f64 bits / f64 bits                   1.5 / 0.5 => 0x4008000000000000
  ;; 11  f64.min                  f64 bits / f64 bits                   min(1.5,0.5) => 0x3fe0000000000000
  ;; 12  f64.max                  f64 bits / f64 bits                   max(1.5,0.5) => 0x3ff8000000000000
  ;; 13  f64.copysign             f64 bits / f64 sign                  copysign(1.5,-0.5) => 0xbff8000000000000
  ;; 14  f32.abs                  f32 bits / ignored                    abs(-1.5) => 0x000000003fc00000
  ;; 15  f32.neg                  f32 bits / ignored                    neg(1.5) => 0x00000000bfc00000
  ;; 16  f32.ceil                 f32 bits / ignored                    ceil(1.25) => 0x0000000040000000
  ;; 17  f32.floor                f32 bits / ignored                    floor(1.75) => 0x000000003f800000
  ;; 18  f32.trunc                f32 bits / ignored                    trunc(-1.75) => 0x00000000bf800000
  ;; 19  f32.nearest              f32 bits / ignored                    nearest(2.5) => 0x0000000040000000
  ;; 20  f32.sqrt                 f32 bits / ignored                    sqrt(4) => 0x0000000040000000
  ;; 21  f64.abs                  f64 bits / ignored                    abs(-1.5) => 0x3ff8000000000000
  ;; 22  f64.neg                  f64 bits / ignored                    neg(1.5) => 0xbff8000000000000
  ;; 23  f64.ceil                 f64 bits / ignored                    ceil(1.25) => 0x4000000000000000
  ;; 24  f64.floor                f64 bits / ignored                    floor(1.75) => 0x3ff0000000000000
  ;; 25  f64.trunc                f64 bits / ignored                    trunc(-1.75) => 0xbff0000000000000
  ;; 26  f64.nearest              f64 bits / ignored                    nearest(2.5) => 0x4000000000000000
  ;; 27  f64.sqrt                 f64 bits / ignored                    sqrt(4) => 0x4000000000000000
  ;; 28  f32.eq                   f32 bits / f32 bits                   1.5 == 1.5 => 1
  ;; 29  f32.ne                   f32 bits / f32 bits                   1.5 != 0.5 => 1
  ;; 30  f32.lt                   f32 bits / f32 bits                   0.5 < 1.5 => 1
  ;; 31  f32.gt                   f32 bits / f32 bits                   1.5 > 0.5 => 1
  ;; 32  f32.le                   f32 bits / f32 bits                   1.5 <= 1.5 => 1
  ;; 33  f32.ge                   f32 bits / f32 bits                   1.5 >= 1.5 => 1
  ;; 34  f64.eq                   f64 bits / f64 bits                   1.5 == 1.5 => 1
  ;; 35  f64.ne                   f64 bits / f64 bits                   1.5 != 0.5 => 1
  ;; 36  f64.lt                   f64 bits / f64 bits                   0.5 < 1.5 => 1
  ;; 37  f64.gt                   f64 bits / f64 bits                   1.5 > 0.5 => 1
  ;; 38  f64.le                   f64 bits / f64 bits                   1.5 <= 1.5 => 1
  ;; 39  f64.ge                   f64 bits / f64 bits                   1.5 >= 1.5 => 1
  ;; 40  i32.trunc_f32_s          f32 bits / ignored                    -7.75 => 0xfffffffffffffff9
  ;; 41  i32.trunc_f32_u          f32 bits / ignored                    7.75 => 7
  ;; 42  i64.trunc_f32_s          f32 bits / ignored                    -7.75 => 0xfffffffffffffff9
  ;; 43  i64.trunc_f32_u          f32 bits / ignored                    7.75 => 7
  ;; 44  i32.trunc_f64_s          f64 bits / ignored                    -7.75 => 0xfffffffffffffff9
  ;; 45  i32.trunc_f64_u          f64 bits / ignored                    7.75 => 7
  ;; 46  i64.trunc_f64_s          f64 bits / ignored                    -7.75 => 0xfffffffffffffff9
  ;; 47  i64.trunc_f64_u          f64 bits / ignored                    7.75 => 7
  ;; 48  f32.convert_i32_s        low i32 bits / ignored                -7 => 0x00000000c0e00000
  ;; 49  f32.convert_i32_u        low i32 bits / ignored                0xffffffff => 0x000000004f800000
  ;; 50  f32.convert_i64_s        signed i64 / ignored                  -7 => 0x00000000c0e00000
  ;; 51  f32.convert_i64_u        unsigned i64 / ignored                0xffffffffffffffff => 0x000000005f800000
  ;; 52  f64.convert_i32_s        low i32 bits / ignored                -7 => 0xc01c000000000000
  ;; 53  f64.convert_i32_u        low i32 bits / ignored                0xffffffff => 0x41efffffffe00000
  ;; 54  f64.convert_i64_s        signed i64 / ignored                  -7 => 0xc01c000000000000
  ;; 55  f64.convert_i64_u        unsigned i64 / ignored                0xffffffffffffffff => 0x43f0000000000000
  ;; 56  f64.promote_f32          f32 bits / ignored                    1.5 => 0x3ff8000000000000
  ;; 57  f32.demote_f64           f64 bits / ignored                    1.5 => 0x000000003fc00000
  ;; 58  f32.local                f32 bits / ignored                    local(1.5) => 0x000000003fc00000
  ;; 59  f64.local                f64 bits / ignored                    local(1.5) => 0x3ff8000000000000
  ;; 60  f32.global               f32 bits / ignored                    global(1.5) => 0x000000003fc00000
  ;; 61  f64.global               f64 bits / ignored                    global(1.5) => 0x3ff8000000000000
  ;; 62  f32.memory               f32 bits / ignored                    store/load(1.5) => 0x000000003fc00000
  ;; 63  f64.memory               f64 bits / ignored                    store/load(1.5) => 0x3ff8000000000000
  ;; 64  f32.select               f32 bits / f32 bits                   select(1.5,0.5,1) => 0x000000003fc00000
  ;; 65  f64.select               f64 bits / f64 bits                   select(1.5,0.5,1) => 0x3ff8000000000000
  ;; 66  f32.call                 f32 bits / ignored                    identity(1.5) => 0x000000003fc00000
  ;; 67  f64.call                 f64 bits / ignored                    identity(1.5) => 0x3ff8000000000000
  ;; 68  f32.reinterpret          f32 bits / ignored                    roundtrip(1.5) => 0x000000003fc00000
  ;; 69  f64.reinterpret          f64 bits / ignored                    roundtrip(1.5) => 0x3ff8000000000000
  ;; 70  invalid-conversion       f32 bits (caller supplies NaN)         f32 NaN -> i32.trunc_f32_s traps
  ;; 71  integer-overflow         f64 bits (caller supplies +inf)        f64 +inf -> i64.trunc_f64_s traps
  ;;
  ;; Runtime select ops return `a` when `b` is +0 and otherwise return `b`;
  ;; this keeps both candidate values and the condition dynamically derived.

  (memory 1 1)
  ;; Profile 2 deliberately keeps mutable globals disabled. The immutable
  ;; sentinels are the non-selected arm of the dynamic global transport cases.
  (global $f32-slot f32 (f32.const 0))
  (global $f64-slot f64 (f64.const 0))

  (func $identity-f32 (param $value f32) (result f32)
    local.get $value)
  (func $identity-f64 (param $value f64) (result f64)
    local.get $value)

  ;; Dynamic integer-bit paths, grouped so the strict candidate's minimum
  ;; average-function-size limit remains an enforced boundary, not padding.

  (func $r-f32-binary (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.add i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.sub i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.mul i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.div i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.min i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.max i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.copysign i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    unreachable)

  (func $r-f64-binary (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.add i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.sub i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.mul i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.div i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.min i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.max i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.copysign i64.reinterpret_f64
      return
    end
    unreachable)

  (func $r-f32-unary (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      f32.abs i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      f32.neg i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      f32.ceil i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      f32.floor i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      f32.trunc i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      f32.nearest i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      f32.sqrt i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    unreachable)

  (func $r-f64-unary (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 f64.abs i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 f64.neg i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 f64.ceil i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 f64.floor i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 f64.trunc i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 f64.nearest i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 f64.sqrt i64.reinterpret_f64
      return
    end
    unreachable)

  (func $r-f32-compare (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.eq i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.ne i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.lt i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.gt i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.le i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      f32.ge i64.extend_i32_u
      return
    end
    unreachable)

  (func $r-f64-compare (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.eq i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.ne i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.lt i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.gt i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.le i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.get 1 f64.reinterpret_i64
      f64.ge i64.extend_i32_u
      return
    end
    unreachable)

  (func $r-trunc (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      i32.trunc_f32_s i64.extend_i32_s
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      i32.trunc_f32_u i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32 i64.trunc_f32_s
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32 i64.trunc_f32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 i32.trunc_f64_s i64.extend_i32_s
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 i32.trunc_f64_u i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 i64.trunc_f64_s
      return
    end
    local.get $sub
    i32.const 7
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 i64.trunc_f64_u
      return
    end
    unreachable)

  (func $r-convert (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.convert_i32_s
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.convert_i32_u
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      local.get 0 f32.convert_i64_s i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      local.get 0 f32.convert_i64_u i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      local.get 0 i32.wrap_i64 f64.convert_i32_s i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      local.get 0 i32.wrap_i64 f64.convert_i32_u i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      local.get 0 f64.convert_i64_s i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 7
    i32.eq
    if
      local.get 0 f64.convert_i64_u i64.reinterpret_f64
      return
    end
    unreachable)

  (func $r-promote-demote (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      f64.promote_f32 i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 f32.demote_f64
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    unreachable)

  (func $r-transport (param $a i64) (param $b i64) (param $sub i32) (result i64) (local $value58 f32) (local $value59 f64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32 local.set $value58
      local.get $value58 i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 local.set $value59
      local.get $value59 i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      global.get $f32-slot i32.const 1 select
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      local.get 0 f64.reinterpret_i64
      global.get $f64-slot i32.const 1 select i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      i32.const 0 local.get 0 i32.wrap_i64 f32.reinterpret_i32 f32.store
      i32.const 0 f32.load i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      i32.const 8 local.get 0 f64.reinterpret_i64 f64.store
      i32.const 8 f64.load i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i32.wrap_i64 f32.reinterpret_i32
      local.get 1 i64.eqz select
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 7
    i32.eq
    if
      local.get 0 f64.reinterpret_i64
      local.get 1 f64.reinterpret_i64
      local.get 1 i64.eqz select i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 8
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32 call $identity-f32
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 9
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 call $identity-f64 i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 10
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      i32.reinterpret_f32 f32.reinterpret_i32
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 11
    i32.eq
    if
      local.get 0 f64.reinterpret_i64
      i64.reinterpret_f64 f64.reinterpret_i64 i64.reinterpret_f64
      return
    end
    unreachable)

  (func $r-trap (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      local.get 0 i32.wrap_i64 f32.reinterpret_i32
      i32.trunc_f32_s i64.extend_i32_s
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      local.get 0 f64.reinterpret_i64 i64.trunc_f64_s
      return
    end
    unreachable)



  ;; Literal paths use the identical op partition and numbering.

  (func $f-f32-binary (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      f32.const 1.5 f32.const 0.5 f32.add
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      f32.const 1.5 f32.const 0.5 f32.sub
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      f32.const 1.5 f32.const 0.5 f32.mul
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      f32.const 1.5 f32.const 0.5 f32.div
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      f32.const 1.5 f32.const 0.5 f32.min
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      f32.const 1.5 f32.const 0.5 f32.max
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      f32.const 1.5 f32.const -0.5 f32.copysign
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    unreachable)

  (func $f-f64-binary (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      f64.const 1.5 f64.const 0.5 f64.add i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      f64.const 1.5 f64.const 0.5 f64.sub i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      f64.const 1.5 f64.const 0.5 f64.mul i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      f64.const 1.5 f64.const 0.5 f64.div i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      f64.const 1.5 f64.const 0.5 f64.min i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      f64.const 1.5 f64.const 0.5 f64.max i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      f64.const 1.5 f64.const -0.5 f64.copysign i64.reinterpret_f64
      return
    end
    unreachable)

  (func $f-f32-unary (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      f32.const -1.5 f32.abs i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      f32.const 1.5 f32.neg i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      f32.const 1.25 f32.ceil i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      f32.const 1.75 f32.floor i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      f32.const -1.75 f32.trunc i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      f32.const 2.5 f32.nearest i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      f32.const 4 f32.sqrt i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    unreachable)

  (func $f-f64-unary (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      f64.const -1.5 f64.abs i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      f64.const 1.5 f64.neg i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      f64.const 1.25 f64.ceil i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      f64.const 1.75 f64.floor i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      f64.const -1.75 f64.trunc i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      f64.const 2.5 f64.nearest i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      f64.const 4 f64.sqrt i64.reinterpret_f64
      return
    end
    unreachable)

  (func $f-f32-compare (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      f32.const 1.5 f32.const 1.5 f32.eq i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      f32.const 1.5 f32.const 0.5 f32.ne i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      f32.const 0.5 f32.const 1.5 f32.lt i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      f32.const 1.5 f32.const 0.5 f32.gt i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      f32.const 1.5 f32.const 1.5 f32.le i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      f32.const 1.5 f32.const 1.5 f32.ge i64.extend_i32_u
      return
    end
    unreachable)

  (func $f-f64-compare (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      f64.const 1.5 f64.const 1.5 f64.eq i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      f64.const 1.5 f64.const 0.5 f64.ne i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      f64.const 0.5 f64.const 1.5 f64.lt i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      f64.const 1.5 f64.const 0.5 f64.gt i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      f64.const 1.5 f64.const 1.5 f64.le i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      f64.const 1.5 f64.const 1.5 f64.ge i64.extend_i32_u
      return
    end
    unreachable)

  (func $f-trunc (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      f32.const -7.75 i32.trunc_f32_s i64.extend_i32_s
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      f32.const 7.75 i32.trunc_f32_u i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      f32.const -7.75 i64.trunc_f32_s
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      f32.const 7.75 i64.trunc_f32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      f64.const -7.75 i32.trunc_f64_s i64.extend_i32_s
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      f64.const 7.75 i32.trunc_f64_u i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      f64.const -7.75 i64.trunc_f64_s
      return
    end
    local.get $sub
    i32.const 7
    i32.eq
    if
      f64.const 7.75 i64.trunc_f64_u
      return
    end
    unreachable)

  (func $f-convert (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      i32.const -7 f32.convert_i32_s i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      i32.const -1 f32.convert_i32_u i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      i64.const -7 f32.convert_i64_s i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      i64.const -1 f32.convert_i64_u i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      i32.const -7 f64.convert_i32_s i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      i32.const -1 f64.convert_i32_u i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      i64.const -7 f64.convert_i64_s i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 7
    i32.eq
    if
      i64.const -1 f64.convert_i64_u i64.reinterpret_f64
      return
    end
    unreachable)

  (func $f-promote-demote (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      f32.const 1.5 f64.promote_f32 i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      f64.const 1.5 f32.demote_f64 i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    unreachable)

  (func $f-transport (param $a i64) (param $b i64) (param $sub i32) (result i64) (local $value58 f32) (local $value59 f64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      f32.const 1.5 local.set $value58
      local.get $value58 i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      f64.const 1.5 local.set $value59 local.get $value59 i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 2
    i32.eq
    if
      f32.const 1.5 global.get $f32-slot i32.const 1 select
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 3
    i32.eq
    if
      f64.const 1.5 global.get $f64-slot i32.const 1 select i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 4
    i32.eq
    if
      i32.const 0 f32.const 1.5 f32.store
      i32.const 0 f32.load i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 5
    i32.eq
    if
      i32.const 8 f64.const 1.5 f64.store
      i32.const 8 f64.load i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 6
    i32.eq
    if
      f32.const 1.5 f32.const 0.5 i32.const 1 select
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 7
    i32.eq
    if
      f64.const 1.5 f64.const 0.5 i32.const 1 select i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 8
    i32.eq
    if
      f32.const 1.5 call $identity-f32 i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 9
    i32.eq
    if
      f64.const 1.5 call $identity-f64 i64.reinterpret_f64
      return
    end
    local.get $sub
    i32.const 10
    i32.eq
    if
      f32.const 1.5 i32.reinterpret_f32 f32.reinterpret_i32
      i32.reinterpret_f32 i64.extend_i32_u
      return
    end
    local.get $sub
    i32.const 11
    i32.eq
    if
      f64.const 1.5 i64.reinterpret_f64 f64.reinterpret_i64 i64.reinterpret_f64
      return
    end
    unreachable)

  (func $f-trap (param $a i64) (param $b i64) (param $sub i32) (result i64)
    local.get $sub
    i32.const 0
    i32.eq
    if
      f32.const nan i32.trunc_f32_s i64.extend_i32_s
      return
    end
    local.get $sub
    i32.const 1
    i32.eq
    if
      f64.const inf i64.trunc_f64_s
      return
    end
    unreachable)



  (func (export "runtime") (param $op i32) (param $a i64) (param $b i64) (result i64)
    local.get $op
    i32.const 7
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 0
      i32.sub
      call $r-f32-binary
      return
    end
    local.get $op
    i32.const 14
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 7
      i32.sub
      call $r-f64-binary
      return
    end
    local.get $op
    i32.const 21
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 14
      i32.sub
      call $r-f32-unary
      return
    end
    local.get $op
    i32.const 28
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 21
      i32.sub
      call $r-f64-unary
      return
    end
    local.get $op
    i32.const 34
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 28
      i32.sub
      call $r-f32-compare
      return
    end
    local.get $op
    i32.const 40
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 34
      i32.sub
      call $r-f64-compare
      return
    end
    local.get $op
    i32.const 48
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 40
      i32.sub
      call $r-trunc
      return
    end
    local.get $op
    i32.const 56
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 48
      i32.sub
      call $r-convert
      return
    end
    local.get $op
    i32.const 58
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 56
      i32.sub
      call $r-promote-demote
      return
    end
    local.get $op
    i32.const 70
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 58
      i32.sub
      call $r-transport
      return
    end
    local.get $op
    i32.const 72
    i32.lt_u
    if
      local.get $a
      local.get $b
      local.get $op
      i32.const 70
      i32.sub
      call $r-trap
      return
    end
    unreachable)



  (func (export "fold") (param $op i32) (result i64)
    local.get $op
    i32.const 7
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 0
      i32.sub
      call $f-f32-binary
      return
    end
    local.get $op
    i32.const 14
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 7
      i32.sub
      call $f-f64-binary
      return
    end
    local.get $op
    i32.const 21
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 14
      i32.sub
      call $f-f32-unary
      return
    end
    local.get $op
    i32.const 28
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 21
      i32.sub
      call $f-f64-unary
      return
    end
    local.get $op
    i32.const 34
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 28
      i32.sub
      call $f-f32-compare
      return
    end
    local.get $op
    i32.const 40
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 34
      i32.sub
      call $f-f64-compare
      return
    end
    local.get $op
    i32.const 48
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 40
      i32.sub
      call $f-trunc
      return
    end
    local.get $op
    i32.const 56
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 48
      i32.sub
      call $f-convert
      return
    end
    local.get $op
    i32.const 58
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 56
      i32.sub
      call $f-promote-demote
      return
    end
    local.get $op
    i32.const 70
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 58
      i32.sub
      call $f-transport
      return
    end
    local.get $op
    i32.const 72
    i32.lt_u
    if
      i64.const 0
      i64.const 0
      local.get $op
      i32.const 70
      i32.sub
      call $f-trap
      return
    end
    unreachable)


  ;; Deterministic non-termination for exact fuel/quantum qualification. The
  ;; loop performs real scalar-float work and has no memory or host side effect.
  (func (export "spin")
    (local $value f64)
    f64.const 1
    local.set $value
    loop $again
      local.get $value
      f64.const 1
      f64.add
      local.set $value
      br $again
    end))
