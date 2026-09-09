//! Assembly-only probe keeps the Rust caller's complete FP context intact.
core::arch::global_asm!(r#"
.option push
.option arch, +f, +d
.section .text
.balign 4
.global wasmtime_fp_context_probe
wasmtime_fp_context_probe:
    addi sp, sp, -560
    sd ra, 552(sp)
    mv a0, sp
    call vibeos_wasmtime_save_fp
    li t0, 1000
    fmv.d.x f0, t0
    li t0, 1001
    fmv.d.x f1, t0
    li t0, 1002
    fmv.d.x f2, t0
    li t0, 1003
    fmv.d.x f3, t0
    li t0, 1004
    fmv.d.x f4, t0
    li t0, 1005
    fmv.d.x f5, t0
    li t0, 1006
    fmv.d.x f6, t0
    li t0, 1007
    fmv.d.x f7, t0
    li t0, 1008
    fmv.d.x f8, t0
    li t0, 1009
    fmv.d.x f9, t0
    li t0, 1010
    fmv.d.x f10, t0
    li t0, 1011
    fmv.d.x f11, t0
    li t0, 1012
    fmv.d.x f12, t0
    li t0, 1013
    fmv.d.x f13, t0
    li t0, 1014
    fmv.d.x f14, t0
    li t0, 1015
    fmv.d.x f15, t0
    li t0, 1016
    fmv.d.x f16, t0
    li t0, 1017
    fmv.d.x f17, t0
    li t0, 1018
    fmv.d.x f18, t0
    li t0, 1019
    fmv.d.x f19, t0
    li t0, 1020
    fmv.d.x f20, t0
    li t0, 1021
    fmv.d.x f21, t0
    li t0, 1022
    fmv.d.x f22, t0
    li t0, 1023
    fmv.d.x f23, t0
    li t0, 1024
    fmv.d.x f24, t0
    li t0, 1025
    fmv.d.x f25, t0
    li t0, 1026
    fmv.d.x f26, t0
    li t0, 1027
    fmv.d.x f27, t0
    li t0, 1028
    fmv.d.x f28, t0
    li t0, 1029
    fmv.d.x f29, t0
    li t0, 1030
    fmv.d.x f30, t0
    li t0, 1031
    fmv.d.x f31, t0
    li t0, 0x60
    fscsr t0
    addi a0, sp, 272
    call vibeos_wasmtime_save_fp
    fmv.d.x f0, zero
    fmv.d.x f1, zero
    fmv.d.x f2, zero
    fmv.d.x f3, zero
    fmv.d.x f4, zero
    fmv.d.x f5, zero
    fmv.d.x f6, zero
    fmv.d.x f7, zero
    fmv.d.x f8, zero
    fmv.d.x f9, zero
    fmv.d.x f10, zero
    fmv.d.x f11, zero
    fmv.d.x f12, zero
    fmv.d.x f13, zero
    fmv.d.x f14, zero
    fmv.d.x f15, zero
    fmv.d.x f16, zero
    fmv.d.x f17, zero
    fmv.d.x f18, zero
    fmv.d.x f19, zero
    fmv.d.x f20, zero
    fmv.d.x f21, zero
    fmv.d.x f22, zero
    fmv.d.x f23, zero
    fmv.d.x f24, zero
    fmv.d.x f25, zero
    fmv.d.x f26, zero
    fmv.d.x f27, zero
    fmv.d.x f28, zero
    fmv.d.x f29, zero
    fmv.d.x f30, zero
    fmv.d.x f31, zero
    fscsr zero
    addi a0, sp, 272
    call vibeos_wasmtime_restore_fp
    fmv.x.d t0, f0
    li t1, 1000
    bne t0, t1, 2f
    fmv.x.d t0, f1
    li t1, 1001
    bne t0, t1, 2f
    fmv.x.d t0, f2
    li t1, 1002
    bne t0, t1, 2f
    fmv.x.d t0, f3
    li t1, 1003
    bne t0, t1, 2f
    fmv.x.d t0, f4
    li t1, 1004
    bne t0, t1, 2f
    fmv.x.d t0, f5
    li t1, 1005
    bne t0, t1, 2f
    fmv.x.d t0, f6
    li t1, 1006
    bne t0, t1, 2f
    fmv.x.d t0, f7
    li t1, 1007
    bne t0, t1, 2f
    fmv.x.d t0, f8
    li t1, 1008
    bne t0, t1, 2f
    fmv.x.d t0, f9
    li t1, 1009
    bne t0, t1, 2f
    fmv.x.d t0, f10
    li t1, 1010
    bne t0, t1, 2f
    fmv.x.d t0, f11
    li t1, 1011
    bne t0, t1, 2f
    fmv.x.d t0, f12
    li t1, 1012
    bne t0, t1, 2f
    fmv.x.d t0, f13
    li t1, 1013
    bne t0, t1, 2f
    fmv.x.d t0, f14
    li t1, 1014
    bne t0, t1, 2f
    fmv.x.d t0, f15
    li t1, 1015
    bne t0, t1, 2f
    fmv.x.d t0, f16
    li t1, 1016
    bne t0, t1, 2f
    fmv.x.d t0, f17
    li t1, 1017
    bne t0, t1, 2f
    fmv.x.d t0, f18
    li t1, 1018
    bne t0, t1, 2f
    fmv.x.d t0, f19
    li t1, 1019
    bne t0, t1, 2f
    fmv.x.d t0, f20
    li t1, 1020
    bne t0, t1, 2f
    fmv.x.d t0, f21
    li t1, 1021
    bne t0, t1, 2f
    fmv.x.d t0, f22
    li t1, 1022
    bne t0, t1, 2f
    fmv.x.d t0, f23
    li t1, 1023
    bne t0, t1, 2f
    fmv.x.d t0, f24
    li t1, 1024
    bne t0, t1, 2f
    fmv.x.d t0, f25
    li t1, 1025
    bne t0, t1, 2f
    fmv.x.d t0, f26
    li t1, 1026
    bne t0, t1, 2f
    fmv.x.d t0, f27
    li t1, 1027
    bne t0, t1, 2f
    fmv.x.d t0, f28
    li t1, 1028
    bne t0, t1, 2f
    fmv.x.d t0, f29
    li t1, 1029
    bne t0, t1, 2f
    fmv.x.d t0, f30
    li t1, 1030
    bne t0, t1, 2f
    fmv.x.d t0, f31
    li t1, 1031
    bne t0, t1, 2f
    frcsr t0
    li t1, 0x60
    bne t0, t1, 2f
    li a0, 0
    j 3f
2:
    li a0, 1
3:
    sd a0, 544(sp)
    mv a0, sp
    call vibeos_wasmtime_restore_fp
    ld a0, 544(sp)
    ld ra, 552(sp)
    addi sp, sp, 560
    ret
.option pop
"#);
unsafe extern "C" { pub fn wasmtime_fp_context_probe() -> u32; }
