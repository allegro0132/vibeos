// Instrument only bulk, out-of-line calls. Per-call attribution uses the
// original return PC. Both ABI entries return the unmodified destination.
.section .text.rv2_timed_copy,"ax",@progbits
.p2align 2
.macro timed_call target, kind
    addi sp, sp, -32
    sd   ra, 0(sp)
    sd   a2, 8(sp)
    rdtime t1
    sd   t1, 16(sp)
    call \target
    rdtime t1
    ld   t0, 16(sp)
    sd   a0, 24(sp)
    sub  a2, t1, t0
    ld   a0, 0(sp)
    ld   a1, 8(sp)
    li   a3, \kind
    call rv2_account_copy
    ld   ra, 0(sp)
    ld   a0, 24(sp)
    addi sp, sp, 32
    ret
.endm
rv2_timed_copy:
    timed_call .Lcopy_body, 0
.global __wrap_memmove
.type __wrap_memmove,@function
__wrap_memmove:
    li t0, 128
    bltu a2, t0, 1f
    timed_call __real_memmove, 1
1:  tail __real_memmove
.size __wrap_memmove, .-__wrap_memmove
