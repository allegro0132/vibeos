.section .text.boot.entry,"ax"
.option push
.option nopic
.option norelax
.option norvc
.global _start
_start:
    csrw sie, zero
    csrw sip, zero
    // All addresses in this stub are PC-relative; no GOT is usable yet.
    lla t0, _start
    lla t1, __rela_start
    lla t2, __rela_end
    lla t5, __image_file_end
    sub t5, t5, t0
    lla t6, __image_mem_end
    sub t6, t6, t0
1:
    bgeu t1, t2, 3f
    ld t3, 8(t1)
    li t4, 3
    bne t3, t4, 4f
    ld t3, 0(t1)
    lla t4, __text_end
    sub t4, t4, t0
    bltu t3, t4, 4f
    andi t4, t3, 7
    bnez t4, 4f
    addi t4, t3, 8
    bltu t4, t3, 4f
    bgtu t4, t5, 4f
    ld t4, 16(t1)
    bgtu t4, t6, 4f
    add t3, t3, t0
    add t4, t4, t0
    sd t4, 0(t3)
    addi t1, t1, 24
    j 1b
3:
    fence rw, rw
    fence.i
    // The kernel owns BSS clearing and stack initialization. a0/a1 survive.
    tail vibeos_kernel_start
4:
    // No admitted console exists yet. Request SBI failure shutdown, then park.
    li a7, 0x53525354
    li a6, 0
    li a0, 0
    li a1, 1
    ecall
5:  wfi
    j 5b
.option pop
