// C memcpy ABI: a0=destination (also the return value), a1=source, a2=length.
// Both ranges must be wholly in cacheable DRAM above the non-cacheable DMA
// arena. The generic implementation retains all smaller and other copies.
.section .text.rv2_packet_copy,"ax",@progbits
.option push
.option arch,+zbb
.p2align 2
.global __wrap_memcpy
.type __wrap_memcpy,@function
__wrap_memcpy:
.ifdef rv2_profile_copy
    li      t0, 128
    bgeu    a2, t0, rv2_timed_copy
.endif
.Lcopy_body:
    li      t0, 32
    bltu    a2, t0, .Loriginal
    li      t0, {cached_start}
    minu    t1, a0, a1
    bltu    t1, t0, .Loriginal
    lla     t0, __heap_end
    maxu    t1, a0, a1
    bltu    t0, t1, .Loriginal
    sub     t0, t0, t1
    bltu    t0, a2, .Loriginal

    mv      a3, a0
    neg     t0, a3
    andi    t0, t0, 7
    beqz    t0, .Lcheck_source
    sub     a2, a2, t0
    add     t0, t0, a3
.Lalign_destination:
    lbu     t1, 0(a1)
    sb      t1, 0(a3)
    addi    a1, a1, 1
    addi    a3, a3, 1
    bne     a3, t0, .Lalign_destination
.Lcheck_source:
    andi    t1, a1, 7
    bnez    t1, .Ldifferent_alignment
    li      t0, 32
    bltu    a2, t0, .Lwords
.Laligned32:
    ld      a4,  0(a1)
    ld      a5,  8(a1)
    ld      a6, 16(a1)
    ld      a7, 24(a1)
    sd      a4,  0(a3)
    sd      a5,  8(a3)
    sd      a6, 16(a3)
    sd      a7, 24(a3)
    addi    a1, a1, 32
    addi    a3, a3, 32
    addi    a2, a2, -32
    bgeu    a2, t0, .Laligned32
.Lwords:
    li      t0, 8
    bltu    a2, t0, .Lbytes
.Lword:
    ld      t1, 0(a1)
    sd      t1, 0(a3)
    addi    a1, a1, 8
    addi    a3, a3, 8
    addi    a2, a2, -8
    bgeu    a2, t0, .Lword
.Lbytes:
    beqz    a2, .Ldone
.Lbyte:
    lbu     t1, 0(a1)
    sb      t1, 0(a3)
    addi    a1, a1, 1
    addi    a3, a3, 1
    addi    a2, a2, -1
    bnez    a2, .Lbyte
.Ldone:
    ret
.Loriginal:
    tail    __real_memcpy

.Ldifferent_alignment:
    // Keep the destination aligned. Copy the first eight bytes in bounds
    // so rounding the following source down cannot read before the slice.
    // t2 is the minimum input remaining for the last aligned load of a group.
    li      t2, 40
    sub     t2, t2, t1
    andi    t0, t1, 1
    bnez    t0, .Lbyte_lead
    lhu     a4, 0(a1)
    lhu     a5, 2(a1)
    lhu     a6, 4(a1)
    lhu     a7, 6(a1)
    sh      a4, 0(a3)
    sh      a5, 2(a3)
    sh      a6, 4(a3)
    sh      a7, 6(a3)
    addi    a1, a1, 8
    addi    a3, a3, 8
    j       .Llead_done
.Lbyte_lead:
    addi    t0, a3, 8
.Llead:
    lbu     t3, 0(a1)
    sb      t3, 0(a3)
    addi    a1, a1, 1
    addi    a3, a3, 1
    bne     a3, t0, .Llead
.Llead_done:
    addi    a2, a2, -8

    andi    t3, a1, -8
    slli    t4, t1, 3
    neg     t5, t4              // RV64 shifts use the low six bits
    ld      t0, 0(t3)
    bltu    a2, t2, .Lmerge_words
.Lmerge32:
    ld      a4,  8(t3)
    ld      a5, 16(t3)
    ld      a6, 24(t3)
    ld      a7, 32(t3)
    srl     t0, t0, t4
    sll     t6, a4, t5
    or      t0, t0, t6
    sd      t0, 0(a3)
    srl     a4, a4, t4
    sll     t6, a5, t5
    or      a4, a4, t6
    sd      a4, 8(a3)
    srl     a5, a5, t4
    sll     t6, a6, t5
    or      a5, a5, t6
    sd      a5, 16(a3)
    srl     a6, a6, t4
    sll     t6, a7, t5
    or      a6, a6, t6
    sd      a6, 24(a3)
    mv      t0, a7
    addi    t3, t3, 32
    addi    a3, a3, 32
    addi    a2, a2, -32
    bgeu    a2, t2, .Lmerge32
.Lmerge_words:
    addi    t2, t2, -24         // 16 - source_offset bytes cover a word pair
    bltu    a2, t2, .Lmerge_tail
.Lmerge8:
    ld      a4, 8(t3)
    srl     t0, t0, t4
    sll     t6, a4, t5
    or      t0, t0, t6
    sd      t0, 0(a3)
    mv      t0, a4
    addi    t3, t3, 8
    addi    a3, a3, 8
    addi    a2, a2, -8
    bgeu    a2, t2, .Lmerge8
.Lmerge_tail:
    add     a1, t3, t1
    andi    t0, t1, 1
    bnez    t0, .Lbytes
    li      t0, 2
    bltu    a2, t0, .Lbytes
.Lhalfword:
    lhu     t1, 0(a1)
    sh      t1, 0(a3)
    addi    a1, a1, 2
    addi    a3, a3, 2
    addi    a2, a2, -2
    bgeu    a2, t0, .Lhalfword
    j       .Lbytes
.size __wrap_memcpy, .-__wrap_memcpy
.option pop
