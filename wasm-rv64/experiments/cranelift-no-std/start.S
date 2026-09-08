.section .text.start,"ax"
.option norelax
.global _start
_start:
la sp,stack_top
call probe
1: wfi
j 1b
.balign 16
.global trap_entry
trap_entry:
la sp,trap_stack_top
call trap_report
j 1b
.section .bss
.balign 16
.skip 16384
stack_top:
.skip 4096
trap_stack_top:
