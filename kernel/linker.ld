OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  RAM (rwxa) : ORIGIN = 0x80200000, LENGTH = 126M
}

SECTIONS {
  . = ORIGIN(RAM);

  .text : ALIGN(4K) {
    __text_start = .;
    KEEP(*(.text.boot))
    *(.text .text.*)
    . = ALIGN(4K);
    __text_end = .;
  } > RAM

  .rodata : ALIGN(4K) {
    __rodata_start = .;
    *(.rodata .rodata.*)
    . = ALIGN(4K);
    __rodata_end = .;
  } > RAM

  .data : ALIGN(4K) {
    __global_pointer$ = . + 0x800;
    *(.sdata .sdata.*)
    *(.data .data.*)
  } > RAM

  .bss (NOLOAD) : ALIGN(4K) {
    __bss_start = .;
    *(.sbss .sbss.*)
    *(.bss .bss.*)
    . = ALIGN(16);
    __bss_end = .;
  } > RAM

  /* Device-visible storage is stable across component arena reclamation. It
     is explicitly initialized by the driver before use. */
  .dma (NOLOAD) : ALIGN(4K) {
    __dma_start = .;
    KEEP(*(.dma))
    . = ALIGN(4K);
    __dma_end = .;
  } > RAM

  /* Generated code never shares a page with heap data. Pages start RW-NX,
     become execute-only after linking, and return to RW-NX before reuse. */
  .code_pool (NOLOAD) : ALIGN(4K) {
    __code_pool_start = .;
    . += 2M;
    __code_pool_end = .;
  } > RAM

  /* Authoritative capability-table snapshots use page-exclusive storage.
     Builders are RW-NX; publication makes the complete snapshot read-only. */
  .cap_table_pool (NOLOAD) : ALIGN(4K) {
    __cap_table_pool_start = .;
    . += 4M;
    __cap_table_pool_end = .;
  } > RAM

  /* One fixed stack slot per logical scheduler hart. The first 4 KiB of every
     256 KiB slot is physically reserved but left unmapped by Sv39; the
     remaining 252 KiB is the usable downward-growing stack. Keeping the slot
     stride at 256 KiB preserves the shift-only HSM entry path. */
  . = ALIGN(4K);
  __stacks_bottom = .;
  __stack_guard_size = 4K;
  __kernel_stack_stride = 256K;
  __kernel_stack_size = __kernel_stack_stride - __stack_guard_size;
  __stack_bottom = __stacks_bottom + __stack_guard_size;
  . += 4 * __kernel_stack_stride;
  __stacks_top = .;

  /* Retain the historical boot-stack top symbol for the cold entry path. */
  __stack_top = __stacks_bottom + __kernel_stack_stride;

  . = ALIGN(4K);
  __heap_start = .;
  . = ORIGIN(RAM) + LENGTH(RAM);
  __heap_end = .;

  /DISCARD/ : { *(.eh_frame) *(.comment) *(.note .note.*) }
}
