OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  RAM (rwxa) : ORIGIN = 0x80200000, LENGTH = 126M
}

SECTIONS {
  . = ORIGIN(RAM);

  .text : ALIGN(4K) {
    KEEP(*(.text.boot))
    *(.text .text.*)
  } > RAM

  .rodata : ALIGN(4K) {
    *(.rodata .rodata.*)
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

  /* One fixed kernel stack per logical scheduler hart.  The bank is indexed
     by the HSM opaque logical id before the secondary enters Rust, so no two
     physical harts ever share a live stack. */
  . = ALIGN(4K);
  __stack_bottom = .;
  __stacks_bottom = .;
  __kernel_stack_size = 256K;
  . += 4 * 256K;
  __stacks_top = .;

  /* Retain the historical boot-stack top symbol for the cold entry path. */
  __stack_top = __stack_bottom + 256K;

  . = ALIGN(4K);
  __heap_start = .;
  . = ORIGIN(RAM) + LENGTH(RAM);
  __heap_end = .;

  /DISCARD/ : { *(.eh_frame) *(.comment) *(.note .note.*) }
}
