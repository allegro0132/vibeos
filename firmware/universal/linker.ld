OUTPUT_ARCH(riscv)
ENTRY(_start)

/* Offsets are relocated by entry.S; every selected board must fit the image. */
MEMORY {
  RAM (rwxa) : ORIGIN = 0, LENGTH = 60M
}

SECTIONS {
  . = ORIGIN(RAM);

  .text : ALIGN(4K) {
    __text_start = .;
    KEEP(*(.text.boot.entry))
    KEEP(*(.text.boot))
    *(.text .text.*)
    . = ALIGN(4K);
    __text_end = .;
  } > RAM

  .rodata : ALIGN(4K) {
    __rodata_start = .;
    *(.rodata .rodata.*)
    *(.data.rel.ro .data.rel.ro.*)
    . = ALIGN(4K);
    __rodata_end = .;
  } > RAM

  .data : ALIGN(4K) {
    __global_pointer$ = . + 0x800;
    *(.sdata .sdata.*)
    *(.data .data.*)
    *(.got .got.*)
  } > RAM

  .rela.dyn : ALIGN(8) {
    __rela_start = .;
    KEEP(*(.rela.dyn))
    __rela_end = .;
  } > RAM
  .dynsym : { *(.dynsym) } > RAM
  .dynstr : { *(.dynstr) } > RAM
  .hash : { *(.hash) } > RAM
  .gnu.hash : { *(.gnu.hash) } > RAM
  .dynamic : { *(.dynamic) } > RAM
  __image_file_end = .;

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
  __image_mem_end = .;
  __heap_end = .;

  /DISCARD/ : { *(.eh_frame) *(.comment) *(.note .note.*) }
}

ASSERT(_start == 0, "universal entry must be offset zero");
ASSERT((__rela_end - __rela_start) % 24 == 0, "invalid RELA extent");
