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

  . = ALIGN(4K);
  __stack_bottom = .;
  . += 256K;
  __stack_top = .;

  . = ALIGN(4K);
  __heap_start = .;
  . = ORIGIN(RAM) + LENGTH(RAM);
  __heap_end = .;

  /DISCARD/ : { *(.eh_frame) *(.comment) *(.note .note.*) }
}
