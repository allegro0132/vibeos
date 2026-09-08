ENTRY(_start)
SECTIONS {
 . = 0x80200000; text_start = .;
 .text : { *(.text.start) *(.text*) }
 . = ALIGN(4096); text_end = .;
 .clif : { *(.clif) }
 . = ALIGN(4096); .clif_external : { *(.clif_external) }
 . = ALIGN(4096); .clif_wasmi : { *(.clif_wasmi) }
 . = ALIGN(4096); ro_start = .;
 .rodata : { *(.rodata*) }
 . = ALIGN(4096); ro_end = .;
 .data : { *(.data*) *(.sdata*) }
 .bss : { *(.bss*) *(.sbss*) *(COMMON) }
}
