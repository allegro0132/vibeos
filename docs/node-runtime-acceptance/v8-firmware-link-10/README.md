# V8 firmware link diagnostic 10

The read-only open adapter resolves the last previously undefined syscall.
There are now zero reported undefined symbols, but the firmware link still
FAILS (exit 101). Three R_RISCV_PCREL_HI20 relocations are out of range in
newlib's __call_atexit/fini objects, referring to __libc_fini and
__fini_array_start/__fini_array_end. Static C runtime constructor/destructor
layout and startup integration must be supplied before a runnable gate exists.

This is a fixture link diagnostic, not V8 execution. It must not be booted as
acceptance firmware; its fixture flags section remains incompatible with the
real V8 flag object. M1 is not passed. The successful QEMU read-only-file
prerequisite is recorded separately under ../native-open.
