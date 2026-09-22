# First successful real-V8 firmware link

The actual V8 smoke object, native Rust bridges, bundled V8/Abseil/platform
archives and pinned static newlib/libstdc++/libgcc now link: exit 0, no undefined
symbols, no linker error classes. This is still diagnostic fixture firmware,
NOT a runnable V8 acceptance image. M1 has not passed.

The linker retains aligned preinit/init/fini arrays in the read-only image
range, sorting priority entries. Pinned newlib disassembly established that
register_fini tests the __libc_fini address and registers __libc_fini_array with
atexit. __libc_fini now has a real implementation invoking that array routine.
The V8 smoke entry calls a process-once wrapper around __libc_init_array after
native context admission. Recursion/concurrent initialization is rejected;
finished initialization is idempotent. It is not repeated per Node invocation.

ELF symbols show 11 init-array entries and empty preinit/fini arrays. This proves
retention and link resolution, not that constructors ran. Runtime initialization,
actual newlib IO/allocation, V8 expression/exception/GC and safe teardown remain
unqualified. The fixture V8 flag page must be removed from the runnable gate.
