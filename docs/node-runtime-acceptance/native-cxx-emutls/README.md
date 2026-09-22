# Native GCC emulated TLS prerequisite

The pinned bare-metal GCC emits __emutls_get_address calls for actual C++
thread_local declarations. Relocations from the compiled C++ fixture are
retained here. The first linker attempt rejected the unresolved emutls symbol;
a proposed ELF TLS template implementation was removed before acceptance.
The final firmware linker script is unchanged.

The descriptor ABI was checked against
[GCC 14.2.0 libgcc/emutls.c](https://github.com/gcc-mirror/gcc/blob/releases/gcc-14.2.0/libgcc/emutls.c).
Its exact source digest is recorded in abi-source.json. The Rust bridge keys
values by descriptor inside the admitted execution context, copies initial
values or zeroes new slots, and respects requested alignment. It never writes
per-context values into a descriptor's shared location field. Only one native
context can be active, and tp must match its registered pointer. A guard keeps
the context alive across the call and is released after tp is restored.

The real C++ fixture has initialized and zero-initialized volatile TLS values,
both aligned to 64 bytes. Five protected-stack calls alternate between two
live contexts, checking their distinct expected counters. QEMU passes the
initial-value, zero-fill, alignment, isolation and caller-tp restoration checks.
Owned slots are deallocated on context drop after all calls return normally.
Existing suspension, C++ RAII, page, cache, four-hart and VSH probes also pass.

This probe covers trivial TLS values in normal-return calls. It does not yet
qualify dynamic TLS initialization, thread-exit destructors, TLS values across
executor suspension, resource-limit/revocation admission, libc TLS, or V8/Node.
The existing suspension fixture still uses a synthetic tp value. Full static
C/C++ runtime integration and real V8 execution remain open.
