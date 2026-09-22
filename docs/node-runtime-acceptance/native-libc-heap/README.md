# Native libc heap prerequisite

QEMU RV64GC/LP64D, four harts, 128 MiB: PASS. The fixture enters the actual
native stack/TLS context and calls the Rust sbrk bridge. It verifies lower and
upper bounds, signed overflow/underflow rejection, unchanged break on failure,
trim/regrow zeroing, RW/NX mappings across the whole backing, and TCB accounting.
All preceding native probes and the granted entropy probe also pass.

The newlib heap has 16 MiB usable capacity and a separate 64 MiB accounting
quota. The observed retained allocation is 33,562,624 bytes including allocator
rounding and metadata. Backing is deliberately process-lifetime because newlib
allocator globals survive individual invocations. Returning the break to zero
does NOT release this reservation. This is not evidence of instance reclamation,
per-invocation malloc quotas, or 100-run stability.

The C++ `_sbrk(ptrdiff_t)` adapter sets ENOMEM for the bridge failure sentinel;
target libbase compilation and host mock adapter tests pass. This fixture does
not link or run newlib malloc/free, V8, or Node. M1 remains unqualified.

Reproduce after a native-cxx-probe firmware build:
`python3 scripts/test-native-tls-qemu.py --work target/native-libc-heap-repeat --kernel target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt --native-cxx --entropy`
