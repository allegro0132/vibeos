# Static V8 flag-section protection prerequisite

Four-hart QEMU passed using the exact recorded kernel/source hashes. A probe
page occupies the linker-admitted flag section. Calls on an oversized or
out-of-range extent fail; freezing the exact extent succeeds and is idempotent.
The resulting PTE is READ only (NX), data remains intact, and heap protect/free
calls cannot thaw or release it. No deliberate CPU write-fault was injected.

Separately, a copy of actual V8 flags.cc with the target section attribute
cross-compiled successfully. readelf reports `.vibeos_v8_flags` as a 4096-byte,
4096-aligned WA input section. Patch 0021 passes a zero-fuzz dry run. This is
not runtime execution of V8's real flag-freezing path: the live engine build
still predates the patch. A real V8 image must omit the C++ fixture's flag page.
