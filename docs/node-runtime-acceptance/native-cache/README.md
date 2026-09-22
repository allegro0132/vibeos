# Native instruction-cache bridge prerequisite

A real RV64GC C++ fixture calls `vibeos_native_flush_instruction_cache` through
its C ABI on the protected native stack. The kernel executes local fence.i and
SBI remote fence.i for other online harts. The four-hart QEMU run checks that
the completed remote-fence counter increased across the C++ invocation; an SBI
failure shuts down instead of reporting successful synchronization. Existing
page discard/decommit, suspension, C++ destruction, executor parking and VSH
checks also pass in this image.

This validates invocation and completion of the actual fence path. It does not
write or execute new instructions, prove stale instruction replacement, or
qualify real V8 execution. Data pages still have no executable permission.
Patch 0012 routes V8's RISC-V FlushICache to this bridge rather than Linux's
syscall; the complete V8 engine is not linked into this probe.
