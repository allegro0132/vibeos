# Node link attempt 23: first complete firmware ELF

Firmware linking succeeds with no unresolved symbols or relocation errors.
Zstd tracing is disabled via its upstream ZSTD_TRACE switch for VibeOS because
no weak trace provider exists in the static image; compression remains enabled.
Patch 55 applies with zero fuzz. Explicit zstd archive rebuild was necessary;
requesting only the already-built libnode target did not rebuild that dependency.

This is build success only. First QEMU execution failed at duplicate cppgc
initialization; see node-first-execution/run-1. No Node runtime milestone yet.
