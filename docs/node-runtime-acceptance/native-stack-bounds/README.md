# Native registered stack boundaries

The admitted TLS/execution context now records its usable native stack range.
A C ABI query returns the two uintptr_t bounds and checks the current native
sp before returning. Real target C++ calls this query during initial TLS access
and after each suspended execution resumes. It checks that an actual volatile
local variable lies strictly inside the 256 KiB usable stack; the guard page
is outside that range. Existing dynamic TLS/destruction, page, cache, executor
parking, four-hart and VSH checks pass in QEMU.

The initial test incorrectly required the compiler's frame address to be
strictly below the upper bound and failed in the initial TLS call. Frame/CFA
addresses can equal the exclusive stack end after a tail call. The corrected
check permits that boundary value while checking an actual local variable's
address strictly inside the range. The original failure log and kernel/source
identities are retained alongside the passing run.

The V8 stack adapter compiles separately with the generated RV64 libbase flags.
It obtains the registered upper bound and uses the compiler frame-address
builtin for current stack position. Patch 0013 adds it to future prepared V8
builds; it is not yet linked into this QEMU image or the active engine build.
This validates the kernel C ABI and stack bounds, not V8 stack scanning/GC.
