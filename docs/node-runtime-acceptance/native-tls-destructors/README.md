# Native dynamic TLS and exit destructors

The pinned compiler emits __cxa_thread_atexit plus __dso_handle for dynamic
thread_local objects. The ABI was checked against
[GCC 14.2.0 atexit_thread.cc](https://github.com/gcc-mirror/gcc/blob/releases/gcc-14.2.0/libstdc%2B%2B-v3/libsupc%2B%2B/atexit_thread.cc);
the source digest is retained here. The Rust registration bridge accepts the
statically linked image, stores callbacks per context and exposes an explicit
normal-exit cleanup operation. A context cannot release storage with pending
destructors or while it is active.

The native entry invokes cleanup after the C++ function's ordinary stack RAII
has completed, while its protected stack, tp and TLS storage still exist.
Callbacks are popped in reverse registration order without retaining a mutable
queue borrow during a call. After cleanup, TLS access is rejected. This does
not jump across C++ frames or call C++ destructors from the Rust allocator.

QEMU executes two function-local thread_local objects with nontrivial dynamic
constructors and destructors. Four accesses across three suspension/resume
cycles must construct exactly twice in total. No destructor may run while
suspended. On normal exit, callbacks must arrive in order 2 then 1, after the
ordinary C++ stack guard, and each destructor reads the final TLS counter.
The direct switching fixture and executor-parking fixture each use their own
context; all existing four-hart/page/cache/VSH checks pass as well.

This does not qualify full libstdc++/newlib integration, exceptions, dlopen,
DSO unloading, arbitrary cancellation, destructor re-registration during
cleanup, or V8/Node execution. The compiler-generated dynamic initialization
is tested with exceptions disabled, matching the C++ fixture build.
