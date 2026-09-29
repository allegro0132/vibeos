# Same-hart Node/V8 infinite-loop cancellation

Real locked Node completes the CJS/ESM, sync/Promise file, stdin, Buffer/timer
and zlib checks before running `try { for (;;) {} } finally { ... }` through
its V8 context. A test handshake arms a BOOT-hart Rust peer, which waits 10 ms
and calls the same CommandIo cancellation operation used by command services.
The peer cannot run while native code monopolizes that hart.

Patch 0056 adds VibeOS-only checkpoints to both interpreter bytecode-budget
interrupt paths. The checkpoint suspends through the retained native-stack
bridge and yields the Rust executor once, then reads invocation cancellation
after resuming. A nonzero result returns V8's normal termination exception.
No external task enters V8, no live C++ frame is jumped over or dropped, and
no executable data page is required.

QEMU passes: the same-hart peer requests cancellation; Script::Run returns
empty with HasTerminated; both finally and post-loop sentinels remain absent.
After termination is cleared for host cleanup, Node is stopped without another
termination request, and the full environment/isolate/loop/platform/process
teardown returns. Native status is 130, parks=194, waiters=0. Peak kernel heap
usage is 305744896 bytes. All previous runtime checks also pass.

This proves a tight interpreted loop can be cancelled through CommandIo in
the embedding gate. It does not yet prove the VSH Ctrl-C launcher path, every
native long-running callback, pathological regex/JSON work, recursive-stack
limits, 100 successive invocations, or complete M2/M4 acceptance. The patch
applies with zero fuzz to pinned pristine sources; a complete fresh build of
all 56 patches remains required.
