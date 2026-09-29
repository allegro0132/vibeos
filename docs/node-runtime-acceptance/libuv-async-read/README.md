QEMU passes a real libuv async stdin request while three timer callbacks
continue to run before the delayed input arrives. The kernel peer supplies
"uv-ready" after 50 ms. The completion callback verifies all 8 bytes and that
the timers already fired. Submission does not call the callback inline.
The native runner returns after V8 expression/exception/GC/teardown with 11
parks and zero stream waiters. This is an actual VibeOS stream transport, not
host execution or a mock threadpool.

The Rust try-read bridge polls once into a bounded staging buffer. Pending
retains only an Arc notification waker, never a native buffer or callback. The
loop re-polls and dispatches completed requests on its protected native stack;
only Rust futures run on the kernel scheduler. Request accounting keeps the
loop alive until delivery, and callbacks may clean up their completed request.

This first read backend supports offset=-1; async regular-file reads and
positioned reads reject with ENOTSUP. Sync reads use the existing suspendable
native read bridge. FS writes/open/stat, uv_stream/pipe integration, request
cancellation, revocation during an outstanding request, multiple simultaneous
stdin consumers and Node execution remain to be qualified. The fixture uses
native-uv-probe; the ordinary node-runtime V8 gate still receives closed stdin.
Whole-kernel post-run allocations are not a per-request leak audit.
