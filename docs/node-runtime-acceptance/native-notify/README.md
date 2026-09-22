# Native notification prerequisite

The four-hart QEMU fixture passed with the recorded kernel and source hashes.
A notification delivered between registration and the first poll is observed.
A second case registers a wait and is resumed by a same-hart peer after a
2 ms executor timer. Concurrent registration is rejected, dropping an unused
wait permits a new registration, and completion leaves no waiter or extra Arc
owner. Existing C++/TLS/memory/static-page/VSH checks also passed.

This verifies the scheduler-side Rust notification primitive. It does not
execute the V8/Abseil wait C ABI, suspend C++ frames through that ABI, qualify
timeout races, or cancel arbitrary native code. Those integrations remain
required for the V8/Node runtime.
