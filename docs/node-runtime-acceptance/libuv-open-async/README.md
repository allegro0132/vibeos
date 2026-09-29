# Asynchronous mutating opens

Asynchronous O_CREAT/O_TRUNC now dispatch on the protected native stack and use
the existing suspendable authoritative publication bridge. Readiness polling
does not execute these parking operations on the Rust scheduler stack. Normal
queued cancellation prevents creation/truncation; started requests retain normal
completion. Existing descriptor admission and capability checks remain in force.

QEMU verifies deferred creation, copied path storage, descriptor writes and
closure, cancelled truncation preserving file length, cancelled creation leaving
no path, successful asynchronous truncation and request/loop cleanup. Cumulative
real-V8/libuv tests pass: 167 parks, zero waiters, normal shutdown. Concurrent
cwd changes, in-publication revocation and persistent storage fault injection
remain unqualified. Node-level use is separately tested in node-project-execution.
