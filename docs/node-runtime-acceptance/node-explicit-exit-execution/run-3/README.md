# Explicit process.exit(7) target acceptance

Real Node calls process.exit(process.exitCode) from a timer after the project,
stdin, Buffer/Promise/timer and zlib checks complete. The custom embedding exit
handler observes code 7 and the actual exit-event argument 7, then calls
node::Stop. After uv_run returns normally, JavaScript immediately after
process.exit remains unexecuted. No cross-C++-stack jump is used.

Node environment, isolate, loop, allocator, V8/platform, cppgc and process
cleanup all return before the kernel completion probe reports success.
QEMU records native returned=7 and waiters=0; every verifier check passes.
Host QEMU shutdown status 0 is separate from the Node invocation status 7.

Earlier failed runs are retained. Node's timer-local TryCatch consumes the
termination, so the test checks observable control flow and the exit handler
instead of requiring a termination exception in the outer embedding catcher.
This is one-shot explicit exit evidence, not cancellation of an infinite loop,
repeated-instance reclamation or production VSH command qualification.
