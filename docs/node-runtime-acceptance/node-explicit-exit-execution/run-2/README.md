# Explicit exit diagnostic

QEMU reports caught=0, isolate=0, checks=1, code=7 after uv_run returns.
The actual exit handler observes all script completion flags and exit event 7.
Pinned Node src/env.cc Environment::RunTimers wraps its callback in its own
TryCatchScope; termination need not remain in the outer embedding catcher.
This run still fails the original test and returns 1 with zero waiters.
The corrected test must check the handler/event and unreachable post-exit JS
sentinel, clear any remaining termination after callback return, and complete
normal cleanup before accepting the actual exit code.
