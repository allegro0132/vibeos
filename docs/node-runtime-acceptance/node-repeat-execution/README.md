# Sequential Node invocation lifecycle

Process-wide Node/V8 initialization is now separate from invocation-owned
environment/isolate/loop and Rust stack/TLS/grants. The gate creates a fresh
NativeAsync context, project and standard streams for every iteration, then
shuts down the global runtime only after the final invocation.

Runs 1–2 fail on the second invocation. A bounded fatal frame walk identifies
Node SetIsolateMiscHandlers -> uv_mutex_lock on cli_options_mutex. Its semaphore
was invocation-local and disappeared with the first TLS. Run 3 fixes this by
explicitly sharing a process-owned synchronization domain (registry + notifier)
among serial Node invocations. Unrelated native tasks retain fresh domains.

Run 3 passes two complete Node main-file executions and normal cleanup, with
independent native identities 1 and 2, status 0 and zero stream waiters each.
Its old verifier records only the first memory sample; both raw samples remain
in serial.log. The verifier is being extended to retain every sample. Live
bytes stay almost constant, but bump capacity falls; a longer run must prove
freed large regions are reused before claiming 100-cycle qualification.

This is an embedding lifecycle gate, not production VSH command integration.

Run 4 completes the 100-invocation workload. Every sampled cleanup point is
within a 256-byte live-memory range, and bump remaining stabilizes after the
second iteration. See run-4/README.md and the complete memory history in its
results.json. The previous failures are retained as evidence of the lifecycle
bug that the shared synchronization domain fixes.
