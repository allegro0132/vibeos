The dedicated VibeOS libuv loop backend executes upstream timer and
prepare/check/idle code on the protected native stack. Polling uses the existing
suspendable native wait bridge and monotonic clock, with no host thread or OS
poll descriptor. Async notifications coalesce, and handle close callbacks run
in the closing phase.

QEMU run 1 passes: a pending async callback leaves its handle active and
UV_RUN_ONCE returns; two sends yield one callback; NOWAIT does not wait for a
future timer; three timer callbacks respect the repeat interval; prepare/check
ordering holds; four handles close and uv_loop_close returns success. The
combined gate subsequently passes real V8 expression, exception, GC and teardown.
It returns with 10 native parks and zero waiters. Whole-kernel memory accounting
is unchanged from the M1 baseline; it is not a per-libuv allocation audit.

The initial link failure (missing process-title/signal/threadpool cleanup hooks)
is preserved. Those subsystems have no initialized state in this backend; empty
cleanup hooks own no resources. Their operation APIs are not supplied by this
partial backend. Source compilation uses function/data sections so unused
common API functions are discarded: this is NOT proof of a complete libuv
archive, all public APIs, streams, filesystem completions, cross-invocation
async sends, Node execution or user cancellation. The pending-request dispatch
path must be implemented with the file/stream backends before their admission.

Reproduce by linking with check-v8-firmware-link.py --gate --uv-loop and running
test-v8-gate-qemu.py --uv-loop, each with fresh work directories. Patch 0028
selects uv-common.h for the upstream loop watchers; it dry-runs against the M1
prepared source without fuzz. Backend and test are compiled directly from this
repository by the link helper; normal Node/libuv GYP integration is still pending.
