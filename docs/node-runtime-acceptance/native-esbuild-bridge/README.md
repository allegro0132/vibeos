# Retained native stack to esbuild WASI bridge

The `node-toolkit` profile now includes the existing bounded esbuild WASI
execution service. `native_esbuild.rs` connects it to invocation-owned native
state through begin/poll/wait/release C ABI functions. Requests must pass the
transform-only binary validator. The module is read through the independently
granted read-only tool directory; the WASI instance receives only standard
streams, not the project filesystem. Input is capped at 1 MiB, output at 4 MiB,
stderr at 64 KiB, and only one transform handle is admitted per native invocation.

The synchronous path takes its Rust future out of TLS before parking, preserving
native stack frames without holding a RefCell borrow across suspension. The poll
path registers the existing native notification waker. Both paths drain the
bounded pipes and wait for the existing WASI reaper to publish completion before
returning a result. Releasing a still-pending future signals cancellation; the
independent WASI reaper retains ownership of its guest until cleanup finishes.

`run-3/` qualifies this C ABI on QEMU using the official module:

- A synchronous transform suspends and returns generated JavaScript.
- A second transform completes through begin/poll and notification-based waits.
- A third transform is cancelled after launch by its parent invocation. The
  authority callback denies the WASI task, and the native bridge returns denial.
- Invalid input, busy admission, and released-handle rejection pass.
- All three WASI jobs report reclaimed arenas, zero capabilities and waiters.
  Each WASI owner peaks at 96,523,904 bytes. The native runner reports 11 parks.

Run 1 records the initial synchronous gate. Run 2 records an incorrect fixed
length in the async output assertion; the predicate now derives its window size
from the expected bytes. The driver also stops on fatal guest diagnostics.

Reproduce by adding `--esbuild-probe` to the documented toolkit image link
command, then running `scripts/test-native-esbuild-qemu.py --kernel IMAGE
--work target/FRESH_DIRECTORY`. The probe-only feature shuts QEMU down after
the checks; production toolkit images do not run it.

This is native C ABI and WASI evidence. Subsequent Node JavaScript binding and
Promise/event-loop evidence is recorded in `../esbuild-node-binding/`.
Upstream esbuild API adaptation and tsx execution remain pending. These checks
do not close M3 or the complete lifecycle/security audit.
