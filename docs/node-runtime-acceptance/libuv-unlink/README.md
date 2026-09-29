# Capability-backed libuv unlink

uv_fs_unlink implements synchronous deletion through the native transaction
bridge and asynchronous deletion through a bounded Rust-owned future table.
The asynchronous path does not call the parking synchronous bridge: it starts
an owned transaction/lease and polls it with the native notification waker.
Pending retains no C buffer or callback. Request IDs are monotonic and consumed
on completion; invocation teardown asserts no mutations remain outstanding.
The existing capability lease is held through authoritative publication.

The first Rust build required a Send bound for scheduler compatibility; its
failure is preserved. Run 1 passed deletion. Run 2's added read-only probe
incorrectly allocated a second native stack while the main stack was reserved;
that fatal fixture failure is preserved. Run 3 runs the read-only admission
probe first, releases its stack, then admits the main V8/libuv gate.

Final QEMU results: read-only async admission denied without deleting its file;
explicit READ|WRITE|REVOKE project fixture deletes separate sync/async files;
async callback deferred until the loop runs; loop close busy while request is
queued; escaped paths, directories and post-revocation deletion denied. Existing
V8, metrics, sync, clock, newlib and IO tests pass; 33 parks, zero waiters.
The project fixture now explicitly has WRITE; earlier read-only evidence remains
in prior runs. Tool-directory read-only separation is still a later Node gate.

This uses an in-memory file store. A slow durable publication with timer progress,
mid-publication revocation, mutation cancellation and full Node execution remain
unqualified. No new Node milestone or general async filesystem claim is made.
