# Trusted-runtime page backend prerequisite

The kernel implements the TCB page C ABI using an independent process-lifetime
heap owner with a 64 MiB charged-allocation quota and 128 fixed registry slots.
Backing and per-page metadata are charged to that owner, not SYSTEM or the
calling invocation. Entry requires an admitted native TLS context. Allocation
returns eager zeroed RW/NX pages. Allocation failure returns null without
falling back to another owner.

Release validates the entire range against original registered allocations
before freeing any block. It rejects partial allocations, gaps, unowned ranges,
overflow and repeated release; adjacent complete blocks can be reclaimed using
their individual original layouts. No sub-pointer is handed to the allocator.
The owner identity persists for future process-lifetime arenas, while backing
and metadata are genuinely reclaimed on release.

Real C++ calls in four-hart QEMU allocate and inspect 8 KiB of zeroed memory,
reject a partial release and an oversized release, verify retained data,
release the full allocation and reject a second release. After both native
fixture runs, the registry is empty and the owner's live_bytes and
live_allocations are both zero with a nonzero recorded peak. Existing TLS,
destructor, native parking, page, cache and VSH checks pass.

This does not execute Abseil's actual arena allocator, exercise successful
multi-block coalesced release, exhaust the quota/registry, or qualify V8/Node.
Those integrations and broader lifecycle/security acceptance remain open.
