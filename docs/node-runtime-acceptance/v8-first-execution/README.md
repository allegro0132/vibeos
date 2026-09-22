# Real V8 execution — run 3 PASS; runs 1 and 2 retained

The dedicated node-runtime profile sets matching 1 GiB board/linker bounds,
disables native fixture boot calls, excludes the extra fixture flag page,
and calls the actual V8 smoke gate on an admitted protected native stack.
It grants virtio entropy and bounded standard streams drained by same-hart
peer tasks. V8 initialization invokes real pinned newlib constructor arrays.
No host JavaScript or alternate engine is used.

Run 1 enters V8 but traps executing Abseil LowLevelAlloc::Alloc at 0x815a9000.
The executable malloc_hook orphan section was outside __text_end and thus NX.
The linker now places malloc_hook inside RX text and .srodata inside RO data.
The gate harness rejects executable sections outside the admitted text range.
Run 1's old no_fatal subcheck missed the fatal-trap spelling; overall passed was
false. The checker has been corrected, and this original evidence is retained.

Run 2 gets past that trap and reaches a real V8 fatal OOM:
SegmentedTable::InitializeTable (subspace allocation). Source inspection shows
Leap Tiering enables a 256 MiB JSDispatchTable reservation even with jitless,
while this bounded native page pool is 128 MiB. Patch 0025 disables Leap Tiering
for VibeOS through the existing GYP configuration path for both host generators
and target. A complete engine/snapshot rebuild has been started; its result is
not established by these logs.

Neither expression, JS exception, GC nor teardown passed in runs 1 and 2.
The profile still shares native implementation feature gates with fixtures,
but excludes their boot execution and flag storage. It is an acceptance image,
not yet the production node/tsc/tsx command launcher.


Run 3 passes the real expression (`6 * 7 = 42`), expected JS Error, full GC
(callback count 1, used V8 heap 151144 bytes), normal isolate/process teardown,
and return to the Rust scheduler with 6 parks and zero waiters. QEMU exits 0
without a fatal trap. Wall time including boot is 0.569 seconds on this host;
it is not a performance guarantee. The ELF SHA-256 is
`df3c384314e6ca5391d9b4ffbfa230d6dbf76395105198f6b32223d0a08d34d8`.

Kernel allocator accounting (whole image, not V8 alone) reports live bytes
767360 before and 36158976 after, with peak 305719424 bytes. Newlib's process
heap intentionally remains allocated; this one-shot gate does not establish
per-invocation reclamation or the later 100-Node-invocation requirement.
The link input manifest hashes all thin-archive member objects as well as
archives and verifies they do not change while linking. The target uses the
locked Node 24.14.0 bundled V8, static GCC/newlib/libstdc++, RV64GC/LP64D,
JIT-less/lite mode and disabled Leap Tiering. Patches 1–26 and overlays match
an independently prepared and configured locked source tree; the passing
engine build was incremental, not a fresh full-build reproducibility claim.

M1's expression/exception/GC feasibility gate is now complete. Together with
the earlier independent official esbuild WASI target execution, this passes
the plan's first feasibility stage. Node commands, libuv, TypeScript/tsx,
cooperative cancellation, production authority admission and repeated native
invocation qualification remain unimplemented or unqualified.
