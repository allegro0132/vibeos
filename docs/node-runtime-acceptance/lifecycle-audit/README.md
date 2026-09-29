# Native lifecycle audit (M4 qualified)

M4 passes on QEMU with the fresh locked-source build and patch 0058. Final
100-cycle inventories are in `sync-file-cycles/`, `sync-eval-cycles/`, and
`sync-error-cycles/`; live authority revocation is in `sync-authority/`.
Boundary, backpressure, transform cancellation, OOM and independent fatal
evidence is under `fresh/`. M5 final regressions remain outstanding.

## Initial audit history

The optional `node-lifecycle-audit` feature records TLS slots after release,
file tables after descriptor release, and native page owners after their pool
is destroyed, accounting reaches zero, and owner registration is removed.
`check-v8-firmware-link.py --lifecycle-audit --node-shell` enables it.
Default images do not print these records.

The initial audit ELF SHA-256 is
`6964f6b78bbbc206c598979bab5318fe4b1faac957680d137d1b3bc92150ace0`.
`link/` retains the link command and pinned archive/object hashes. On 1 GiB,
four-hart QEMU, `cycles/` passes all 100 ordered teardown checks (133.34 s),
`node/` passes files/modules/streams/exit/exception/CPU and idle cancellation
(17.56 s), and `tsx-cancel/` passes cancellation during WASI conversion and
successful relaunch (33.61 s). Each execution report records the source hashes
and verifies they stayed unchanged during the test. Raw UART logs are retained.

Teardown now also asserts that no notification waiter survives the native
invocation and that remaining descriptors have no escaped `OpenFile` references.
Pending reads and mutations must already be empty. These assertions also apply
without the audit feature. C++ frames still return normally before cleanup;
there is no forced stack unwind or replacement execution engine.

The cycle test's `--lifecycle-audit` option requires exactly 100 distinct TLS
identities and the output/TLS/file/page teardown sequence for each invocation.
Its project intentionally leaves a descriptor open for Node's normal cleanup.
These checks supplement the existing whole-system rounded heap observations.

Scope: page-owner accounting covers the invocation's native page pool. It does
not account for live allocations inside the retained process-wide newlib heap,
process V8 metadata, CSpace inventories, or every Rust allocation. File-table
release drops its grant providers but does not prove that all other capability
providers or leases have been released. At this initial stage, M4 still required
those inventories and final live-authority revocation coverage. Later sections
record their completion; M5 remains outstanding. The logs here must not be described as proof of zero total leaks.

## newlib accounting ABI investigation

The first `mallinfo` integration failed on the first cycle: the installed
xPack GCC 14.2.0-3 `malloc.h` declares ten `size_t` fields, but the pinned
LP64D `libc.a` implementation writes ten 32-bit fields. The mismatch combined
adjacent values and uninitialized stack bytes into impossible totals; the
accounting consistency assertion stopped the guest. `libc-abi-failure/`
retains that failure, its image link manifest, and the actual `_mallinfo_r`
disassembly showing 32-bit stores at offsets 0 through 36. This is not leak
evidence. The audit shim now explicitly binds that pinned 40-byte binary ABI;
toolchain upgrades must revalidate it.

## Initial result: process allocator growth

`libc-link/` records the corrected audit image. `libc-node/` passes the Node
functionality, exception and cancellation regression (17.97 s). The full
`libc-cycles/` run completes 100 invocations (137.33 s), with all TLS/file/page
teardown checks passing and all 100 newlib snapshots internally consistent.
However, its exact allocated-byte stability check **fails**: `uordblks` grows
from 252,208 bytes after invocation 1 to 285,152 after invocation 100, a 32,944
byte increase. The original rounded whole-system heap test still passes.

This is evidence requiring allocation-source investigation, not proof of an
unbounded leak or permission to relax the check. Process caches, allocator
overhead and surviving allocations have not yet been distinguished. M4 stays
open. The feature samples after Node and C++ TLS destructors, on the admitted
native stack; it does not reclaim or reset the process allocator to conceal
the growth. Historical `cycles/` predates the newlib checks and remains only
the narrower page/TLS/file-table evidence described above.

## Allocation-source diagnosis and correction

`trace-initial/` repeats the 100-cycle growth with fixed-storage malloc-family
tracking. `trace-callers/` and its matching link manifest additionally intercept
the pinned C++ `operator new` boundary because its library implementation omits
frame pointers. The symbolized surviving 56/64/64/264/512/512-byte allocations
originate in `DefaultPlatform::GetForegroundTaskRunner`, called by
`CppgcPlatformAdapter::GetForegroundTaskRunner`, `Sweeper::Start`,
`HeapBase::Terminate`, `CppHeap::~CppHeap`, and isolate heap teardown.

Previously the launcher notified the platform before `Isolate::Dispose()`,
which correctly drained tasks containing live V8 handles but removed the runner
from the platform map. cppgc teardown then created a new runner in that map;
it survived the isolate. Reused isolate addresses sometimes replaced a previous
entry, explaining the intermittent growth rather than a fixed increase per run.

The runtime now derives its single-threaded platform from the pinned upstream
default platform. During disposal it retains the existing runner, notifies
shutdown to drain it while V8 handles are valid, and returns that same terminated
runner to any teardown request. Only after normal `Isolate::Dispose()` completes
does it release the retained reference. This preserves task cancellation and
prevents recreation of a runner for a disappearing isolate. No allocator reset,
forced unwind, or relaxed memory threshold is used.

The optional `--allocation-trace` diagnostic uses 65,536 fixed slots and records
surviving allocations plus bounded native frame walks. Capacity overflow is
fatal; an incomplete trace cannot silently qualify a test. Requested allocation
bytes and newlib's allocated chunk bytes are different measurements.

## Runner fix execution: remaining findings keep M4 open

`runner-fix-trace-cycles/` and `runner-fix-audit-cycles/` each complete 100
ordered invocations, with and without allocation interception respectively.
All file/TLS/page cleanup checks pass. The repeating foreground-runner survivor
group is gone. The traced run stays at 250,928 allocated bytes until invocation
72, when one 36-byte request from newlib `_Balloc` increases allocated chunk
bytes by 48. Its final count is 250,976. The untraced run similarly increases
from 250,944 to 250,992. Both strict post-warmup stability checks still fail;
neither run is labeled fully passing.

`runner-fix-node/` passes functional/exception/cancellation checks (17.86 s),
and `runner-fix-tsx-cancel/` passes transform cancellation and relaunch (39.09 s).
Allocation tracing of the mixed Node suite identifies a separate 32-byte
survivor from `ContextifyScript::New`: disassembly maps it to
`Realm::TrackCppgcWrapper` allocating `CppgcWrapperListNode`. In the pinned
source, `CppgcWrapperList::Cleanup()` finalizes pointees but does not delete
those list nodes. This remains a separate cleanup investigation, along with
classifying the newlib bigint allocation's process lifetime. Symbolized PCs
are retained in `runner-fix-symbols.json` against the exact traced ELF.

These results fix and verify the runner recreation defect, not all native
allocation cleanup. Capability inventories and final authority-revocation
coverage also remain outstanding; no M4 completion or milestone push is claimed.

## Explicit newlib cache inventory and cppgc regression

The audit now enumerates the pinned newlib `_freelist` after native destructors.
The actual `_Bfree` binary links unused bigint blocks into that process-owned
cache. `_Balloc` allocates 65 bucket heads on RV64 and removes a reused block
from its bucket. Layout assertions match the installed `_reent`/`_Bigint`
headers to the observed offsets. `_malloc_usable_size_r` supplies the usable
size; adding the pinned non-mmap allocator's one-word overhead gives the exact
allocated chunk bytes. Disassembly and the compiled layout-check source are
retained under `libc-cache-abi/`.

Each snapshot retains raw live bytes and prints every cached block's pointer
and chunk bytes. The cycle test compares exact `live - cached_bytes` after
warm-up. It excludes only unused blocks physically present in that cache,
with list validity, accounting and bounded traversal checks. It does not allow
arbitrary drift or infer cache membership from a tolerance or caller name.

The cycle test's `--eval-entrypoint` runs the same 100 file/Promise/ESM/stream
workloads via `node -e`, exercising `ContextifyScript` wrapper ownership.
Patch `0058` adds an owning-list destructor to free the weak-persistent list
nodes before the cppgc heap is destroyed. Normal `Cleanup()` still finalizes
the pointees; their destruction remains cppgc's responsibility. The clean
`m4-clean-1` cross-build is required before claiming this patch passes on target.

`cache-file-cycles/` completes all 100 file-entry invocations and passes the
cache-aware exact audit (146.34 s): non-cache allocated chunk bytes are 250,656
for every invocation, including the first. `eval-wrapper-baseline/` uses the
same image, same workload and same accounting, changing only the entrypoint to
`node -e`. It completes 100 invocations but fails the non-cache stability check
(149.66 s), growing from 250,704 to 255,472 bytes. These images include the
runner fix and cache inventory but still link the pre-0058 Node archive. The
passing file result does not qualify the wrapper-node patch or close M4.

The 0058-patched `cppgc_helpers.cc` compiles with the fresh configured target
flags. `wrapper-build-precheck/` records this compile-only check and the prepared
source/patch hashes. The complete fresh engine/Node build and its subsequent
target execution remain required.

## Invocation authority lifetime audit

With `node-lifecycle-audit`, each admitted Node project/tool grant is wrapped
in a fresh lifetime owner. Its provider closure retains the owner, and every
successfully acquired `FileLease` retains it until after the actual invocation
authority and projected directory view are dropped. A weak observer then
requires zero surviving references. This detects escaped provider clones and
in-flight leases, including asynchronous operations and tool-module loading.
The original process-owned read-only tool grant remains a separate intentional
image-lifetime resource.

The supervisor now scopes its monitor and native future together, drops both
project/tool grants after normal native teardown, and checks the observers
before publishing terminal completion. The same release order applies without
the audit feature. The cycle verifier requires an ordered project-authority
reclamation record after every TLS/file/page cleanup record. This is evidence
about the native invocation's authority graph, not a global CSpace slot count.

`grant-cycles/` passes all 100 ordered native/project-authority teardown checks
and exact non-cache accounting (142.28 s). `grant-node/` passes functional,
exception, CPU and idle cancellation checks (19.93 s); `grant-tsx-cancel/`
passes WASI conversion cancellation and relaunch (39.19 s), recording zero
project/tool invocation authority references for both runs. This still uses
the pre-0058 Node archive. A subsequent audit addition checks that terminal
stream closure leaves zero I/O waiter registrations; that assertion must be
qualified with the upcoming rebuilt image and is not covered by these logs.

## Live parent-authority revocation through the production supervisor

The optional `node-authority-probe` image calls the production
`native_node::launch` supervisor with explicit fixture grants. It mints separate
project/tool parents, derives a read/write project grant and read-only tool
grant, and runs real Node until both file descriptors have been opened and read
and a tool write has been rejected. It then revokes either parent while Node
waits on a timer. Both cases require `Denied` completion, absence of the
post-revocation write, zero I/O waiters, and zero live fixture capability slots
after the other parent is revoked. A fresh capability must successfully launch
Node again. Finally a weak CSpace observer must see zero remaining owners.

`live-authority/` passes both cases against `live-authority-link/`: four project
grant and page-owner releases, two tool-grant releases and four stream-waiter
registry releases. This qualifies the new terminal I/O assertion as well as
the combined supervisor/revocation cleanup path. It complements the earlier
native/Node tests that explicitly attempt operations on revoked descriptors;
here the supervisor denies execution before the delayed operation runs.

The probe is absent from normal images and adds no VSH revocation command or
ambient project/tool authority. It still links the pre-0058 Node archive; the
upcoming complete build must requalify it alongside the wrapper-memory fix.

## Independent non-OOM V8 fatal path

`--fatal-probe` is a separate C++ build option that attempts a second platform
initialization after successful Node/V8 process startup. It is absent from
normal images. The real upstream startup-order check emits `V8_Fatal`, then
`v8::base::OS::Abort()` executes a RISC-V breakpoint. The kernel reports trap
cause 3 and requests SBI shutdown with the system-failure reason. QEMU/OpenSBI
still returns host exit code 0; that code alone does not indicate guest success.

`fatal/` passes with symbols resolved from its exact ELF (`fatal-link/`), proving
the initialization-order fatal, `OS::Abort`, breakpoint, no user-script execution
and whole-image shutdown. No native-stack recovery is attempted. This path is
distinct from the separately qualified `FatalProcessOutOfMemory` route.
`fatal-initial-harness/` preserves the initial wrong expectation of a native
fatal-exit marker; `fatal-shutdown-observation/` preserves the subsequent wrong
expectation of host exit code 1. The runtime was not changed to match either
expectation; the verifier was corrected to the observed, symbolized fatal path.

## Fresh cross-build including wrapper cleanup

`fresh-build/` records successful configure, engine, libuv, Node dependencies
and Node phases, prepared from the locked archive with patch 0058. Host wall
times are 0.609 s, 1553.705 s, 4.0 s, 12.934 s and 46.143 s respectively.
Raw phase output is compressed with uncompressed hashes/sizes recorded alongside.
This build includes the owning cppgc wrapper-list destructor; unlike the earlier
diagnostic links, its subsequent images do not reuse the pre-0058 Node archive.

`fresh/audit-link/` is the new audit image. Both `fresh/eval-cycles/` and
`fresh/file-cycles/` pass all 100 ordered teardown checks, including project
authority and terminal I/O registries. Non-cache newlib allocated chunk bytes
are exactly **250,640 for every invocation** in both runs (129.73 s and 129.51 s).
The eval entrypoint that exposed the wrapper-node leak now passes without a
drift allowance. `fresh/node/` passes functional/exception/CPU and idle
cancellation checks (16.42 s).

The matching new `fresh/authority-link/` also passes both parent-revocation,
CSpace-destruction and restart cases (`fresh/authority/`, 3.39 s).
`fresh/boundary/` passes path/readonly/cwd/descriptor checks (37.73 s), and
`fresh/tsx-cancel/` passes cancellation during the real WASI transform and
successful restart (31.67 s). These manifests bind the updated source hashes
and fresh archive inputs; earlier failed growth traces remain historical evidence.


The remaining fresh-image suites also pass: `fresh/backpressure/` (8.12 s),
`fresh/oom/` (3.93 s), and `fresh/fatal/` (2.56 s). The latter uses the matching
`fresh/fatal-link/` deliberate initialization-order failure image.

## Repeated uncaught-error reclamation

`fresh/error-cycles/` runs 100 eval-entrypoint workloads, each ending with a
distinct uncaught error after file, ESM, timer, Buffer and stdin work. All 100
exit statuses are 1, with ordered file/TLS/page/project-grant/I/O teardown.
Non-cache newlib allocated chunk bytes are exactly **250,688 on every cycle**;
this 128.41 s run passes with no drift allowance.

The mixed Node suite first acquired another 48-byte allocated chunk on its
uncaught-error path. The historical trace identifies a 35-byte `_strdup_r`
request. `tracing-category-cache/` preserves the exact diagnostic ELF's callsite
and pinned upstream source: its caller is
`TracingController::GetCategoryGroupEnabled`, which interns category names in
the process-wide bounded 200-entry table, reuses existing names, and frees them
in the controller destructor. This is process-lifetime storage, not per-error
growth. The repeated-error test retains these bytes in its accounting; it does
not subtract them as an allowance.


## Shared synchronization inventory

The audit now also enumerates the process-shared semaphore registry after each
native invocation. Each retained semaphore must have exactly its registry's one
strong reference, and the shared notification registry must have no waiter.
The cycle verifier requires 100 matching owner snapshots and an exactly stable
handle count after warm-up. This distinguishes intentional process-owned
synchronization from per-invocation handle or posting-right retention. `sync-audit-link/` records the updated image (48.17 s link). Its
`sync-error-cycles/` run passes all 100 uncaught-error invocations in 125.42 s:
exactly 13 retained synchronization handles and 250,704 non-cache newlib bytes
at every snapshot, with zero external semaphore references and waiters.
`sync-node/` also passes functional, CPU/idle cancellation and restart cases
(16.40 s); all 15 invocations retain exactly 13 handles. Earlier evidence
pre-dates this observation. `sync-file-cycles/` and `sync-eval-cycles/` now both pass all 100 normal
invocations (128.39 s and 129.74 s). Every cycle records 13 synchronization handles,
250,640 non-cache newlib allocated bytes, and complete invocation teardown.
`sync-authority/` qualifies project/tools revocation and restart with this same
additional inventory assertion (2.80 s); all four invocations retain 13 handles.
The matching probe image is recorded in `sync-authority-link/`. M4 is complete;
M5 final production-image regressions remain outstanding.
