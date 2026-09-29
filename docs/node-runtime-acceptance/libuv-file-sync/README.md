# File synchronization against authoritative publication

Native file writes already await commit_authoritative before reporting success.
FileTreeRoot::completed_generation observes the current generation while holding
state then writer locks, matching the volatile commit lock order. It returns
Busy while a writer claim exists. The native file sync bridge revalidates the
file descriptor and READ authority before consulting this publication boundary.
No empty transaction is published and no generation is incremented by sync.

uv_fs_fsync/fdatasync share this check because content and metadata publish in
the same transaction. Synchronous requests report immediately; asynchronous
requests use the existing filesystem completion/cancellation queue. This first
port returns EBUSY instead of waiting for an in-progress publication. Callers
must await their writes before syncing. A deliberately volatile FileTreeRoot
remains volatile; success adds no disk durability beyond the selected backend's
existing authoritative commit policy.

QEMU uses the volatile root: it stages an owned write future, verifies sync is
busy before polling its publication, completes the write, then verifies both
sync APIs succeed. It checks deferred callbacks, queued cancellation, unchanged
metadata/generation, exact data readback, pipe/closed-fd rejection and capability
revocation. The cumulative V8/libuv gate passes with 100 native parks (not 100
invocations), zero waiters, normal shutdown, 305733248-byte allocator peak and
36162176-byte post-run live memory.

The file-store host suite passes 32 tests with 5 ignored, including a new test
for active, aborted and committed writer claims. The initial cargo +toolchain
launch failed because the available cargo executable is not a rustup proxy;
the rerun uses the pinned toolchain's absolute cargo/rustc/rustdoc paths.

Physical-media flushing, delayed persistent-backend publication, power-loss
recovery, waiting rather than returning EBUSY, Node JS invocation and full
TypeScript acceptance remain unqualified. No Node execution milestone is claimed.
