# Native discard/decommit prerequisite

The RV64GC/LP64D QEMU image adds actual native-page discard and decommit to the
owned-page probe. A mixed RO/inaccessible/RW range is discarded; its permissions
are checked before restoring read access and verifying every cleared byte.
Neighboring pages keep their original contents. Dirty pages are decommitted,
confirmed inaccessible in the live Sv39 page table, then recommitted RO and
checked byte-by-byte for zeros. Invalid bounds and a mismatched later PTE reject
before changing earlier contents. Destruction restores allocator access.

All validation precedes page-table mutation under the existing page-table lock.
Clearing temporarily maps owned pages RW/NX, clears them, then uses
break-before-make and TLB synchronization to restore per-page permissions or
leave the range inaccessible. Physical backing remains reserved. No allocation
or recoverable failure follows the first mutation. Callers must exclude every
raw-pointer user for the entire operation.

The same run passed protected native calls, C++ RAII over suspension, executor
parking, four-hart identities and VSH. Source/kernel identities and the exact
QEMU command are in results.json. The build used nightly-2026-08-01 and features
wasi-ssh-upload,native-runtime-probe,native-cxx-probe.

This does not qualify V8 execution, invocation capability admission, partial
release, static V8 image protection, prohibited-access faults or independent
remote-TLB behavior. The V8 C ABI registry is not connected yet.
