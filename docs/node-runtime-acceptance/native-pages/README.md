# Native owned-page/MMU prerequisite

The LP64D `native-cxx-probe` image allocates eight zeroed pages aligned to an
eight-page boundary. The page object owns the allocation and its per-page
permission metadata. QEMU checks the live Sv39 mappings for RO, inaccessible,
and RW/NX transitions. A deliberately wrong expected PTE in the middle rejects
the entire range without changing its earlier pages. Overflow and bounds
requests fail. Destruction restores mixed RO/inaccessible pages to RW/NX before
returning memory to the allocator. Existing C++ parking, four-hart and VSH
checks also pass.

The MMU implementation validates all expected PTEs under the page-table lock,
then performs break-before-make and TLB synchronization. This test inspects
actual page tables and valid reads/writes; it does not inject prohibited
accesses or independently demonstrate another hart's TLB invalidation.

The C ABI allocation registry, invocation admission, partial release,
discard/decommit and registered static V8 data protection are not implemented
by this page object yet. This is not V8 execution or the full memory security
gate. No executable permission is representable in this native-data API.
