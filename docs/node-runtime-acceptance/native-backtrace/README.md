# Native frame-walker prerequisite

The four-hart QEMU C++ fixture passed using the recorded kernel and source
hashes. It obtains at least one return address from its real protected native
stack, including repeated entries and executor resumes. It rejects an address
at the bottom bound, above the upper bound, an unaligned frame, and zero output
capacity. Existing TLS, destructor, page, peer-progress and VSH checks passed.

This qualifies the shared frame-walker helper, not execution of the V8
StackTrace constructor/output methods (which only cross-compiled). Completeness
of traces, symbolization, corrupted in-bounds frame chains and signal handling
are not qualified. V8 and Node execution gates remain open.
