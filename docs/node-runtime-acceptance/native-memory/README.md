# Per-context native memory ABI prerequisite

Four-hart QEMU execution passed with the recorded kernel/source hashes.
The actual C++ fixture calls allocation/release/protect/decommit/discard through
the native C ABI. It verifies address-stable tail reuse, zeroed reused and
recommitted bytes, invalid-permission rejection, cross-allocation release
rejection, and double-release rejection.

A separate protected-stack fixture enters two native contexts: the second
cannot protect the first's page, while its owner can. After owner revocation,
protection and new allocation fail. Normal context destruction releases the
pool, asserts zero live bytes and allocations, and unregisters its heap owner,
including the still-live page of the revoked context. The fixture uses a 1 MiB
visible pool capacity and a 4 MiB backing/metadata accounting ceiling.

This does not qualify production V8 capacity, quota exhaustion, full invocation
capability admission, static-image flag protection, or real V8/Node execution.
Revocation denies bridge operations; it does not instantly unmap every existing
raw pointer or safely terminate arbitrary active C++ code.
