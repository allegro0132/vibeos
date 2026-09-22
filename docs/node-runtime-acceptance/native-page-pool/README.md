# Address-stable native page pool prerequisite

Four-hart QEMU execution passed with the recorded kernel/source hashes. An
eight-page pool releases the tail of a four-page allocation and reuses its
exact address for a distinct two-page allocation, preserving prefix bytes
and providing zeroed reused pages. Released pages are inaccessible before
reuse. Double releases, operations on freed pages, and ranges crossing
allocation identities are denied. Decommit/recommit and normal pool destruction
also execute. Other native C++/TLS/page/peer-progress/VSH checks passed.

This is the page-pool helper, not the invocation-aware V8 C ABI. Released
subranges return to the pool immediately; backing stays reserved until pool
drop. No quota, revocation, pool-exhaustion or real V8 allocation workload is
qualified. The marker's reclamation denotes normal pool destruction; separate
owner-account byte accounting is not asserted by this probe.
