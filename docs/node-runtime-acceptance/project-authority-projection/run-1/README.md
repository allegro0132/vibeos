# Project projection retains original capability authority

FileGrant::directory captures an admitted directory identity and a selector.
Every lease acquisition first invokes the original provider, recreates its
bounded directory view, and checks that identity. The underlying source lease
remains alive throughout the projected operation, including async reads and
mutations. No independent project capability is minted by this adapter.

The target probe checks source-capability revocation, directory replacement,
symlink retargeting and READ-only rejection of WRITE. Existing admitted leases
retain the core active-invocation contract; revocation denies the next lease.

Real Node then runs through this projection from a parent-tree capability.
All main-file, CJS/ESM, sync/Promise file, stream, async work, subtree escape
and teardown checks pass; native status 0, parks=196, waiters=0. Parent bytes
remain protected. The first build's PendingRead lease-type mismatch is retained
with the successful correction: async reads must keep the complete FileLease.

The source provider in this gate is kernel-created. Production VSH command
registration and its bounded context provider still need wiring.
