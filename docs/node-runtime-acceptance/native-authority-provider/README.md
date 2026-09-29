# Native file lease-provider bridge

FileGrant now retains an owned lease-provider closure. Every existing native
file operation requests a fresh lease; a raw cached FileTreeRoot does not
replace capability checks. The kernel fixture constructor uses this same
provider path, with separate test-only metadata for its revocation hook.
The original compile failure from that hook is retained.

VSH CapabilityCommandContext now provides a bounded resource lookup closure
that retains the stage CSpace, command and job liveness. It rejects requests
outside the specified maximum rights or after job cancellation, checks command
INVOKE authority and obtains a fresh typed source lease under the same CSpace
lock. The lock is released before resource I/O. Already admitted leases retain
the existing capability active-invocation semantics.

Host VSH suite: 33 passed. Tests cover root revocation during an active command,
rejection of WRITE from a READ-bounded provider, and a retained provider becoming
unusable after background-job cancellation. They do not independently isolate
command-only revocation or concurrent cancellation/lease-admission races.

QEMU Node main-module regression passes the generic FileGrant provider path,
including all prior module/file/stream/runtime checks, return 0 and zero waiters.
The QEMU gate still uses a kernel-created project capability. It does not yet
connect a VSH-provided closure to a production node command, implement subtree
root confinement for --root @home/project, or qualify full M2.
