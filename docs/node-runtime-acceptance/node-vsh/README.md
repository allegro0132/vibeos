# Native Node VSH launcher integration

The node-runtime feature now registers the capability command in standard local
and authorized remote VSH command sets. The node-runtime-gate feature separately
opts into automatic target gate startup; --node-shell links the production ABI
without the C++ smoke fixture. The default image remains without Node.

The launcher strips --root, projects the original project capability with fresh
leases, supplies an empty explicit environment, and copies argv/eval into SYSTEM.
A pinned SYSTEM supervisor owns a Send FnOnce entry until normal native return.
Its lifetime does not depend on the cancellable VSH future. It shares only the
process synchronization domain, enforces one active admission, pumps stdio, and
monitors live project authority every 10 ms. Completion follows native cleanup.

The owned-entry change passes the prior main-file target regression. The first
actual VSH run (run-1, link 63) passes eval=3, cross-file CJS=42 and piped stdin,
then faults in cppgc::internal::HeapObjectHeader::Finalize. Disassembly identifies
the failing read through GlobalGCInfoTable's process-wide table pointer, after
the first invocation page pool has been dropped. The table is initialized by
V8::Initialize but is retained globally. Repeating one identical script did not
expose this ownership bug; varying commands did.

The correction scopes Node/V8 process initialization page allocations into a
separate bounded 4 MiB TCB pool. Subsequent page operations select ownership by
validated allocated address range. Invocation pools remain independent. This
pool lives for the trusted process lifetime and is not charged as a job leak.
Target revalidation is pending below. SSH transport, cancellation/exit status,
readonly tool mounts, resource inventory, and the full M2 gate remain pending.

Run 2 (link 64) passes the previously failing mixed-command sequence through
VSH: eval=3, cross-file CJS=42, piped stdin, persistent-project fs write/read,
and timer completion. No automatic gate or fatal error occurs. This provides
execution evidence for the process-lifetime page ownership correction.

Run 3 extends the sequence with dynamic ESM, redirection, conditional exit,
uncaught error and real Ctrl-C. ESM, uncaught diagnostics, CPU/idle cancellation
and subsequent Node invocations pass without fatal errors. Two harness syntax
mistakes fail: VSH redirection accepts a stream capability, not a file-tree path,
and the current shell parses `if` directly without a leading `vsh` command.

Run 4 uses the same link-65 image with corrected existing VSH syntax. All checks
pass: dynamic ESM=99, explicit stdout redirection to @console, a nonzero exit
selects the conditional else branch, an uncaught error reports [eval]:1:7, and
Ctrl-C interrupts both a real infinite loop and a 60-second timer. Fresh Node
calls succeed after each cancellation. This verifies VSH cancellation actually
reaches the persistent native supervisor and that it retires the prior instance.
The exact numeric VSH exit status and SSH transport still need further evidence;
nonzero conditional behavior alone does not prove propagation of the value 7.

Link 65 additionally releases single-instance admission before publishing
completion, preventing a sequential command on another hart from racing the
previous invocation's admission guard. This change is covered by the immediate
conditional branch invocation in run 4.

The fixed 0.3-second gaps are harness pacing for console redraws, not runtime
busy polling. Runtime waiting remains driven by native notifications, timers
and VSH stream futures. The driver timeout bounds cancellation cases, but these
runs do not measure cancellation latency precisely (the dedicated idle gate did).

Run 5 passes the full corrected command sequence plus an independent
process.exit(7) command, which VSH reports as Returned(7). The verifier also
requires the uncaught error location [eval]:1:7. Thus exact numeric VSH exit
propagation and eval error location are now qualified. SSH transport and final
source lifecycle/resource/regression checks remain pending.
