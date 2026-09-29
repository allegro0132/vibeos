# M2 final regression

Affected host packages (`vibeos-vsh`, `vibeos-file-store`, `vibeos-wasi-command`,
`vibeos-sshd`) produce 169 passing unit/integration/doctest results, no failures,
and five ignored tests. The complete log and arithmetic summary are retained.
The host native libc mock-bridge contracts also pass; this is not target proof.

The default file-tree image passes the existing three-boot QEMU acceptance:
durable hard links, symlinks, recursive removal, GC pressure, cold recovery and
powered-off verification. `file-tree-qemu/` retains the driver and guest logs;
large disposable disk images stay in the temporary test directory.

The native ABI QEMU regression also passes after correcting an obsolete
write-only-open fixture expectation; `native-abi/` retains both runs.

The WASI QEMU/OpenSSH regression also passes: standard Rust/C modules, argv,
binary stdin/stderr, exit codes, upload rejection/containment, disconnect and
Ctrl-C recovery, local pipelines, post-boot compilation, 100 reclaimed
invocations with zero capabilities/waiters, and execution after reboot. Logs
and source-bound results are in `wasi-qemu/`; test fixture keys are excluded.

The V8-only feature guard regression passes target expression, exception, GC
and teardown checks; evidence is in `v8-feature-guard/`.

The fresh 57-patch V8, libuv, Node dependency and Node builds pass. The fresh
production ELF also passes local VSH and authenticated OpenSSH PTY tests.
Evidence is in `../node-fresh-57/`; the final 100-cycle launcher run also
passes, with 100 zero-waiter returns and bounded post-cleanup live memory.
These results do not close the broader M4/M5 safety and regression milestones.
