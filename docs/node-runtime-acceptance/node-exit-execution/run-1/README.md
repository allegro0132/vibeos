# Node exitCode 7 propagation

The target script sets process.exitCode=7, completes all project/stream/async
checks, and records the actual exit event argument. EmitProcessExit must return
7 and agree with that event. Only after full native teardown does the gate
return the observed code to Rust. QEMU records returned=7, parks=13, waiters=0;
all runtime checks pass. QEMU itself shuts down with host code 0; that is not
confused with the Node invocation's exit status. Active process.exit() is not
covered by this run; a separate scenario is being added.
