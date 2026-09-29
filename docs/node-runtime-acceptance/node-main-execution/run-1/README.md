# Upstream Node main-module entry on QEMU

The gate passes argv `node /main.cjs 0 0` to CreateEnvironment and uses
LoadEnvironment with an empty StartExecutionCallback. Node selects its own
internal/main/run_main_module bootstrap and loads the project file through
the capability filesystem. The file is the shared target-only project test
fixture; no project transformation or execution occurs on the host.

QEMU verifies require.main === module, __filename === /main.cjs, cwd === /,
and argv-controlled exit mode. The full CJS/ESM, sync/Promise file, stdin,
Buffer/timer and zlib checks pass. Native teardown returns 0, parks=193,
waiters=0; peak kernel heap usage is 305757952 bytes.

The test fixture was extracted from the embedding C++ source so file startup
and inline startup share the same checks. The generated raw-string include
is retained alongside the link logs, and the QEMU report hashes the JS fixture.
This first link report predates explicit fixture/include hashes in the linker
report; those are added for subsequent builds.

This proves upstream file startup, not a registered production VSH node
command, reusable process initialization, arbitrary CLI options or full M2.
