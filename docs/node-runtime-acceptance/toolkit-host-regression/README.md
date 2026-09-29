# Toolkit host regression checks

`run-1/` records successful pinned-nightly (`nightly-2026-08-01`) host tests
for `vibeos-file-store`, `vibeos-vsh` with `file-tree`, and
`vibeos-wasi-command`, using the locked dependency graph. Logs retain individual
test results, including ignored tests; zero command exit status does not imply
ignored tests were executed.

The transform protocol's three admission tests also pass. A driver subprocess
check confirms that `@wait-exit` preserves a nonzero guest-process exit status
and retains final output instead of sending the interactive quit sequence.

These host checks supplement target evidence. They do not execute V8,
TypeScript or tsx and do not replace the pending clean-build QEMU gate or the
broader final MMU/WASI/filesystem regression.
