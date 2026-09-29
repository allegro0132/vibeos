# Default-image file-tree regression

The existing `scripts/qemu-file-tree-test.sh` passes on the current worktree
with the pinned Rust toolchain. It builds the default 128 MiB `file-tree`
firmware without Node dependencies, then performs three QEMU boots against a
persistent disk. Checks cover durable hard links, symlinks, recursive removal,
GC pressure, cold recovery and powered-off disk verification.

`driver.log` retains the build/test outcome, `boot*.log` the guest output, and
`artifact.json` the resulting ELF hash. Disposable disk images are excluded.
This supplements host file-store tests; it does not replace final toolkit-image
WASI/MMU and command regressions.
