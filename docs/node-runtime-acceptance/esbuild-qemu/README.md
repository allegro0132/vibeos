# esbuild WASI target acceptance

Captured by `scripts/test-esbuild-qemu.py` from the pinned official esbuild 0.25.0
WASI Preview 1 module, running in VibeOS on QEMU RISC-V. `results.json` contains
kernel/module identities, cases, timings, owner peak allocation and fuel counts.
`qemu.log` and the `.stdin`/`.stdout`/`.stderr` files preserve captured bytes,
including terminal carriage returns and compiler diagnostic whitespace.

The report names the pre-commit Git base. `source-fingerprints.json` identifies
the modified runtime/build files used by the frozen tested kernel; these hashes
match this milestone's source. Submodule revisions and tool versions are also
recorded. The ordinary 128 MiB firmware boot/echo regression is recorded in
`default-results.json` and `default-qemu.log`.

The runtime logs cover default, Python and esbuild profiles. The separate
boundary logs cover the declaration-ceiling test added after those suite runs.
The integration log covers network, SSH and WASI command transport tests.

This gate covers standalone esbuild transforms. V8/Node execution, tsc type
checking, the adapted tsx loader/service, and full lifecycle qualification are
not established by these results. See `docs/NODE_RUNTIME.md` for open milestones.
