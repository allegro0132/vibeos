# Cancel tsx while its WASI transform is running

The production VSH `tsx --root` command is cancelled with Ctrl-C after the
guest reports `WASI running`. Its parent command becomes Cancelled, the child
WASI authority is denied, and the audited WASI reaper reports
`reclaimed=true caps=0 waiters=0`. A subsequent tsx invocation transforms and
executes the same TypeScript file successfully. Only that second invocation
may print the JavaScript completion marker. Both started transforms must have
matching reclamation records.

Run 1 reached these outcomes but failed because the verifier required the
child terminal state to be Cancelled. The child launch authority includes the
parent cancellation state, so Denied is also correct. Run 2 accepts either
child state, still requires the parent command's Cancelled result and all
reclamation/relaunch checks, and passes. The original failed result is retained.

This image includes the esbuild TLS destructor assertion: an unreleased
transform handle prevents normal invocation teardown. Link inputs and logs
are retained in `../tsx-qemu/cleanup-guard/link/`. That directory also records
the full production tsx regression on the same image: cross-file CJS/ESM,
dynamic import, offline dependency, custom TSX factory, source-mapped failure,
relaunch, and exactly ten reclaimed WASI transforms all pass.

These are incremental-image results. Complete fresh cross-build qualification
remains pending. This test does not substitute for independently revoking a
project or tool capability while the parent command remains active.

Reproduce with `python3 scripts/test-tsx-cancel-qemu.py --kernel IMAGE --work
target/FRESH_DIRECTORY`.
