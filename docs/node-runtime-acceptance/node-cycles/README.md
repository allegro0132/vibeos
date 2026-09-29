# 100 production Node invocations with the toolkit-enabled image

`run-1/` passes 100 separately launched VSH `node --root` commands on the
corrected production ELF from `../toolkit-boundary/run-5/`. Each invocation
checks its persisted sequence number, pipeline stdin, synchronous and Promise
file IO, ESM dynamic import, a timer and a 64 KiB Buffer. It deliberately leaves
one `fs.openSync` descriptor for environment teardown instead of closing it in
JavaScript. All 100 ordered completion markers are required.

The test records guest `vtop --once` snapshots after invocations 1, 10, 50 and
100. These are whole-system heap statistics, displayed to 0.1 MiB precision.
The final three samples must stay within a 2 MiB spread; this is a coarse
growth check, not an assertion that zero bytes or capabilities are retained.
The result manifest stores the rounded live/peak samples and their exact log
representation remains in `serial.log`.

This exercises construction/destruction of the toolkit-enabled native Node
environment, including its bridge object, through production commands. It does
not run 100 TypeScript compilations or 100 WASI transforms. Separate transform
cleanup evidence is in the esbuild/tsx tests. Precise handle/capability auditing,
fatal/OOM cases and final clean-build execution qualification remain pending;
this result alone does not close M4 or the overall goal.

Reproduce with `scripts/test-node-cycles-qemu.py --kernel IMAGE --work
target/FRESH_DIRECTORY`. Source inputs are hashed before and after execution.
