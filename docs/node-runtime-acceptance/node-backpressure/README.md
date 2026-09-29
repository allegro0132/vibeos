# Native Node stdout backpressure through VSH

Both runs execute production `node` commands on the corrected toolkit image
from `../toolkit-boundary/run-5/`. The ELF hash binds these tests to that
directory's retained runtime/libuv link evidence.

The producer writes 131072 bytes to stdout, requires `write()` to return false,
and records both the write completion callback and the `drain` event through
project files. VSH pipes stdout to its capability-backed `write` command.
A subsequent Node invocation verifies every saved byte, the exact file length,
and both callback records. Another invocation confirms normal relaunch.

Run 1 passes using separate driver commands. Run 2 also passes with the
pipeline and verification sequenced in one VSH command, so a prompt redraw
cannot start verification before the pipeline finishes. The test records
source hashes before execution and verifies they remain unchanged.

`node-read-fill-regression/` additionally passes the existing Node/VSH suite
on this same corrected image, including CJS/ESM, files, stdin, redirection,
timers, exit codes, exceptions, CPU/idle cancellation and relaunch.

This is actual Node stream/VSH output-backpressure evidence, supplementing the
native stdio bridge's bounded-buffer tests. It does not by itself prove live
capability revocation or 100-cycle memory/handle reclamation, which remain
separate M4 requirements. Final clean-build execution qualification is pending.

Reproduce with `scripts/test-node-backpressure-qemu.py --kernel IMAGE --work
target/FRESH_DIRECTORY`.
