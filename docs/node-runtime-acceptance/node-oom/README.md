# Unrecoverable V8 OOM in a separate QEMU instance

Both runs execute the production Node command on the corrected toolkit ELF
qualified in `../toolkit-boundary/run-5/` (SHA-256
`370d28974082adff979d9daf80d5fb4eaf6e20026841acd169999fbd583f9552`).
The guest retains large JavaScript arrays until V8 cannot allocate more heap.
No host JavaScript execution or simulated fatal event is involved.

Run 1 reached the actual V8 OOM path and shut down QEMU, but its verifier
required a textual fatal diagnostic that was absent from the serial output.
The original failing result is retained. Symbolizing the recorded PCs against
the exact guest ELF identifies `V8::FatalProcessOutOfMemory`,
`Utils::ReportOOMFailure`, and the heap allocator retry/failure path.

Run 2 uses a verifier requiring both the V8 fatal-OOM and heap-allocation-failure
frames, symbolized with the pinned RISC-V toolchain against the copied guest
ELF. It passes in 4.56 seconds. The result records the addresses, ELF and
symbolizer hashes, source hashes captured before execution, and the unchanged
source check. A generic native abort cannot satisfy this verifier.

Observed behavior is `NATIVE FATAL EXIT status=1 scope=trusted-image
recovery=none`, followed by firmware shutdown (QEMU exits with status 0).
QEMU's process status is not the Node exit status. There is no normal Node
completion and no recovery attempt. This records the accepted whole-image
failure boundary; it does not demonstrate instance isolation or recovery.
Final clean-build qualification remains pending.

Reproduce with `python3 scripts/test-node-oom-qemu.py --kernel IMAGE --work
target/FRESH_DIRECTORY`.
