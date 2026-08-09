# Testing VibeOS

Four layers, cheapest first. Run them all before pushing.

```sh
cargo test --workspace         # fast portable tests, no QEMU
./scripts/differential.sh      # verify committed output with pinned real rustc
./scripts/qemu-test.sh         # golden cases plus the differential oracle
./scripts/bench.py             # fixed QEMU/TCG run checked against the baseline
./scripts/status.sh            # derive current test/corpus counts on the host
```

`status.sh` lists runnable and ignored host tests separately and derives corpus
and transcript counts from the tree. Target checks are not guessed from source:
`./scripts/qemu-test.sh selftest` reports the count observed in that QEMU run.

| Layer | What it covers | Where |
|---|---|---|
| Host unit tests | Capability algebra including cross-space revocation, explicit leases, persistent witnesses, atomic recovered-graph installation, and tombstoned slot generations; unified authority/object journal decoding, partitioned global root selection, exhaustive prefix/flush recovery, canonical ProgramArtifact/VIBEEXE decoding and relocation, cross-kind ID/transaction collisions, and allocation-amplification inputs; modern virtio block/net feature negotiation, descriptor direction, RX length/header validation, exact tokens, multi-flight queue wrap, device-wide reset/quarantine, and reset-before-reuse; fixed-point scheduler lifecycle, four-queue ownership, per-hart running/current-task/domain state, and IPI lost-wakeup models; work stealing, wake/remote-cancel/fault boundaries and cross-hart fault survival; reason coalescing, stale SSIP, offline/online handoff, physical hart mapping, and send-failure retry; atomic IRQ publication, SPSC byte ordering, SpinLock contention/generation recovery/hart ownership; fault arenas; wait/timer registration ownership; per-hart heap provenance and OOM diagnostics; typed channels and the compiler | `core/tests/`, `compiler/tests/` |
| In-kernel self-test | Real timer interrupts and wakeups, cancellation cleanup, sixteen fault/restart cycles with bounded heap use and no interrupted Drop, normal/abort release of exclusive generated-memory claims, component allocation isolation/reclaim, `ComponentId`/`TaskId`/CSpace binding, retained fault state, the live capability graph, machine code actually executing | `kernel/src/selftest.rs`, via `selftest` in the shell |
| Golden transcripts | End-to-end shell behaviour, including retained cancelled state, revoke-during-invocation lease boundaries, durable-log recovery, real virtio-blk read/write/flush, virtio-net raw-L2 exchange and fault recovery, timeout reset, cancellation/fault restart, capability-addressed object commit/read/revoke, three boots of one persistent CSpace, and two boots of a saved source/VIBEEXE artifact against the same disk | `tests/cases/`, `tests/golden/` |
| Differential vs real rustc | Whether generated code computes the *right answer* | `tests/programs/`, `scripts/differential.sh` |
| Fuzzing | Whether the front end can be made to panic | `compiler/tests/fuzz.rs` |
| Mutation checks | Whether the above actually catch anything | ad hoc; see below |

The `block` QEMU case is intentionally stronger than a transcript: every case
gets a fresh raw disk, sector 7 is seeded by the host, and after `blk test` exits
the host compares all 512 bytes of sector 8. `block_recovery` suppresses one real
QueueNotify to exercise the timer/reset path, injects a component fault after DMA
publication, and separately verifies cancellation plus explicit restart.

The `store` case is likewise stronger than its transcript. The host first seeds
506 valid records containing a 180,720-byte object, leaving exactly six journal
slots. Four injected raw component faults must each reach the task/domain-bound
pre-write hook after this dense recovery, clear the exact store claim, reclaim
each arena, and reach a stable heap plateau. Store calls require 4 MiB of free
caller headroom before claiming the writer; the shell and probe each have an 8 MiB
quota. The next command commits and reads a
deterministic 900-byte object, filling all 512 slots. After shutdown,
`store-image.py` independently checks the fixed sectors 64--575, platform StoreId,
canonical kinds 1--8, shared ID/transaction classes, chain/CRC/commit binding,
and both exact payloads. Its positive interleaving and negative parity fixtures
run before the real backing image is accepted.

The `persistent_cspace` case reboots three times against one unchanged raw disk.
Boot 1 persists and installs a `root -> child -> grandchild` object-capability
graph; boot 2 reads it, flushes a tombstone for the child ancestor, and proves
both child and grandchild absent; boot 3 keeps that tombstone effective and
reuses child slot 1 only at generation 1. Every boot also checks that the target
`persistent-test` CSpace has no Store `WRITE` authority and that its first dependent
observation occurs only after recovery reaches `Ready`. After the third shutdown,
`persistent-cspace-image.py` independently parses the raw journal. Its host-side
self-test applies all 512 strict byte-prefix cuts to each of 19 canonical fixture
records (9,728 cuts) and requires every cut to recover exactly the preceding
flushed boundary before checking malformed graph and root-policy fixtures.
Core tests additionally prove that persistent quarantine denies generic lookups,
invalidates `Revocable` tokens, preserves an already acquired invocation lease,
and retains resource entries without running `Drop`. The service's stable
task/domain/token ledger lets raw-fault cleanup clear only the exact abandoned
reservation without touching another caller.

The `program_persistence` case reboots twice against one unchanged raw disk.
Boot 1 publishes the fixed `hello` source plus canonical relocatable VIBEEXE as
one read-only ProgramArtifact root and runs it. Boot 2 proves a repeat save
appends nothing, recovers the exact slot-0/generation-0 capability, recompiles the
source with the current trusted compiler, requires byte-identical VIBEEXE, and
runs using only reconstructed console `WRITE` and memory `READ|WRITE` authority.
After shutdown, `program-image.py` independently validates the journal, artifact,
hashes, relocation table, stable imports, publication order, authority manifest,
and strict 512-byte prefix cuts. See `docs/PROGRAM_PERSISTENCE.md`.

The `net` and `net_recovery` cases are also stronger than their transcripts.
Only those cases add a modern virtio-net device. Before QEMU starts, the harness
launches `scripts/net-peer.py` on an ephemeral localhost TCP port and connects
QEMU's socket netdev to it. The peer parses the four-byte big-endian QEMU frame
length and compares every byte of the 60-byte raw Ethernet messages. `net`
requires HELLO, CHALLENGE, and ACK in order. `net_recovery` first observes the
HELLO exposed before an injected component fault, withholds its response, and
then requires a second HELLO plus the complete exchange after the shared device
epoch advances. A canonical evidence file is checked separately from the guest
golden; TAP, root privileges, and host network access are never used.

The `smp_queues` case keeps the one-CPU physical QEMU boundary and places one
untracked task on each of the three logical remote queues. It requires logical
hart 0 to report an exact steal delta of three with every probe executing once.
Because those logical targets are offline, their Release-published reasons must
remain pending with no SBI attempts. A separate ready boot-hart probe deliberately
forces one self-doorbell and requires real OpenSBI delivery, SSIP acknowledgement,
and executor return. The same transcript confirms the PLIC/UART RX/virtio IRQ-data
handoffs have no SpinLock and samples the retained scheduler counter with an exact
zero single-hart contention delta. M5.4's host test nests the hart-1 executor while
a hart-0 task remains active and checks running/current-task/domain isolation,
remote cancellation, and fault survival. Physical secondary execution is still
reported as gated until M5.5, and no timing value appears in the golden. A pre-M5.5 `-smp 4` smoke did not
reach the shell, so it remains M5.5 work rather than parked-hart evidence.

## Performance baseline

The shell's `bench` command measures two-endpoint IPC round trips, timer-IRQ to
task-poll latency, capability lookup at derivation depths 0 through 32, global
heap high-water, compiler throughput, and generated code/data size and runtime.
Every timing distribution reports warmup/sample counts plus min, p50, p95, max,
and integer mean in raw `rdtime` ticks.

`scripts/bench.py` boots the release kernel with `virt`, `rv64`, one hart,
single-threaded TCG, and deterministic `icount`; it rejects missing, duplicate,
or schema-changed metrics before comparing the checked-in
`benchmarks/qemu-tcg-rv64.json`. Latency/size regressions are upper-bounded and
throughput is lower-bounded. Relative budgets are combined with small absolute
allowances for timer quantisation; heap and generated buffers use the documented
larger byte allowances.

```sh
./scripts/bench.py                 # collect and check; never rewrites truth
./scripts/bench.py --update        # intentional baseline replacement
./scripts/bench.py --input log.txt # validate/recheck a saved transcript
```

The guest IPC number is a repeatable VibeOS trend measurement, not yet a claim
against a Linux pipe: a host pipe measured on another ISA/runtime would not be a
controlled comparison.

## Why four layers

Each layer catches what the one above it structurally cannot.

Host tests cannot reproduce interrupt ordering, because the host arch shim makes
interrupts a no-op — so timer and wakeup behaviour belongs to the in-kernel
self-test. Neither host tests nor the self-test can check the *semantics* of
emitted machine code as thoroughly as running a program whose every output value
is known, which is what the `conform` golden transcript is for.

This is not hypothetical. Changing one frame offset in the code generator:

```rust
-  self.emit(ld(T0, S0, off));
+  self.emit(ld(T0, S0, off + 8));
```

passes **every host test**, including the confinement audit — the instruction is
still a structurally valid load through the frame pointer. The QEMU conformance
run catches it immediately:

```
-call 42 3628800
+call 2149628476 8634481114540408832
```

`2149628476` is `0x8020xxxx`: a kernel address, read off the stack by a compiled
program. That is the privilege-escalation class this project's design rests on
preventing, and only the integration layer sees it.

## Differential testing against real rustc

Every program in `tests/programs/` is valid Rust *and* valid in the VibeOS
subset, so `rustc` is a free oracle for the code generator — the strongest check
available for something this security-critical.

`scripts/differential.sh` compiles each with the exact real `rustc` pinned in
`rust-toolchain.toml`, runs it, and verifies the committed output byte-for-byte.
It is read-only unless passed `--update`; a missing expectation fails instead of
silently becoming truth. The QEMU `differential` case feeds the same source
through `rustc edit` inside VibeOS and requires identical bytes. The case file is
regenerated from the corpus on every run, so the two cannot drift.

Keeping the corpus inside the intersection of the two languages is a real
constraint, and getting it wrong is caught immediately — rustc rejected the
first draft because bare integer literals infer as `i32` while the subset is
`i64`-only. See `tests/programs/README.md` for the rules.

## Updating goldens

```sh
./scripts/differential.sh --update  # real-rustc corpus expectations
./scripts/qemu-test.sh --update      # all cases
./scripts/qemu-test.sh conform       # run one case
./scripts/qemu-test.sh net           # raw L2 exchange plus host evidence
./scripts/qemu-test.sh net_recovery  # post-publish fault and fresh-epoch retry
./scripts/qemu-test.sh program_persistence # two boots plus raw artifact evidence
./scripts/qemu-test.sh smp_queues   # logical queues + boot-hart SBI/SSIP, one CPU
```

Read the diff before updating. The `--update` flag is the only thing standing
between a deliberate behaviour change and a silent regression.

## Adding a test

- **A bug that reached `main` gets a regression test in the same commit as its
  fix.** Both bugs found so far are in the suite: the dropped self-wake
  (`core/tests/runtime.rs`) and the invisible running task (both there and in
  `kernel/src/selftest.rs`).
- **Diagnostics are asserted verbatim.** Error messages are a UI; a silently
  reworded error is a regression a user notices first.
- **New compiler syntax gets a line in `samples::CONFORMANCE`** with a printable,
  hand-checkable value — not just a "does it compile" test.

## Checking that a test can fail

A test that cannot fail is worse than no test, because it looks like coverage.
To check one, break the code it covers and confirm it goes red:

```sh
# in core/src/cap.rs, temporarily:
-  if !e.rights.contains(need) {
+  if false {
cargo test -p vibeos-core --test cap     # must FAIL
```

Mutations verified to be caught: dropped self-wake, bypassed rights check,
non-cascading revoke, unbumped generation, permitted amplification, memory access
through a non-frame register, dropped `li64` chunk, wrong store opcode, corrupted
precedence table, dropped heap free-list entry.

Mutations **not** caught by host tests, caught only under QEMU: wrong frame
offset. That gap is the reason the golden transcripts are not optional.
