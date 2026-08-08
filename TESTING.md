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
| Host unit tests | Capability algebra including cross-space revocation, explicit revocable/invocation lease semantics, dishonest type-erasure implementations, and CSpace reset ABA; fixed-point scheduler lifecycle model; cancellation/join boundaries; fault-arena teardown; wait/timer registration ownership and stress; owner-tagged heap quotas/provenance; channels, lexer, parser, instruction encoding | `core/tests/`, `compiler/tests/` |
| In-kernel self-test | Real timer interrupts and wakeups, cancellation cleanup, sixteen fault/restart cycles with bounded heap use and no interrupted Drop, normal/abort release of exclusive generated-memory claims, component allocation isolation/reclaim, `ComponentId`/`TaskId`/CSpace binding, retained fault state, the live capability graph, machine code actually executing | `kernel/src/selftest.rs`, via `selftest` in the shell |
| Golden transcripts | End-to-end shell behaviour, including retained cancelled state, revoke-during-invocation lease boundaries, and program output | `tests/cases/`, `tests/golden/` |
| Differential vs real rustc | Whether generated code computes the *right answer* | `tests/programs/`, `scripts/differential.sh` |
| Fuzzing | Whether the front end can be made to panic | `compiler/tests/fuzz.rs` |
| Mutation checks | Whether the above actually catch anything | ad hoc; see below |

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
