# Testing VibeOS

Four layers, cheapest first. Run them all before pushing.

```sh
cargo test --workspace     # 96 host tests, no QEMU, ~1s
./scripts/qemu-test.sh     # 5 golden transcripts under QEMU, ~2min
```

| Layer | What it covers | Where |
|---|---|---|
| Host unit tests | Capability algebra, scheduler, timers, channels, allocator, lexer, parser, instruction encoding | `core/tests/`, `compiler/tests/` |
| In-kernel self-test | Real timer interrupts, real wakeups, the live capability graph, machine code actually executing | `kernel/src/selftest.rs`, via `selftest` in the shell |
| Golden transcripts | End-to-end shell behaviour and program output | `tests/cases/`, `tests/golden/` |
| Mutation checks | Whether the above actually catch anything | ad hoc; see below |

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

## Updating goldens

```sh
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
