---
name: os-compiler-dev
description: Use when writing, changing, or reviewing operating-system or compiler code — kernels, bootloaders, allocators, schedulers, interrupt handlers, drivers, code generators, parsers, or anything emitting machine code. Covers how to test code that has no operating system under it, why a green suite can still be worthless, and the failure modes specific to this domain.
---

# Developing an OS or a compiler

The distinguishing feature of this work is that **the usual feedback signals are
absent or lying**. There is no runtime to catch your mistake, no exception to
propagate, no stack trace. A wrong offset does not crash — it silently reads
someone else's memory and keeps going. A dropped wakeup does not error — the
machine simply stops making progress, ten seconds later, somewhere else.

So the discipline is different from application work in one specific way: **you
cannot test at the end.** By the time you have written enough to run it, you have
written enough to be unable to find the bug.

## Write the test in the same change as the code

Not before, not after — with. For every non-trivial function you add, add the
test that would catch it being wrong.

The reason is not process hygiene. It is that in this domain the cost of finding
a bug rises faster with time-since-writing than in any other kind of programming.
An interrupt-ordering bug found ten minutes after you wrote it is a puzzle. The
same bug found three subsystems later is a week, because it now presents as a
hang in unrelated code.

**A bug that reaches main gets a regression test in the same commit as its fix.**
This is the one rule that compounds — the suite ends up encoding exactly the
mistakes this codebase is prone to, which is more valuable than any generic
coverage target.

## Make the code testable before you make it correct

The single highest-leverage move is separating the portable logic from the
machine, so most of the system can be tested without booting anything.

```
arch/            # inline asm, MMIO, CSRs, interrupt enable/disable
  riscv.rs       # the real thing
  host.rs        # no-op interrupts, a clock the test drives by hand
scheduler.rs     # pure logic, tests on the host in milliseconds
```

Then the scheduler, the allocator, the capability system, the lexer, the parser,
and the code generator are all ordinary Rust that `cargo test` can exercise. Boot
time goes from thirty seconds to zero for the majority of your changes.

Two things this requires you to be honest about:

- **State the shim's blind spot in the shim itself.** If host interrupts are a
  no-op, then interrupt-*ordering* bugs are exactly what host tests cannot see —
  and those are the bugs this domain produces most. Write that in the file, and
  put ordering tests in the on-target layer.
- **Split the crate early.** It touches every file, and the cost only grows.

## Four layers, because each one is blind to something

| Layer | Catches | Structurally cannot catch |
|---|---|---|
| Host unit tests | Logic, algebra, encodings, diagnostics | Anything involving real interrupts or real execution |
| On-target self-test | Interrupt delivery, timer wakeups, live object graphs | Whole-system behaviour, output formatting |
| Golden transcripts | End-to-end behaviour, program output, UI | Internal invariants |
| Mutation checks | Whether any of the above actually work | — |

Do not skip the on-target layer because the host layer is green. A concrete case
from this repository: changing one frame offset in a code generator,
`ld(T0, S0, off)` to `ld(T0, S0, off + 8)`, passes every host test including an
explicit confinement audit — the instruction is still a structurally valid load
through the frame pointer. Under QEMU the compiled program immediately prints
`2149628476`, a kernel address read off the stack. Only the layer that *runs the
program* sees it.

## Verify your tests can fail

A test that cannot fail is worse than no test: it looks like coverage.

After writing a test, break the thing it covers and confirm it goes red. Do this
by hand, deliberately, on the assertions that matter:

```
-  if !entry.rights.contains(needed) {
+  if false {
```

Then run the suite. If it stays green, the test was theatre.

Keep a short list in the testing docs of which mutations are caught and which are
not. The *uncaught* list is the useful half — it is a precise statement of what
your suite does not defend, and it is where the next bug will come from.

## Domain-specific failure modes to test for directly

**Wakeups and scheduling.** The classic is a task that wakes itself, or is woken
by an interrupt, *while it is being polled* — if the scheduler has lifted it out
of its run queue, that wake is silently dropped and the task never runs again.
Test: a task that yields in a loop must complete. Test: poll once, deliver a wake,
then confirm the task resumes.

**Check-then-sleep races.** "Ready queue is empty" followed by "sleep" is not
atomic. A wake landing in that gap is lost until something else happens. If you
paper over it with a periodic heartbeat, say so in a comment, because that
heartbeat is now load-bearing and someone will try to raise it.

**Every error path in an allocator.** Exhaustion must return null, not wrap.
Freed blocks must be reusable and still writable. Size classes must not bleed
into each other. Over-aligned requests must actually be aligned.

**Diagnostics, asserted verbatim.** Compiler error messages are a UI. Assert the
exact string, including line numbers. A reworded error is a regression a user
notices before you do.

**Code generators need an execution oracle.** Encoding tests prove you emitted
the instruction you meant; they say nothing about whether the program computes
the right answer. Write one conformance program that exercises every construct
and prints a hand-checkable value for each, and run it on real hardware or an
emulator. If your source language is a subset of a real language, compile the
same program with the real compiler and diff the output — a free oracle.

**Off-target arithmetic.** Sign extension, integer overflow, and shift semantics
differ from what you assume. Test boundary constants explicitly: 0, 1, -1, 2047,
2048, 2^31, 2^62, MAX, MIN.

## Anchor the invariants that security rests on

If a design claims something is impossible — "generated code cannot reach
hardware", "authority can only shrink" — that claim will live in a comment and
rot. Turn it into a test that walks the actual output:

- Assert the *opcode set* an emitter can produce, and name what each excluded
  opcode would allow. A test that fails with "opcode 0x73 is SYSTEM (ecall/csr),
  an escape from the sandbox" teaches the next reader what the rule is for.
- Assert every memory access uses an expected base register.
- Assert every indirect jump is a recognised call or return, so no computed jump
  can appear.
- Assert that every absolute address a program materializes belongs to its own
  data, its own code, or a known runtime hook.

These are cheap, they run in milliseconds, and they convert prose into a
mechanism.

## Encode known gaps as tests that fail when fixed

When you knowingly ship an incomplete invariant, write the test that documents
it and make its failure the signal:

```rust
/// Documents a known gap: revoking the source of a cross-space grant does not
/// kill the copy. When that lands this test should fail, and its failure is the
/// signal to delete it and assert the cascade instead.
#[test]
fn known_gap_cross_space_revoke_does_not_cascade() {
    assert!(dst.lookup(given, READ).is_ok(),
        "the cascade has landed -- delete this test and assert the cascade");
}
```

This beats a TODO comment: it cannot drift, and it tells whoever fixes the gap
exactly what to do next.

## Debugging when there is no debugger

- **Bisect with output, not with a debugger.** Print between initialization
  steps; the last line printed names the failing step. Remove the prints in the
  same session — they are scaffolding, not artifacts.
- **Suspect the harness before the kernel.** A backgrounded emulator inherits
  `/dev/null` on stdin, so keystrokes never arrive; a `\r`-based redraw makes a
  correct transcript *look* like a hang. Both of those cost real time in this
  repo. Before concluding the code is broken, confirm the test setup can observe
  a success.
- **Normalize before diffing.** Timings, addresses, and terminal control codes
  vary between runs. Strip them in the harness, or every golden is flaky.
- **Read the linker script when memory misbehaves.** Where the stack sits
  relative to the heap and `.bss` determines whether an overflow faults or
  silently corrupts. Usually it silently corrupts.

## Report what is actually true

State plainly which layers you ran and what they cover. If a suite is green but
you know a mutation it would miss, say so in the same breath. "96 host tests and
5 golden transcripts pass; host tests do not catch a wrong frame offset, only the
QEMU layer does" is a useful sentence. "All tests pass" is not.
