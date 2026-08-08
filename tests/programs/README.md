# Differential corpus

Every file here is a valid Rust program *and* a valid program in the VibeOS
subset. `scripts/differential.sh` compiles each with the real `rustc`, runs it,
and stores the output as the expected result; the QEMU `differential` case
compiles the same source inside VibeOS and must produce the same bytes.

That makes real rustc a free oracle for the in-kernel code generator, which is
the strongest check available for something this security-critical.

## Corpus rules

The subset is not a strict superset or subset of Rust — it accepts a few things
Rust rejects. Programs here must stay inside the intersection:

- **Conditions must be comparisons**, never bare integers. `if n < 2` is valid in
  both; `if 1` is a type error in Rust.
- **`&&` and `||` take comparisons**, for the same reason.
- **`main` must not return a value**, since our `main` returns `i64` and Rust's
  does not. Print results instead of returning them.
- **Never print a comparison.** `a < b` is `bool` in Rust and `i64` here, so
  Rust prints `true` and VibeOS prints `1`. Write `if a < b { 1 } else { 0 }`,
  which reads the same in both.
- **Annotate `i64` on every binding.** Rust infers `i32` for a bare integer
  literal; the subset has only `i64`. Without the annotation the two languages
  compute in different widths, which real rustc catches as an overflow error.
- **No arithmetic that overflows**, unless the point of the program is the abort
  — real rustc in release mode wraps rather than panicking, so the two disagree.
