#!/bin/sh
# Integration tests: boot VibeOS, drive the shell, diff against golden output.
#
# Run with --update to regenerate the goldens after an intentional change.
# Always read the diff before updating; that is the only thing standing between
# a deliberate behaviour change and a silent regression.
set -eu

cd "$(dirname "$0")/.."
KERNEL=target/riscv64gc-unknown-none-elf/release/vibeos-kernel
UPDATE=0
FILTER=""
for arg in "$@"; do
  case "$arg" in
    --update) UPDATE=1 ;;
    *) FILTER="$arg" ;;
  esac
done

RUSTC_BOOTSTRAP=1 sh -c 'cd kernel && cargo build --release' >&2

# Strip everything that legitimately varies between runs: timings, addresses,
# heap sizes, and the terminal control codes the line discipline emits.
normalize() {
  tr '\r' '\n' \
  | sed -E -e 's/\x1b\[[0-9;]*[A-Za-z]//g' \
           -e 's/in [0-9]+ us/in N us/g' \
           -e 's/0x[0-9a-f]+/0xADDR/g' \
           -e 's/up [0-9]+\.[0-9]+ s/up N s/' \
           -e 's/[0-9]+ KiB/N KiB/g' \
           -e 's/^  live +[0-9]+ B.*$/  live N B peak N B bump remaining N B/' \
           -e 's/\{[0-9]+\}//g' \
  | grep -v '^[[:space:]]*$' \
  | grep -v 'terminating on signal' \
  | grep -v '^OpenSBI' || true
}

# Feed a case file to the shell. Lines starting with @sleep pause instead.
feed() {
  sleep 2
  while IFS= read -r line; do
    case "$line" in
      '@sleep '*) sleep "${line#@sleep }" ;;
      *) printf '%s\n' "$line"; sleep 0.5 ;;
    esac
  done < "$1"
  sleep 2
}

fail=0
for case_file in tests/cases/*.in; do
  name=$(basename "$case_file" .in)
  if [ -n "$FILTER" ] && [ "$FILTER" != "$name" ]; then continue; fi
  golden="tests/golden/$name.txt"
  actual="$(mktemp)"

  ( sleep 25; pkill -f "qemu-system-riscv64.*vibeos-kernel" >/dev/null 2>&1 ) &
  killer=$!
  feed "$case_file" \
    | qemu-system-riscv64 -machine virt -cpu rv64 -smp 1 -m 128M \
        -nographic -bios default -kernel "$KERNEL" 2>/dev/null \
    | normalize \
    | sed -n '/VibeOS shell ready/,$p' > "$actual" || true
  kill "$killer" 2>/dev/null || true

  if [ ! -s "$actual" ]; then
    echo "FAIL $name: no output captured (did the kernel boot?)"
    fail=1
    continue
  fi

  if [ "$UPDATE" = "1" ]; then
    cp "$actual" "$golden"
    echo "updated $name"
  elif [ ! -f "$golden" ]; then
    echo "FAIL $name: no golden file; run with --update"
    fail=1
  elif diff -u "$golden" "$actual" > /dev/null; then
    echo "ok   $name"
  else
    echo "FAIL $name"
    diff -u "$golden" "$actual" | head -40
    fail=1
  fi
  rm -f "$actual"
done

exit $fail
