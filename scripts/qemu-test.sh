#!/bin/sh
# Integration tests: boot VibeOS, drive the shell, diff against golden output.
#
# Run with --update to regenerate the goldens after an intentional change.
# Always read the diff before updating; that is the only thing standing between
# a deliberate behaviour change and a silent regression.
set -eu

cd "$(dirname "$0")/.."
KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-kernel
UPDATE=0
FILTER=""
for arg in "$@"; do
  case "$arg" in
    --update) UPDATE=1 ;;
    *) FILTER="$arg" ;;
  esac
done

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then
  echo "qemu-test.sh: rustup and an exact rust-toolchain.toml channel are required" >&2
  exit 1
fi
pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)
(cd kernel && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release) >&2

# Strip everything that legitimately varies between runs: timings, addresses,
# heap sizes, and the terminal control codes the line discipline emits.
normalize() {
  tr '\r' '\n' \
  | sed -E -e 's/\x1b\[[0-9;]*[A-Za-z]//g' \
           -e 's/in [0-9]+ us/in N us/g' \
           -e 's/after [0-9]+ us/after N us/g' \
           -e 's/0x[0-9a-f]+/0xADDR/g' \
           -e 's/up [0-9]+\.[0-9]+ s/up N s/' \
           -e 's/(panicked at [^:]+):[0-9]+:[0-9]+:/\1:LINE:COL:/' \
           -e 's/[0-9]+ KiB/N KiB/g' \
           -e 's/^  live +[0-9]+ B.*$/  live N B peak N B bump remaining N B/' \
           -e 's/\{[0-9]+\}//g' \
           -e '/^  component:.*  running   /s/ +[0-9]+ +([0-9]+ B)$/        N    \1/' \
  | grep -a -v '^[[:space:]]*$' \
  | grep -a -v 'terminating on signal' \
  | grep -a -v '^OpenSBI' || true
}

# Feed a case file to the shell. Lines starting with @sleep pause instead.
# PACE is per line; the UART ring and the line discipline keep up easily, but
# the shell has to be polled between lines.
PACE=${PACE:-0.2}
feed() {
  sleep 2
  while IFS= read -r line; do
    case "$line" in
      '@sleep '*) sleep "${line#@sleep }" ;;
      *) printf '%s\n' "$line"; sleep "$PACE" ;;
    esac
  done < "$1"
  sleep 2
}

# Long enough for the whole case to be typed, plus its explicit sleeps.
budget_for() {
  awk -v pace="$PACE" '
    /^@sleep /{ extra += $2; next }
    { lines++ }
    END { printf "%d", 20 + lines * pace + extra }
  ' "$1"
}

# The block acceptance case uses a real raw backing file.  The sectors are
# deliberately complete 512-byte records (marker followed by zero padding),
# so checking the whole sector catches short writes and accidental in-memory
# emulation just as well as checking the human-readable prefix.
BLOCK_SEED_MARKER='VIBEOS-BLK-SECTOR-7-SEED-v1'
BLOCK_WRITE_MARKER='VIBEOS-BLK-SECTOR-8-WRITE-v1'

marker_sector() {
  path=$1
  marker=$2
  dd if=/dev/zero of="$path" bs=512 count=1 >/dev/null 2>&1
  printf '%s' "$marker" | dd of="$path" bs=1 conv=notrunc >/dev/null 2>&1
}

CASE_TMP=""
QEMU_PID=""
FEED_PID=""
KILLER_PID=""

cleanup_case() {
  for pid in "$QEMU_PID" "$FEED_PID" "$KILLER_PID"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  QEMU_PID=""
  FEED_PID=""
  KILLER_PID=""

  if [ -n "$CASE_TMP" ]; then
    rm -f "$CASE_TMP/actual" \
          "$CASE_TMP/block.raw" \
          "$CASE_TMP/expected-sector" \
          "$CASE_TMP/input" \
          "$CASE_TMP/observed-sector" \
          "$CASE_TMP/qemu.log" \
          "$CASE_TMP/rustc-expected" \
          "$CASE_TMP/vibeos-observed"
    rmdir "$CASE_TMP" 2>/dev/null || true
    CASE_TMP=""
  fi
}

trap cleanup_case EXIT
trap 'exit 130' HUP INT TERM

# The differential case is derived from the corpus every run, so the two can
# never drift apart -- a stale case file would silently test the wrong program.
{
  echo quiet
  for src in tests/programs/*.rs; do
    echo "rustc edit"
    grep -vE '^[[:space:]]*(//.*)?$' "$src"
    echo "."
    echo "@sleep 4"
  done
} > tests/cases/differential.in

fail=0
for case_file in tests/cases/*.in; do
  name=$(basename "$case_file" .in)
  if [ -n "$FILTER" ] && [ "$FILTER" != "$name" ]; then continue; fi
  golden="tests/golden/$name.txt"
  CASE_TMP=$(mktemp -d)
  actual="$CASE_TMP/actual"
  disk="$CASE_TMP/block.raw"
  expected_sector="$CASE_TMP/expected-sector"
  observed_sector="$CASE_TMP/observed-sector"
  input_fifo="$CASE_TMP/input"
  qemu_log="$CASE_TMP/qemu.log"

  # Every case gets a fresh device, preventing one transcript from inheriting
  # data or negotiated state from another. Sector 7 is the read fixture.
  dd if=/dev/zero of="$disk" bs=512 count=2048 >/dev/null 2>&1
  marker_sector "$expected_sector" "$BLOCK_SEED_MARKER"
  dd if="$expected_sector" of="$disk" bs=512 seek=7 conv=notrunc >/dev/null 2>&1
  mkfifo "$input_fifo"

  feed "$case_file" > "$input_fifo" &
  FEED_PID=$!
  qemu-system-riscv64 -machine virt -cpu rv64 -smp 1 -m 128M \
    -nographic -bios default -kernel "$KERNEL" \
    -drive if=none,id=vibeos-test-disk,format=raw,file="$disk",cache=writeback \
    -device virtio-blk-device,drive=vibeos-test-disk,bus=virtio-mmio-bus.0,queue-size=8 \
    -global virtio-mmio.force-legacy=false \
    < "$input_fifo" > "$qemu_log" 2>/dev/null &
  QEMU_PID=$!
  ( sleep "$(budget_for "$case_file")"; kill "$QEMU_PID" 2>/dev/null || true ) &
  KILLER_PID=$!

  wait "$QEMU_PID" 2>/dev/null || true
  QEMU_PID=""
  kill "$KILLER_PID" 2>/dev/null || true
  wait "$KILLER_PID" 2>/dev/null || true
  KILLER_PID=""
  wait "$FEED_PID" 2>/dev/null || true
  FEED_PID=""

  normalize < "$qemu_log" \
    | sed -n '/VibeOS shell ready/,$p' > "$actual" || true

  backing_ok=1
  if [ "$name" = "block" ]; then
    marker_sector "$expected_sector" "$BLOCK_WRITE_MARKER"
    dd if="$disk" of="$observed_sector" bs=512 skip=8 count=1 >/dev/null 2>&1
    if ! cmp -s "$expected_sector" "$observed_sector"; then
      echo "FAIL block: raw backing sector 8 does not contain $BLOCK_WRITE_MARKER"
      backing_ok=0
      fail=1
    fi
  fi

  if [ ! -s "$actual" ]; then
    echo "FAIL $name: no output captured (did the kernel boot?)"
    fail=1
    cleanup_case
    continue
  fi

  # The differential case is checked against rustc's expectations, which are
  # extracted from the transcript rather than recorded from it.
  if [ "$name" = "differential" ]; then
    expected="$CASE_TMP/rustc-expected"
    cat tests/programs/*.expected > "$expected"
    got="$CASE_TMP/vibeos-observed"
    sed -n '/--- running natively ---/,/--- exited/p' "$actual" \
      | grep -vE '^(  --- |vibe> )' > "$got"
    if diff -u "$expected" "$got" > /dev/null; then
      echo "ok   $name (matches real rustc)"
    else
      echo "FAIL $name: VibeOS and real rustc disagree"
      diff -u "$expected" "$got" | head -30
      fail=1
    fi
    cleanup_case
    continue
  fi

  if [ "$UPDATE" = "1" ]; then
    cp "$actual" "$golden"
    echo "updated $name"
  elif [ ! -f "$golden" ]; then
    echo "FAIL $name: no golden file; run with --update"
    fail=1
  elif diff -u "$golden" "$actual" > /dev/null; then
    if [ "$name" = "selftest" ]; then
      checks=$(sed -n 's/.*SELFTEST OK (\([0-9][0-9]*\) checks).*/\1/p' "$actual")
      if [ -n "$checks" ]; then
        echo "ok   $name ($checks checks)"
      else
        echo "FAIL $name: transcript has no SELFTEST OK summary"
        fail=1
      fi
    elif [ "$name" = "block" ] && [ "$backing_ok" = "1" ]; then
      echo "ok   block (raw backing sector 8 verified)"
    else
      echo "ok   $name"
    fi
  else
    echo "FAIL $name"
    diff -u "$golden" "$actual" | head -40
    fail=1
  fi
  cleanup_case
done

exit $fail
