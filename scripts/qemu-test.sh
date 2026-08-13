#!/bin/sh
# Integration tests: boot VibeOS, drive the shell, diff against golden output.
#
# Run with --update to regenerate the goldens after an intentional change.
# Always read the diff before updating; that is the only thing standing between
# a deliberate behaviour change and a silent regression.
set -eu

cd "$(dirname "$0")/.."
KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
UPDATE=0
FILTER=""
QEMU_SMP=${QEMU_SMP:-4}
QEMU_ACCEL=${QEMU_ACCEL:-tcg,thread=multi}
case "$QEMU_SMP" in
  ''|*[!0-9]*|0) echo "qemu-test.sh: QEMU_SMP must be a positive integer" >&2; exit 1 ;;
esac
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
(cd firmware/qemu-virt && RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \
  rustup run "$toolchain" cargo build --release --features legacy-shell) >&2

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
           -e 's/capability-addressed object store \[0 objects, 0 journal sectors\]/capability-addressed object store (recovery pending)/' \
           -e 's/^  live +[0-9]+ B.*$/  live N B peak N B bump remaining N B/' \
           -e 's/scheduler acquisitions delta=[0-9]+ contention delta=[0-9]+/scheduler acquisitions delta=N contention delta=N/' \
           -e 's/\{[0-9]+\}//g' \
           -e '/^  component:.* +running +/s/ +[0-9]+ +([0-9]+ B)$/        N    \1/' \
  | grep -a -v '^[[:space:]]*$' \
  | grep -a -v 'terminating on signal' \
  | grep -a -v '^OpenSBI' || true
}

# Feed a case file to the shell. Directive lines can pause or send raw editing
# input without an implicit newline.
# PACE is per line; the UART ring and the line discipline keep up easily, but
# the shell has to be polled between lines.
PACE=${PACE:-0.2}
feed() {
  sleep 2
  while IFS= read -r line; do
    case "$line" in
      '@sleep '*) sleep "${line#@sleep }" ;;
      '@ctrl-c') printf '\003'; sleep "$PACE" ;;
      '@up') printf '\033[A'; sleep "$PACE" ;;
      '@down') printf '\033[B'; sleep "$PACE" ;;
      '@right') printf '\033[C'; sleep "$PACE" ;;
      '@left') printf '\033[D'; sleep "$PACE" ;;
      '@enter') printf '\n'; sleep "$PACE" ;;
      '@text '*) printf '%s' "${line#@text }"; sleep "$PACE" ;;
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

# Run the independent powered-off migration verifier and require the exact
# selector state/generation for this durability boundary. A merely valid image
# in the wrong state must not satisfy the multi-boot state-machine gate.
verify_storage_v2_migration_state() {
  sv2_expected_state=$1
  sv2_expected_generation=$2
  sv2_image=$3
  sv2_evidence=$4
  if ! python3 -B scripts/verify-storage-v2-migration.py \
    --unmanaged-prefix-baseline "$prefix_baseline" \
    --frozen-m4-baseline "$frozen_m4_baseline" \
    "$sv2_image" > "$sv2_evidence"; then
    cat "$sv2_evidence" >&2 || true
    return 1
  fi
  cat "$sv2_evidence"
  python3 -c '
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as source:
    evidence = json.load(source)
selected = evidence.get("control", {}).get("selected")
actual = None if selected is None else (selected.get("state"), selected.get("generation"))
expected = (sys.argv[2], int(sys.argv[3]))
if evidence.get("status") != "ok" or evidence.get("mode") != "migration" or actual != expected:
    print(f"powered-off selector mismatch: expected {expected}, observed {actual}", file=sys.stderr)
    raise SystemExit(1)
' "$sv2_evidence" "$sv2_expected_state" "$sv2_expected_generation"
}

# Prove that a boot observed its predecessor before publishing the requested
# transition and then reported the successor afterwards.
require_storage_v2_transition_order() {
  sv2_before=$1
  sv2_transition=$2
  sv2_after=$3
  sv2_before_line=$(grep -a -n -F "$sv2_before" "$qemu_log" \
    | head -1 | cut -d: -f1 || true)
  sv2_transition_line=$(grep -a -n -F "$sv2_transition" "$qemu_log" \
    | head -1 | cut -d: -f1 || true)
  sv2_after_line=$(grep -a -n -F "$sv2_after" "$qemu_log" \
    | tail -1 | cut -d: -f1 || true)
  [ -n "$sv2_before_line" ] \
    && [ -n "$sv2_transition_line" ] \
    && [ -n "$sv2_after_line" ] \
    && [ "$sv2_before_line" -lt "$sv2_transition_line" ] \
    && [ "$sv2_transition_line" -lt "$sv2_after_line" ]
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
PEER_PID=""
NET_PEER_PORT=""

cleanup_case() {
  for pid in "$QEMU_PID" "$FEED_PID" "$KILLER_PID" "$PEER_PID"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  QEMU_PID=""
  FEED_PID=""
  KILLER_PID=""
  PEER_PID=""
  NET_PEER_PORT=""

  if [ -n "$CASE_TMP" ]; then
    rm -f "$CASE_TMP/actual" \
          "$CASE_TMP/block.raw" \
          "$CASE_TMP/expected-sector" \
          "$CASE_TMP/frozen-m4.baseline" \
          "$CASE_TMP/input" \
          "$CASE_TMP/native-m4.baseline" \
          "$CASE_TMP/observed-sector" \
          "$CASE_TMP/observed-prefix" \
          "$CASE_TMP/observed-m4" \
          "$CASE_TMP/unmanaged-prefix.baseline" \
          "$CASE_TMP/qemu.log" \
          "$CASE_TMP/net-peer.evidence" \
          "$CASE_TMP/net-peer.log" \
          "$CASE_TMP/net-peer.ready" \
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
  observed_prefix="$CASE_TMP/observed-prefix"
  observed_m4="$CASE_TMP/observed-m4"
  prefix_baseline="$CASE_TMP/unmanaged-prefix.baseline"
  frozen_m4_baseline="$CASE_TMP/frozen-m4.baseline"
  native_m4_baseline="$CASE_TMP/native-m4.baseline"
  input_fifo="$CASE_TMP/input"
  qemu_log="$CASE_TMP/qemu.log"
  net_peer_evidence="$CASE_TMP/net-peer.evidence"
  net_peer_log="$CASE_TMP/net-peer.log"
  net_peer_ready="$CASE_TMP/net-peer.ready"

  # Every case gets a fresh device, preventing one transcript from inheriting
  # data or negotiated state from another. Sector 7 is the read fixture.
  dd if=/dev/zero of="$disk" bs=512 count=131072 >/dev/null 2>&1
  marker_sector "$expected_sector" "$BLOCK_SEED_MARKER"
  dd if="$expected_sector" of="$disk" bs=512 seek=7 conv=notrunc >/dev/null 2>&1
  if [ "$name" = "store" ]; then
    python3 scripts/store-image.py --seed "$disk"
  fi
  case "$name" in
    blob|persistent_cspace|program_persistence)
      # These acceptance cases deliberately exercise the frozen M4 ABI. A
      # truly blank managed range now selects native V2 instead.
      python3 scripts/store-image.py --seed-empty "$disk"
      ;;
  esac
  if [ "$name" = "storage_v2" ]; then
    # Native blank media now provisions V2 directly. The migration acceptance
    # must therefore start from an explicit canonical legacy authority source.
    python3 scripts/store-image.py --seed-empty "$disk"
    # The migration controller owns neither [0,64) nor the suffix after its
    # fixed V2 range. Preserve the exact pre-migration prefix (including the
    # intentional sector-7 block fixture) as independent isolation evidence.
    dd if="$disk" of="$prefix_baseline" bs=512 count=64 >/dev/null 2>&1
    mkdir -p target
    cp "$prefix_baseline" target/storage-v2-unmanaged-prefix.baseline
  fi
  if [ "$name" = "storage_v2_native" ]; then
    # Keep both managed formats blank. Native initialization may write only
    # V2 plus the selector; the exact legacy range remains zero forever.
    dd if="$disk" of="$prefix_baseline" bs=512 count=64 >/dev/null 2>&1
    dd if="$disk" of="$native_m4_baseline" bs=512 skip=64 count=512 \
      >/dev/null 2>&1
    mkdir -p target
    cp "$prefix_baseline" target/storage-v2-native-unmanaged-prefix.baseline
    cp "$native_m4_baseline" target/storage-v2-native-m4.baseline
  fi
  mkfifo "$input_fifo"

  # Only the two networking cases get a NIC or a peer. The peer binds an
  # ephemeral 127.0.0.1 TCP port and speaks QEMU's four-byte big-endian framed
  # socket protocol, so acceptance needs neither TAP nor root privileges.
  net_case=0
  net_peer_mode=normal
  case "$name" in
    net)
      net_case=1
      ;;
    net_recovery)
      net_case=1
      net_peer_mode=recovery
      ;;
  esac
  if [ "$net_case" = "1" ]; then
    if ! python3 scripts/net-peer.py --selftest >/dev/null; then
      echo "FAIL $name: host network peer self-test failed"
      fail=1
      cleanup_case
      continue
    fi
    python3 scripts/net-peer.py \
      --mode "$net_peer_mode" \
      --ready "$net_peer_ready" \
      --evidence "$net_peer_evidence" \
      >"$net_peer_log" 2>&1 &
    PEER_PID=$!

    ready_attempt=0
    while [ ! -s "$net_peer_ready" ] && [ "$ready_attempt" -lt 200 ]; do
      sleep 0.05
      ready_attempt=$((ready_attempt + 1))
    done
    if [ ! -s "$net_peer_ready" ]; then
      echo "FAIL $name: localhost network peer did not become ready"
      sed -n '1,20p' "$net_peer_log" >&2 || true
      fail=1
      cleanup_case
      continue
    fi
    NET_PEER_PORT=$(sed -n '1p' "$net_peer_ready")
    case "$NET_PEER_PORT" in
      ''|*[!0-9]*)
        echo "FAIL $name: network peer published an invalid port"
        fail=1
        cleanup_case
        continue
        ;;
    esac
    if [ "$NET_PEER_PORT" -lt 1 ] || [ "$NET_PEER_PORT" -gt 65535 ]; then
      echo "FAIL $name: network peer port is out of range"
      fail=1
      cleanup_case
      continue
    fi
  fi

  # Durable CSpace acceptance deliberately reboots three times against the
  # exact same raw image. Program persistence uses two boots. Storage V2 uses
  # seven boot-specific command files against one image: legacy publication,
  # Stage, rollback, re-Stage, activation, rollback closure, then terminal V2
  # recovery and refusal checks. The native blank-disk gate uses two boots.
  # Every other case retains one fresh image and one boot per transcript.
  boots=1
  if [ "$name" = "persistent_cspace" ]; then
    boots=3
  elif [ "$name" = "program_persistence" ]; then
    boots=2
  elif [ "$name" = "storage_v2" ]; then
    boots=7
  elif [ "$name" = "storage_v2_native" ]; then
    boots=2
  fi
  : > "$actual"
  boot_output_ok=1
  boot=1
  while [ "$boot" -le "$boots" ]; do
    boot_case="$case_file"
    if [ "$name" = "storage_v2" ] || [ "$name" = "storage_v2_native" ]; then
      boot_case="tests/cases/$name.boot$boot"
      if [ ! -f "$boot_case" ]; then
        echo "FAIL $name: missing boot command file $boot_case"
        boot_output_ok=0
        fail=1
        break
      fi
    fi
    feed "$boot_case" > "$input_fifo" &
    FEED_PID=$!
    set -- qemu-system-riscv64 -machine virt -cpu rv64 -smp "$QEMU_SMP" -m 128M \
      -accel "$QEMU_ACCEL" \
      -nographic -bios default -kernel "$KERNEL" \
      -drive if=none,id=vibeos-test-disk,format=raw,file="$disk",cache=writeback \
      -device virtio-blk-device,drive=vibeos-test-disk,bus=virtio-mmio-bus.0,queue-size=8 \
      -global virtio-mmio.force-legacy=false
    if [ "$net_case" = "1" ]; then
      set -- "$@" \
        -netdev "socket,id=vibeos-net,connect=127.0.0.1:$NET_PEER_PORT" \
        -device "virtio-net-device,netdev=vibeos-net,bus=virtio-mmio-bus.1,mac=02:00:00:00:00:01"
    fi
    "$@" < "$input_fifo" > "$qemu_log" 2>/dev/null &
    QEMU_PID=$!
    ( sleep "$(budget_for "$boot_case")"; kill "$QEMU_PID" 2>/dev/null || true ) &
    KILLER_PID=$!

    wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""
    kill "$KILLER_PID" 2>/dev/null || true
    wait "$KILLER_PID" 2>/dev/null || true
    KILLER_PID=""
    wait "$FEED_PID" 2>/dev/null || true
    FEED_PID=""

    if [ "$name" = "storage_v2" ]; then
      mkdir -p target
      cp "$qemu_log" "target/storage-v2-boot$boot.log"
      dd if="$disk" of="$observed_prefix" bs=512 count=64 >/dev/null 2>&1
      if ! cmp -s "$prefix_baseline" "$observed_prefix"; then
        echo "FAIL storage_v2: boot $boot modified unmanaged prefix [0,64)"
        boot_output_ok=0
        fail=1
      fi
      if [ "$boot" = "1" ]; then
        # Freeze the rollback source immediately after the last legacy boot.
        # Migration begins on boot 2, so taking this baseline any later could
        # bless a migration write into M4 instead of detecting it.
        dd if="$disk" of="$frozen_m4_baseline" bs=512 skip=64 count=512 \
          >/dev/null 2>&1
        cp "$frozen_m4_baseline" target/storage-v2-frozen-m4.baseline
      else
        dd if="$disk" of="$observed_m4" bs=512 skip=64 count=512 \
          >/dev/null 2>&1
        if ! cmp -s "$frozen_m4_baseline" "$observed_m4"; then
          echo "FAIL storage_v2: boot $boot modified frozen M4 rollback range [64,576)"
          boot_output_ok=0
          fail=1
        fi
      fi
      if [ "$boot" -ge 2 ]; then
        case "$boot" in
          2) expected_state=v2_staged; expected_generation=2 ;;
          3) expected_state=frozen_m4; expected_generation=3 ;;
          4) expected_state=v2_staged; expected_generation=4 ;;
          5) expected_state=v2_active; expected_generation=5 ;;
          6|7) expected_state=rollback_closed; expected_generation=6 ;;
        esac
        powered_off_image="target/storage-v2-boot${boot}-${expected_state}.raw"
        powered_off_evidence="target/storage-v2-boot${boot}-verifier.json"
        cp "$disk" "$powered_off_image"
        if ! verify_storage_v2_migration_state \
          "$expected_state" "$expected_generation" \
          "$powered_off_image" "$powered_off_evidence"; then
          echo "FAIL storage_v2: powered-off boot $boot did not verify as $expected_state generation $expected_generation"
          boot_output_ok=0
          fail=1
        fi
      fi
      if grep -a -Eq '\[!\] (fatal trap|panic)|panicked at|Storage V2 migration (failed|worker failed)|saved `hello`: failed|run `hello`: refused|durable CSpace test: failed|900-byte object commit: (failed|refused)|BlobFS (commit|full verification|chunk proof): (failed|mismatch)|boot fail-closed|recovery failed closed' "$qemu_log"; then
        echo "FAIL storage_v2: boot $boot reported a fatal or fail-closed outcome"
        boot_output_ok=0
        fail=1
      fi
      if [ "$boot" -lt 7 ] \
        && grep -a -F -q 'Storage V2 operation failed:' "$qemu_log"; then
        echo "FAIL storage_v2: boot $boot rejected a required state transition"
        boot_output_ok=0
        fail=1
      fi
      case "$boot" in
        1)
          required='Storage V2: boot M4, migration control absent|saved `hello`: 45 B source|Hello, world!|boot1 child:'
          ;;
        2)
          required='Hello, world!|Storage V2: boot M4, migration control absent|VIBE_STORAGE_V2_STAGED state=V2Staged generation=2|Storage V2: boot M4, migration V2Staged generation 2'
          ;;
        3)
          required='Hello, world!|Storage V2: boot M4, migration V2Staged generation 2|VIBE_STORAGE_V2_ROLLED_BACK state=FrozenM4 generation=3|Storage V2: boot M4, migration FrozenM4 generation 3'
          ;;
        4)
          required='Hello, world!|Storage V2: boot M4, migration FrozenM4 generation 3|VIBE_STORAGE_V2_STAGED state=V2Staged generation=4|Storage V2: boot M4, migration V2Staged generation 4'
          ;;
        5)
          required='Hello, world!|Storage V2: boot M4, migration V2Staged generation 4|VIBE_STORAGE_V2_MIGRATED state=V2Active generation=5|Storage V2: boot V2, migration V2Active generation 5'
          ;;
        6)
          required='Hello, world!|Storage V2: boot V2, migration V2Active generation 5|VIBE_STORAGE_V2_ROLLBACK_CLOSED state=RollbackClosed generation=6|Storage V2: boot V2, migration RollbackClosed generation 6'
          ;;
        7)
          required='Hello, world!|Storage V2: boot V2, migration RollbackClosed generation 6|boot2 restored child:|900-byte object commit + disk readback: ok|BlobFS commit + full verification:|Storage V2 operation failed: Control'
          ;;
      esac
      old_ifs=$IFS
      IFS='|'
      for marker in $required; do
        if ! grep -a -F -q "$marker" "$qemu_log"; then
          echo "FAIL storage_v2: boot $boot missing acceptance marker: $marker"
          boot_output_ok=0
          fail=1
        fi
      done
      IFS=$old_ifs
      transition_before=""
      transition_marker=""
      transition_after=""
      case "$boot" in
        2)
          transition_before='Storage V2: boot M4, migration control absent'
          transition_marker='VIBE_STORAGE_V2_STAGED state=V2Staged generation=2'
          transition_after='Storage V2: boot M4, migration V2Staged generation 2'
          ;;
        3)
          transition_before='Storage V2: boot M4, migration V2Staged generation 2'
          transition_marker='VIBE_STORAGE_V2_ROLLED_BACK state=FrozenM4 generation=3'
          transition_after='Storage V2: boot M4, migration FrozenM4 generation 3'
          ;;
        4)
          transition_before='Storage V2: boot M4, migration FrozenM4 generation 3'
          transition_marker='VIBE_STORAGE_V2_STAGED state=V2Staged generation=4'
          transition_after='Storage V2: boot M4, migration V2Staged generation 4'
          ;;
        5)
          transition_before='Storage V2: boot M4, migration V2Staged generation 4'
          transition_marker='VIBE_STORAGE_V2_MIGRATED state=V2Active generation=5'
          transition_after='Storage V2: boot V2, migration V2Active generation 5'
          ;;
        6)
          transition_before='Storage V2: boot V2, migration V2Active generation 5'
          transition_marker='VIBE_STORAGE_V2_ROLLBACK_CLOSED state=RollbackClosed generation=6'
          transition_after='Storage V2: boot V2, migration RollbackClosed generation 6'
          ;;
      esac
      if [ -n "$transition_marker" ] \
        && ! require_storage_v2_transition_order \
          "$transition_before" "$transition_marker" "$transition_after"; then
        echo "FAIL storage_v2: boot $boot lacks ordered predecessor/transition/successor evidence"
        boot_output_ok=0
        fail=1
      fi
      if [ "$boot" = "7" ]; then
        refused_count=$(grep -a -F -c 'Storage V2 operation failed: Control' "$qemu_log" || true)
        if [ "$refused_count" -ne 2 ]; then
          echo "FAIL storage_v2: boot 7 expected exactly two terminal Control refusals, observed $refused_count"
          boot_output_ok=0
          fail=1
        fi
        if grep -a -F 'Storage V2 operation failed:' "$qemu_log" \
          | grep -a -F -v 'Storage V2 operation failed: Control' >/dev/null; then
          echo "FAIL storage_v2: boot 7 reported an unexpected operation failure"
          boot_output_ok=0
          fail=1
        fi
        payload_line=$(grep -a -n -F 'BlobFS commit + full verification:' "$qemu_log" \
          | tail -1 | cut -d: -f1 || true)
        rollback_prompt_line=$(grep -a -n -F 'vibe> storage rollback' "$qemu_log" \
          | head -1 | cut -d: -f1 || true)
        first_refusal_line=$(grep -a -n -F 'Storage V2 operation failed: Control' "$qemu_log" \
          | head -1 | cut -d: -f1 || true)
        close_prompt_line=$(grep -a -n -F 'vibe> storage close-rollback' "$qemu_log" \
          | head -1 | cut -d: -f1 || true)
        second_refusal_line=$(grep -a -n -F 'Storage V2 operation failed: Control' "$qemu_log" \
          | tail -1 | cut -d: -f1 || true)
        final_closed_line=$(grep -a -n -F \
          'Storage V2: boot V2, migration RollbackClosed generation 6' "$qemu_log" \
          | tail -1 | cut -d: -f1 || true)
        if [ -z "$payload_line" ] \
          || [ -z "$rollback_prompt_line" ] \
          || [ -z "$first_refusal_line" ] \
          || [ -z "$close_prompt_line" ] \
          || [ -z "$second_refusal_line" ] \
          || [ -z "$final_closed_line" ] \
          || [ "$payload_line" -ge "$rollback_prompt_line" ] \
          || [ "$rollback_prompt_line" -ge "$first_refusal_line" ] \
          || [ "$first_refusal_line" -ge "$close_prompt_line" ] \
          || [ "$close_prompt_line" -ge "$second_refusal_line" ] \
          || [ "$second_refusal_line" -ge "$final_closed_line" ]; then
          echo "FAIL storage_v2: boot 7 lacks ordered payload/rollback-refusal/close-refusal/final-state evidence"
          boot_output_ok=0
          fail=1
        fi
      fi
    fi

    if [ "$name" = "storage_v2_native" ]; then
      mkdir -p target
      cp "$qemu_log" "target/storage-v2-native-boot$boot.log"
      dd if="$disk" of="$observed_prefix" bs=512 count=64 >/dev/null 2>&1
      dd if="$disk" of="$observed_m4" bs=512 skip=64 count=512 \
        >/dev/null 2>&1
      if ! cmp -s "$prefix_baseline" "$observed_prefix"; then
        echo "FAIL storage_v2_native: boot $boot modified unmanaged prefix [0,64)"
        boot_output_ok=0
        fail=1
      fi
      if ! cmp -s "$native_m4_baseline" "$observed_m4"; then
        echo "FAIL storage_v2_native: boot $boot modified zero M4 range [64,576)"
        boot_output_ok=0
        fail=1
      fi
      if grep -a -Eq '\[!\] (fatal trap|panic)|panicked at|Storage V2 migration (failed|worker failed)|saved `hello`: failed|run `hello`: refused|durable CSpace test: failed|900-byte object commit: (failed|refused)|BlobFS (commit|full verification|chunk proof): (failed|mismatch)|boot fail-closed|recovery failed closed' "$qemu_log"; then
        echo "FAIL storage_v2_native: boot $boot reported a fatal or fail-closed outcome"
        boot_output_ok=0
        fail=1
      fi
      case "$boot" in
        1)
          required='Storage V2: boot V2, migration RollbackClosed generation 1|saved `hello`: 45 B source|Hello, world!|boot1 child:'
          ;;
        2)
          required='Storage V2: boot V2, migration RollbackClosed generation 1|Hello, world!|boot2 restored child:|900-byte object commit + disk readback: ok|BlobFS commit + full verification:'
          ;;
      esac
      old_ifs=$IFS
      IFS='|'
      for marker in $required; do
        if ! grep -a -F -q "$marker" "$qemu_log"; then
          echo "FAIL storage_v2_native: boot $boot missing acceptance marker: $marker"
          boot_output_ok=0
          fail=1
        fi
      done
      IFS=$old_ifs
    fi

    if ! grep -a -q 'VibeOS shell ready' "$qemu_log"; then
      echo "FAIL $name: boot $boot produced no shell-ready marker"
      boot_output_ok=0
      fail=1
    fi
    if [ "$QEMU_SMP" -ge 4 ] \
      && ! grep -a -Eq 'smp +4 hart\(s\) online' "$qemu_log"; then
      echo "FAIL $name: boot $boot did not publish the four-hart online barrier"
      boot_output_ok=0
      fail=1
    fi
    if ! grep -a -Eq 'mmu +Sv39 single address space, hart mask 0x[0-9a-f]+' "$qemu_log"; then
      echo "FAIL $name: boot $boot did not publish the Sv39 activation marker"
      boot_output_ok=0
      fail=1
    fi
    if ! grep -a -Eq 'W\^X +[0-9]+ KiB code pool 0x[0-9a-f]+\.\.0x[0-9a-f]+, MXR clear, RFENCE ready' "$qemu_log"; then
      echo "FAIL $name: boot $boot did not publish the W^X/RFENCE marker"
      boot_output_ok=0
      fail=1
    fi
    if ! grep -a -Eq 'read-only +[0-9]+ KiB \.rodata 0x[0-9a-f]+\.\.0x[0-9a-f]+; [0-9]+ KiB COW capability-table pool' "$qemu_log"; then
      echo "FAIL $name: boot $boot did not publish the read-only data/capability-table marker"
      boot_output_ok=0
      fail=1
    fi

    if [ "$name" = "persistent_cspace" ]; then
      printf '=== persistent CSpace boot %s ===\n' "$boot" >> "$actual"
    elif [ "$name" = "program_persistence" ]; then
      printf '=== program persistence boot %s ===\n' "$boot" >> "$actual"
    elif [ "$name" = "storage_v2" ]; then
      printf '=== Storage V2 boot %s ===\n' "$boot" >> "$actual"
    elif [ "$name" = "storage_v2_native" ]; then
      printf '=== Storage V2 native boot %s ===\n' "$boot" >> "$actual"
    fi
    normalize < "$qemu_log" \
      | sed -n '/VibeOS shell ready/,$p' >> "$actual" || true
    boot=$((boot + 1))
  done

  if [ "$name" = "guard_page" ]; then
    guard_probe=$(sed -n 's/.*guard probe: hart0 store into \(0x[0-9a-f][0-9a-f]*\).*/\1/p' "$qemu_log" | tail -1)
    guard_stval=$(sed -n 's/.*fatal trap: cause=15 stval=\(0x[0-9a-f][0-9a-f]*\).*/\1/p' "$qemu_log" | tail -1)
    if [ -z "$guard_probe" ] || [ "$guard_probe" != "$guard_stval" ] \
      || ! grep -a -q '\[!\] stack guard: hart0 blocked store page fault' "$qemu_log"; then
      echo "FAIL guard_page: expected store-page-fault stval did not match hart0 guard"
      boot_output_ok=0
      fail=1
    fi
  fi

  wx_action=""
  wx_cause=""
  wx_exception=""
  case "$name" in
    wx_execute_fault)
      wx_action="execute writable"; wx_cause=12; wx_exception="instruction page fault" ;;
    wx_read_fault)
      wx_action="read sealed"; wx_cause=13; wx_exception="load page fault" ;;
    wx_write_fault)
      wx_action="write sealed"; wx_cause=15; wx_exception="store page fault" ;;
  esac
  if [ -n "$wx_action" ]; then
    wx_probe=$(sed -n "s/.*W\^X probe: $wx_action \(0x[0-9a-f][0-9a-f]*\).*/\1/p" "$qemu_log" | tail -1)
    wx_stval=$(sed -n "s/.*fatal trap: cause=$wx_cause stval=\(0x[0-9a-f][0-9a-f]*\).*/\1/p" "$qemu_log" | tail -1)
    if [ -z "$wx_probe" ] || [ "$wx_probe" != "$wx_stval" ] \
      || ! grep -a -q "\[!\] W\^X code pool blocked $wx_exception" "$qemu_log"; then
      echo "FAIL $name: expected W^X page-fault stval did not match the printed probe"
      boot_output_ok=0
      fail=1
    fi
  fi

  ro_action=""
  ro_marker=""
  case "$name" in
    rodata_write_fault)
      ro_action="write rodata"; ro_marker="read-only \.rodata" ;;
    cap_table_write_fault)
      ro_action="write capability table"; ro_marker="read-only capability table" ;;
  esac
  if [ -n "$ro_action" ]; then
    ro_probe=$(sed -n "s/.*read-only probe: $ro_action \(0x[0-9a-f][0-9a-f]*\).*/\1/p" "$qemu_log" | tail -1)
    ro_stval=$(sed -n 's/.*fatal trap: cause=15 stval=\(0x[0-9a-f][0-9a-f]*\).*/\1/p' "$qemu_log" | tail -1)
    if [ -z "$ro_probe" ] || [ "$ro_probe" != "$ro_stval" ] \
      || ! grep -a -q "\[!\] $ro_marker blocked store page fault" "$qemu_log"; then
      echo "FAIL $name: expected read-only store-page-fault stval did not match the printed probe"
      boot_output_ok=0
      fail=1
    fi
  fi

  backing_ok=1
  network_ok=1
  if [ "$net_case" = "1" ]; then
    if wait "$PEER_PID"; then
      :
    else
      echo "FAIL $name: host peer rejected the raw L2 exchange"
      sed -n '1,20p' "$net_peer_log" >&2 || true
      echo "guest transcript follows:" >&2
      sed -n '1,160p' "$actual" >&2 || true
      network_ok=0
      fail=1
    fi
    PEER_PID=""
    if [ "$network_ok" = "1" ] && ! python3 scripts/net-peer.py \
      --mode "$net_peer_mode" --check-evidence "$net_peer_evidence"; then
      echo "FAIL $name: canonical host-peer evidence is missing or malformed"
      network_ok=0
      fail=1
    fi
  fi
  if [ "$name" = "block" ]; then
    marker_sector "$expected_sector" "$BLOCK_WRITE_MARKER"
    dd if="$disk" of="$observed_sector" bs=512 skip=8 count=1 >/dev/null 2>&1
    if ! cmp -s "$expected_sector" "$observed_sector"; then
      echo "FAIL block: raw backing sector 8 does not contain $BLOCK_WRITE_MARKER"
      backing_ok=0
      fail=1
    fi
  fi
  if [ "$name" = "store" ]; then
    if ! python3 scripts/store-image.py --selftest \
      || ! python3 scripts/store-image.py "$disk"; then
      backing_ok=0
      fail=1
    fi
  fi
  if [ "$name" = "blob" ]; then
    if ! python3 -B scripts/blob-image.py --selftest \
      || ! python3 -B scripts/blob-image.py "$disk"; then
      backing_ok=0
      fail=1
    fi
  fi
  if [ "$name" = "persistent_cspace" ]; then
    if ! python3 scripts/persistent-cspace-image.py --selftest \
      || ! python3 scripts/persistent-cspace-image.py "$disk"; then
      backing_ok=0
      fail=1
    fi
  fi
  if [ "$name" = "program_persistence" ]; then
    if ! python3 -B scripts/program-image.py --selftest \
      || ! python3 -B scripts/program-image.py "$disk"; then
      backing_ok=0
      fail=1
    fi
  fi
  if [ "$name" = "storage_v2" ]; then
    mkdir -p target
    cp "$disk" target/storage-v2-last.raw
    if ! python3 -B scripts/verify-storage-v2-migration.py --selftest \
      || ! verify_storage_v2_migration_state rollback_closed 6 \
        "$disk" target/storage-v2-final-verifier.json; then
      backing_ok=0
      fail=1
    else
      cp "$disk" target/storage-v2-migrated.raw
    fi
  fi
  if [ "$name" = "storage_v2_native" ]; then
    mkdir -p target
    cp "$disk" target/storage-v2-native-last.raw
    if ! python3 -B scripts/verify-storage-v2-migration.py \
      --expect-native \
      --unmanaged-prefix-baseline "$prefix_baseline" "$disk"; then
      backing_ok=0
      fail=1
    else
      cp "$disk" target/storage-v2-native-verified.raw
    fi
  fi

  if [ ! -s "$actual" ] || [ "$boot_output_ok" != "1" ]; then
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

  if [ "$UPDATE" = "1" ] \
    && { [ "$network_ok" != "1" ] || [ "$backing_ok" != "1" ] || [ "$boot_output_ok" != "1" ]; }; then
    echo "FAIL $name: refusing to update a golden without valid acceptance evidence"
    fail=1
  elif [ "$UPDATE" = "1" ]; then
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
    elif [ "$name" = "store" ] && [ "$backing_ok" = "1" ]; then
      echo "ok   store (raw backing journal verified)"
    elif [ "$name" = "persistent_cspace" ] && [ "$backing_ok" = "1" ]; then
      echo "ok   persistent_cspace (three boots and raw authority graph verified)"
    elif [ "$name" = "program_persistence" ] && [ "$backing_ok" = "1" ]; then
      echo "ok   program_persistence (rebooted source, binary, and authority verified)"
    elif [ "$name" = "storage_v2" ] && [ "$backing_ok" = "1" ]; then
      echo "ok   storage_v2 (seven boots and every powered-off transition verified)"
    elif [ "$name" = "storage_v2_native" ] && [ "$backing_ok" = "1" ]; then
      echo "ok   storage_v2_native (two native V2 boots and powered-off state verified)"
    elif [ "$name" = "net" ] && [ "$network_ok" = "1" ]; then
      echo "ok   net (raw L2 HELLO/CHALLENGE/ACK verified)"
    elif [ "$name" = "net_recovery" ] && [ "$network_ok" = "1" ]; then
      echo "ok   net_recovery (faulted HELLO abandoned; fresh-epoch handshake verified)"
    elif [ "$name" = "smp_queues" ]; then
      lock_line=$(grep -a 'smp locks: scheduler acquisitions delta=' "$qemu_log" | tail -1 || true)
      acquisitions=$(printf '%s\n' "$lock_line" | sed -n 's/.*acquisitions delta=\([0-9][0-9]*\).*/\1/p')
      contention=$(printf '%s\n' "$lock_line" | sed -n 's/.*contention delta=\([0-9][0-9]*\).*/\1/p')
      if [ -z "$acquisitions" ] || [ -z "$contention" ] \
        || [ "$acquisitions" -eq 0 ] || [ "$contention" -eq 0 ] \
        || [ "$contention" -gt "$acquisitions" ]; then
        echo "FAIL smp_queues: invalid physical scheduler-lock telemetry"
        fail=1
      else
        echo "ok   smp_queues ($contention contended / $acquisitions acquisitions)"
      fi
    elif [ "$net_case" = "1" ]; then
      echo "FAIL $name: transcript matched but host network evidence failed"
      fail=1
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
