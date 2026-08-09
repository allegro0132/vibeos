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
           -e 's/scheduler acquisitions delta=[0-9]+ contention delta=[0-9]+/scheduler acquisitions delta=N contention delta=N/' \
           -e 's/\{[0-9]+\}//g' \
           -e '/^  component:.* +running +/s/ +[0-9]+ +([0-9]+ B)$/        N    \1/' \
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
          "$CASE_TMP/input" \
          "$CASE_TMP/observed-sector" \
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
  input_fifo="$CASE_TMP/input"
  qemu_log="$CASE_TMP/qemu.log"
  net_peer_evidence="$CASE_TMP/net-peer.evidence"
  net_peer_log="$CASE_TMP/net-peer.log"
  net_peer_ready="$CASE_TMP/net-peer.ready"

  # Every case gets a fresh device, preventing one transcript from inheriting
  # data or negotiated state from another. Sector 7 is the read fixture.
  dd if=/dev/zero of="$disk" bs=512 count=2048 >/dev/null 2>&1
  marker_sector "$expected_sector" "$BLOCK_SEED_MARKER"
  dd if="$expected_sector" of="$disk" bs=512 seek=7 conv=notrunc >/dev/null 2>&1
  if [ "$name" = "store" ]; then
    python3 scripts/store-image.py --seed "$disk"
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
  # exact same raw image. Program persistence uses two boots: the first
  # publishes the fixed `hello` artifact and the second must recover and run
  # that exact source/binary/capability object without another publication.
  # Every other case retains one fresh image and one boot per transcript.
  boots=1
  if [ "$name" = "persistent_cspace" ]; then
    boots=3
  elif [ "$name" = "program_persistence" ]; then
    boots=2
  fi
  : > "$actual"
  boot_output_ok=1
  boot=1
  while [ "$boot" -le "$boots" ]; do
    feed "$case_file" > "$input_fifo" &
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
    ( sleep "$(budget_for "$case_file")"; kill "$QEMU_PID" 2>/dev/null || true ) &
    KILLER_PID=$!

    wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""
    kill "$KILLER_PID" 2>/dev/null || true
    wait "$KILLER_PID" 2>/dev/null || true
    KILLER_PID=""
    wait "$FEED_PID" 2>/dev/null || true
    FEED_PID=""

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

    if [ "$name" = "persistent_cspace" ]; then
      printf '=== persistent CSpace boot %s ===\n' "$boot" >> "$actual"
    elif [ "$name" = "program_persistence" ]; then
      printf '=== program persistence boot %s ===\n' "$boot" >> "$actual"
    fi
    normalize < "$qemu_log" \
      | sed -n '/VibeOS shell ready/,$p' >> "$actual" || true
    boot=$((boot + 1))
  done

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

  if [ "$UPDATE" = "1" ] && [ "$network_ok" != "1" ]; then
    echo "FAIL $name: refusing to update a golden without valid network evidence"
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
