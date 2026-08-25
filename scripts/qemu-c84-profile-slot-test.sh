#!/bin/sh
# C8.4 fixed-storage, allocation-free-per-sample profile-slot acceptance.
set -eu

cd "$(dirname "$0")/.."

KERNEL=target/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt
QEMU_BIN=${QEMU_BIN:-qemu-system-riscv64}
C84_SLOT_TIMEOUT=${C84_SLOT_TIMEOUT:-60}

PASS_MARKER='WASM_C84_PROFILE_SLOT PASS detached_active=1 detached_stream=1 epochs=1,2,3 intervals=7 indexed=1 complete=1 ready_epoch=4'
TOPOLOGY_MARKER='WASM_C84_PROFILE_SLOT TOPOLOGY_REJECT mask=0x3 logical=0 physical=0 epoch=1'
FAIL_MARKER='WASM_C84_PROFILE_SLOT FAIL'
FAMILY_MARKER='WASM_C84_PROFILE_SLOT'

TEST_TMP=$(mktemp -d)
SMP1_LOG="$TEST_TMP/smp1.log"
SMP2_LOG="$TEST_TMP/smp2.log"
QEMU_PID=""
KILLER_PID=""
RESULT_REPORTED=0

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$KILLER_PID" ]; then
        kill "$KILLER_PID" 2>/dev/null || true
        wait "$KILLER_PID" 2>/dev/null || true
    fi
    if [ -n "$QEMU_PID" ]; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    rm -f "$SMP1_LOG" "$SMP2_LOG"
    rmdir "$TEST_TMP" 2>/dev/null || true
    if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
        echo "qemu-c84-profile-slot-test: FAIL (unexpected exit)" >&2
    fi
    exit "$status"
}

fail() {
    RESULT_REPORTED=1
    echo "qemu-c84-profile-slot-test: FAIL ($1)" >&2
    echo "--- smp=1 serial ---" >&2
    if [ -f "$SMP1_LOG" ]; then
        cat "$SMP1_LOG" >&2
    fi
    echo "--- smp=2 serial ---" >&2
    if [ -f "$SMP2_LOG" ]; then
        cat "$SMP2_LOG" >&2
    fi
    exit 1
}

count_exact_marker() {
    log=$1
    marker=$2
    LC_ALL=C tr '\r' '\n' < "$log" | awk -v marker="$marker" '
        BEGIN { clear_line = sprintf("%c", 27) "[2K" }
        $0 == marker || $0 == clear_line marker { count++ }
        END { print count + 0 }
    '
}

count_unexpected_markers() {
    log=$1
    expected=$2
    LC_ALL=C tr '\r' '\n' < "$log" | awk -v family="$FAMILY_MARKER" -v expected="$expected" '
        BEGIN { clear_line = sprintf("%c", 27) "[2K" }
        {
            line = $0
            if (index(line, clear_line) == 1) {
                line = substr(line, length(clear_line) + 1)
            }
            if (index(line, family) == 1 && line != expected) {
                count++
            }
        }
        END { print count + 0 }
    '
}

stop_qemu() {
    if [ -n "$KILLER_PID" ]; then
        kill "$KILLER_PID" 2>/dev/null || true
        wait "$KILLER_PID" 2>/dev/null || true
        KILLER_PID=""
    fi
    if [ -n "$QEMU_PID" ]; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
        QEMU_PID=""
    fi
}

boot_and_require() {
    smp=$1
    log=$2
    expected=$3
    forbidden=$4
    scenario=$5

    "$QEMU_BIN" \
        -machine virt \
        -cpu rv64 \
        -smp "$smp" \
        -m 128M \
        -accel tcg,thread=single \
        -nographic \
        -bios default \
        -kernel "$KERNEL" < /dev/null > "$log" 2>&1 &
    QEMU_PID=$!

    (
        sleep "$C84_SLOT_TIMEOUT"
        kill "$QEMU_PID" 2>/dev/null || true
    ) &
    KILLER_PID=$!

    remaining=$((C84_SLOT_TIMEOUT * 10))
    while [ "$remaining" -gt 0 ]; do
        if grep -a -F "$FAIL_MARKER" "$log" >/dev/null 2>&1; then
            fail "$scenario guest reported a FAIL marker"
        fi
        if grep -a -E '\[!\] (fatal|panic)|panicked at' "$log" >/dev/null 2>&1; then
            fail "$scenario guest panicked"
        fi

        expected_count=$(count_exact_marker "$log" "$expected")
        if [ "$expected_count" -gt 1 ]; then
            fail "$scenario emitted the expected marker more than once"
        fi

        forbidden_count=$(count_exact_marker "$log" "$forbidden")
        if [ "$forbidden_count" -ne 0 ]; then
            fail "$scenario emitted the other scenario marker"
        fi

        unexpected_count=$(count_unexpected_markers "$log" "$expected")
        if [ "$unexpected_count" -ne 0 ]; then
            fail "$scenario emitted an unexpected profile-slot marker"
        fi

        if [ "$expected_count" -eq 1 ]; then
            sleep 0.1

            if grep -a -F "$FAIL_MARKER" "$log" >/dev/null 2>&1; then
                fail "$scenario guest reported a FAIL marker after PASS"
            fi
            if grep -a -E '\[!\] (fatal|panic)|panicked at' "$log" >/dev/null 2>&1; then
                fail "$scenario guest panicked after PASS"
            fi
            if [ "$(count_exact_marker "$log" "$expected")" -ne 1 ]; then
                fail "$scenario emitted the expected marker more than once"
            fi
            if [ "$(count_exact_marker "$log" "$forbidden")" -ne 0 ]; then
                fail "$scenario emitted the other scenario marker"
            fi
            if [ "$(count_unexpected_markers "$log" "$expected")" -ne 0 ]; then
                fail "$scenario emitted an unexpected profile-slot marker"
            fi

            stop_qemu
            return 0
        fi

        if ! kill -0 "$QEMU_PID" 2>/dev/null; then
            fail "$scenario QEMU exited before the expected marker"
        fi

        sleep 0.1
        remaining=$((remaining - 1))
    done

    fail "$scenario timed out waiting for the expected marker"
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "$C84_SLOT_TIMEOUT" in
    ''|*[!0-9]*|0)
        fail "C84_SLOT_TIMEOUT must be a positive integer"
        ;;
esac

if ! command -v rustup >/dev/null 2>&1; then
    fail "rustup is required"
fi
if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
    fail "$QEMU_BIN is required"
fi

toolchain=$(awk -F '"' '/^channel[[:space:]]*=/{print $2; exit}' rust-toolchain.toml)
if [ -z "$toolchain" ]; then
    fail "rust-toolchain.toml does not pin a toolchain"
fi

pinned_rustc=$(rustup which --toolchain "$toolchain" rustc) || fail "cannot locate pinned rustc"
pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc) || fail "cannot locate pinned rustdoc"

(
    cd firmware/qemu-virt
    RUSTC="$pinned_rustc" \
    RUSTDOC="$pinned_rustdoc" \
    rustup run "$toolchain" cargo build \
        --release \
        --locked \
        --no-default-features \
        --features wasm-c84-profile-slot-qemu-acceptance
) >&2

boot_and_require 1 "$SMP1_LOG" "$PASS_MARKER" "$TOPOLOGY_MARKER" "smp=1"
boot_and_require 2 "$SMP2_LOG" "$TOPOLOGY_MARKER" "$PASS_MARKER" "smp=2"

RESULT_REPORTED=1
echo "qemu-c84-profile-slot-test: PASS"
