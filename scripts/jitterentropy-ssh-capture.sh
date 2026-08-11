#!/bin/sh
# Capture one authenticated, framed raw-delta stream from the qualification image.
set -eu

cd "$(dirname "$0")/.."

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 TARGET_IPV4 SAMPLES OUTPUT_DATA [PORT]" >&2
  exit 2
fi

target=$1
samples=$2
output=$3
port=${4:-2222}
frame="${output}.ssh-frame"
metadata="${output}.json"
ssh_log="${output}.ssh.log"
capture_tmp=$(mktemp -d "${TMPDIR:-/tmp}/vibeos-jent-ssh.XXXXXX")

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$capture_tmp" ] && [ -d "$capture_tmp" ]; then
    rm -rf "$capture_tmp"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "$samples" in
  ''|*[!0-9]*) echo "SAMPLES must be an integer in 1..1000000" >&2; exit 2 ;;
esac
if [ "$samples" -lt 1 ] || [ "$samples" -gt 1000000 ]; then
  echo "SAMPLES must be an integer in 1..1000000" >&2
  exit 2
fi
for artifact in "$output" "$frame" "$metadata" "$ssh_log"; do
  if [ -e "$artifact" ]; then
    echo "refusing to overwrite evidence artifact: $artifact" >&2
    exit 2
  fi
done

key="$capture_tmp/id_ed25519_accepted"
known_hosts="$capture_tmp/known_hosts"
host_key="$capture_tmp/host_key"
python3 -B scripts/openssh-test-key.py \
  --fixture accepted --comment vibeos-jitterentropy-test-only --output "$key" >/dev/null
python3 -B scripts/openssh-peer.py \
  --host "$target" --port "$port" --accepted-key "$key" \
  --known-hosts "$known_hosts" --host-key-output "$host_key" --scan-only

set -- ssh -F /dev/null -T -p "$port" -i "$key" \
  -o IdentitiesOnly=yes \
  -o UserKnownHostsFile="$known_hosts" \
  -o StrictHostKeyChecking=yes \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o BatchMode=yes \
  -o KexAlgorithms=curve25519-sha256 \
  -o HostKeyAlgorithms=ssh-ed25519 \
  -o PubkeyAcceptedAlgorithms=ssh-ed25519 \
  -o Ciphers=chacha20-poly1305@openssh.com \
  -o Compression=no \
  -o ServerAliveInterval=10 \
  -o ServerAliveCountMax=12
if [ -n "${SSH_BIND_ADDRESS:-}" ]; then
  set -- "$@" -b "$SSH_BIND_ADDRESS"
fi
set -- "$@" "vibe@$target" "jent raw $samples"

mkdir -p "$(dirname "$output")"
echo "capturing $samples deltas from $target:$port into $frame" >&2
"$@" >"$frame" 2>"$ssh_log"
python3 -B scripts/jitterentropy-ssh-decode.py \
  --input "$frame" --output "$output" --metadata "$metadata" \
  --expect-samples "$samples"
