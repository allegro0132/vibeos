#!/bin/sh
# Verify the UART evidence captured during the physical Milk-V Duo HID gate.
set -eu

usage() {
  echo "Usage: $0 UART_LOG" >&2
  echo "Analyze a diagnostic-image UART log after the documented HID hotplug test." >&2
}

fail() {
  echo "FAIL milkv-usb-hid: $*" >&2
  exit 1
}

if [ "$#" -ne 1 ]; then
  usage
  exit 2
fi

log=$1
[ -r "$log" ] || fail "UART log is not readable: $log"

require() {
  pattern=$1
  label=$2
  grep -a -E -q "$pattern" "$log" || fail "missing $label"
}

require_count() {
  pattern=$1
  minimum=$2
  label=$3
  count=$(grep -a -E -c "$pattern" "$log" || true)
  [ "$count" -ge "$minimum" ] \
    || fail "$label occurred $count time(s), expected at least $minimum"
}

if grep -a -E -q '\[!\] panic|usb (dev|hid) +.*FAILED' "$log"; then
  fail "panic or USB failure marker present"
fi

require 'usb +DWC2 .*IRQ 30' 'DWC2 host-controller banner'
require_count 'usb dev +(addr|hotplug addr) [1-9][0-9]*, (Low|Full|High)' 2 \
  'successful device enumeration'
require_count 'usb hid +((attached )?(Boot|Report)|attached boot|boot) keyboard' 2 \
  'HID keyboard configuration'
require 'usb hid +device disconnected; waiting for reconnect' \
  'disconnect transition'
require_count '(vibe|vsh)> *uptime' 2 'keyboard-entered uptime command'
require_count 'up [0-9]+\.[0-9][0-9][0-9] s' 2 'uptime command response'

echo "PASS milkv-usb-hid: enumerate, type, disconnect, reconnect, and type again"
