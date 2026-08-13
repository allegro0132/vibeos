#!/bin/sh
# Verify UART evidence for simultaneous DWMAC and USB CDC-ECM operation.
set -eu

usage() {
  echo "Usage: $0 UART_LOG" >&2
  echo "Analyze a Milk-V DHCP-image UART log containing ip link/addr output." >&2
}

fail() {
  echo "FAIL milkv-dual-net: $*" >&2
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

if grep -a -E -q '\[!\] panic|dwmac net driver (claim failed|stopped)|usb net +driver stopped|CDC-ECM configuration FAILED' "$log"; then
  fail "panic or network-driver failure marker present"
fi

require 'dwmac net +online, IRQ 31, DMA 0x[0-9a-f]+, epoch [1-9][0-9]*' \
  'instance-owned DWMAC activation'
require 'usb +DWC2 .*IRQ 30' 'DWC2 host-controller banner'
require 'usb net +CDC-ECM configured, interface [0-9]+ alt [1-9][0-9]*, IN ep [0-9]+, OUT ep [0-9]+' \
  'CDC-ECM class configuration'
require 'usb net +CDC-ECM online, MAC ([0-9a-f]{2}:){5}[0-9a-f]{2}, epoch [1-9][0-9]*' \
  'independent USB network activation'
require 'net map +net[0-9]+ <- mmio@0x4070000 \(dwmac\)' 'DWMAC topology mapping'
require 'net map +net[0-9]+ <- usb@0x4340000(/[1-9][0-9]*)+ \(usb-cdc-ecm\)' \
  'USB topology mapping'

dwmac_interface=$(grep -a -E 'net map +net[0-9]+ <- mmio@0x4070000 \(dwmac\)' "$log" \
  | tail -n 1 | sed -E 's/.*net map +((net)[0-9]+).*/\1/')
usb_interface=$(grep -a -E 'net map +net[0-9]+ <- usb@0x4340000(/[1-9][0-9]*)+ \(usb-cdc-ecm\)' "$log" \
  | tail -n 1 | sed -E 's/.*net map +((net)[0-9]+).*/\1/')
[ "$dwmac_interface" != "$usb_interface" ] \
  || fail "both drivers mapped to $dwmac_interface"

require "[0-9]+: $dwmac_interface: <UP,LOWER_UP> mtu 1500 state UP" \
  'DWMAC carrier'
require "[0-9]+: $usb_interface: <UP,LOWER_UP> mtu 1500 state UP" \
  'USB carrier'
require "inet ([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]+ scope global dynamic $dwmac_interface" \
  'DWMAC DHCP lease'
require "inet ([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]+ scope global dynamic $usb_interface" \
  'USB DHCP lease'

dwmac_address=$(grep -a -E "inet ([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]+ scope global dynamic $dwmac_interface" "$log" \
  | tail -n 1 | sed -E 's/.*inet ([0-9.]+)\/.*/\1/')
usb_address=$(grep -a -E "inet ([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]+ scope global dynamic $usb_interface" "$log" \
  | tail -n 1 | sed -E 's/.*inet ([0-9.]+)\/.*/\1/')
[ "$dwmac_address" != "$usb_address" ] \
  || fail "both interfaces reported the same DHCP address: $dwmac_address"

echo "PASS milkv-dual-net: $dwmac_interface=$dwmac_address (DWMAC), $usb_interface=$usb_address (CDC-ECM)"
