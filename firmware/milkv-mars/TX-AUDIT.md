# Mars TX path audit

`network-tx-audit` is a default-off, one-shot diagnostic. It does not change
queue sizes, TCP windows, cache synchronization, packet admission, or reset
policy. The current filter deliberately matches only IPv4 TCP source
`192.168.77.10:5300` to `192.168.77.1`, the explicitly admitted laboratory link.
It is not a general network-address assumption or a production interface.

Two stages count canonical TCP headers: protocol frame construction and
successful HAL driver submission. Counters contain frame count, TCP payload
bytes, wrapping hash sum, hash XOR, SYN count and FIN count. The fingerprints
exclude offloaded checksums and payload and do not prove payload integrity or
packet order. A submission is not proof of DMA completion or wire delivery.

## Capture procedure

Use an isolated source connection and a fresh boot. Compare throughput before
and after arming on the same image; instrumentation can change the behavior
being measured. Keep other test traffic off this source port.

1. Start tcpdump on the confirmed host interface before arming. Capture full
   frames (`-s 0`) for payload/checksum analysis, or at least 160 bytes for
   complete Ethernet/IPv4/TCP headers. A 4 MiB buffer (`-B 4096`) was used on the
   tested Mac. Keep tcpdump's completion log, including kernel drops.
2. Send `ntxaudit start` over serial and require `accepted=true`. In the MAC
   audit image, a hardware snapshot precedes activation. No live reset exists.
3. Run `scripts/mars-tcp-probe.py --address 192.168.77.10 --protocol 2 --mode
   source --flows 1 --bytes 536870912 --output NEW.json`.
4. After successful transfer and closure, allow 12 seconds for close/TIME_WAIT
   traffic to settle. Send `ntxaudit stop` and save the complete serial dump including both start and stop snapshots.
   If a writer is still finishing, retry stop; never rearm the same boot.
5. Stop tcpdump and verify its kernel-drop count. Analyze with:

```sh
python3 scripts/mars-tx-audit.py trace.pcap serial.log \
  --allow-header-only --capture-log tcpdump.log --output NEW-audit.json
```

Omit `--allow-header-only` to reject snaplen truncation. The script never
reconstructs payload evidence from a header capture; padding is used only by
the shared header fingerprint calculation. A missing or nonzero capture-drop
count prevents a defensible inference about missing wire data. Also check
capture scope, SYN/FIN and absence of resets; the parser cannot prove these
external conditions by itself.

## Hardware snapshot

The shell requests a snapshot; the existing driver services it immediately
after TX reaping under exclusive HAL engine ownership. The shell never
borrows or directly accesses the DMA engine. Eleven values are reported (older captures contain the first nine):

`available, accepted, pending, control, frames_good_bad, frames_good,
underflow, carrier_error, pause, local_advertisement, partner_advertisement`.

The last two are read-only Clause-22 registers 4 and 5; 65536 denotes an
unavailable read. They do not change the configured negotiation policy.

MAC counters cover **all transmitted frames**, unlike the filtered TCP audit.
Only compare deltas with supported MMC, zero pending descriptors at both
boundaries, unchanged non-destructive counter mode, no saturated counter, and
no intervening reset/link recovery. The software accepted counter must remain
monotonic and the interval must fit a 32-bit frame count. No MAC reset,
freeze, read-clear or interrupt-acknowledgement writes are issued.

GMAC4 offsets and counter modes follow upstream Linux
[mmc.h](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/ethernet/stmicro/stmmac/mmc.h)
and [mmc_core.c](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/ethernet/stmicro/stmmac/mmc_core.c).
Controller model tests verify that unsupported MMC and unsafe modes do not
read the counters. This source agreement is not physical qualification.

A matched software/driver fingerprint excludes an observed loss between those
boundaries for the captured flow, subject to fingerprint limitations. A validated MAC
good-frame count matched to accepted frames would narrow further investigation to
the wire/host receive side; it does not itself prove host delivery. A mismatch
with nonzero pending descriptors or capture drops is not a location proof.


The initial physical MAC audit returned a matching total good-and-bad frame
counter but a good-only counter stuck at zero. Do not use that good-only field
as evidence of either good delivery or all-bad frames until its implementation
and semantics are independently qualified. Preserve this discrepancy in reports.
