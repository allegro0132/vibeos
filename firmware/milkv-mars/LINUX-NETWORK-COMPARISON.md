# JH7110 Ethernet: Linux comparison

Reviewed 2026-09-13 against Linux upstream `master` as served at review time;
these links are moving references, not a pinned or tested Linux build.
VibeOS reference: `14b01b9`, with the RX-only control-lock experiment included.
This is a source comparison, not evidence of Linux throughput on this board.

## DMA is already active

`drivers/eqos-net/src/controller.rs` programs physical descriptor bases, ring
lengths and tail pointers, then enables TX ST and RX SR and verifies readback.
`ring.rs` publishes descriptor OWN after synchronizing buffers. The firmware
uses 32 descriptors per direction in a permanent DMA pool. Interrupts are
disabled; completion is polled. CPU copies into/out of that pool and software
checksum work are separate from the MAC's DMA transfer.

## Concrete differences

| Area | VibeOS | Linux reference | Experiment |
| --- | --- | --- | --- |
| TX/RX PBL | 8 / 8 beats | JH7110 DT: 16 / 16 | Test PBL 16 alone, retaining FIFO admission and no PBLx8 |
| PBLx8 | Disabled | Explicitly disabled in JH7110 DT | Keep disabled |
| AXI outstanding limit fields | Read 2, write 0 | DT fields both 15 | Test separately after PBL; these are encoded fields, not literal request counts |
| AXI burst mask | 4, 8, 16 | DT permits 32, 64, 128, 256 | Evaluate as a separate bus configuration; do not infer gain from larger numbers |
| Operate on second packet | TX OSP enabled | DMA init enables OSP | Already present |
| MTL mode | Store and forward | JH7110 DT forces threshold mode | Separate from checksum experiment |
| Checksum | CPU IPv4/TCP/UDP | Hardware capability and DMA mode dependent | RX offload needs per-packet validity/fallback; TX needs compatible descriptor flags and mode |
| Descriptor memory | Cached, explicit maintenance, 64-byte isolation | Coherent DMA allocation | Investigate descriptor synchronization cost; never simply remove cache maintenance |
| RX payload | Copy from fixed DMA pool | DMA-mapped page pool, packet built around received page | Consider owned packet-buffer handoff to reduce copying |
| Completion | Bounded cooperative polling | NAPI processing and interrupt/coalescing paths | Compare batch/reclaim costs before assuming interrupts increase throughput |

The DT PBL, AXI and MTL values above come from
[JH7110 device tree](https://github.com/torvalds/linux/blob/master/arch/riscv/boot/dts/starfive/jh7110.dtsi).
Their programming and OSP are in
[dwmac4_dma.c](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_dma.c);
register field definitions are in
[dwmac4_dma.h](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_dma.h).

Linux's [stmmac_main.c](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/stmmac_main.c)
disables ordinary TX checksum offload when threshold DMA mode is forced. It
also allocates coherent descriptor memory and uses DMA-mapped RX page pools.
Thus “copy every Linux setting and enable all offloads” is not a valid recipe.
VibeOS's two checksum booleans cannot represent a received packet whose hardware
checksum is unknown: such packets require software validation or a richer
metadata contract before globally disabling software checks.

The [StarFive glue](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac-starfive.c)
also enables DCHE and disables split headers. DCHE requires a separate hardware
semantics/errata review before use; it is not permission to omit CPU cache
synchronization. JH7110 must retain its own cache implementation.

## Measurement order

1. Keep the measured 494.07 / 530.15 Mbps RX-lock FIT as the control. Change
   PBL only, then AXI configuration separately; log programmed/read-back values,
   DMA errors and directional 60-second throughput for each candidate.
2. Measure ring starvation and descriptor maintenance costs. Test 64/128-entry
   rings independently; preserve bounded service work and queue revocation.
3. Add qualified checksum handling, then packet-buffer ownership transfer and
   batched tail updates. Include malformed checksums, odd lengths, ring wrap,
   reset/rebind and concurrent load in validation.

Existing timing places substantial work in both driver and TCP stack; therefore
bus tuning alone is not evidence that 900 Mbps is attainable. This comparison
does not change the running firmware or qualify any new DMA configuration.

## Diagnostic issue found during the PBL experiment

The service composition can intentionally withhold raw network capabilities
from `init`. `legacy_shell::net_command` currently calls that state “offline
(no modern network transport discovered)”. That message cannot establish device
absence or link failure. Correct the diagnostic without granting shell raw
packet access or bypassing the network service's ownership. The PBL experiment
does not change this independent policy/diagnostic path.

## PBL 16 result

The single-variable PBL 16 candidate was built and booted from RAM, with FIT
SHA-256 `1922a77824838e4ab00303ea591514d3f0f6bc27300fca0dc8fb8b6cec829e5a`.
U-Boot verified both FIT image hashes; the PHY reported 1000 Mbps full duplex.
Separate 60-second single-stream tests measured 489.48 Mbps host-to-board and
527.74 Mbps board-to-host, versus the prior PBL 8 result of 494.07 / 530.15 Mbps.
This one pair does not establish statistical equivalence, but shows no observed
improvement. Source PBL was restored to 8; candidate artifacts remain available
under `target/mars-boot-20260913-gigabit-pbl16/`. At the end of this experiment
the board still runs that RAM PBL 16 candidate; installed SD contents are unchanged.

Evidence: `target/mars-acceptance/20260913-gigabit/pbl16-sustained/`,
`pbl16-source.patch`, `pbl16-load.log`, `pbl16-boot.log`, and
`pbl16-health-during.log`. During load, all components were running with zero
faults/cancellations and one expected bootstrap exit. Driver host tests passed
38 cases. Channel PBL readback was not independently logged on hardware; this
experiment records the built configuration, boot verification and traffic.

## AXI outstanding-limit candidate (not accepted)

Candidate FIT `17505ad8ac92d99aeeef8e77ddc89ee7eec256e699c1655bf62f73d7689d4018`
changes only read/write outstanding fields to 15/15 and adds a strict bus-field
readback guard. It built with 39 driver tests passing, but failed to bring the
link online, reporting `Ring(Controller)` during link activation and repeated
driver recovery. No throughput result exists for this candidate. The controller
error is collapsed by the ring adapter, so field truncation remains a hypothesis
until a runtime readback is logged.

U-Boot reads of `0x16031004` and both channel controls returned zero even after
TFTP; writing/restoring the stopped bus register also returned zero. Without
verified clock/access state this is not evidence of unsupported fields. The
known RX-lock FIT was reloaded and hash-verified for recovery. Runtime AXI
readback logging is added to the next diagnostic candidate. Evidence resides in
`target/mars-acceptance/20260913-gigabit/axi-*.log` and `axi-source.patch`.

### Actual Mars AXI readback

The diagnostic FIT `ea61d13b7c6cbbf7282ec1ea68e9b064168fcf32e93851781578cf96572e7205`
logged `MARS_NET_AXI base=0x16030000 bus=0x0303000e` repeatedly when the driver
requested `0x0f0f000e`. This directly explains the strict-check failure: upper
two bits of each requested limit field did not read back. The next candidate
requests 3/3, retains PBL 8 and the 4/8/16 burst mask, and keeps readback checks.
The stopped U-Boot probes above remain inconclusive; the runtime driver log is
the authoritative observation (`axi-readback-boot.log`).

### Supported 3/3 experiment result

FIT `6a86e5e7c97ffcc41c58f0fd018c73cba6055fd812752dd4c6f21d35c49d389d`
booted successfully, read back `0x0303000e`, and established 1000 Mbps full duplex.
Separate 60-second single-stream TCP tests measured 509.26 Mbps host-to-board
and 520.71 Mbps board-to-host. The prior baseline was 494.07 / 530.15 Mbps;
this mixed result is not evidence of a consistent bidirectional improvement.
All components remained running, with zero faults/cancellations and the expected
single bootstrap exit; netstack live memory stayed 2,105,216 bytes with no quota
denials. Evidence: `axi3-sustained/`, `axi3-boot.log`, `axi3-health.log`,
`axi3-memory.log`, and `axi3-source.patch` under the experiment directory.

Source outstanding limits were restored to the baseline read=2/write=0 fields.
The readback guard and runtime diagnostic remain; the board currently runs the
RAM 3/3 candidate. No SD/SPI writes occurred. New optimization experiments should
use the baseline fields rather than treating 3/3 as a proven gain.

## Checksum capability and encoding groundwork

Mars read GMAC_HW_FEATURE0 (offset 0x11c) as 0x1a2173f7. Both TXCOSEL
(bit 14) and RXCOESEL (bit 16) are set. This advertises TX/RX checksum capability;
it does not qualify packet behavior. The driver exposes this read-only decoded
value and firmware logs it after platform clock/reset preparation.

TX descriptor construction now has explicit None, IPv4-header and Full CIC
modes in word 3 bits 17:16. Full encodes 3 (IP header and pseudoheader), as in
[Linux descriptor definitions](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_descs.h)
and [CIC definitions](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/descs.h).
That capability-only diagnostic used the original default constructor (None)
and advertised both offloads as false. The later opt-in experiment below adds
packet selection, fallback and captured IPv4/TCP validation. The default
Ethernet composition continues to use software checksums.

All 41 EQoS host tests passed. Capability decode, CIC encoding, unchanged OWN
publication and address/length rejection are covered. Diagnostic FIT SHA-256:
`ee2d9e17ad50a1c049c4a1f285f4c73527d5e9cbaa23e8862aec102fc8ed63a9`.
Evidence: `checksum-cap-boot.log`, `checksum-cap-load.log` and
`checksum-cap-source.patch` in the gigabit experiment directory. Reference
source contents and hashes are under `target/mars-reference/linux-checksum/`.

## TX checksum experiment integration (IPv4/TCP capture verified)

`checksum::prepare` validates complete Ethernet/IPv4 requests before mutating
CPU-owned bytes. Normal untagged IPv4 TCP/UDP clears both checksum fields and
selects CIC Full only when the backend advertises TXCOE. Unsupported hardware,
VLAN, IP options and differing UDP/IP lengths complete checksums in software.
ICMP/other IP protocols retain their payload checksum and receive a software IP
header checksum. Ethernet padding is excluded. Non-IP traffic is unchanged.
The complete-request API rejects fragments; the experimental firmware preserves
already-checksummed raw fragments through ordinary TX. The composed smoltcp
configuration has no IPv4 fragmentation feature, so it emits complete requests.

The `tx-checksum-experiment` feature was selected for the isolated qualification
build; it is not enabled by the default Mars Ethernet composition. It copies the caller packet into owned
scratch space, invokes checksum preparation and submits via the ordinary ring
ownership/publication path. The backend caches hardware capability at assembly;
the existing controller uses store-and-forward. RX offload remains disabled.
48 EQoS host tests pass; the captured IPv4/TCP hardware verification and
throughput results are below. UDP wire checks, backpressure/reconnect tests
and experiment selftest remain pending. The installed SD is unchanged.

The experimental FIT built successfully with SHA-256
`50f6f370635c114cf0af89e5250d3a68a06cbfe4aeb52c7ebf70257c8822c710`.
Before it could be transferred, the previous running board stopped responding
to serial/newline and a bounded network probe after a reboot attempt. The TFTP
service saw no request and was stopped; the experimental FIT was not booted.
A physical power cycle was requested. This was not evidence of an offload
failure: it preceded loading the experiment. 48 EQoS tests and 6 packet-engine
tests passed; the standard Ethernet feature continues to use software checksums.
To reproduce the isolated build, the archived `tx-checksum-source.patch` includes
the temporary feature selection that was removed from the default composition.

After the requested physical power cycle, serial recovered and the TX experiment
was loaded into RAM. U-Boot verified both kernel and DTB hashes, matching the
local experiment artifacts. DHCP and 1000 Mbps full-duplex link came up. A
full-length en7 capture of reverse iperf traffic contains 364,377 board-origin
TCP packets: all have Good IPv4 and TCP checksums with explicit Wireshark
checksum verification enabled. Maximum IP length is 1500; capture reports zero
kernel drops. This establishes the captured IPv4/TCP path, not UDP checksum
correctness, recovery, or long-term stability.

Uncaptured, separate 60-second single-stream runs measured 496.81 Mbps
host-to-board and 492.01 Mbps board-to-host. All service tasks remained running
with zero faults/cancellations. The experiment also rebooted successfully into
U-Boot. Offload stays opt-in: the scratch copy and repeated preparation add
CPU work, and this implementation has not demonstrated a performance gain.
Evidence is archived as `tx-checksum-wire-summary.json`,
`tx-checksum-status.tsv`, `tx-checksum-reverse-headers.pcap` (despite its name,
this capture retains full packets), `tx-checksum-60s/`, and
`tx-checksum-health.log` under the gigabit acceptance directory.

The same-session software-checksum baseline measured **541.99 / 628.96 Mbps**
over separate 60-second single-stream runs, versus the experiment's
496.81 / 492.01 Mbps. Both runs used the same board, host, MTU and direct link;
no capture ran during these measurements. Baseline task health also reported
zero faults/cancellations. The experiment therefore remains opt-in and the
board remains on the `cancel-ready` baseline. This pair is a regression signal,
not a statistical estimate; it does not establish which added operation caused
the loss. Raw baseline results: `tx-checksum-ab-baseline-60s/summary.json`.

## Borrowed TX request experiment

`checksum::Request` binds a private validated plan to an immutable packet borrow.
The firmware parses once; the ring consumes that request synchronously. Normal
untagged IPv4/TCP/UDP with zero checksum fields and admitted TXCOE passes the
original bytes directly to the existing DMA copy with Full CIC. Non-IP traffic
also borrows directly. Nonzero checksum fields, unsupported hardware and format
fallbacks use a separate non-inlined scratch routine with the same validated
plan; caller memory is never modified. No DMA-memory alias or new ownership
shortcut is introduced. Raw already-checksummed fragments retain the firmware
compatibility path, while the strict ring request API rejects fragments.

49 EQoS model tests and 6 packet-engine tests pass. Tests observe the actual
copy source pointer and copied bytes to distinguish borrowing from fallback,
verify unchanged caller bytes and valid publication, and reject malformed or
fragmented requests before DMA activity. The feature remains experimental;
this change still needs its own real-board packet and performance validation.

The borrowed-request image subsequently passed real-board IPv4/TCP capture
validation (448,319 good packets), measured 534.50 / 632.39 Mbps in separate
60-second tests, and passed system selftest 395 / 0. The scratch-copy regression
is largely removed, but software TX checksumming alone does not explain the
remaining performance gap. TX offload stays opt-in; RX remains in software.
See `NETWORK-PERFORMANCE.md` and `tx-borrow-*` artifacts for evidence.

## RX checksum status prerequisite

The opt-in `rx-status-experiment` requests MAC IPC (bit 27) only while stopped
and only with RXCOE capability; configure checks the bit readback. It retains
software RX checksum verification in the protocol stack. A separate ring
receive API returns length and checksum observation for the same copied frame.
It reads word 1 only after a complete CPU-owned descriptor declares RDES1 valid,
and before rearming that slot. The original receive API does not request the
additional status read. Descriptor-provided addresses never replace the private
DMA buffer map.

The observation distinguishes unavailable, bypassed, checksum error, IPv4 and
IPv6 (including the raw payload type). Missing or inconsistent metadata does
not establish checksum success. These fields follow Linux `dwmac4_descs.h` and
`dwmac4_descs.c`; MAC IPC follows `dwmac4.h`. A future consumer must also match
packet headers and enabled MAC mode, with software fallback for every
unverified packet. No global RX-offload advertisement is enabled by this step.

52 EQoS tests and 6 firmware engine tests pass, including ownership/validity
gating, same-frame metadata lifetime, invalid descriptor states and stopped
mode reconfiguration. Diagnostic counters are ordered as unavailable, bypassed,
error, IPv4, IPv6 and exposed as `MARS_NET_RX_CHECKSUM`.

The diagnostic FIT `8eeb07c17b2c54c80f262e61e3721816b585e884bac661c9365254044769e512`
booted on Mars; DHCP and both 10-second TCP directions passed (566.35 / 626.90
Mbps). Normal traffic produced 513,986 IPv4 observations with no error status.
A bounded twelve-frame UDP injection and full outgoing capture verified three
each of valid, bad IPv4 checksum, bad UDP checksum and IPv4 zero UDP checksum.
The observed counters changed from [0,29,0,513986,0] to [0,34,0,513992,0].
Background traffic affects bypass counts. Six additional IPv4 observations are
consistent with valid and zero-checksum UDP; no checksum-error observation was
returned. This does not isolate MAC discard from descriptor error rejection:
`rx_complete` rejects error-summary descriptors before metadata is returned.
Software RX verification remains enabled. A subsequent step must expose those
drop stages before qualifying software-verification bypass.

Evidence: `rx-status-*`, `rx-checksum-injected.pcap`,
`rx-checksum-injected-status.tsv`, and serialized injected frames in
`rx-checksum-injected.json` under the gigabit acceptance directory. 53 EQoS
tests now also cover MAC IPC readback rejection preventing DMA start.

## Rejected RX descriptor evidence

The status receive path now retains a cumulative rejection count and the last
word-3/word-1 snapshot even when the base descriptor codec rejects a frame.
Word 1 is read only for a normal complete CPU-owned descriptor declaring it
valid, before any rearm. Rejected descriptors never authorize a payload copy
or delivery; the existing error return and rearm behavior remain unchanged.
The ordinary receive path does not collect these additional observations.
Firmware exposes `MARS_NET_RX_REJECT count=... status=... word1=...`.

54 EQoS host tests and 6 packet-engine tests pass. The new model test proves
that OWN suppresses observation, hardware errors preserve evidence without a
payload copy, slots are rearmed, and absent validity cannot reuse stale word 1.
Physical injection is being repeated in four groups spaced seven seconds apart
to distinguish valid UDP, bad IPv4 header, bad UDP payload and IPv4 zero UDP
checksum behavior in the five-second diagnostic snapshots.

The first paced injection on FIT
`6904d37921523010b9dfba6d989bd1bd644fb65f4ea7a7f6720ef3e75131141a`
produced no rejected descriptors. Default MTL queue configuration leaves
DISTCPEF (bit 6) and FEP (bit 4) clear. The shared GMAC register semantics in
[ST's official HAL](https://github.com/STMicroelectronics/stm32h7xx-hal-driver/blob/master/Src/stm32h7xx_hal_eth.c)
confirm that this configuration drops checksum-error frames before DMA. The
[official descriptor header](https://github.com/STMicroelectronics/stm32h7xx-hal-driver/blob/master/Inc/stm32h7xx_hal_eth.h)
also defines UDP/TCP payload codes as 1/2. Retrieved source hashes are saved in
`target/mars-reference/linux-checksum/st-reference-sources.json`.

A separate `rx-error-forward-experiment` explicitly sets both bits while stopped
and checks readback, leaving all software RX checks enabled. Its FIT
`7c86052684e5ef7042be82e0c05ed20b8c7431ec5f9de82951fd3c6f89f51386`
was RAM-booted and the twelve-frame paced injection repeated. Full outgoing
capture verified all intended checksum values. Three bad-IP packets and three
bad-UDP packets incremented checksum-error observations to six, while descriptor
rejection stayed zero. Thus checksum errors need not set descriptor error
summary; accepting every completed descriptor is insufficient for RX offload.
Valid and zero-checksum UDP still produced normal IPv4 observations.

Firmware now explicitly drops `RxChecksum::Error` before returning a packet to
its caller. The new engine test covers IP and UDP error flags without descriptor
ES, slot rearm and a subsequent good packet. This last change has passed seven
engine tests but is not yet in a physical image. 56 EQoS tests and driver boundary
checks also pass. The hardware experiment retained software verification and
did not qualify bypass: closed-port UDP responses are not proof of transport
checksum rejection. The board was restored to the default hardware-drop
`rx-reject` image; none of these options is enabled in default Ethernet builds.

Evidence prefixes: `rx-reject-*`, `rx-forward-*`; captured packets and decoded
checksum status are under the same gigabit acceptance directory.

Restored default-drop image passed both five-second TCP smoke directions
(555.88 / 614.08 Mbps). These are connectivity checks, not a new performance
baseline. The explicit checksum-error client-delivery fix remains host-tested
only; the currently running rollback predates that source change.

## Complete IPv4 RX verification experiment

`verify_rx_ipv4` validates the frame layout before deciding whether an admitted
IPC observation can replace software sums. Only ordinary complete untagged
IPv4 TCP/UDP with matching payload type and matching lengths returns Hardware.
Unavailable, bypassed or protocol-mismatched metadata, VLAN/IP options and
short UDP lengths use software IPv4/TCP/UDP verification. IPv4 UDP zero checksum
is accepted by its protocol rule; odd lengths and padding are handled precisely.
ICMP/other IPv4 protocols still require their protocol layer's payload checks.
Fragments return an explicit error; NonIpv4 is never transport verification.

The opt-in `rx-ipv4-checksum-experiment` is restricted to the current complete
IPv4 + ARP service profile (`net-protocol` composes smoltcp with IPv4 only and
without IP fragmentation). It drops other EtherTypes/fragments before exposing
a global RX transport-offload capability. This is not a general raw Ethernet or
IPv6 offload contract; those consumers must retain their own verification. The
default Ethernet profile is unchanged. Error metadata is dropped before client
delivery. Counters `MARS_NET_RX_VERIFY` mean hardware, software, rejected.

60 EQoS tests and 8 engine tests pass, including unchanged input, corrupt header
and transport data, odd lengths, missing UDP checksum, options/VLAN fallback,
protocol mismatch and rejection of unchecked IP. The isolated build also selects
TX offload and diagnostic error forwarding so bad RX packets must be rejected
by the new path. FIT SHA-256:
`414e8d843e399dd46d0841dc5e8b58380bbba119ccc1fdfef7529e3a328623d7`.

The image booted with TX and RX checksum capability advertised. DHCP succeeded.
Fifteen paced UDP probes then produced verification deltas [6 hardware,
3 software, 6 dropped]: IP-options probes exercised software fallback and
bad-IP/bad-UDP probes exercised explicit error rejection despite error forwarding.
Full capture verifies outgoing checksum values, with no ICMP response to either
bad group. Captured responses were 2/3 ordinary-valid UDP, 3/3 zero-checksum UDP
and 3/3 IP-options UDP; this does not prove every valid probe responded.
Evidence is `rx-verify-injection-summary.json`, the capture and decoded TSV.
The capture also shows zero checksum in quoted inner IPv4 headers of ICMP errors
while TX offload is enabled; outer IPv4 checksum is valid. This nested-header
TX behavior needs review before making the combined offload profile default.

Separate uncaptured 60-second tests measured 520.69 / 630.76 Mbps. Physical
selftest passed 395 / 0. Hardware RX checksum completion is now exercised, but
these results do not show a speed gain over the software baseline. The next
performance investigation should target device/cache/executor costs rather
than assume IPv4/TCP checksum sums explain the remaining gap.

The ICMP quote issue is repaired in source: TX preparation completes a bounded
quoted IPv4 header in ICMP errors, then recomputes the ICMP checksum. It never
requires the missing quoted transport payload, never uses CIC for ICMP and
leaves padding unchanged. An independent checksum test covers five ICMP error
types and repeated preparation. 61 EQoS tests pass; this repair is not in the
running FIT yet. The current image still has the documented nested-quote issue.

The ICMP quote repair was subsequently verified physically in FIT
`a967acc59d165de03544ccc4863d58c9854b1461a4db687e84e3f20c9cdf4142`: all eight
captured ICMP errors have Good outer/inner IPv4 and ICMP checksums. Bad probe
groups still produced no captured response. This image disables executor
profiling but retains driver profiling and the combined offload experiments.
Separate 60-second throughput was 508.78 / 631.44 Mbps, versus 520.69 / 630.76
with executor profiling. No performance gain is established; source default
profiling selection is retained. Evidence prefix: `no-exec-profile-*`.

### Read-only RX recycle experiment (2026-09-13)

Linux RISC-V DMA_FROM_DEVICE still performs pre-device maintenance, and
SiFive CCache maps clean/invalidate/flush to the same FLUSH64 range operation.
The optional `rx-readonly-recycle-experiment` is a narrower ownership optimization,
not a claim that Linux omits synchronization. HAL exposes an unsafe read-only
recycle operation with a conservative full-sync default. EQoS uses it only
after descriptor completion on previously fully prepared RX slots. Pool copy
reads payloads without exporting aliases; reset always prepares all bytes again.
The JH7110 opt-in path validates the whole span and retains a full ordering
barrier, while every later payload read retains post-DMA invalidation.

The clean-line assumption requires hardware qualification: no CPU writer or
writable alias can exist, including other harts, and clean cached lines must
not write stale data over subsequent DMA writes. The feature is disabled by
default. Host models cover initial/reset preparation, successful/error/small
output recycle ordering before OWN, conservative fallback, address admission
and retained post-DMA invalidation. Performance/correctness on hardware remain
separate evidence gates.

The RAM-booted recycle experiment FIT SHA-256 is
`5076727256a9793e8d262817cb90cdcd1ff4376d114efacc268e87d4849d39ed`.
One 60-second TCP run per direction measured 541.05 / 628.73 Mbps
(host-to-board / board-to-host), versus 508.78 / 631.44 for the preceding
no-executor-profile image. This suggests an RX benefit, but needs repeated A/B
and patterned-payload DMA integrity testing before default enablement. The
15-packet diagnostic produced nine valid ICMP replies with good outer IPv4,
quoted IPv4 and ICMP checksums; six invalid checksum probes were rejected.
Verification counters gained six hardware, three software and six rejected
frames. Kernel selftest passed 395 checks with zero failures. Evidence is in
`target/mars-acceptance/20260913-gigabit/rx-recycle-*`.

### Load-loss localization (2026-09-14)

A bounded ICMP capture concurrent with TCP saw all 8192 requests leave the
host, all checksums good, and only 8185 replies. The seven absent replies
exactly match probe timeouts; received replies took at most 14.22 ms. tcpdump
reported zero capture drops. This excludes missing host socket submissions or
late replies at this capture point, but does not locate the loss beyond it.
Evidence: `20260914-load-capture/icmp.pcap`, `20260914-load-analysis.json`.

Read-only diagnostics now sample DMA channel-0 status (0x1160), MTL queue-0
interrupt control/status (0xd2c) and RX debug (0xd38). Per upstream Linux
`dwmac4_dma.h`, DMA status bit 7 is RX buffer unavailable, bit 8 RX stopped,
bit 9 RX watchdog, bit 12 fatal bus error. Per `dwmac4.h`, MTL bit 16
records RX overflow, and RX debug bits 5:4 show FIFO state. These snapshots
never acknowledge W1C events or read missed-packet counters, and are not
counts. Absence of a sampled event is not proof of zero packet loss.

Sources inspected:
- https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_dma.h
- https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4.h

The diagnostics FIT `1839bd7ad4ec19a6b12232505d83b61fb1f99f9f7f4a571ffd6f5baaa82c4b6c` booted and exposed
DMA `0xc04`, MTL IRQ `0` before load. After a 20-second TCP pair with
8192 patterned probes, DMA changed to `0xc84` and MTL IRQ to `0x10000`: RX
buffer unavailable and RX overflow events occurred. Capture saw all 8192
requests and 8184 valid replies, matching the eight probe timeouts; maximum
received-reply RTT was 20.15 ms, with no late-over-2-second response or bad
checksum. This establishes hardware receive starvation/overflow under load,
not a count of packets lost to each cause. The next controlled experiment is
a larger descriptor ring (currently 32) with the same cache/checksum profile.
Mixed-load TCP measured 536.15 / 593.48 Mbps; this is diagnostic workload
evidence and should not replace the uncaptured throughput baseline.
