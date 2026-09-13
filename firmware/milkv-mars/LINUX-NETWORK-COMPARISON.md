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
