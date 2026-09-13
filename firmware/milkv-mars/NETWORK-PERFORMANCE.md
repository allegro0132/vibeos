# Mars network performance experiments

The 2026-09-13 experiments use a 4 GiB Mars, SPI firmware loading a FIT into
RAM, and a direct Mac Ethernet test network. The PHY reports 1000 Mbps full
duplex. All results below are single TCP streams with MTU 1500 / MSS 1460.
They are throughput measurements, not complete Mars hardware qualification.

## Changes

- A bounded cooperative polling grace follows actual progress in the device,
  protocol and stream service loops. Each empty poll yields to the executor;
  grace expires after 1 ms or 64 attempts. Idle services retain their sleep.
- JH7110 cache maintenance batches isolated cache-line flushes between full
  barriers. CPU reclaim of read-only TX payloads validates the DMA region and
  orders completion without flushing unchanged payload data. RX and descriptor
  ownership still require cache synchronization.
- The Mars Ethernet service composition enables 256 KiB TCP buffers instead of
  the default 32 KiB. Its netstack memory quota is 8 MiB; this is an upper bound,
  not a reservation. The allocator rounds charged sizes including metadata,
  so a 2 MiB quota was experimentally insufficient. Other compositions retain
  their default TCP window and memory quota.
- Packet processing and stream frontends are compiled for speed. Capability
  checks, bounded work, and DMA ownership checks remain enabled.

The cache changes follow the ownership rules used by
[RISC-V DMA synchronization](https://raw.githubusercontent.com/torvalds/linux/master/arch/riscv/mm/dma-noncoherent.c)
and the batched maintenance sequence in
[SiFive ccache](https://raw.githubusercontent.com/torvalds/linux/master/drivers/cache/sifive_ccache.c).

## Reproduction and evidence

Build a fresh output directory:

```sh
sh scripts/build-mars-sd.sh --ethernet --trng-probe --work-dir target/mars-network-candidate
```

After booting and observing the runtime DHCP address, run:

```sh
python3 scripts/mars-network-bench.py --address "$MARS_IP" \
  --output target/mars-network-measurement --seconds 60 --rounds 3
```

Use the address assigned to VibeOS, which can differ from U-Boot's address.
The script records raw iperf3 JSON and fails incomplete tests. Report throughput
from the receiver. Retransmit fields are peer-reported and may be absent or
unsupported; they are not independent evidence that no packets were lost.

The pre-optimization SD baseline measured about 93 Mbps in each direction.
The large-window candidate measured 263.66 Mbps host-to-board and 258.98 Mbps
board-to-host over separate 60-second tests. Its netstack used 2,105,216 bytes
with no quota denials. Raw results, FIT/source provenance and incremental
experiments are retained under `target/mars-acceptance/20260913-gigabit/`;
the generated image manifests record component versions and hashes.

The subsequent frontend speed-optimization candidate measured 275.20 Mbps
host-to-board and 273.14 Mbps board-to-host over separate 60-second tests
(`frontend-sustained/`). Its FIT SHA-256 is
`caa89d4c6f4751432d05d49d3b0eb3d6931ee328c9733e09dc225a1085215c11`.
After the tests, every component remained running, executor fault count was
zero, and netstack memory remained 2,105,216 bytes with zero quota denials.
This candidate was tested from RAM; the installed SD boot payload was unchanged.

Removing the frontend's 32 KiB temporary buffer and using smoltcp's synchronous
buffer callbacks measured 303.10 Mbps host-to-board and 297.80 Mbps board-to-host
over separate 60-second tests (`direct-sustained/`). Per-call/chunk limits and
authority revalidation remain enforced. The frontend commits only bytes accepted
by the destination queue; borrowed transport slices never escape the call.
The candidate FIT SHA-256 is
`ba3dc05921198cb60a715c16c0b03c718d4e457b84d04387dd65565b25efea02`.
Host tests transfer 600,007 patterned bytes in each direction through small,
odd-sized frontend queues, check wrap/backpressure and revoke network authority.
Both default and large TCP window configurations pass, as do the QEMU and Duo
DHCP/iperf3 composition build checks. The post-benchmark component fault and
quota-denial counts remain zero.

## Execution timing and two-core experiment

The optional core/kernel `executor-profile` feature adds cumulative task-poll
and executor-turn elapsed ticks to `ps`. A host-clock test checks that time
outside executor turns is excluded. Counters include interrupts and are
approximate snapshots, not hardware CPU-cycle attribution. With unchanged
task identities, differences between snapshots showed the single-core driver
using 40–45% of elapsed time, TCP stack 40–41%, iperf service 6–8%, and the
executor residual about 3% (`exec-profile-analysis.json`).

The experimental kernel `network-pipeline` feature constructs the initial
TCP-stack arena on admitted logical hart 1, retaining the driver and stream
service on logical hart 0. A SYSTEM bootstrap publishes the component before
boot installs its supervisor; no existing reclaimable arena moves between
harts. Single-hart machines fall back to the original placement. The automatic
supervisor stays on hart 1 so fault recovery constructs fresh arenas there.
Manual shell restarts still use the caller's hart and need affinity handling
before this placement is considered complete.

The Mars Ethernet experimental composition currently enables both features.
The first two-core measurements were 450.47 Mbps host-to-board and 500.77 Mbps
board-to-host over separate 15-second tests (`pipeline-forward.json` and
`pipeline-reverse.json`). The FIT SHA-256 is
`d94dafd4460e29e994e0585d60507439ea638000083b485a3721740288d5257b`.
Task timing now shows the TCP-stack hart at approximately 85–87% elapsed
occupancy. This includes possible lock waits; measuring control/queue waiting
separately is needed before attributing all of that time to protocol computation.
Separate 60-second tests then measured 455.68 Mbps host-to-board and 504.82 Mbps
board-to-host (`pipeline-sustained/`). The post-test snapshot showed all service
components running, zero faults/cancellations, and one expected exit from the
completed SYSTEM initialization task. QEMU and Duo default DHCP/iperf3 builds
still pass; their placement feature remains disabled.

## Control-lock scope experiment

Releasing the control lock after every TX and RX packet measured 493.43 /
366.47 Mbps over 15 seconds, a substantial reverse regression. That TX change
was rejected. Keeping the original TX batch and releasing only between RX
frames measured 491.36 / 529.77 Mbps over 15 seconds, then 494.07 / 530.15 Mbps
over separate 60-second tests (`rx-lock-sustained/`). The remaining RX change
keeps descriptor consumption, session stamping, endpoint publication and rearm
inside one critical section. The per-turn packet limit is unchanged.

The retained candidate FIT SHA-256 is
`8320371ffc2506f8f152e1a998f30ec6105a03ed1556d10344de987df01050ed`.
The rejected candidate, source patch and timing analysis remain archived under
`packet-lock-*`; it must not replace the retained image.

A separate reverse run captured only test-peer TCP port 5201 headers, with
128-byte snapshots and a ten-second capture limit. tcpdump reported zero kernel
capture drops. Wireshark 4.4.5 analyzed approximately 8.6 seconds of the data
connection (486,003 packets) without retransmission, zero-window or window-full
flags. The host advertised a median receive window of 2,571,904 bytes.
These are capture-interval heuristics, not whole-run loss qualification. ACK
timing at this receiver-side capture point is not the board's full software RTT.
See `rx-lock-tcp-analysis.json` and `rx-lock-capture.log` for the raw analysis.

The approximately 900 Mbps target remains open. Network diagnostic timing is
still enabled in these experimental payloads. Three cold boots, link recovery,
and one hour of concurrent network/storage/WASM testing remain separate
acceptance requirements. TRNG protocol probing does not qualify entropy and
these images do not enable SSH.
