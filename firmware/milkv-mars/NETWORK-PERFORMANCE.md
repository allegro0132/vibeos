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

The approximately 900 Mbps target remains open. Network diagnostic timing is
still enabled in these experimental payloads. Three cold boots, link recovery,
and one hour of concurrent network/storage/WASM testing remain separate
acceptance requirements. TRNG protocol probing does not qualify entropy and
these images do not enable SSH.
