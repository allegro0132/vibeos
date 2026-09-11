# Milk-V Mars bring-up firmware

This package builds a serial/SD payload. Run `sh scripts/build-mars-sd.sh` for
the paired SPL/OpenSBI/U-Boot test SD image, or `scripts/build-milkv-mars.sh`
for the payload alone. Payload outputs are in
`target/milkv-mars/bringup`; `manifest.json` reports the exact source state,
layout, hashes and missing qualification.

The paired SPL/OpenSBI/U-Boot chain must initialize DDR and supported
clock parents, then enter S-mode at `0x40200000` with `satp=0`, `a0` containing
an application physical hart ID (1..4) and `a1` the readable Mars DTB physical
address. Other application harts must be held by SBI HSM until the kernel starts
them. PMP permissions must permit the admitted RAM and UART/PLIC/SD platform
resources. A generic U-Boot `go` command's argc/argv convention is not this
handoff. The packer supplies a FIT with `os = "linux"` to select that bootm
calling convention; the payload itself remains VibeOS.

The payload validates DTB CPU/resources/memory and requires HSM, IPI, RFENCE and
TIME extension probes before publishing the runtime description. The linker
heap envelope ends at `0x140000000`; allocation excludes the firmware area,
loaded/static kernel span, DTB and declared reservations. The existing shared
address space and capability policy remain intact.

The SD device exposes only 1048576 logical sectors translated to physical LBA
262144 (512 MiB data beginning at 128 MiB). Use only the matching test SD layout;
the bring-up firmware does not discover arbitrary GPT/MBR partition layouts.
The packer places all boot components and the FAT partition below the data
boundary. The kernel has no exported raw-card diagnostic entry.

The default payload has no NIC. Add `--ethernet` to either build script for
the EQoS test composition (DHCP and TCP 5201 iperf3); its SD artifacts are kept
separately in `target/mars-boot-ethernet/out`. Neither profile enables SSH.
The TRNG protocol and ordered MMIO lane are available as a separate driver,
but firmware entropy-service composition and physical qualification remain
pending. Compiling or passing the ELF checker does not satisfy Mars physical
acceptance.

For an explicit hardware diagnostic payload, run
`sh scripts/build-milkv-mars.sh --trng-probe` (optionally with `--ethernet`).
It writes to a separate `bringup-trng-probe` or `ethernet-trng-probe` payload
directory. Before secondary harts/services, it admits the TRNG DTB resource,
suppresses its PLIC priority, reads the parent clock, prepares the shared SEC
domain, reads two conditioned blocks and confirms stop. Failure logs the stage
and halts; success says `protocol-observed` and `entropy=unqualified`.
No random capability or SSH is enabled. This is currently a payload build;
`build-mars-sd.sh` does not yet accept the diagnostic option.

The probe requires the paired boot firmware to have relinquished all SEC
clients, including crypto/security DMA, and stable shared clocks through stop.
Do not chain it from firmware that leaves a live security operation behind.
No physical TRNG result has been recorded yet. Reading two blocks checks the
control path only and cannot qualify the source for cryptographic use.

See [bootchain instructions](bootchain/README.md) for layout, build tools,
hardware revision requirements and evidence limitations.
