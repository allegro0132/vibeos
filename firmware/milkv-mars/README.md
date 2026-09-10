# Milk-V Mars bring-up firmware

This package currently builds a serial/SD payload, not a flashable SD image.
Run `scripts/build-milkv-mars.sh` from the repository root. Outputs are in
`target/milkv-mars/bringup`; `manifest.json` reports the exact source state,
layout, hashes and missing qualification.

The future paired SPL/OpenSBI/U-Boot chain must initialize DDR and supported
clock parents, then enter S-mode at `0x40200000` with `satp=0`, `a0` containing
an application physical hart ID (1..4) and `a1` the readable Mars DTB physical
address. Other application harts must be held by SBI HSM until the kernel starts
them. PMP permissions must permit the admitted RAM and UART/PLIC/SD platform
resources. A generic U-Boot `go` command's argc/argv convention is not this
handoff. No Linux Image header or ready-made FIT is bundled yet.

The payload validates DTB CPU/resources/memory and requires HSM, IPI, RFENCE and
TIME extension probes before publishing the runtime description. The linker
heap envelope ends at `0x140000000`; allocation excludes the firmware area,
loaded/static kernel span, DTB and declared reservations. The existing shared
address space and capability policy remain intact.

The SD device exposes only 1048576 logical sectors translated to physical LBA
262144 (512 MiB data beginning at 128 MiB). Use only the matching test SD layout;
the bring-up firmware does not discover arbitrary GPT/MBR partition layouts.
The forthcoming packer must place all boot components and partitions below the
data boundary. The kernel has no exported raw-card diagnostic entry.

EQoS is not composed, so no NIC capabilities or SSH service are available. No
unqualified entropy source or temporary SSH identity is enabled. Compiling or
passing the ELF checker does not satisfy Mars physical acceptance.
