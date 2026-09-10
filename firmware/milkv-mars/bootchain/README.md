# Mars serial/SD test image

From the repository root, run `sh scripts/build-mars-sd.sh`. It requires Docker,
the project's Rust nightly, LLVM objcopy, Git and Python 3 on the host. The
container pins Ubuntu 22.04 by image digest; its exact installed package versions
are recorded in `target/mars-boot/out/artifacts/tool-versions.txt`. The SDK is
pinned to `1fd6bac9f2efde47fbb8afd28d2903c49f893e3f`. Build scripts carry the
U-Boot configuration changes; no vendor source edits or SPI updates are needed.
The scripts download sources and build in `target/mars-boot`; they never write
a physical disk. Move a previous output image before rebuilding.

Output: `target/mars-boot/out/mars-serial-sd.img`, 641 MiB. The same directory
contains `SHA256SUMS`, `manifest.json`, `sd-check.json`, `bootchain-check.json`
and component artifacts/configurations. The manifest records separate payload
and bootchain source states, component hashes, compiler versions and missing
qualification. This is an experimental serial/SD image; EQoS, SSH and qualified
entropy are not enabled. A valid disk image is not evidence of successful boot.

| GPT partition | Offset | Size | Contents |
|---|---:|---:|---|
| 1: SPL | 2 MiB | 2 MiB | SDK DDR/SPL with StarFive header and CRC |
| 2: U-Boot | 4 MiB | 4 MiB | FIT containing OpenSBI 1.2 + U-Boot 2021.10 |
| 3: boot | 8 MiB | 120 MiB | FAT32, `vibeos.itb` with VibeOS and Mars DTB |
| 4: VibeOS data | 128 MiB | 512 MiB | Blank, initialized by VibeOS storage |

The GPT backup resides at the end of the 641 MiB image. Do not format or grow
partition 4 as ext4: it holds the existing VibeOS persistence format. The
firmware only exposes partition 4's fixed physical range as logical LBA 0.
An SD writer must write the whole image, including partitions 1 and 2; copying
the FIT into an unrelated Linux image does not install this paired boot chain.

For direct SD boot, first check the board revision. The [Milk-V setup guide](https://milkv.io/ru/docs/mars/getting-started/setup)
documents the selector on V1.2 and later: GPIO1=0, GPIO0=1 selects SD. Consult
the guide's diagram for switch orientation. Earlier boards normally use SPI;
their RAM/UART chainloading route needs separate verification. Do not silently
fall back to an old SPI bootloader or update SPI as part of this procedure.

After writing the image to the explicitly selected test SD card, power off,
select SD boot, insert the card, and capture UART0 at 115200 8N1 without flow
control. The guide lists GND pin 6, TX pin 8 and RX pin 10; do not connect the
USB-to-TTL adapter's power lead. Serial device paths are host-specific and must
be supplied explicitly. No test SD device has been selected or written by the
build scripts.

Expected chain: SDK SPL initializes DDR, loads partition 2, OpenSBI enters
U-Boot at `0x40200000`, then U-Boot loads partition 3's FIT at `0x46000000` and
uses `bootm` to enter VibeOS at `0x40200000` with `a0=hart`, `a1=DTB`. U-Boot
relocates itself before loading the VibeOS payload. Its persistent environment
is disabled and its S-mode SMP option is off; SPL SMP remains on to transfer
the harts to OpenSBI. The SDK boot DTB selects hart 1. VibeOS independently
admits any of the four application boot harts and rejects missing SBI services.

Look for `MARS_BOOT_ADMISSION PASS` with four harts and 4000000 Hz, followed by
`smp       4 hart(s) online`. Admission alone does not demonstrate four cores
running. Preserve the complete serial log, including any SD initialization or
panic diagnostics. SD persistence, timeout/reset behavior and protection of
the boot region still require board tests. Network/SSH acceptance is pending
implementation and must not be reported as passed by this image.

Host validation checks both GPT copies and CRCs, exact partition geometry,
embedded bytes and a blank data area. Independent `sgdisk` and FAT checks run
inside the build container. Bootchain validation checks SPL header/CRC, paired
payload placement, actual SBI extension symbols, U-Boot options, FIT addresses
and extracted payload hashes. Mutation tests corrupt each important boundary.
These do not execute Mars ROM, DDR, MMIO, cache operations or firmware handoff.

The source reference is the [fixed official SDK](https://github.com/milkv-mars/mars-buildroot-sdk/tree/1fd6bac9f2efde47fbb8afd28d2903c49f893e3f).
U-Boot and the SPL tool retain their upstream GPL licensing; OpenSBI retains its
upstream BSD licensing. Exact sources and configuration changes are available
through the pinned checkout and this directory's build scripts.
