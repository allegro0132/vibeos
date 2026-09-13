# Mars test SD images

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

For the Ethernet test profile, run `sh scripts/build-mars-sd.sh --ethernet`.
It shares the pinned, clean SDK checkout but builds into a separate directory:
`target/mars-boot-ethernet/out/mars-ethernet-sd.img`. Its own manifest, checks,
hashes and component versions are alongside that image. The container mounts
the SDK read-only. Neither profile overwrites an existing output image.

The Ethernet profile composes EQoS/YT8531 with DHCP and the TCP 5201 iperf3
service. SSH remains disabled and physical operation is unverified. Its current
test MAC is `02:00:00:00:00:01`; run one such test board per network. Obtain the
board's actual DHCP address from its serial log or the router lease table before
running `iperf3 --client ACTUAL_MARS_IP --port 5201 --time 60`. Do not use an old
Duo address. Preserve output and logs; successful throughput alone would not
prove persistence, reboot recovery or multicore DMA consistency.

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

The image assembler also reproduces the pinned SDK Makefile's `spl_tool -i`
postprocessing: little-endian `0x200000` at byte `0x04` and `0x5a5a5a5a` at
byte `0x290`. The vendor describes this as a ROM fallback to the backup SPL
address when reading sector zero. These fields do not change GPT CRCs; a GPT
check alone cannot detect their omission. The image checker requires both.
Images generated before this fix omitted them. Whether that omission explains
the observed `dwmci_s: Response Timeout` still requires a board retest.

For the installed Mars SPI U-Boot 2021.10 (2023-07-22), select GPIO1=0,
GPIO0=0. Its default `bootcmd` reads `vf2_uEnv.txt` from `mmc 1:3`, imports
text variables and executes `boot2`. Packaging includes this file next to
`vibeos.itb`; it loads the FIT at `0x46000000` and invokes `bootm`. The
`VIBEOS_AUTOBOOT sd=1:3` marker identifies this path. This requires no
`saveenv` or SPI update. Keep the paired SD boot firmware for direct-SD
investigation; SPI boot instead runs the board's installed SPL/OpenSBI/U-Boot.
On 2026-09-13 this SPI path was verified on hardware by issuing U-Boot `reset`
and observing a new SPL/OpenSBI/U-Boot boot followed by automatic VibeOS entry.
This was a software-reset test, not another verified cold power cycle.

Existing cards need only `vf2_uEnv.txt` and the desired `vibeos.itb` copied to
the root of partition 3. The boot2 command guards `bootm` with successful FIT
loading; image integrity is checked by U-Boot. A missing or invalid FIT leaves
vendor fallback behavior in control. No boot file is written into the VibeOS
data partition, and this configuration does not enable SSH.

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
the boot region still require board tests. Ethernet needs physical validation;
SSH and qualified entropy remain unimplemented in these test profiles.

Host validation checks both GPT copies and CRCs, exact partition geometry,
embedded bytes and a blank data area. Independent `sgdisk` and FAT checks run
inside the build container. Bootchain validation checks SPL header/CRC, paired
payload placement, actual SBI extension symbols, U-Boot options, FIT addresses
and extracted payload hashes. Mutation tests corrupt each important boundary.
These do not execute Mars ROM, DDR, MMIO, cache operations or firmware handoff.

## Passive serial evidence capture

For the TRNG control-path diagnostic plus Ethernet, build with:

```sh
sh scripts/build-mars-sd.sh --ethernet --trng-probe
```

The image is
`target/mars-boot-ethernet-trng-probe/out/mars-ethernet-trng-probe-sd.img`,
with `manifest.json` and `SHA256SUMS` alongside it. It retains the same 641 MiB
GPT layout and data-only block capability. Existing images are not overwritten;
the command refuses an existing output image before fetching or building.
Omit `--ethernet` for the separate serial diagnostic profile.

The first generated combined diagnostic image has SHA-256
`5f9545cc84b34ee583f8194ff06e0fa999c7d0fa1494c9bbd82d575423f591ba`.
This is a test image with DHCP/iperf3 and no SSH. Review the SEC handoff
prerequisite in the [firmware instructions](../README.md). The probe runs before
normal boot reporting; expect either `MARS_TRNG_PROBE protocol-observed` with
`blocks=2 stopped=true entropy=unqualified`, or a failure message followed by
shutdown. Neither message establishes entropy quality. No physical boot of
this image has been observed yet; capture its complete serial log.

When capturing this diagnostic image, add `--require-trng-probe` to the
collector below. It requires exactly one ordered diagnostic line with two
blocks, confirmed stop and an unqualified-entropy label. Missing, malformed,
duplicate or failed diagnostics cannot pass. This remains an observation of
the serial log; it does not qualify entropy or prove a physical cold boot.

Use a separate terminal for each planned cold boot, with the actual port and
operator-checked board revision supplied explicitly:

```sh
python3 scripts/mars-serial-accept.py \
  --port ACTUAL_SERIAL_PORT --board-revision ACTUAL_BOARD_REVISION \
  --output target/mars-acceptance/boot-1 --seconds 120
```

Close other serial clients first. Start this command before powering the board.
Wait for `target/mars-acceptance/boot-1/ready.json` to appear while the command is
still running, then perform the cold boot. The script opens the port read-only,
configures 115200 8N1, discards preexisting input, and sends no commands or reset
signals intentionally. USB serial hardware may change modem lines on open;
connect only RX/TX/GND and perform the physical power cycle yourself.

The script captures the complete requested interval and restores TTY settings.
It saves raw `serial.log`, its SHA-256 and `summary.json`; it refuses any existing
output directory. Repeat with new `boot-2` and `boot-3` directories. Exit 0 means
exactly one ordered set of Mars entry, page-table, Sv39, platform, four-hart
admission, four-core online and `0xf` MMU-mask lines was observed, without a
failure diagnostic during that interval. An interrupted capture, byte limit,
disconnect, partial boot or repeated boot cannot pass.

This cannot verify that a power cycle actually occurred or that the connected
endpoint is physical Mars hardware. `physical_acceptance` and
`cold_boot_verified` remain false. Record the physical power-cycle procedure,
selected SD image hash and board revision separately; review the full boot chain
and complete the storage, network, entropy, SSH/WASM and stability gates before
claiming the full plan passed. The same output cannot be counted three times.

The source reference is the [fixed official SDK](https://github.com/milkv-mars/mars-buildroot-sdk/tree/1fd6bac9f2efde47fbb8afd28d2903c49f893e3f).
U-Boot and the SPL tool retain their upstream GPL licensing; OpenSBI retains its
upstream BSD licensing. Exact sources and configuration changes are available
through the pinned checkout and this directory's build scripts.

## SSH command evidence for a provisioned Mars image

`scripts/mars-ssh-accept.py` is a host-side collector for a future qualified,
provisioned SSH image. The current stage-60 diagnostic SD image has SSH disabled
and cannot pass this check. First finish physical entropy qualification and
configure a separate board identity and authorized client key. Obtain the host
public key over an independently verified channel and place its one Ed25519
entry in a dedicated OpenSSH known-hosts file. The collector never accepts an
unknown host key, enables password login, authorizes clients or reboots a board.

Use explicit connection parameters and the compiled `tests/wasi/hello.c` and
trap fixtures. The upload phase writes the `mars-accept-*.wasm` test programs to
the VibeOS data service, replacing those test names if present:

```sh
python3 scripts/mars-ssh-accept.py \
  --host ACTUAL_MARS_HOST --port ACTUAL_SSH_PORT --user ACTUAL_SSH_USER \
  --identity PATH_TO_CLIENT_PRIVATE_KEY --known-hosts PATH_TO_VERIFIED_HOST_PIN \
  --phase upload --output target/mars-acceptance/ssh-before-reboot \
  --command-module target/wasi-examples/c-hello.wasm \
  --trap-module target/wasi-fixtures/trap.wasm
```

After recording an operator-controlled cold boot, run the same command with
`--phase verify --baseline target/mars-acceptance/ssh-before-reboot/summary.json`
and a new output directory, such as `target/mars-acceptance/ssh-after-reboot`.
Verify never uploads or authorizes anything. It requires a successful upload
baseline with identical fixture hashes, user and host public key. The explicitly
supplied host/port may change after DHCP; its verified host pin must still match
the baseline identity. Retain both directories and the separate serial capture.

Both phases check binary stdin (including NUL bytes), EOF, Unicode and spaced
arguments, exact stdout/stderr, exit status 7 and trap status 125. For a native
thread-enabled image, add both `--thread-fixtures target/wasi-fixtures` and
`--pthread-module target/wasi-examples/c-threads.wasm` in both phases. This adds
the ten existing thread/atomic fixtures and three pthread scenarios. Each
connection is attempted once; a failed command is never replayed. Timeout and
failure summaries retain captured output. Existing evidence directories are
refused. Private credentials are referenced only by path and never copied.

The summary records the endpoint, fixture hashes, public host key, baseline hash,
per-command input/output hashes, durations and exit statuses. Passing verifies
SSH-observed command behavior. It does not read back persisted module bytes,
prove the physical power cycle, identify physical hardware, measure entropy,
prove native execution or multi-hart placement, or replace the one-hour mixed
workload test. Those require the corresponding board/serial evidence. All such
physical qualification fields remain false. Native fault-injection selftests
must finish before starting these command checks.

For software regression of the collector itself, `scripts/test-mars-ssh-qemu.py`
accepts the QEMU composition harness arguments and runs both phases on its
throwaway VM, preserving identities and programs across two boots. QEMU output
must not be submitted as Mars physical qualification.
