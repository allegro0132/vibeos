# BPI-R4PRO-4E reusable platform support

VibeOS owns the AArch64 EL1 runtime, architecture adapters in `core`, the BPI
board memory/device definitions, MT7988 NETSYS/PDMA/QDMA/PPE and MxL switch
drivers, and the MSDC storage driver. These are libraries: importing this port
does not enable NAT, assign WAN/LAN roles, configure VLAN policy or install PPE
flows in another kernel image.

The network protocol library supplies bounded ARP/IPv4/ICMP, neighbor handling,
NAT/TCP receipts, transactional interface configuration and DHCP lease authority.
It accepts explicit configuration; a product supervisor owns routing policy.
The pinned smoltcp DHCP fixes and optional AArch64 crypto support remain shared.

The complete BPI router image, boot integration, PHY setup, hardware-flow owner,
WAN/LAN policy, proxy services and qualification tools are maintained in
[VibeWrt](https://github.com/allegro0132/vibewrt). That repository pins VibeOS as
a submodule rather than copying platform code. Use its build entry to generate
the board image; this workspace deliberately has no BPI router firmware member.

Migration source: `port/bpi-4-pro` at `03fe962`. The original branch retains the
complete pre-split history. VibeWrt's `docs/MIGRATION_INVENTORY.json` maps every
changed source path to its destination; historical hardware evidence lives there.

Host validation:

```sh
git submodule update --init --recursive
cargo test -p vibeos-net-protocol -p vibeos-driver-mtk-netsys \
  -p vibeos-driver-mtk-msdc -p vibeos-runtime-aarch64 -p vibeos-bsp-bpi-r4pro-4e
cargo test -p vibeos-driver-mtk-netsys --features qdma-test
```
