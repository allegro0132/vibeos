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


### Board SFP and status-lamp APIs

The BPI-R4PRO-4E BSP exposes `sfp` and `status_leds` on bare-metal AArch64.
The BSP owns the shared GPIO I2C2 bus and PCA9545 mux, SFP signal wiring,
GDM2/ETH7 media selection, XFI1 10GBASE-R setup and PCA9555 lamp writes.
SFF-8472 EEPROM parsing is portable in `vibeos_ethernet::sfp`, reexported as
`vibeos_bsp_bpi_r4pro_4e::sfp_identity`.

The caller must provide the board Device mappings and serialize configuration
on its control-plane owner. Call `sfp::init()` before discovery, apply the
selected cage enables with `configure`, and complete `direct_mode()` after
GDM2 clock/MAC initialization. Call a single `sfp::Poller::poll()` every 500 ms;
it handles module settling, identification and TX gating without spawning a
task. `signals`, `read_identity` and `link(Cage)` expose diagnostics without
product strings. SFP1 additionally requires the switch's MAC link state.
`configure` and `direct_mode` return readback failures, keeping GDM2 closed.

`status_leds::show(red, blue)` selects electrical states;
`status_leds::state()` reports readiness and failures. Routing-health semantics,
CLI formatting, network roles, VLAN assignments and scheduling stay in the
consumer. There is no VibeWrt dependency in this BSP.

Host checks: `cargo test -p vibeos-ethernet -p vibeos-bsp-bpi-r4pro-4e
-p vibeos-driver-mtk-netsys`. Physical optical-link qualification is still pending.
