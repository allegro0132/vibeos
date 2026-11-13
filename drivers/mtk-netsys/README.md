# MT7988 NETSYS driver

`ppe-capacity-test` enables the explicit maximum-geometry diagnostic API in
`ppe::capacity`: three 32,768-entry tables (128 bytes per directional record).
It does not change the default table geometry or production ownership limits.
The caller must supply permanent NC memory, exclusive engine/ingress ownership
and independent IRQ/task cutoffs; errors require reset before memory reuse.

The board integration, RAM reservation, build profile, wire-level benchmark and
physical evidence live in [VibeWrt](https://github.com/allegro0132/vibewrt/blob/main/docs/BPI_R4PRO_PPE_CAPACITY.md).
The observed nonforwarding final slot `0x7fff` and connection-vs-directional-entry
accounting are documented there. Imported from VibeOS benchmark commit `ae07cae4`.

Validation: `cargo test -p vibeos-driver-mtk-netsys --features ppe-capacity-test,qdma-test`.
