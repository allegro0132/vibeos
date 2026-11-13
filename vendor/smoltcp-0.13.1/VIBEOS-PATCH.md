# VibeOS DHCP server-selection patch

Base: crates.io smoltcp **0.13.1**, upstream commit
`e347a1e2d3ac33c5ce2c0c114e24b85ae23c4897`, as recorded in
`.cargo_vcs_info.json`. Original 0BSD license and package source are retained.
This directory is separate from the existing `vendor/smoltcp` experiment.

Only `src/socket/dhcpv4.rs` differs from the published source:

- REQUESTING and non-rebinding RENEWING ignore replies whose option 54 does
  not match the selected server identifier.
- Successful REBINDING records the responding server for future renewals.
- Unicast requests use the server identifier address, including when the
  offer's IP source differs from that identifier.

[RFC 2131 sections 4.1 and 4.4.5](https://www.rfc-editor.org/rfc/rfc2131.txt)
provide the unicast-address and renewal/rebinding context. Server-ID filtering
is transaction scoping, not cryptographic server authentication: a peer able
to spoof the selected identifier and transaction remains outside this guard.

Regression tests live in `components/net-protocol/tests/router_dhcp.rs` and
exercise full DHCP wire messages through the VibeOS control wrapper. Run:

```
cargo test -p vibeos-net-protocol
cargo test --manifest-path vendor/smoltcp-0.13.1/Cargo.toml --lib \
  --no-default-features \
  --features std,medium-ethernet,proto-ipv4,socket-dhcpv4,socket-tcp,socket-tcp-reno \
  socket::dhcpv4::test
```

Keep this patch explicit when updating the dependency; do not silently revert
to the registry version without rerunning these failure-reproducing tests.
