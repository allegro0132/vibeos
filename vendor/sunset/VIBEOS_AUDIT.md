# VibeOS Sunset provenance and security profile

This directory started from the exact contents of the `sunset` 0.6.0 crate
published on crates.io, except for the generated `.cargo_vcs_info.json` file.

- Upstream repository: <https://github.com/mkj/sunset>
- Upstream release: `0.6.0`
- Upstream commit recorded by the crate: `cb7fbe2c7ba0258a2e9c853668495cc6fc93d502`
- Published `.crate` SHA-256: `3b52312b804ac95f10d3963f6ef5889117ad678bd6ce977be4aa4cf491bad78f`
- License: 0BSD (retained in `LICENSE`)

VibeOS vendors the source because its capability and entropy model cannot be
expressed by the upstream server API. The local delta intentionally makes the
following security properties part of Sunset's protocol state machine:

1. Every connection exclusively borrows a caller-provided, fallible random
   source. There is no ambient operating-system RNG or global RNG fallback.
2. X25519 key generation consumes exactly 32 random bytes, detects an adapter
   that asks for more, and zeroizes temporary key material.
3. The Ed25519 host private key stays behind an external signer interface. The
   signer receives only the exact 32-byte exchange hash, and Sunset verifies the
   returned signature before serializing it.
4. The server's first key exchange requires the OpenSSH strict-KEX client marker
   and advertises only curve25519-sha256, ssh-ed25519,
   chacha20-poly1305@openssh.com, hmac-sha2-256, and no compression.
5. Server authentication is public-key-only, accepts only exact Ed25519 wire
   encodings, locks the username on the first attempt, and enforces a bounded
   attempt count. Password and unauthenticated success paths fail closed.
6. A connection accepts one session channel, at most one validated PTY request
   before at most one shell or `exec` start, and never reuses a rejected start
   slot. Subsystem, environment, forwarding, and later session requests remain
   rejected. Window and signal notifications are surfaced only after their PTY
   or command has been accepted; BREAK additionally requires an explicit
   application response. The N4 VibeOS service still rejects shell and PTY.
7. Command completion is ordered as channel data, exit status, EOF, and close.
   The completion packets are retry-safe under bounded output backpressure.
8. Peer disconnect is terminal and consumes the input packet once.

The default feature set is empty. VibeOS builds the library with
`default-features = false` and enables only `alloc` when owned packet buffers are
needed. Optional upstream algorithms remain source-compatible but are never
advertised by the strict VibeOS server profile.

Before updating this vendor copy, verify the new crate checksum and upstream
commit, re-audit every local delta above, and run both the Sunset unit suite and
the repository's forced-algorithm OpenSSH end-to-end test.
