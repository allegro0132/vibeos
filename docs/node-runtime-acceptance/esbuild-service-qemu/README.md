# Official esbuild WASI binary transform service

The locked, unmodified esbuild 0.25.0 WASI Preview 1 module passes its upstream
`--service=0.25.0` binary protocol on VibeOS/QEMU. The host sends protocol data
only; transformation and source-map generation run in the guest WASI service.

The test verifies:

- TS transform response and source map containing original source and mappings.
- TSX transform with custom `h` JSX factory and its source map.
- A syntax error returned as a structured diagnostic with source line 1.
- The expected version handshake and exactly one response for request ID zero.
- All three invocations reclaimed, with zero capabilities and waiters.

Measured invocation times are 13.903, 13.881 and 14.198 seconds. Exact owner
peak memory and fuel are recorded per case in `results.json`. Private SSH
fixture keys, disks and kernel binaries are excluded from this evidence.

```
python3 scripts/test-esbuild-qemu.py --service-only --work target/esbuild-service-qemu
python3 scripts/test-native-esbuild-protocol.py
```

The new Rust admission validator accepts only one bounded transform request,
with in-memory input and no file input. Host tests reject other service commands,
wrong packet directions/IDs, truncation, extra packets, duplicate fields,
collection overflow and oversized packets. The validator is now connected to the [native C ABI bridge](../native-esbuild-bridge/README.md);
the Node JavaScript binding is still pending. Neither this service test
nor the host parser tests establishes tsx execution or closes M3.
