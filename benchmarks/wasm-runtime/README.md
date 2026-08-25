# C8.3 runtime-cost evidence

`workloads-v1.json` and `schema-v1.json` are the immutable preparation contract
for the first C8.3 collection. Their exact byte hashes are independently pinned
by the producer and verifier.

No performance baseline is present merely because these files exist. A complete
publication adds verified fixed-QEMU and three-cold-boot Milk-V Duo raw logs,
summaries, envelopes, and a derived `RESULTS.md`, all bound to one clean
preparation commit. See [the collection procedure](../../docs/WASM_RUNTIME_COSTS.md).
