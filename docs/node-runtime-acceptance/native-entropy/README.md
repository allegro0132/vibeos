# Capability-granted native entropy bridge

Four-hart QEMU passed using the recorded kernel/source hashes and modern
virtio-rng transport. An ungranted native context receives failure without
buffer modification. The boot policy grants READ on the existing entropy
source into a dedicated probe CSpace; the admitted native context parks while
the supervised device service retrieves exactly 32 bytes and then returns
normally. The test checks the result is not entirely zero; this is not a
statistical or cryptographic quality claim about the trusted host RNG.

Each operation acquires a fresh capability lease. The service sees only its
own bounded value buffers, never the native destination. Delivery rechecks
authority before copying any bytes. Revocation during I/O, invalid pointers,
length boundaries and device fault injection are not yet qualified.

The first attempt omitted modern virtio mode and never received an entropy
grant; it cannot count as a success. Its original log remains under
`target/native-entropy-qemu-1/`. No timer or deterministic fallback was used.
This qualifies the bridge's protected-native-stack path, not real V8 or Node.
