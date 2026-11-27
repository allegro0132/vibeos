# Local AES-GCM backend extension

Based on the crates.io aes-gcm 0.11.0 release (RustCrypto/AEADs commit
`a10b56f281e2d3770e86aec024ea735b2dfa566b`). Original MIT/Apache-2.0 licensing
and upstream test vectors are retained.

The optional `eip197-backend` feature adds a once-installed, immutable backend.
With no backend installed, the original implementation is used. With a backend
installed, KeyInit-created ciphers dispatch both encryption and decryption to
it when constructed after backend installation and enabled at dispatch time.
The supported hardware ABI has 96-bit nonces, 128-bit tags, at most 18432
payload bytes and 16384 AAD bytes, with a combined DMA-input limit of 20480
bytes (including an input authentication tag on decrypt).
Unsupported requests and hardware errors fail without software retry.

`From<Aes>` remains an explicitly software-only constructor: it cannot recover
raw key bytes from an already-expanded block cipher. It is used by differential
self-tests. TLS and Shadowsocks use KeyInit, which is covered by integration
tests in `components/proxy/tests/eip197_path.rs`.

The adapter keeps an additional raw key copy, wiped on drop, and a temporary
payload buffer, wiped on all normal return paths. It copies output to the caller
only after a successful callback. The firmware similarly withholds DMA output
until authentication succeeds. This preserves out-of-place and in-place error
semantics even when the backend has written tentative plaintext.

`AsyncBackend` adds nonblocking context admission and owned `Operation` polling.
`start_encrypt_owned` and `start_decrypt_owned` capture the backend selection and a shared key reference,
then transfers its input Vec to the operation. Firmware stages it in permanent
DMA memory and copies the completed result back into that Vec, eliminating the
synchronous adapter's scratch-buffer round trip. Dropping an operation abandons
delivery; hardware-owned storage and context references remain valid until
completion. The default software implementation returns an immediately ready
operation. TLS 1.2/1.3 application transmit and post-handshake reception use
these APIs, as does Shadowsocks TCP record processing. Handshake/control transmit
and Shadowsocks UDP still use the synchronous compatibility interface. Pending/failed decrypts return no plaintext;
only a successful owned result transfers authenticated data to the caller.

This does not claim a hardware throughput improvement. Boundary vectors,
backend switching, cancellation, real TLS pending/wake behavior, and key-update
ordering are covered in the proxy's EIP197 integration tests.
