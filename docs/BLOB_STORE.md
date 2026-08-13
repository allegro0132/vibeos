# Minimal BlobFS / Merkle storage

VibeOS stores immutable blobs as canonical, self-verifying objects on top of the
capability-addressed durable journal. This first BlobFS profile deliberately has
no paths, directories, mutable files, or ambient object-ID lookup. Possession of
a `StoredObject` capability is the only way to read a committed blob.

## Canonical object format

`blob-format/` is an independent `no_std` crate. Its v1 encoding is:

```text
128-byte VIBEBLB header | exact content bytes | bottom-up SHA-256 tree
```

Leaves cover fixed 4096-byte logical chunks; the final leaf binds its exact
length. The leaf set is padded to a power of two with domain-separated empty
hashes, and every tree node is serialized bottom-up. Domain separation binds
the object kind, leaf index, chunk length, tree level, total byte length, leaf
size, and leaf count. The header contains the resulting bound root and exact
offsets/counts. Decoding rejects unknown versions or hash algorithms, non-zero
reserved bytes, truncation, suffixes, inconsistent geometry, and root changes.

The public format operations are:

```text
encode_blob(kind, bytes)       -> canonical bytes
BlobView::verify_all()         -> verified whole content
BlobView::proof(index)         -> sibling path
verify_proof(desc, chunk, path)-> independently authenticated 4 KiB chunk
```

## Durable capability profile

`services/object-store` wraps the canonical bytes in its existing atomic object
transaction. `put_blob_with` validates the journal size limit before allocating,
commits and flushes the complete envelope, rereads the exact committed bytes,
and only then publishes a `StoredObject` capability. `get_blob_with` requires
`READ` on both the store and object capabilities and returns content only after
checking the complete tree. `get_blob_chunk_with` returns one verified logical
chunk plus its proof. The v1 journal still scans the enclosing object in full;
the chunk API is shaped so a future extent backend can avoid that I/O without
changing proof semantics.

The journal commit remains the publication boundary. Recovery exposes no blob
for any prefix before the sealed object commit. Once the commit is present,
recovery first validates the durable record/CRC chain and then the BlobFS layer
validates the canonical envelope and Merkle root.

## Acceptance

Portable tests cover SHA-256 vectors, empty and multi-leaf blobs, every content
prefix, every serialized tree-node mutation, proof binding, outer/inner kind
mismatch, size preflight, and every durable transaction boundary.

The `blob` QEMU case writes a deterministic 4203-byte two-leaf blob through the
real store capability, reads and verifies it from the block device, and verifies
the 107-byte tail with a one-sibling proof. After shutdown,
`scripts/blob-image.py` independently parses the raw journal and reconstructs
the canonical SHA-256 tree; the guest transcript alone is not accepted as disk
evidence.

Run the focused gate with:

```sh
cargo test -p vibeos-blob-format -p vibeos-object-store
./scripts/qemu-test.sh blob
```
