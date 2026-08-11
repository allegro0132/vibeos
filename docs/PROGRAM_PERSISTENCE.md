# Program persistence

Canonical artifact revalidation and recovered program-graph authorization live
in the independent `services/program-store` crate. Kernel-only compilation,
native execution, policy-cap attenuation, atomic CSpace publication, and
fault-recovery hooks remain in `kernel/src/program_store_platform.rs`.

M4.5 adds one deliberately fixed durable program entry: `hello`. It is the first
end-to-end proof that VibeOS can persist code and restore exactly the authority
under which that code may run.

```text
vibe> rustc save hello
  saved `hello`: 45 B source + 636 B canonical VIBEEXE
  durable artifact cap: slot 0 generation 0, rights r
  authority manifest: console=w memory=rw; Store WRITE absent
vibe> halt

# reboot with the same block image
vibe> run hello
Hello, world!
  recovered `hello`: cap slot 0 generation 0, 45 B source + 636 B VIBEEXE
  verified current compiler match; linked 1 fn -> 460 B RV64 + 14 B data
```

This is not a filesystem or a general program registry. The alias, persistent
SpaceId, slot, generation, object kind, ABI versions, and authority manifest are
all fixed by the v1 format. A second save is idempotently refused without
appending an object or grant.

## Durable object

The only persistent capability is a read-only root to one `StoredObject` in the
`saved-program` CSpace:

| Field | v1 value |
|---|---|
| Alias | `hello` |
| Space / slot / generation | `PROGRAM_SPACE_ID_RAW` / 0 / 0 |
| Root rights | `READ` |
| Source ABI | 1 |
| Executable ABI | VIBEEXE 1 |
| Runtime ABI | 1 |
| Runtime authority | console `WRITE`, memory `READ|WRITE` |

`ProgramArtifact` has a canonical 160-byte little-endian header followed by the
UTF-8 source and a canonical VIBEEXE image. The header binds both payloads with
SHA-256, fixes every ABI and authority field, and requires every reserved byte to
be zero. Decoding rejects truncation, suffixes, non-canonical fields, invalid
UTF-8, over-limit lengths, and hash mismatches.

VIBEEXE is address-independent. Its 64-byte header binds the RV64 target,
compiler/runtime ABI, code/data sizes, relocation count, imports, and CRC32C.
Relocations are ordered, non-overlapping records over canonical fixed-width
placeholders. Stable runtime imports are `PrintStr`, `PrintInt`, `PrintBool`, and
`Abort`. The linker checks all bounds and address arithmetic and changes only
declared relocation sites.

CRC32C detects torn or corrupted executable bytes; it does not authorize native
code. SHA-256 binds the artifact payloads; it is not a signature. Admission rests
on the trusted compiler check described below.

## Publication and crash boundary

One high-water record reserves two transaction IDs, the object ID, and the root
derivation ID before any of them are used. Publication then appends and flushes:

1. an optional format record;
2. the exclusive ID high-water reservation;
3. the complete object prepare/chunks/commit transaction;
4. the root grant prepare/commit transaction.

The grant commit is last. Under the documented M4 single-writer,
prefix-torn-write, ordered-flush media model, every crash prefix therefore
recovers either no saved program or the complete object and its exact root. A
partially written object is unreachable. Slot reservation is tied to the exact
executor task, allocation domain, operation token, and CSpace incarnation; an
abandoned raw-fault operation quarantines the persistent target instead of
publishing uncertain authority.

## Recovery and execution admission

Boot performs one inert journal preflight for all durable CSpaces. External root
policy is selected as a partitioned union keyed by `SpaceId`; `finish` rejects
every root outside that union. The saved-program partition must contain either
nothing or exactly one root at slot 0/generation 0 with read-only StoredObject
rights and the fixed artifact object kind. The program and M4.3 persistent-test
graphs are installed only after the complete global policy passes.

Before a recovered artifact becomes runnable, the kernel:

1. strictly decodes `ProgramArtifact` and VIBEEXE;
2. recompiles the stored source with the current trusted compiler;
3. requires the compiler's canonical VIBEEXE bytes to equal the stored bytes;
4. links that verified relocatable image into fresh code/data buffers;
5. resolves only the reconstructed console and memory capabilities.

Arbitrary native bytes with recomputed checksums are therefore not admitted.
The boot-local legacy `prog` CSpace is never consulted by this path.

Console and memory authority are reconstructed from a private supervisor policy
CSpace and attenuated to the artifact's fixed manifest. The runnable CSpace has
console `WRITE`, memory `READ|WRITE`, and the read-only artifact cap. It receives
neither Store `WRITE` nor a path/name lookup capability. Concurrent runs are
rejected; a raw task fault clears only the exact task/domain run owner.

## Evidence

`services/program-store/tests/model.rs` and `compiler/tests/image.rs` cover canonical codecs,
header/ABI/authority/hash mutations, relocation completeness, import and address
validation, and strict truncation/suffix rejection. `durable-format/tests/policy.rs`
uses two SpaceIds to prove that a local policy cannot hide an extra root.

`scripts/qemu-test.sh program_persistence` boots twice against one raw image.
Boot 1 saves and runs; boot 2 proves the save is already present and runs the
recovered object. After shutdown, `scripts/program-image.py` independently parses
the journal, ProgramArtifact, and VIBEEXE, verifies the object-before-grant order
and exact authority, and runs all 512 strict byte-prefix cuts over each fixture
record.

The proof remains limited to the M4 crash model. It does not provide rollback
resistance, authenticity against a malicious disk, multiple named programs,
program updates, or durable revocation of the reconstructed boot-resource roots.
