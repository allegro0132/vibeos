# Metadata bundle experiment

Status: host-only exploration; no runtime/wire-format change. Existing storage-v2
images and readers are unchanged. Evidence lives in
`target/storage-small-put-trace-20260913/`.

Current direction: prioritize a **checkpoint-roots-only bundle**, leaving blob
manifests separate. The all-member model below remains useful design evidence,
but its whole-container retention cost makes it unsuitable for direct runtime
adoption without member-extracting GC. See the lifetime experiment at the end.

## Measured problem

The current 4 KiB object benchmark already packs its content and metadata into
one segment. A stable put writes 26 pages: header 2, five descriptor/seal pairs
10, content 2, four metadata payloads 4, segment trailer 4, future-scratch preclear
1, checkpoint clear/body/seal 3. The latter preclear amortizes the next writer's
seal invalidation barrier; deleting it is not a valid optimization.

Four metadata members in the latest fixture contain 256 bytes of blob manifest,
896 bytes of CAS catalog, 3,776 bytes of authority snapshot and 137 bytes of
allocation map. An exploratory 64-byte header plus four 64-byte directory entries
produces a 5,385-byte bundle. A hypothetical single extent requires four pages
including its descriptor/seal instead of twelve. This suggests 18 rather than
26 written pages, with unchanged barriers. It is a size estimate, not a
publication implementation or latency result. Future pointer growth can change
these sizes.

## Constraints before integration

1. **No unversioned reinterpretation.** Existing PhysicalPointer validates the
   complete extent's payload hash, length, kind and descriptor relationship.
   Existing decoders must reject incompatible images before considering an older
   checkpoint; silently falling back would allow rollback. The initial prototype
   should format only new disposable images with an explicit incompatible format
   version. In-place upgrades require a separate crash-safe migration design.
2. **Avoid hash self-reference.** A catalog contains manifest pointers. If both
   catalog and manifest share one bundle, a conventional pointer committing to
   the entire bundle hash would make that hash depend on itself. A member
   reference must instead commit to its typed member hash/length and container
   location/generation plus a canonical selector, without embedding the future
   whole-bundle hash in that same bundle. The container's seal and selected
   checkpoint must still authenticate its framing. Encode data references,
   member identities, catalog, directory, container and checkpoint in a defined
   dependency order. Prove that order is acyclic before implementing publication.
3. **Typed resolution.** Catalog snapshot, blob manifest, authority and allocation
   have distinct roles even when two use ExtentKind::Catalog today. A role/index
   mismatch, duplicate directory entry, overlapping/out-of-bounds range,
   noncanonical padding or hash mismatch must fail closed. Do not infer the
   selected role from an untrusted payload's magic alone.
4. **Same authority semantics.** Member resolution must preserve authorization,
   generation checks, object kind/length binding, namespace and grant visibility,
   and invalidation of stale handles. Do not trust an unrelated member merely
   because another member in its container was authorized.
5. **GC works on containers.** Any referenced member keeps its container live.
   Relocation must rewrite affected physical member references and rehash parents
   in dependency order. Aliasing cannot drop live members or let obsolete member
   identities survive generation reuse. Quantify collateral retention and copying.
6. **Account actual memory and I/O.** A range read should not silently require
   retaining every metadata member. Bound directory validation, whole-container
   authentication and transient old/new buffers; measure peak and retained
   allocation at admission limits. Include read amplification and cold mount cost.
7. **Publication gate.** Acknowledgement and existing flush semantics remain
   unchanged. Require old-or-complete recovery at every page-write/flush outcome,
   ambiguous writes, cancellation, retries, both checkpoint slots, GC relocation,
   truncated/corrupt containers and malformed member references. Add independent
   offline verification before accepting benchmark gains.

## Host prototype coverage

`bundle-prototype.py` reads actual metadata bytes from the independently verified
QEMU disk. Its deliberately experimental `EXPBND00` framing round-trips all four
members and rejects twelve selected header/directory/digest/length mutations.
It is not a production codec, contains original unmodified physical pointers,
and does not solve the reference/GC/versioning constraints above. No existing
mount path accepts its output. Keep this artifact outside runtime code until
those constraints have an implemented and verified design.

## Typed member-reference model

`scripts/experimental-metadata-bundle.py` adds a standalone, standard-library
model with experimental `EXPBND01` containers and `EXPMEM00` references. Its
construction order is manifest bytes → typed member commitment → catalog with
member reference → container → externally supplied trusted root. The reference
binds store identity, segment, generation, descriptor location, member index,
role, length and a domain-separated member digest. It never embeds the enclosing
container digest. Its 96-byte width matches the existing pointer width, but its
meaning and tag are incompatible; this is not permission to reinterpret an old
pointer or admit this format in the existing mount path.

Six selftests pass both normally and under `python3 -O`. They exercise acyclic
resolution, all 768 single-bit reference mutations, role substitution, location
and generation rebinding, malformed containers with a recomputed external digest,
and canonical directory/size bounds. Rebinding tests only model reference
replacement; they do not implement GC or prove recovery correctness.

The demo uses the four actual members from the verified QEMU fixture. It adds an
8-byte demonstration catalog tag and a 96-byte manifest reference ahead of the
original opaque catalog, producing **5,489 bytes**, still four hypothetical extent
pages instead of twelve. Evidence is in
`target/storage-member-reference-20260913/demo/report.json`. Existing catalog
pointers are not rewritten, so this remains a size and dependency-order model,
not a mountable image or a measured reduction in writes.

The model deliberately supplies checkpoint trust externally and verifies the
whole container in memory. Production checkpoint authentication, authorization,
format admission, bounded-memory reads, GC rewriting and publication fault tests
remain required before runtime integration or performance claims.

## Actual catalog-slot experiment

The optional `demo --rewrite-fixture-catalog` mode now replaces the matching
manifest pointer in the actual QEMU CAS snapshot, instead of prepending a toy
catalog. Layout constants and offsets come from `cas_codec.rs`'s
`encode_cas_snapshot` and `write_blob_mapping`: 128-byte header, 96-byte object
rows and 160-byte blob rows with a 96-byte pointer after the 64-byte BlobKey.
The converter checks framing, bounds, a unique matching BlobKey and the old
pointer's manifest length/kind/hash commitment before replacement. It consumes
an already verified fixture; it is not a complete CAS decoder or migration tool.

The experiment changes the catalog magic to `EXPCAS01` and uses its former
64-byte reserved header area as an explicit member-reference bitmap. Unset slots
keep ordinary physical pointers. Distinguishing reference types by the pointer's
leading magic would be ambiguous because those bytes hold a store UUID in the
old format. This small prototype admits at most 512 blob slots and does not
define the eventual production selector representation.

In the fixture, slot 2 at byte offset 800 is rewritten; both historical mappings
remain unchanged. The catalog stays 896 bytes and the bundle becomes 5,385 bytes
(four hypothetical extent pages). The embedded replacement resolves against the
external bundle root. Evidence:
`target/storage-member-reference-20260913/converted/report.json`.
Seven selftests now pass, including unchanged historical bytes, an external
pointer whose UUID starts with experimental reference magic, malformed catalog
framing/commitments, and rejection of a second conversion. This establishes a
mixed-reference encoding example; runtime selector decoding, full semantic
validation, checkpoint integration, GC and recovery are still outstanding.

## Local relocation and selector validation

The host model now parses the experimental selector bitmap and rejects unused
bits, malformed member references, non-manifest roles and mismatched BlobKeys.
An external slot is returned as unresolved physical-pointer bytes after checking
its kind/hash-algorithm/reserved fields; this is **not** authentication or full
physical-pointer validation. Only local member references resolve against the
externally supplied bundle root.

`relocate_local_bundle` validates local references before rebinding their
locations, rebuilds the catalog and then hashes the new container. Actual QEMU
fixture evidence in `target/storage-member-relocation-20260913/result/report.json`
shows one local slot rebound and two external slots unchanged, with 5,385 bytes
before and after. All 512 individual selector-bit mutations are rejected even
with recomputed container/member digests. A relocated container retaining the
old internal reference is also rejected. Seven expanded selftests pass. This
does not implement GC root discovery, content copying, durable publication or
reclamation.

### Remaining cross-container reference issue

These fixtures mix a new local member with historical **physical** pointers.
After multiple bundled publications, historical mappings would instead include
members of older bundles. The current local resolver intentionally rejects such
references because its only authenticated root belongs to the current bundle.
Thus the current model cannot yet represent normal multi-generation publication.
A production design must explicitly authenticate older containers: for example,
an external-member reference could commit to the already finalized older bundle
digest, while local references commit to member digests. That requires an
unambiguous reference variant and validation rules; it must not silently trust
an older container's self-reported hash. Before runtime integration, exercise
two successive bundled publications retaining an old member and relocation of
that older container, including rewriting and rehashing the dependent catalog.

## Authenticated external-member model

The model now adds the explicit `EXPEXT00` variant in member-marked catalog slots.
It has the same 96-byte layout as `EXPMEM00`, but commits to the finalized target
container digest rather than the selected member digest. The catalog bitmap
still separates member references from physical pointers; the member tag then
selects local versus external authentication. There is no reinterpretation of a
physical pointer UUID as a tag.

`validate_catalog` first authenticates the parent container. For an external
member it obtains bytes from a location-only fetch callback and validates them
against the digest carried by the authenticated parent. It checks store,
location, index, role, length and manifest BlobKey. It selects a manifest without
recursively following the target catalog. This closes the prior host-model
cross-container gap; the root checkpoint is still supplied by the harness.

`rewrite_external_dependency` validates both target containers and requires the
selected manifest bytes to be identical before copying the parent to a new
location, updating its external root commitment and rebinding local references.
It does not implement the atomic publication/reclamation protocol. In particular,
older checkpoints may still require the older parent and target: the experiment
removes an entry from an in-memory fetch map only to test dependency resolution,
not as a claim that freeing the real extent is safe.

Evidence at `target/storage-cross-container-20260913/result/report.json` uses the
actual fixture catalog. The first container is 5,385 bytes, the dependent second
container 5,065 bytes; relocation preserves both sizes and the two historical
physical slots. After removing access to the old target, the rewritten parent
resolves and the old parent fails. Authority/allocation bytes are opaque copies,
so these are not valid durable storage publications. Eight selftests now include
the two-container dependency, 768 authenticated-parent reference bit mutations,
target corruption, member-digest/container-digest substitution, and dependency
rewriting. Full CAS semantics, physical-pointer authentication, checkpoint
admission, memory bounds and crash-safe GC remain runtime integration gates.

## Lifetime experiment and revised integration direction

Packing a long-lived manifest with short-lived full snapshots couples their
reclamation. The current whole-container relocation model preserves all members,
so a single retained manifest keeps every obsolete catalog/authority/allocation
byte in that container. This is a performance issue for finite-capacity SD media,
even if the initial put issues fewer bytes.

`target/storage-bundle-lifetime-20260913/analyze.py` compares extent-page retention
under explicit assumptions: one unique object per full-snapshot publication,
all manifests live, 256-byte manifests, catalog size `128 + 256*N`, fixed authority
3,776 bytes and allocation 137 bytes, and the last two checkpoint root sets kept
for the separated and roots-only strategies. Segment framing, content pages,
fragmentation and actual GC copying are excluded. At 100 objects the whole-bundle
model retains 682 metadata extent pages versus 330 separated or 320 roots-only;
at 200 it retains 1,988 versus 642 or 632. These are modeled page counts, not disk
occupancy measurements. Member-extracting GC could reduce this retention, but its
copy/rewrite cost and implementation are absent from the current prototype.

The same run encodes the actual fixture's three checkpoint metadata payloads,
without modifying any catalog pointer. A 64-byte header, three 64-byte directory
entries and the original payloads total **5,065 bytes**. Their hypothetical extent
cost falls from nine pages to four. Keeping the separate three-page manifest
gives **21 total put pages instead of 26**, a 20 KiB (19.2%) write-byte reduction
estimate with existing barriers preserved. No runtime write count changed.
This gives up three pages of the all-member estimate while avoiding its
manifest-to-container dependencies and internal pointer conversion.

The roots-only candidate still needs explicit incompatible admission and typed
checkpoint member selection. Full-snapshot publications are the initial intended
path. Authority-only updates, allocation-only GC checkpoints and catalog replay
can reuse old roots with different lifetimes; packing must not assume that all
three roots are always replaced together. Fallback layout, root reachability,
old checkpoint retention, partial-root updates, read amplification and bounded
memory must be covered before integration. The prototype's 64 KiB admission also
fails the modeled all-member case at 238 objects (65,545 bytes); neither strategy
may silently reduce the runtime's existing catalog capacity to this model limit.

Results and exact assumptions are recorded in
`target/storage-bundle-lifetime-20260913/result/report.json`; the roots-only bytes
round-trip exactly, including the unmodified original 896-byte CAS snapshot.

## Rust roots-only codec prototype

`segment-store/src/experimental_root_bundle.rs` implements the three-root framing
under the opt-in `experimental-root-bundle` feature (and unit tests). The feature
only exposes a codec: it does not change mount admission, format version checks,
checkpoint interpretation, writer selection or GC. Default runtime paths remain
unchanged.

The encoder writes to an exactly sized caller-owned buffer; the decoder returns
borrowed payload slices. Neither allocates. Both enforce an explicit caller byte
budget and the existing single-extent maximum (256 pages / 1 MiB), rather than
the Python model's exploratory 64 KiB ceiling. Descriptor placement must also fit
within the segment data area. Over-budget roots require a future writer to use
the separated layout; this codec is not permission to reduce existing admission
limits. Authentication of the expected container digest and semantic validation
of the unchanged catalog/authority/allocation payloads belong to the caller.

Validation covers borrowed-slice roundtrip, store/location/generation binding,
every single-bit mutation of the small fixture both with and without a recomputed
outer digest, every truncation, trailing bytes, exact byte budgets, a 1 MiB
boundary case and segment-end placement. The independent Python integration
test compares all 5,065 encoded bytes and the container digest for root lengths
896 / 3,776 / 137. The codec also checks on `riscv64gc-unknown-none-elf` with the
pinned nightly compiler. The first cross-target attempt used an incompatible
compiler selection and failed to find `core`; explicitly selecting `rustup which
rustc` and `rustup which rustdoc` fixed the toolchain invocation without installing
anything or changing source.

No runtime or QEMU performance claim follows from these codec checks. The next
integration work is authenticated checkpoint root selection with incompatible
format admission, followed by publication/readback and recovery tests.

## Checkpoint root-field prototype

The Rust module now represents each root as `Separate(PhysicalPointer)` or
`Bundle(PhysicalPointer)`. `RootReferences` encodes three existing 96-byte slots
plus an explicit three-bit mask; slot position supplies the expected member role.
Only identical, explicitly bundled whole-container pointers may overlap. Partial
overlap, conflicting digests, mixed segment incarnations, null bundled pointers,
wrong store/kind, out-of-range segments, future generations and unknown mask bits
are rejected. A mixed update with a separate authority root and bundled catalog
and allocation roots round-trips. The existing format overlap helper is now
public without changing its behavior.

This is a field codec, not a new checkpoint page codec. It provisionally uses
Catalog as the physical container extent kind; runtime resolution will also need
a dedicated bundle object-kind check. Physical pointers must retain their raw
whole-payload SHA-256 commitment, which differs from the experimental bundle
codec's domain-separated outer digest. The read adapter must authenticate the
physical extent before validating bundle framing, without confusing those two
hash commitments or unnecessarily retaining extra buffers.

`segment-format/tests/root_bundle_admission.rs` reseals current superblock and
checkpoint pages after setting each of 32 reserved-field bits at offsets `0xf4`
and `0xb4`, respectively. All 64 cases return `NonZeroReserved`, not `Unsealed`,
after valid CRC/hash reconstruction. This verifies the old decoder's fail-closed
behavior for proposed marker locations. It does not prove a complete new mount
admission protocol or in-place migration; both superblock copies and interrupted
formatting still need explicit treatment. Current store read helpers propagate
these decode errors before selection, but an end-to-end mount fixture remains
required once the new format is implemented.

Four targeted Rust codec tests and the sealed-marker test pass. The expanded
feature also checks for the RISC-V bare-metal target. Writers and mount paths
still do not produce or accept bundled root fields.

## Physical payload read adapter

`RootReferences::decode_bundle_payload` now joins the field and payload codecs.
It takes the selected checkpoint root set, a verified extent descriptor and a
bounded payload buffer, then validates pointer/descriptor identity, dedicated
experimental object kind `0xffff_0030`, lengths, extent count/index, checkpoint
generation and the raw physical SHA-256 commitment. The descriptor must already
belong to a verified sealed segment chain; the adapter does not establish that
membership or authenticate a checkpoint by itself.

The adapter checks the raw whole-payload hash once and calls a private framing
decoder, avoiding another whole-payload pass for the host model's domain-separated
outer hash. Member hashes are still checked. It returns a borrowed
`DecodedRootBundle` whose typed accessor exposes only members actually selected
by the supplied root set. If authority moved to a separate extent, the obsolete
authority bytes remaining in an older shared catalog/allocation container are
not accessible through that result. No payload allocation is introduced.

Adapter tests build and seal real extent descriptors with the existing format
codec. They cover mixed-root visibility, borrowed pointers, wrong object kind,
extent shape, ordinal, future target checkpoint, byte budget, corruption, and
substitution of the host-model digest for the physical hash. Rehashing the
physical pointer and descriptor after corrupting a member still fails the inner
member commitment. This is payload-level integration only; PageDevice reads,
checkpoint admission and the publication path remain unconnected.

## PageDevice read path

`RootReferences::read_bundle` now calls the existing sealed-segment scanner and
physical payload reader. It validates the explicit root set and payload budget
before I/O, then verifies the dedicated object kind and canonical bundle framing
after the scanner has authenticated the descriptor chain and raw payload hash.
The returned `OwnedRootBundle` moves the existing read buffer into its result and
stores three fixed member ranges. Subsequent typed member access neither reads
the device nor hashes the container again. The existing bounded tail-coalescing
read path is used only within the supplied payload-capacity budget.

The budget here covers retained payload capacity, not the scanner's fixed pages,
descriptor metadata or tail scratch. It is not yet an overall recovery-memory
admission proof. The caller must still provide authenticated checkpoint roots
and perform the existing semantic decoders on selected member bytes.

`experimental_root_bundle_device_tests.rs` constructs a complete segment using
the actual header, record writer and segment finalizer, then reads the bundle
through an in-memory PageDevice. The 5,065-byte fixture is read once; accessing
all three members causes no additional device calls. The test checks payload
capacity, the 32-page request ceiling, rejection before any I/O for a short
budget, an injected failure at every observed read request, payload corruption,
segment-seal corruption and successful reread after restoring the original page.
Six targeted tests pass. This connects the reader to device I/O, but does not
connect bundled roots to mount selection or checkpoint publication and is not a
QEMU latency measurement.

## Write preparation and observed device page reduction

`prepare_bundle` now prepares one real `FinalRecord` and its payload buffer for
the existing record writer. It returns `None` when the bundle exceeds one extent,
does not fit at the reserved descriptor position, lacks workspace, or saves no
pages. The caller must then keep the separated layout. Invalid input remains an
error. Workspace includes newly allocated payload capacity plus the two 4 KiB
descriptor/seal buffers; retained input buffers and other publication state are
explicitly excluded and still need caller accounting. Preparation performs no
device I/O, reservation or checkpoint publication.

The writer uses a private framing encoder followed by raw payload SHA-256, so it
does not compute and discard the host-model outer digest. The prepared descriptor
therefore commits to exactly the same physical payload hash expected by the
existing segment writer and new reader.

The device fixture now compares separate 896 / 3,776 / 137-byte roots against the
prepared bundle using the actual record writer and segment finalizer. It observes
**15 versus 10 page writes**, including the common two-page header and four-page
trailer: five fewer pages / 20 KiB. Both fixture paths use deferred barriers and
one explicit final flush; this is a controlled extent/segment experiment, not a
claim that one flush implements the full checkpoint durability protocol. Both
layouts read back their original bytes through the corresponding device readers.
The test also exercises workspace one byte short, insufficient segment tail and
an oversized root requiring fallback. Seven targeted tests pass. Full put timing,
checkpoint publication, power-loss recovery and QEMU measurements remain pending.

## Experimental checkpoint page codec

The format crate's opt-in `experimental-root-bundle` feature now exposes
`experimental_root_checkpoint::BundleCheckpoint`. It retains the existing common
checkpoint fields and pointer widths, seals a three-bit mask at `0xb4` and an
explicit `EBR1` tag at `0xb8`, and reuses the existing body/seal integrity codec.
Even a separated fallback checkpoint with mask zero carries the tag. The current
checkpoint decoder rejects these pages; the experimental decoder rejects
untagged legacy pages. This is not yet incompatible superblock admission.

Validation preserves existing slot, previous-generation, admission, replay and
geometry checks, then checks typed roots and intentional bundle aliases. The
replay tail cannot be a bundle member or overlap a selected root. Full, mixed and
separated layouts round-trip through real sealed checkpoint pages. Unknown masks,
implicit aliases, invalid slot/generation and null bundled roots are rejected;
mutating the mask, tag or any root slot under the old seal cannot produce a sealed
decoded checkpoint. Two new checkpoint tests and the prior 64-case reserved-field
test pass.

`RootReferences::from_checkpoint` adapts a verified experimental checkpoint to
the reader's root set and context. The feature-enabled device test now encodes
and seals an experimental checkpoint, decodes it, derives the root references,
then reads the actual sealed segment and all selected members. The harness still
supplies the checkpoint directly: it does not establish freshness, choose between
slots, authenticate experimental superblocks or implement atomic publication.
Those admission/selection steps are required before any mount integration.

The checkpoint serializers share a field-writing helper and compute the body
CRC/hash only after the appropriate format fields are complete. This avoids an
intermediate legacy checkpoint hash during experimental encoding. Five existing
production codec tests, the reserved-field test, two experimental checkpoint
tests and seven feature-enabled store tests pass; the latter include the sealed
checkpoint-to-device-reader path. RISC-V bare-metal compilation remains checked.
