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

## Tagged superblock admission and structural selection

The experimental codec now seals the same explicit `EBR1` format tag in
superblock field `0xf4`. `admit` decodes both copies through the tagged codec
before applying the existing superblock agreement rules. A legacy or corrupt
sealed copy is an error even when its peer is valid. Empty/unsealed copies retain
the existing behavior; this supports interrupted formatting of new disposable
media, not an in-place upgrade from a legacy volume.

Admission returns an `AdmittedFormat` with private construction. Its
`select_checkpoints` method decodes both slots, checks their physical slot and
superblock binding/admitted range, enforces the existing adjacent-generation and
monotonic-allocation-field rules, then returns a privately constructed
`SelectedCheckpoint`. The store's `from_checkpoint` adapter now requires this
selected type instead of a merely sealed record. This distinguishes structural
selection from individual-record integrity without claiming full store recovery.

Tests cover both valid copies, either empty copy, two empty copies, old/new format
mixes in either position, swapped copies, corruption, newest-slot selection,
swapped checkpoint slots, a generation gap, an undersized device-page bound,
seven incomplete seal prefixes, a corrupt sealed newer checkpoint and an untagged
newer checkpoint. Incomplete seals retain the older checkpoint; complete corrupt
or untagged records fail instead of silently selecting the older one. The device
fixture now derives its reader context through tagged superblocks and structural
checkpoint selection before reading the sealed segment.

Actual device identity/range matching, allocation-map transition validation,
root semantic recovery, publication ordering and end-to-end interrupted-format
tests remain store integration work. No existing mount path invokes this codec.

## Device-backed anchor selection

`select_device_checkpoint` now reads superblock pages 0–3 and checkpoint pages
4–7 through PageDevice, using one reusable four-page allocation. It validates
device block/page geometry before I/O and matches the admitted superblock's
device ID, logical range start, block size, initial capacity and replay limit
against the actual device context. It then selects the checkpoint under the
device's real page bound. The workspace is released when selection returns,
before a caller reads a root bundle.

The feature-enabled device fixture writes tagged anchors into its page map and
uses this function, replacing direct in-memory codec calls. It observes exactly
two four-page anchor requests, rejects a workspace budget one byte short before
I/O, propagates failures on both anchor reads, and rejects device ID/range/size/
capacity/replay mismatches. Injected read failures now overwrite the first output
page before returning an error, checking that partial buffer fills cannot become
selected state. Corrupt superblock/checkpoint pages fail closed; temporarily
removing all anchors returns Unformatted, and restoring them permits selection.
The same test then reads the sealed segment and checks all selected root bytes.

This is a device-backed structural selection entry point, not SegmentStore::mount.
It still does not recover allocation transitions, grant authority, install mounted
state or publish a checkpoint. Its 16 KiB anchor budget excludes fixed stack and
returned metadata structures; overall recovery memory still requires accounting.

## Allocation member recovery

`OwnedRootBundle::recover_allocation` now preserves and checks the source physical
pointer and extent target checkpoint generation before decoding a selected
allocation member. It reuses existing allocation codecs, allocation decode-size
estimates, resident-byte accounting and allocated-pointer checks. Both legacy
prefix and v2 bitmap encodings are handled; generation, admitted segments, next
segment generation and cleaner reserve must match the selected checkpoint. The
legacy prefix must end immediately after the allocation carrier. Every current
root and replay pointer must name an Allocated segment.

Preflight and post-decode checks account for caller-reported resident memory,
the retained whole bundle capacity and decoded allocation memory together. This
does not claim a bound for the preceding segment scanner's fixed overhead.

The device fixture now uses a canonical v2 allocation map instead of placeholder
bytes and recovers it through the complete device selection/read path. It checks
the exact combined-memory boundary, one byte short and additional resident state.
Separate semantic-layer cases cover a stale generation, Free/Retired carrier
states and valid/incorrect v1 prefix endings. Those semantic cases deliberately
alter private test buffers after the authentication stage; they are not claimed
to be sealed on-disk corruption fixtures. Full two-checkpoint allocation
transition validation, CAS and authority semantic recovery remain pending.

## Recovered allocation transition witness

Allocation recovery now returns an immutable `RecoveredAllocation` wrapper which
retains the decoded map, its actual encoding version and the selected checkpoint
binding. Callers can inspect the map but cannot substitute a version argument or
mutate the stored binding. `validate_same_admission_successor` requires adjacent
checkpoint generations, matching store/policy and an unchanged admitted range,
then invokes the existing allocation transition validator without changing its
rules. Ordinary allocation, relocation retirement and complete next-generation
reclamation therefore share the production checks.

Semantic transition tests accept ordinary allocation, retirement with a new
carrier, and complete reclamation with a distinct new carrier. They reject direct
Allocated-to-Free reuse, assigned-generation count mismatches, generation gaps,
advancing an ordinary checkpoint while retirement is pending, partial reclamation
and store mismatch. These are typed-map transition fixtures, not a two-checkpoint
disk crash campaign. The device-backed pair recovery below now reads both actual
checkpoint maps and invokes this check; installing mounted state remains pending.

Growth is intentionally outside this unchanged-range entry point: its existing
carrier, previous-segment seal chain, unchanged-root and suffix checks remain
necessary. This is an incomplete integration gate, not removal of growth support
from the intended runtime. CAS and authority recovery are also outstanding.

## Device-backed allocation pair recovery

Structural checkpoint selection now retains immutable recovery tokens for both
the current and previous sealed candidates. The experimental pair reader decodes
the old allocation bundle first, drops its container, then reads the current
bundle while charging the retained old bitmap against the memory budget. It
validates the allocation transition before returning either recovered pair.

A device fixture writes two sealed segments and tagged checkpoint slots with
canonical allocation maps. Ordinary allocation succeeds; a fully sealed successor
that directly changes an Allocated segment to Free fails transition validation.
The fixture also checks the exact combined-memory boundary, one byte short, and
corruption of the previous container. This covers actual anchor selection and
segment authentication, rather than only private decoded-map mutations.

The nine root-bundle unit tests and ten format/compatibility tests pass. This is
still an in-memory PageDevice test, not a QEMU timing or crash campaign. Catalog
and authority members in this pair fixture are placeholders. Bootstrap, separated
allocation roots, growth, full semantic recovery and runtime publication remain
integration gates; no production mount or performance claim follows from this
test.

## Allocation layout fallback across checkpoints

`recover_same_admission_allocations` now accepts either an explicitly bundled
allocation root or a separate Allocation extent in each selected checkpoint.
Both paths use the existing sealed-segment reader and share allocation decode,
checkpoint binding, allocated-pointer and memory checks. The separate path also
requires the extent's target checkpoint generation to match the recovery token.
The encoded buffer is dropped before reading the next generation in either path.

The device pair fixture now exercises all four old/new allocation layout
combinations, with both valid allocation and fully sealed illegal direct reuse.
Catalog and authority remain bundled placeholders; this does not test a complete
all-roots-separated mount. Memory boundaries include whichever generation has
the larger live encoded-buffer-plus-map footprint. Corruption targets the actual
previous allocation payload, which differs between the two layouts.

Bootstrap and growth remain unsupported in this pair entry point. These changes
remove the allocation layout fallback gate only; catalog/authority recovery,
production publication, crash validation and QEMU performance remain outstanding.

## Empty bootstrap allocation recovery

The pair reader now handles an allocation-root-null checkpoint only at generation
1, with next segment generation 1 and all remaining roots null. It constructs
the existing v1-compatible all-Free map after checking the maximum segment count
and preflighting bitmap memory, then checks actual resident allocation capacity.
No payload or segment reads are needed for this case.

A sealed-anchor device fixture checks the empty map for all 16 segments, its
four-byte bitmap budget, one byte short and caller-resident memory. Noninitial
empty checkpoints and an initial checkpoint with an advanced next segment
generation fail without payload I/O. All ten experimental root-bundle unit tests
pass. This adds empty bootstrap recovery only: a device-backed initial-to-first-
publication transition and runtime formatting/publication still need validation.
Growth and complete catalog/authority semantic recovery remain outstanding.

## First-publication device fixture

The allocation-pair fixture now includes a generation-1 empty checkpoint followed
by a generation-2 sealed segment, for both bundled and separate allocation roots.
The valid successor allocates one segment and advances the next segment generation
once. Its negative counterpart is fully sealed but marks an extra segment
Allocated without a corresponding generation advance; transition validation must
reject it. Memory and payload corruption checks also cover these bootstrap cases.

Seven incomplete checkpoint-seal prefixes exercise selection of the initial
checkpoint despite the already-written new segment and body. Recovery must return
an all-Free map within the initial bitmap budget; restoring the complete seal
must select and recover generation 2. These are explicit device-image fixtures,
not an exhaustive write/flush failure campaign or a production writer. Catalog
and authority payloads remain placeholders, and QEMU latency remains unmeasured
for the experimental format.

## Bundled CAS snapshot decoding

`OwnedRootBundle::decode_catalog_snapshot` binds the selected Catalog member to
the recovered allocation checkpoint, reuses the production CAS codec and decode
capacity estimate, and checks snapshot/extent generation equality, entry limits
and manifest carrier allocation. Its budget charges the retained container,
current allocation map, caller-reported resident state and decoded table capacity.
It returns a decoded snapshot only: replay, manifest contents and Blob descriptors
must still be validated before installation as mounted state.

The paired-device fixture now encodes canonical empty CAS snapshots instead of
catalog placeholder bytes. It decodes the selected snapshot in every successful
layout/bootstrap case, checks the exact memory boundary and rejects using the
previous allocation checkpoint with the new container. These empty fixtures do
not yet exercise nonempty tables, manifest references or replay; authority remains
a placeholder. No production mount or QEMU performance claim is made.

## Nonempty CAS decode limits

The bundled snapshot adapter now checks object/blob counts against the configured
entry limit after header/length preflight but before allocating decoded tables.
The existing post-decode checks remain. A nonempty semantic fixture covers one
object and one Blob mapping, exact encoded-plus-map-plus-table memory, one byte
short, entry-limit rejection before memory allocation, stale snapshot generation
and a manifest pointer into a Free segment.

These additional cases deliberately construct private decoded-member buffers;
they are not sealed bundle fixtures and their manifest contents do not exist on
disk. They verify the adapter's semantic checks, not complete reference recovery.
The device-backed canonical empty snapshots remain the authentication coverage.

## No-replay manifest and descriptor recovery

`OwnedRootBundle::recover_catalog_without_replay` consumes the container and
releases it after snapshot decoding, before reading each manifest. It invokes
the existing physical payload reader, manifest codec and Blob descriptor
validator, checks BlobKey equality and allocated extent carriers, and preflights
and checks decoded manifest capacity against retained maps/tables and caller
memory. Encoded manifest storage is released before descriptor validation.

This entry point explicitly rejects replay checkpoints. It returns a catalog,
not mounted authority or complete store state. Existing empty sealed-device
fixtures now call the entry point. The nonempty semantic fixture additionally
checks that its unresolved manifest reference causes device reads and rejection;
it is not a successful nonempty end-to-end reference fixture. Successful actual
manifest/Blob data fixtures, replay integration and QEMU timing remain necessary.
Scanner fixed buffers are still outside the dynamic-memory accounting claim.

## Sealed nonempty catalog reference fixture

A new PageDevice fixture encodes a four-byte canonical Blob, a separate compact
manifest and a nonempty CAS snapshot inside the root bundle. It writes actual
extent records and seals, finalizes the containing segment and selects tagged
checkpoint anchors before recovering allocation and catalog. The returned object
and Blob mappings must equal the encoded snapshot. Corrupting the manifest
payload or the Blob descriptor seal must reject reference recovery.

This is successful no-replay metadata/descriptor recovery with real physical
references, not full Blob payload verification, authority recovery or production
mount. The fixture still uses authority placeholder bytes. QEMU performance and
publication crash validation remain outstanding.

## Full authority snapshot adapter

The bundled authority member now has a decode adapter using the existing bounded
persistent-authority decoder and root extraction. It binds the member to the
allocation checkpoint, checks its extent generation, and resolves extracted roots
against the caller's catalog by object ID, commit generation and object kind.
Memory accounting includes retained container, allocation, catalog tables, caller
state, decoder peak, authority storage and extracted roots. The caller must pass
a recovered catalog; this API does not authenticate an arbitrary supplied table.

The checkpoint-pair device fixture replaces its authority placeholder with a
canonical Format record stream and empty authority bindings, then decodes it
across successful layout and bootstrap cases. Nonempty authority bindings,
legacy root sets, authority deltas and end-to-end mount remain integration work.
The separate nonempty Blob fixture still has placeholder authority bytes.

## Sealed external authority root fixture

The nonempty catalog fixture now replaces its authority placeholder with a
canonical Format record stream and a persisted external root naming the catalog
object. Device-backed bundle recovery decodes that authority and resolves the
root successfully. Separate caller-table mutations check missing objects,
mismatched commit generation and object kind. These mutations are semantic tests,
not separately sealed malformed authority images.

A bounded search finds the adapter's smallest accepted memory budget for this
fixture, then checks that one byte less or one extra resident byte fails with
MemoryLimit. The updated targeted fixture passes. This budget checks the adapter's
accounting contract, not whole-process resident memory. Full managed-principal
bindings, replay/deltas, runtime mount and QEMU performance remain outstanding.

## Combined no-replay root recovery

`recover_roots_without_replay` consumes a single authenticated container, decodes
its CAS snapshot once and resolves full authority against that same table. It
then releases the container and invokes shared manifest/descriptor validation,
charging retained authority and extracted roots in addition to allocation and
catalog memory. The existing catalog-only entry point uses the same reference
validator. The result is recovery data, not installed mount state or an authority
grant; both members must be in the selected container and replay is rejected.

The sealed nonempty external-root fixture invokes the combined path and asserts
that its root-container payload is requested only once. This covers reuse within
catalog/authority recovery, not the earlier allocation-pair reader, which still
reads allocation independently. It establishes an I/O property of the fixture,
not a measured QEMU latency improvement.

## Reuse current allocation container for all-root recovery

`recover_bundled_checkpoint_without_replay` now retains the current container
from allocation-pair recovery and hands it to combined catalog/authority
recovery. Older containers are dropped as before. Both allocation generations
are validated before root recovery; retained previous-map memory is charged
throughout. The existing allocation-only API still drops the current container.
This fast entry point requires all three current roots to share one bundle and
no replay, while other layouts use their existing entry points.

The nonempty sealed fixture checks that allocation, catalog and authority share
one current-container payload read. The paired fixtures exercise the fast path
with ordinary and bootstrap predecessors, including a separate old allocation,
and ensure illegal transitions remain rejected. This reduces duplicate fixture
I/O; production mount integration and QEMU performance are still unverified.

## Combined recovery failure and memory boundaries

The combined no-replay path is now exercised with an injected partial-fill error
at every read request observed in successful recovery. Coverage includes the
nonempty manifest/authority fixture and paired ordinary/bootstrap predecessors,
including a separate previous allocation root. Every injection must fail rather
than return recovered roots; the device's original bytes are preserved.

The nonempty fixture also searches the smallest accepted combined recovery
budget and checks one byte less and one extra resident byte. This checks the
entry point's dynamic-memory contract across allocation, catalog, authority and
manifest phases. It excludes anchor selection (performed beforehand), fixed
scanner/stack storage and process-level allocations. This remains a bounded
read-error campaign, not write/crash validation or a QEMU performance result.

## CAS replay recovery adapter

A catalog-only `recover_catalog` entry point now releases the bundle after
snapshot decoding, reads the selected CAS delta chain backwards and applies it
in commit order. It checks chain depth/termination, descriptor generation,
monotonic generation and ObjectId, existing-Blob reuse versus new-Blob insertion,
allocated carriers and final entry limits. The materialized table is stamped
with the selected checkpoint generation before reference validation.

Preflight charges resident maps/tables, delta chain capacity and complete
successor table capacity during reservation; actual capacities are checked again.
The nonempty device fixture adds a sealed reuse delta for ObjectId 2 and checks
that recovery returns two objects backed by the original single Blob. A one-entry
limit rejects it. Multi-delta/new-Blob/error cases remain to be exercised, and
combined authority recovery still uses its explicit no-replay path. Production
mount and QEMU performance are not established by this adapter.

## Multi-delta replay fixture

The sealed nonempty fixture now runs with zero, one and three CAS reuse deltas.
It verifies ordered materialization of ObjectIds 1 through 4 with one shared Blob,
selected checkpoint generation and entry-limit rejection. Corrupting the tail
payload fails recovery. A separately re-encoded and sealed checkpoint that
understates the chain count also fails, testing semantic chain-depth validation
rather than only digest rejection. The updated targeted fixture passes.

These chains remain within one sealed segment and generation and introduce no
new Blob mapping. Cross-generation/multi-segment replay, new-Blob insertion,
authority integration and production/QEMU validation remain outstanding.

## Replay new-Blob insertion and budget errors

The fixture now starts with an empty catalog, introduces a real sealed Blob
mapping in the first delta and reuses it in later deltas. A fully sealed chain
that attempts a second insertion of the same Blob is rejected. Successful replay
cases inject partial-fill errors at every observed replay/reference read and
search the minimum accepted dynamic-memory budget.

That budget test exposed a classification bug: the physical reader treats its
maximum payload length as a format constraint, so passing insufficient remaining
memory could yield Corrupt. Replay and manifest adapters now check declared
payload length against remaining memory before reading and return MemoryLimit.
The updated eleven root-bundle tests pass, including boundary and read-error
cases. These fixtures remain within one segment/generation; mount, cross-segment
replay, authority integration and QEMU performance remain outstanding.

## Combined CAS replay and authority recovery

Catalog-only and combined recovery now share the same bounded replay helper.
`recover_roots` applies CAS replay before resolving full authority roots, keeping
and charging the container through those phases, then releasing it before
manifest reads. `recover_bundled_checkpoint` additionally reuses the allocation
reader's current container and preserves predecessor transition validation.
Explicit no-replay entry points retain their rejection behavior and delegate.

The sealed replay fixture calls the all-bundled checkpoint entry point, including
an initially empty catalog whose authority root names a replay-created object.
It checks materialized tables, authority resolution and one current-container
payload request across allocation, replay and authority recovery. Authority
deltas, mixed current-root layouts, cross-generation/segment replay and actual
mount/publication/QEMU validation remain outstanding.

## Replay in a separate sealed segment

The nonempty fixture now places its three new-Blob/reuse deltas in segment 8,
while Blob, manifest and root bundle remain in segment 7. Both carriers are
Allocated, the next segment generation advances accordingly, and the delta
segment header names the sealed root segment as predecessor. Recovery follows
actual cross-segment references, resolves authority and still reads the root
container once. The same read-failure and memory-boundary checks cover this mode.
Corrupting the separate delta segment seal must fail combined recovery.

This exercises a delta chain in a separate segment at the same checkpoint
generation. It does not yet exercise a chain spanning several delta segments or
multiple checkpoint generations, nor production mount/publication/QEMU timing.

## Replay chain spanning three delta segments

The fixture additionally places each of three deltas in its own segment (8, 9,
10), with distinct segment generations, allocated carriers and sealed predecessor
links. Replay pointers now cross between delta segments, rather than merely
pointing from the root segment to one delta segment. Existing ordered recovery,
new-Blob reuse, read-failure and memory-budget checks exercise this layout.
Each delta segment seal is independently corrupted and must cause rejection.

All records still target the same checkpoint generation. Cross-checkpoint replay,
mixed current-root layouts and actual mount/publication/QEMU validation remain
outstanding; this is not a latency benchmark.

## Mixed allocation and shared catalog/authority bundle

Checkpoint recovery now accepts separate allocation storage while catalog and
full authority share a bundle. After allocation-pair validation it reuses a
matching retained container or drops the allocation container before reading
the catalog/authority bundle, charging both retained maps. Current catalog and
authority must still share one bundle; separated catalog/authority need further
integration. A separate allocation read now preflights payload length against
remaining memory, matching replay/manifest MemoryLimit classification.

All old/new allocation layout combinations and bootstrap predecessors now call
the combined entry point, including illegal-transition rejection, one catalog
container request, partial-read failures and minimum-memory boundary checks.
This integrates allocation fallback only, not production mount/publication or
QEMU performance.

## Replay across checkpoint generations

The split-delta fixture now also selects checkpoint generation 6 while retaining
a generation-4 catalog/authority bundle. Its three delta segments target
generations 4, 5 and 6, and a separate generation-6 allocation extent records all
current carriers. Recovery materializes generation 6, resolves the older full
authority snapshot and reads the shared catalog/authority container once.
Existing replay read failures, minimum-memory checks, tail corruption and each
delta segment's seal corruption cover this variant. The targeted fixture passes.

This is a single selected checkpoint backed by cross-generation records; it does
not provide a prior sealed checkpoint slot for this variant, simulate historical
publication/crashes, or establish production mount/QEMU performance.

## Separate catalog recovery adapter

`recover_separate_catalog` reads an explicitly separate Catalog extent and uses
the same extracted snapshot decoder, replay helper and manifest/descriptor
validator as bundled recovery. It checks remaining payload memory before I/O,
charges allocation/encoded/table capacities and drops encoded catalog storage
before replay/reference reads. It does not install authority or mounted state.

The nonempty device fixture adds an actual separate catalog record selected by
mask 6, while allocation and authority remain bundled. It recovers the catalog,
resolves bundled authority against it, rejects insufficient memory and rejects
catalog payload corruption. Eleven root-bundle tests pass. Separate-catalog replay
and complete layout dispatch remain to be exercised/integrated.

## Separate authority and root layout dispatch

`recover_separate_authority` uses the same extracted bounded authority decoder,
root extraction and catalog matching as bundled authority. It charges catalog
and allocation state before reading its separate extent. The fixture adds mask 4
with separate catalog and full authority, checking restored roots, insufficient
memory and authority payload corruption.

`recover_checkpoint_roots` dispatches non-null CAS/full-authority roots using the
explicit mask: shared catalog/authority bundles use the retained-container path;
other layouts recover catalog first, then authority with all retained tables
charged. Separate-catalog/bundled-authority and separate-catalog/separate-authority
fixtures call this dispatcher. Null bootstrap roots, growth, legacy roots and
authority deltas remain integration gates. This is not production mount state.

## Device recovery wrapper and experiment wrap-up

`recover_device_checkpoint` selects authenticated device anchors, handles the
strict empty bootstrap, and dispatches supported nonempty root layouts. It
returns recovered data, not mounted state or write authority. The anchor buffer
is released before payload recovery. Device fixtures cover bootstrap anchor-only
reads, insufficient budgets, supported nonempty layouts and rejected duplicate
Blob insertion. The 11 targeted root-bundle tests and the RISC-V bare-metal
feature compile check passed on 2026-09-13.

Development of this experiment is paused at this boundary. Production mount,
publication/crash qualification, growth, legacy authority root sets and authority
deltas remain outstanding. The experiment is disabled in the production QEMU
performance comparison and has no measured performance acceptance claim.
