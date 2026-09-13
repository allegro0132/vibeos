#!/usr/bin/env python3
"""Host-only member-reference model. NOT an accepted storage-v2 disk format.

Run `selftest`, or `demo --members-json FILE --output DIRECTORY`.
Demo members are objects with integer `role` and hex `payload` fields.
"""
import argparse
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import struct
import unittest
from typing import ClassVar

HEADER = 64
ENTRY = 64
REFERENCE = 96
MAX_BYTES = 64 * 1024
ROLES = {1, 2, 3, 4}  # manifest, catalog, authority, allocation


def require(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class Location:
    store: bytes
    segment: int
    generation: int
    descriptor: int

    def validate(self):
        require(len(self.store) == 16 and any(self.store), 'store identity')
        require(0 <= self.segment < 2**64 and 0 < self.generation < 2**64, 'generation/location')
        require(2 <= self.descriptor < 1020, 'descriptor location')


def member_hash(role, payload):
    require(role in ROLES and len(payload) <= MAX_BYTES, 'member shape')
    return hashlib.sha256(b'EXPERIMENT-MEMBER-v0\0' + struct.pack('<HQ', role, len(payload)) + payload).digest()


@dataclass(frozen=True)
class MemberRef:
    MAGIC: ClassVar[bytes] = b'EXPMEM00'
    location: Location
    index: int
    role: int
    length: int
    digest: bytes

    def encode(self):
        self.location.validate()
        require(0 <= self.index < 4 and self.role in ROLES, 'selector')
        require(0 <= self.length <= MAX_BYTES and len(self.digest) == 32, 'member commitment')
        b = bytearray(REFERENCE)
        b[:8] = self.MAGIC
        b[8:24] = self.location.store
        struct.pack_into('<QQIHHQ', b, 24, self.location.segment, self.location.generation,
                         self.location.descriptor, self.index, self.role, self.length)
        b[64:] = self.digest
        return bytes(b)

    @classmethod
    def decode(cls, b):
        require(len(b) == REFERENCE and b[:8] == cls.MAGIC, 'reference framing')
        require(not any(b[56:64]), 'reference reserved bytes')
        segment, generation, descriptor, index, role, length = struct.unpack_from('<QQIHHQ', b, 24)
        ref = cls(Location(b[8:24], segment, generation, descriptor), index, role, length, b[64:])
        require(ref.encode() == b, 'noncanonical reference')
        return ref


class ExternalMemberRef(MemberRef):
    """The digest authenticates a finalized external container, not a member."""
    MAGIC = b'EXPEXT00'


def reference(location, index, role, payload):
    return MemberRef(location, index, role, len(payload), member_hash(role, payload))


@dataclass(frozen=True)
class TrustedRoot:
    """Supplied externally by the test; models, but does not implement, checkpoint trust."""
    location: Location
    digest: bytes


def container_hash(b):
    return hashlib.sha256(b'EXPERIMENT-CONTAINER-v0\0' + b).digest()


def encode(location, members):
    location.validate()
    require(1 <= len(members) <= 4, 'member count')
    roles = [role for role, _ in members]
    require(roles == sorted(set(roles)) and set(roles) <= ROLES, 'canonical roles')
    total = HEADER + ENTRY * len(members) + sum(len(data) for _, data in members)
    require(total <= MAX_BYTES, 'container budget')
    b = bytearray(HEADER + ENTRY * len(members))
    b[:8] = b'EXPBND01'
    b[8:24] = location.store
    struct.pack_into('<QQIHHQ', b, 24, location.segment, location.generation,
                     location.descriptor, len(members), 0, total)
    for index, (role, data) in enumerate(members):
        struct.pack_into('<HHIQQ32s', b, HEADER + index * ENTRY,
                         role, index, 0, len(b), len(data), member_hash(role, data))
        b.extend(data)
    result = bytes(b)
    return result, TrustedRoot(location, container_hash(result))


def decode(b, root):
    require(HEADER <= len(b) <= MAX_BYTES, 'container size')
    require(container_hash(b) == root.digest, 'external root mismatch')
    require(b[:8] == b'EXPBND01', 'container magic')
    segment, generation, descriptor, count, version, total = struct.unpack_from('<QQIHHQ', b, 24)
    location = Location(b[8:24], segment, generation, descriptor)
    location.validate()
    require(location == root.location, 'root location mismatch')
    require(version == 0 and total == len(b) and not any(b[56:64]), 'container header')
    require(1 <= count <= 4 and HEADER + count * ENTRY <= len(b), 'directory count')
    at = HEADER + count * ENTRY
    result = []
    last_role = 0
    for index in range(count):
        pos = HEADER + index * ENTRY
        role, observed_index, flags, offset, length, digest = struct.unpack_from('<HHIQQ32s', b, pos)
        require(role in ROLES and role > last_role and observed_index == index, 'directory identity')
        require(flags == 0 and not any(b[pos + 56:pos + ENTRY]), 'directory reserved bytes')
        require(offset == at and length <= len(b) - at, 'directory range')
        data = b[at:at + length]
        require(member_hash(role, data) == digest, 'member digest mismatch')
        result.append((role, data))
        at += length
        last_role = role
    require(at == len(b), 'trailing data')
    return result


def resolve(b, root, encoded_ref, expected_role):
    ref = MemberRef.decode(encoded_ref)
    require(ref.location == root.location and ref.role == expected_role, 'reference binding')
    members = decode(b, root)
    require(ref.index < len(members), 'member index')
    role, data = members[ref.index]
    require(role == ref.role and len(data) == ref.length and member_hash(role, data) == ref.digest,
            'member identity')
    return data


def build_example(location, manifest, catalog_tail=b'', authority=b'', allocation=b''):
    # Acyclic: manifest -> its reference -> catalog -> container -> external root.
    ref = reference(location, 0, 1, manifest)
    catalog = b'EXPCAT00' + ref.encode() + catalog_tail
    members = [(1, manifest), (2, catalog), (3, authority), (4, allocation)]
    b, root = encode(location, members)
    return b, root, ref


def catalog_layout(catalog, magic):
    require(128 <= len(catalog) <= MAX_BYTES and catalog[:8] == magic, 'fixture catalog')
    version, kind, header = struct.unpack_from('<HHI', catalog, 8)
    objects, blobs, object_width, blob_width = struct.unpack_from('<IIII', catalog, 24)
    object_offset, blob_offset, total = struct.unpack_from('<QQQ', catalog, 40)
    require(version in (1, 2) and kind == 1 and header == 128, 'fixture codec')
    require(object_width == 96 and blob_width == 160 and object_offset == 128,
            'fixture table widths')
    require(blob_offset == 128 + objects * 96 and total == blob_offset + blobs * 160
            and total == len(catalog) and blobs <= 512, 'fixture table bounds')
    return blobs, blob_offset


def convert_fixture_catalog(catalog, manifest, ref):
    """Rewrite one verified fixture mapping, not a general CAS validator/migrator.

    EXPCAS01 uses header bytes 64..128 as an explicit member-slot bitmap.
    Unset slots retain physical pointers; never distinguish them by UUID/magic.
    """
    blobs, blob_offset = catalog_layout(catalog, b'VIBECAS2')
    require(not any(catalog[64:128]), 'fixture reserved bytes')
    require(len(manifest) >= 256 and manifest[:8] == b'VIBEBMF2', 'fixture manifest')
    require(ref.role == 1 and ref.length == len(manifest)
            and ref.digest == member_hash(1, manifest), 'replacement commitment')
    key = manifest[16:80]
    matches = [i for i in range(blobs)
               if catalog[blob_offset + i * 160:blob_offset + i * 160 + 64] == key]
    require(len(matches) == 1, 'exactly one matching blob key required')
    index = matches[0]
    pointer_offset = blob_offset + index * 160 + 64
    old = catalog[pointer_offset:pointer_offset + REFERENCE]
    require(struct.unpack_from('<Q', old, 48)[0] == len(manifest)
            and struct.unpack_from('<HHI', old, 56) == (2, 1, 0)
            and old[64:] == hashlib.sha256(manifest).digest(), 'old manifest commitment')
    out = bytearray(catalog)
    out[:8] = b'EXPCAS01'
    out[64 + index // 8] = 1 << (index % 8)
    out[pointer_offset:pointer_offset + REFERENCE] = ref.encode()
    return bytes(out), index, pointer_offset


def mixed_catalog_slots(catalog):
    """Structural parser. External pointers stay unresolved and unauthenticated."""
    count, start = catalog_layout(catalog, b'EXPCAS01')
    bitmap = int.from_bytes(catalog[64:128], 'little')
    require(bitmap >> count == 0, 'unused selector bits')
    result = []
    for index in range(count):
        offset = start + index * 160
        key = catalog[offset:offset + 64]
        pointer = catalog[offset + 64:offset + 160]
        internal = bool(bitmap & (1 << index))
        if internal:
            codec = ExternalMemberRef if pointer[:8] == ExternalMemberRef.MAGIC else MemberRef
            require(codec.decode(pointer).role == 1, 'catalog requires manifest role')
        else:
            # This only checks the physical-pointer discriminator fields. Full
            # location, authority and payload validation belongs to the resolver.
            require(struct.unpack_from('<HHI', pointer, 56) == (2, 1, 0),
                    'external pointer framing')
        result.append((key, internal, pointer, offset + 64))
    return result


def validate_catalog(b, root, fetch):
    """Authenticate member edges from a trusted parent; physical slots unresolved.

    Fetch returns bytes only. It cannot supply the expected hash or root.
    Resolution reads one selected manifest and never recursively follows catalogs.
    """
    members = decode(b, root)
    catalogs = [data for role, data in members if role == 2]
    require(len(catalogs) == 1, 'one catalog required')
    slots = mixed_catalog_slots(catalogs[0])
    for key, is_member, pointer, _ in slots:
        if not is_member:
            continue
        if pointer[:8] == ExternalMemberRef.MAGIC:
            ref = ExternalMemberRef.decode(pointer)
            require(ref.location.store == root.location.store and ref.location != root.location,
                    'external container location')
            target = fetch(ref.location)
            target_members = decode(target, TrustedRoot(ref.location, ref.digest))
            require(ref.index < len(target_members), 'external selector')
            role, manifest = target_members[ref.index]
            require(role == ref.role and len(manifest) == ref.length, 'external member binding')
        else:
            manifest = resolve(b, root, pointer, 1)
        require(len(manifest) >= 256 and manifest[:8] == b'VIBEBMF2'
                and manifest[16:80] == key, 'catalog BlobKey binding')
    return members, slots


def validate_local_catalog(b, root):
    members = decode(b, root)
    catalogs = [data for role, data in members if role == 2]
    require(len(catalogs) == 1, 'one catalog required')
    slots = mixed_catalog_slots(catalogs[0])
    for key, internal, pointer, _ in slots:
        if internal:
            manifest = resolve(b, root, pointer, 1)
            require(len(manifest) >= 256 and manifest[:8] == b'VIBEBMF2'
                    and manifest[16:80] == key, 'catalog BlobKey binding')
    return members, slots


def rewrite_external_dependency(b, root, old_target, new_target, destination, fetch):
    """Copy a parent in dependency order; no checkpoint publication/reclamation."""
    destination.validate()
    require(destination.store == root.location.store and destination != root.location,
            'new parent location required')
    require(old_target.location.store == root.location.store
            and new_target.location.store == root.location.store
            and new_target.location != old_target.location, 'target relocation binding')
    members, slots = validate_catalog(b, root, fetch)
    old_members = decode(fetch(old_target.location), old_target)
    new_members = decode(fetch(new_target.location), new_target)
    catalog = bytearray(next(data for role, data in members if role == 2))
    rewritten = 0
    for _, is_member, pointer, offset in slots:
        if not is_member:
            continue
        if pointer[:8] == ExternalMemberRef.MAGIC:
            ref = ExternalMemberRef.decode(pointer)
            if ref.location != old_target.location:
                continue
            require(ref.digest == old_target.digest, 'target root mismatch')
            require(ref.index < len(new_members) and old_members[ref.index] == new_members[ref.index],
                    'relocated manifest changed')
            replacement = replace(ref, location=new_target.location, digest=new_target.digest)
            rewritten += 1
        else:
            replacement = replace(MemberRef.decode(pointer), location=destination)
        catalog[offset:offset + REFERENCE] = replacement.encode()
    require(rewritten > 0, 'dependency absent')
    result, result_root = encode(destination, [(role, bytes(catalog) if role == 2 else data)
                                              for role, data in members])
    validate_catalog(result, result_root, fetch)
    return result, result_root


def relocate_local_bundle(b, root, destination):
    """Model only: rebind local manifest references, preserving external slots.

    Does not copy content, discover GC roots, publish checkpoints or free storage.
    """
    destination.validate()
    require(destination.store == root.location.store and destination != root.location,
            'relocation requires a new location in the same store')
    members, slots = validate_local_catalog(b, root)
    catalog = bytearray(next(data for role, data in members if role == 2))
    for _, internal, pointer, offset in slots:
        if internal:
            old = MemberRef.decode(pointer)
            catalog[offset:offset + REFERENCE] = replace(old, location=destination).encode()
    rebuilt = [(role, bytes(catalog) if role == 2 else data) for role, data in members]
    relocated, new_root = encode(destination, rebuilt)
    validate_local_catalog(relocated, new_root)
    return relocated, new_root


class ModelTests(unittest.TestCase):
    def test_cross_container_publication_and_dependency_relocation(self):
        location = Location(bytes(range(16)), 7, 3, 2)
        manifest = b'VIBEBMF2' + bytes(8) + b'K' * 64 + bytes(176)

        def catalog(pointer):
            out = bytearray(288)
            out[:8] = b'EXPCAS01'
            struct.pack_into('<HHI', out, 8, 1, 1, 128)
            struct.pack_into('<IIII', out, 24, 0, 1, 96, 160)
            struct.pack_into('<QQQ', out, 40, 128, 128, len(out))
            out[64] = 1
            out[128:192] = manifest[16:80]
            out[192:288] = pointer
            return bytes(out)

        local = reference(location, 0, 1, manifest)
        first, first_root = encode(location, [(1, manifest), (2, catalog(local.encode()))])
        external = ExternalMemberRef(location, 0, 1, len(manifest), first_root.digest)
        second_location = replace(location, segment=8, generation=4)
        second, second_root = encode(second_location, [(2, catalog(external.encode()))])
        disk = {location: first}
        validate_catalog(second, second_root, disk.__getitem__)
        # Every external-reference bit is bound by the authenticated parent.
        for bit in range(REFERENCE * 8):
            corrupt = bytearray(second)
            corrupt[HEADER + ENTRY + 192 + bit // 8] ^= 1 << (bit % 8)
            with self.assertRaises(ValueError):
                validate_catalog(bytes(corrupt), second_root, disk.__getitem__)
        with self.assertRaises(ValueError):
            validate_catalog(second, second_root, lambda _: first[:-1] + b'!')
        # A member digest cannot substitute for the expected whole-container hash.
        wrong = replace(external, digest=local.digest)
        wrong_parent, wrong_root = encode(second_location, [(2, catalog(wrong.encode()))])
        with self.assertRaises(ValueError):
            validate_catalog(wrong_parent, wrong_root, disk.__getitem__)
        moved, moved_root = relocate_local_bundle(first, first_root,
                                                  replace(location, segment=11, generation=5))
        disk[moved_root.location] = moved
        updated, updated_root = rewrite_external_dependency(second, second_root, first_root,
            moved_root, replace(second_location, segment=12, generation=6), disk.__getitem__)
        self.assertNotEqual(updated_root.digest, second_root.digest)
        # Once old bytes are unavailable, only the rewritten parent resolves.
        del disk[location]
        validate_catalog(updated, updated_root, disk.__getitem__)
        with self.assertRaises(KeyError):
            validate_catalog(second, second_root, disk.__getitem__)

    def test_fixture_catalog_rewrites_only_selected_slot(self):
        manifest = bytearray(256)
        manifest[:8] = b'VIBEBMF2'
        manifest[16:80] = b'K' * 64
        manifest = bytes(manifest)
        ref = reference(Location(bytes(range(16)), 7, 3, 2), 0, 1, manifest)
        catalog = bytearray(128 + 2 * 160)
        catalog[:8] = b'VIBECAS2'
        struct.pack_into('<HHI', catalog, 8, 1, 1, 128)
        struct.pack_into('<IIII', catalog, 24, 0, 2, 96, 160)
        struct.pack_into('<QQQ', catalog, 40, 128, 128, len(catalog))
        catalog[128:192] = b'J' * 64
        # A physical pointer UUID may resemble our magic: selectors must be explicit.
        catalog[192:200] = b'EXPMEM00'
        struct.pack_into('<HHI', catalog, 192 + 56, 2, 1, 0)
        catalog[288:352] = manifest[16:80]
        struct.pack_into('<Q', catalog, 352 + 48, len(manifest))
        struct.pack_into('<HHI', catalog, 352 + 56, 2, 1, 0)
        catalog[416:448] = hashlib.sha256(manifest).digest()
        catalog = bytes(catalog)
        converted, index, offset = convert_fixture_catalog(catalog, manifest, ref)
        self.assertEqual((index, offset), (1, 352))
        self.assertEqual(converted[64:128], b'\x02' + bytes(63))
        self.assertEqual(converted[128:352], catalog[128:352])
        self.assertEqual(MemberRef.decode(converted[offset:]), ref)
        self.assertEqual(len(converted), len(catalog))
        for at in [0, 8, 12, 24, 32, 40, 48, 56, 64, 288, 400, 408, 416]:
            bad = bytearray(catalog)
            bad[at] ^= 1
            with self.assertRaises(ValueError):
                convert_fixture_catalog(bytes(bad), manifest, ref)
        with self.assertRaises(ValueError):
            convert_fixture_catalog(converted, manifest, ref)
        slots = mixed_catalog_slots(converted)
        self.assertFalse(slots[0][1])
        self.assertTrue(slots[1][1])
        bundle, root = encode(ref.location, [(1, manifest), (2, converted)])
        validate_local_catalog(bundle, root)
        destination = replace(ref.location, generation=4, segment=11)
        relocated, new_root = relocate_local_bundle(bundle, root, destination)
        new_members, new_slots = validate_local_catalog(relocated, new_root)
        self.assertEqual(new_slots[0], slots[0])
        self.assertNotEqual(new_slots[1][2], slots[1][2])
        self.assertEqual(new_members[0][1], manifest)
        self.assertEqual(resolve(relocated, new_root, new_slots[1][2], 1), manifest)
        with self.assertRaises(ValueError):
            resolve(relocated, new_root, slots[1][2], 1)
        with self.assertRaises(ValueError):
            resolve(bundle, root, new_slots[1][2], 1)
        # Recomputing the outer digest must not hide stale internal references.
        stale_bundle, stale_root = encode(destination, [(1, manifest), (2, converted)])
        with self.assertRaises(ValueError):
            validate_local_catalog(stale_bundle, stale_root)
        for at, mask in [(64, 1), (64, 2), (64, 4), (127, 128), (288, 1)]:
            bad = bytearray(converted)
            bad[at] ^= mask
            bad_bundle, bad_root = encode(ref.location, [(1, manifest), (2, bytes(bad))])
            with self.assertRaises(ValueError):
                validate_local_catalog(bad_bundle, bad_root)
        for invalid_destination in [ref.location, replace(destination, store=b'Z' * 16)]:
            with self.assertRaises(ValueError):
                relocate_local_bundle(bundle, root, invalid_destination)

    def setUp(self):
        self.location = Location(bytes(range(16)), 7, 3, 2)
        self.b, self.root, self.ref = build_example(self.location, b'manifest', b'opaque catalog')

    def test_acyclic_catalog_reference(self):
        members = decode(self.b, self.root)
        embedded = members[1][1][8:8 + REFERENCE]
        self.assertEqual(embedded, self.ref.encode())
        self.assertEqual(resolve(self.b, self.root, embedded, 1), b'manifest')

    def test_every_reference_bit_is_bound(self):
        original = self.ref.encode()
        for byte in range(len(original)):
            for bit in range(8):
                changed = bytearray(original)
                changed[byte] ^= 1 << bit
                with self.assertRaises(ValueError):
                    resolve(self.b, self.root, bytes(changed), 1)

    def test_role_substitution(self):
        with self.assertRaises(ValueError):
            resolve(self.b, self.root, self.ref.encode(), 2)
        wrong = replace(self.ref, role=2)
        with self.assertRaises(ValueError):
            resolve(self.b, self.root, wrong.encode(), 2)
        self.assertNotEqual(member_hash(1, b'x'), member_hash(2, b'x'))

    def test_relocation_requires_new_references_and_root(self):
        for location in [replace(self.location, generation=4), replace(self.location, segment=9),
                         replace(self.location, store=b'Z' * 16), replace(self.location, descriptor=9)]:
            b, root, ref = build_example(location, b'manifest', b'opaque catalog')
            self.assertEqual(ref.digest, self.ref.digest)
            self.assertNotEqual(root.digest, self.root.digest)
            with self.assertRaises(ValueError):
                resolve(b, root, self.ref.encode(), 1)
            with self.assertRaises(ValueError):
                resolve(b, self.root, ref.encode(), 1)
            self.assertEqual(resolve(b, root, ref.encode(), 1), b'manifest')

    def test_malformed_container_even_with_recomputed_root(self):
        for offset in [0, 46, 48, 56, HEADER, HEADER + 2, HEADER + 4, HEADER + 8,
                       HEADER + 16, HEADER + 24, HEADER + 56, len(self.b) - 1]:
            changed = bytearray(self.b)
            changed[offset] ^= 1
            changed = bytes(changed)
            with self.assertRaises(ValueError):
                decode(changed, TrustedRoot(self.location, container_hash(changed)))
        for changed in [self.b[:-1], self.b + b'\0']:
            with self.assertRaises(ValueError):
                decode(changed, TrustedRoot(self.location, container_hash(changed)))

    def test_budgets_and_canonical_directory(self):
        for members in [[], [(1, b'a'), (1, b'b')], [(2, b'a'), (1, b'b')], [(5, b'a')],
                        [(1, b'x' * MAX_BYTES)]]:
            with self.assertRaises(ValueError):
                encode(self.location, members)
        b, root = encode(self.location, [(1, b'')])
        self.assertEqual(resolve(b, root, reference(self.location, 0, 1, b'').encode(), 1), b'')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('selftest')
    demo = sub.add_parser('demo')
    demo.add_argument('--members-json', type=Path, required=True)
    demo.add_argument('--output', type=Path, required=True)
    demo.add_argument('--rewrite-fixture-catalog', action='store_true')
    args = parser.parse_args()
    if args.command == 'selftest':
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ModelTests))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    members = {r['role']: bytes.fromhex(r['payload']) for r in json.loads(args.members_json.read_text())}
    require(set(members) == ROLES, 'demo requires all four roles')
    location = Location(bytes(range(16)), 7, 3, 2)
    b, root, ref = build_example(location, members[1], members[2], members[3], members[4])
    conversion = None
    if args.rewrite_fixture_catalog:
        catalog, index, offset = convert_fixture_catalog(members[2], members[1], ref)
        b, root = encode(location, [(1, members[1]), (2, catalog),
                                    (3, members[3]), (4, members[4])])
        require(resolve(b, root, decode(b, root)[1][1][offset:offset + REFERENCE], 1)
                == members[1], 'converted catalog resolution failed')
        conversion = {'member_slot': index, 'pointer_offset': offset,
                      'catalog_bytes_before': len(members[2]), 'catalog_bytes_after': len(catalog),
                      'selector': 'explicit bitmap; other slots retain original physical pointers'}
    require(resolve(b, root, ref.encode(), 1) == members[1], 'roundtrip failed')
    args.output.mkdir(exist_ok=False, parents=True)
    (args.output / 'experimental.bundle').write_bytes(b)
    report = {'scope': 'host-only reference model; not an existing disk codec',
              'bundle_bytes': len(b), 'reference_bytes': len(ref.encode()),
              'bundle_extent_pages': 2 + (len(b) + 4095) // 4096,
              'root_hash': root.digest.hex(), 'acyclic_construction': True,
              'catalog_tail': 'opaque original bytes; existing CAS pointer codec is not converted',
              'runtime_integration': False}
    if conversion is not None:
        report['catalog_tail'] = 'one actual mapping rewritten; remaining mappings preserved'
        report['fixture_conversion'] = conversion
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
