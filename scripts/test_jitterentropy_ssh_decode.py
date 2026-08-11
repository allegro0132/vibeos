#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("jitterentropy-ssh-decode.py")
SPEC = importlib.util.spec_from_file_location("jitterentropy_ssh_decode", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def frame(values: list[int], *, status: str = "COMPLETE", health: int = 0) -> bytes:
    count = len(values)
    header = (
        f"VIBE_JENT_STREAM_V1 requested={count} captured={count} encoding=u64le "
        f"osr=3 version=3070100 stuck=not-exposed health={health:#x} read=0\n"
    ).encode()
    payload = b"".join(struct.pack("<Q", value) for value in values)
    trailer = (
        f"\nVIBE_JENT_END {status} samples={count} stuck=not-exposed "
        f"health={health:#x} read=0\n"
    ).encode()
    return header + payload + trailer


class DecodeTests(unittest.TestCase):
    def test_decodes_exact_u64le_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output, metadata = root / "frame", root / "data", root / "meta.json"
            source.write_bytes(frame([0, 1, 0x123456789ABCDEF0, (1 << 64) - 1]))
            result = MODULE.decode(source, output, metadata)
            self.assertEqual(output.read_text(), "0\n1\n1311768467463790320\n18446744073709551615\n")
            self.assertEqual(result["captured_samples"], 4)
            self.assertTrue(metadata.is_file())

    def test_rejects_truncation_without_publishing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "frame", root / "data"
            source.write_bytes(frame([1, 2, 3])[:-5])
            with self.assertRaises(ValueError):
                MODULE.decode(source, output, None)
            self.assertFalse(output.exists())

    def test_rejects_health_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "frame", root / "data"
            source.write_bytes(frame([1], status="HEALTH-FAIL", health=1))
            with self.assertRaisesRegex(ValueError, "board rejected stream"):
                MODULE.decode(source, output, None)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
