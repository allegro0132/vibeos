#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("jitterentropy-extract.py")
SPEC = importlib.util.spec_from_file_location("jitterentropy_extract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExtractorTests(unittest.TestCase):
    def log(self, text: str) -> Path:
        handle = tempfile.NamedTemporaryFile("w", encoding="ascii", delete=False)
        self.addCleanup(Path(handle.name).unlink, missing_ok=True)
        with handle:
            handle.write(text)
        return Path(handle.name)

    def test_extracts_complete_indexed_block(self) -> None:
        path = self.log(
            "noise\n"
            "VIBE_JENT_BEGIN version=3070000 mode=raw-evidence samples=2 osr=3\n"
            "VIBE_JENT_RAW 0 000000000000000a\r\n"
            "VIBE_JENT_RAW 1 00000000000000ff\n"
            "VIBE_JENT_END COMPLETE samples=2 stuck=1 health=0x0\n"
        )
        blocks = MODULE.parse_log(path)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["values"], [10, 255])
        self.assertEqual(blocks[0]["stuck"], 1)

    def test_rejects_incomplete_block(self) -> None:
        path = self.log(
            "VIBE_JENT_BEGIN version=3070000 mode=raw-evidence samples=2 osr=3\n"
            "VIBE_JENT_RAW 0 000000000000000a\n"
            "VIBE_JENT_END COMPLETE samples=2 stuck=0 health=0x0\n"
        )
        with self.assertRaisesRegex(ValueError, "incomplete block"):
            MODULE.parse_log(path)

    def test_rejects_reordered_index(self) -> None:
        path = self.log(
            "VIBE_JENT_BEGIN version=3070000 mode=raw-evidence samples=1 osr=3\n"
            "VIBE_JENT_RAW 1 000000000000000a\n"
        )
        with self.assertRaisesRegex(ValueError, "raw index 1, expected 0"):
            MODULE.parse_log(path)

    def test_accepts_rust_probe_without_upstream_stuck_counter(self) -> None:
        path = self.log(
            "VIBE_JENT_BEGIN source=jitterentropy-rs version=3070100 "
            "mode=raw-timer-delta samples=1 osr=3\n"
            "VIBE_JENT_RAW 0 000000000000002a\n"
            "VIBE_JENT_END COMPLETE samples=1 stuck=not-exposed health=0x0\n"
        )
        blocks = MODULE.parse_log(path)
        self.assertEqual(blocks[0]["values"], [42])
        self.assertIsNone(blocks[0]["stuck"])


if __name__ == "__main__":
    unittest.main()
