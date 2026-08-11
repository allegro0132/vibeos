#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("jitterentropy-assess.py")
SPEC = importlib.util.spec_from_file_location("jitterentropy_assess", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AssessmentTests(unittest.TestCase):
    def test_parses_reviewed_masks(self) -> None:
        self.assertEqual(MODULE.masks(["0F:4", "FF:8"]), [("0F", 4), ("FF", 8)])

    def test_rejects_mask_bit_count_mismatch(self) -> None:
        with self.assertRaisesRegex(ValueError, "select exactly"):
            MODULE.masks(["0F:8"])

    def test_rejects_incomplete_runtime_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.data"
            path.write_text("1\n2\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "found 2 samples"):
                MODULE.validate_decimal_file(path, MODULE.RUNTIME_SAMPLES)


if __name__ == "__main__":
    unittest.main()
