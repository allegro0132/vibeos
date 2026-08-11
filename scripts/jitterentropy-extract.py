#!/usr/bin/env python3
"""Extract VibeOS Jitterentropy raw-delta markers into upstream .data files."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

BEGIN = re.compile(r"VIBE_JENT_BEGIN .*\bsamples=(\d+)\b")
RAW = re.compile(r"VIBE_JENT_RAW (\d+) ([0-9a-fA-F]{16})\b")
END = re.compile(
    r"VIBE_JENT_END (COMPLETE|HEALTH-FAIL) samples=(\d+) "
    r"stuck=(\d+|not-exposed) health=(0x[0-9a-fA-F]+)\b"
)


def parse_log(path: Path) -> list[dict[str, object]]:
    blocks: list[dict[str, object]] = []
    active: dict[str, object] | None = None
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line_number, line in enumerate(source, 1):
            if match := BEGIN.search(line):
                if active is not None:
                    raise ValueError(f"{path}:{line_number}: nested BEGIN marker")
                active = {
                    "expected": int(match.group(1)),
                    "values": [],
                    "source": path,
                    "line": line_number,
                }
                continue
            if match := RAW.search(line):
                if active is None:
                    raise ValueError(f"{path}:{line_number}: RAW marker outside a block")
                values = active["values"]
                assert isinstance(values, list)
                index = int(match.group(1))
                if index != len(values):
                    raise ValueError(
                        f"{path}:{line_number}: raw index {index}, expected {len(values)}"
                    )
                values.append(int(match.group(2), 16))
                continue
            if match := END.search(line):
                if active is None:
                    raise ValueError(f"{path}:{line_number}: END marker outside a block")
                values = active["values"]
                expected = active["expected"]
                assert isinstance(values, list) and isinstance(expected, int)
                reported = int(match.group(2))
                if reported != expected or len(values) != expected:
                    raise ValueError(
                        f"{path}:{line_number}: incomplete block: BEGIN={expected}, "
                        f"RAW={len(values)}, END={reported}"
                    )
                active["status"] = match.group(1)
                active["stuck"] = (
                    None if match.group(3) == "not-exposed" else int(match.group(3))
                )
                active["health"] = int(match.group(4), 16)
                blocks.append(active)
                active = None

    if active is not None:
        raise ValueError(f"{path}: unterminated block beginning at line {active['line']}")
    return blocks


def write_values(path: Path, values: list[int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="\n") as output:
        for value in values:
            output.write(f"{value}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path, help="captured UART log(s)")
    parser.add_argument("--mode", choices=("runtime", "restart"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-blocks", type=int)
    parser.add_argument("--expect-samples", type=int)
    args = parser.parse_args()

    try:
        blocks = [block for log in args.logs for block in parse_log(log)]
        if not blocks:
            raise ValueError("no complete VIBE_JENT raw blocks found")
        if args.expect_blocks is not None and len(blocks) != args.expect_blocks:
            raise ValueError(
                f"found {len(blocks)} blocks, expected {args.expect_blocks}"
            )
        if args.expect_samples is not None:
            for index, block in enumerate(blocks):
                values = block["values"]
                assert isinstance(values, list)
                if len(values) != args.expect_samples:
                    raise ValueError(
                        f"block {index} has {len(values)} samples, "
                        f"expected {args.expect_samples}"
                    )

        if args.mode == "runtime":
            if len(blocks) != 1:
                raise ValueError(
                    f"runtime mode requires exactly one block, found {len(blocks)}"
                )
            values = blocks[0]["values"]
            assert isinstance(values, list)
            write_values(args.output, values)
        else:
            args.output.mkdir(parents=True, exist_ok=True)
            for index, block in enumerate(blocks):
                values = block["values"]
                assert isinstance(values, list)
                write_values(
                    args.output / f"jent-raw-noise-restart.{index:06d}.data",
                    values,
                )

        health_failures = sum(block["status"] != "COMPLETE" for block in blocks)
        stuck_values = [block["stuck"] for block in blocks]
        stuck = (
            "not-exposed"
            if any(value is None for value in stuck_values)
            else str(sum(int(value) for value in stuck_values))
        )
        samples = sum(len(block["values"]) for block in blocks)  # type: ignore[arg-type]
        print(
            f"extracted {samples} samples in {len(blocks)} block(s); "
            f"stuck={stuck}, health-fail blocks={health_failures}"
        )
        return 0
    except (OSError, ValueError) as error:
        parser.error(str(error))
        return 2


if __name__ == "__main__":
    sys.exit(main())
