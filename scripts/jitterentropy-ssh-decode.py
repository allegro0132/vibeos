#!/usr/bin/env python3
"""Decode one framed VibeOS SSH jitterentropy stream into decimal deltas."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

HEADER = re.compile(
    rb"VIBE_JENT_STREAM_V1 requested=(\d+) captured=(\d+) encoding=u64le "
    rb"osr=(\d+) version=(\d+) stuck=not-exposed health=(0x[0-9a-f]+) read=(-?\d+)\n"
)
TRAILER = re.compile(
    rb"\nVIBE_JENT_END (COMPLETE|HEALTH-FAIL) samples=(\d+) "
    rb"stuck=not-exposed health=(0x[0-9a-f]+) read=(-?\d+)\n"
)


def decode(
    source_path: Path,
    output_path: Path,
    metadata_path: Path | None,
    expect_samples: int | None = None,
) -> dict[str, object]:
    frame_hash = hashlib.sha256()
    data_hash = hashlib.sha256()
    temporary = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        with source_path.open("rb") as source:
            header = source.readline(4096)
            frame_hash.update(header)
            match = HEADER.fullmatch(header)
            if match is None:
                raise ValueError("invalid or truncated VIBE_JENT_STREAM_V1 header")
            requested, captured, osr, version = (int(value) for value in match.group(1, 2, 3, 4))
            header_health = int(match.group(5), 16)
            header_read = int(match.group(6))
            if requested <= 0 or captured > requested:
                raise ValueError("invalid requested/captured sample counts")
            if expect_samples is not None and requested != expect_samples:
                raise ValueError(
                    f"stream requested {requested} samples, expected {expect_samples}"
                )

            output_path.parent.mkdir(parents=True, exist_ok=True)
            remaining = captured * 8
            samples = 0
            with temporary.open("w", encoding="ascii", newline="\n") as output:
                while remaining:
                    chunk = source.read(min(64 * 1024, remaining))
                    if not chunk:
                        raise ValueError("stream ended inside the u64le payload")
                    if len(chunk) % 8:
                        raise ValueError("u64le payload chunk is not 8-byte aligned")
                    frame_hash.update(chunk)
                    for (delta,) in struct.iter_unpack("<Q", chunk):
                        line = f"{delta}\n"
                        output.write(line)
                        data_hash.update(line.encode("ascii"))
                        samples += 1
                    remaining -= len(chunk)

            trailer = source.read()
            frame_hash.update(trailer)
            trailer_match = TRAILER.fullmatch(trailer)
            if trailer_match is None:
                raise ValueError("invalid, missing, or trailing bytes after VIBE_JENT_END")
            status = trailer_match.group(1).decode("ascii")
            reported = int(trailer_match.group(2))
            trailer_health = int(trailer_match.group(3), 16)
            trailer_read = int(trailer_match.group(4))
            if reported != captured or samples != captured:
                raise ValueError("header, payload, and trailer sample counts disagree")
            if header_health != trailer_health or header_read != trailer_read:
                raise ValueError("header and trailer health state disagree")
            if (
                status != "COMPLETE"
                or captured != requested
                or header_health != 0
                or header_read != 0
            ):
                raise ValueError(
                    f"board rejected stream: status={status} captured={captured}/{requested} "
                    f"health={header_health:#x} read={header_read}"
                )
        temporary.replace(output_path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    result: dict[str, object] = {
        "format": "VIBE_JENT_STREAM_V1",
        "requested_samples": requested,
        "captured_samples": captured,
        "encoding": "u64le",
        "osr": osr,
        "jitterentropy_version": version,
        "health": header_health,
        "read_error": header_read,
        "frame": str(source_path.resolve()),
        "frame_sha256": frame_hash.hexdigest(),
        "data": str(output_path.resolve()),
        "data_sha256": data_hash.hexdigest(),
    }
    if metadata_path is not None:
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="raw SSH stdout frame")
    parser.add_argument("--output", required=True, type=Path, help="decimal .data output")
    parser.add_argument("--metadata", type=Path, help="optional JSON evidence record")
    parser.add_argument("--expect-samples", type=int)
    arguments = parser.parse_args()
    try:
        result = decode(
            arguments.input,
            arguments.output,
            arguments.metadata,
            arguments.expect_samples,
        )
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError) as error:
        parser.error(str(error))
        return 2


if __name__ == "__main__":
    sys.exit(main())
