#!/usr/bin/env python3
"""Run the upstream Jitterentropy masking flow with NIST SP800-90B tools."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

RUNTIME_SAMPLES = 1_000_000
RESTART_BLOCKS = 1_000
RESTART_SAMPLES = 1_000
UPSTREAM_370 = "e783cf1c450bce4d72f95c9f9c84546a6094976a"
MIN_ENTROPY_RE = re.compile(
    r"min\(H_original,\s*\d+\s*X\s*H_bitstring\):\s*([0-9.eE+-]+)"
)
H_R_RE = re.compile(r"^H_r:\s*([0-9.eE+-]+)\s*$", re.MULTILINE)
H_C_RE = re.compile(r"^H_c:\s*([0-9.eE+-]+)\s*$", re.MULTILINE)


def run(command: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode != 0:
        rendered = " ".join(command)
        raise RuntimeError(f"command failed ({completed.returncode}): {rendered}\n{completed.stdout}")
    return completed.stdout


def run_estimator(command: list[str]) -> tuple[int, str]:
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return completed.returncode, completed.stdout


def git_revision(path: Path) -> str:
    return run(["git", "rev-parse", "HEAD"], cwd=path).strip()


def validate_decimal_file(path: Path, expected: int) -> None:
    count = 0
    with path.open("r", encoding="ascii") as source:
        for line_number, line in enumerate(source, 1):
            value = line.strip()
            if not value or not value.isascii() or not value.isdecimal():
                raise ValueError(f"{path}:{line_number}: expected one unsigned decimal delta")
            parsed = int(value)
            if parsed > (1 << 64) - 1:
                raise ValueError(f"{path}:{line_number}: delta exceeds u64")
            count += 1
    if count != expected:
        raise ValueError(f"{path}: found {count} samples, expected {expected}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def masks(values: list[str]) -> list[tuple[str, int]]:
    parsed = []
    for value in values:
        try:
            mask_text, bits_text = value.split(":", 1)
            mask = int(mask_text, 16)
            bits = int(bits_text)
        except ValueError as error:
            raise ValueError(f"invalid mask {value!r}; expected HEX:BITS") from error
        if mask <= 0 or mask >= 1 << 64 or mask.bit_count() != bits or not 1 <= bits <= 8:
            raise ValueError(f"invalid mask {value!r}; mask must select exactly 1..8 bits")
        parsed.append((mask_text.upper(), bits))
    return parsed


def prepare_input(mode: str, source: Path, output: Path) -> tuple[Path, list[dict[str, str]]]:
    if mode == "runtime":
        validate_decimal_file(source, RUNTIME_SAMPLES)
        return source, [{"path": str(source.resolve()), "sha256": sha256(source)}]

    files = sorted(source.glob("jent-raw-noise-restart.*.data"))
    if len(files) != RESTART_BLOCKS:
        raise ValueError(f"{source}: found {len(files)} restart files, expected {RESTART_BLOCKS}")
    manifest = []
    consolidated = output / "jent-raw-noise-restart-consolidated.data"
    with consolidated.open("wb") as destination:
        for index, path in enumerate(files):
            expected_name = f"jent-raw-noise-restart.{index:06d}.data"
            if path.name != expected_name:
                raise ValueError(f"restart file {path.name!r}, expected {expected_name!r}")
            validate_decimal_file(path, RESTART_SAMPLES)
            manifest.append({"path": str(path.resolve()), "sha256": sha256(path)})
            with path.open("rb") as item:
                for chunk in iter(lambda: item.read(1024 * 1024), b""):
                    destination.write(chunk)
    return consolidated, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("runtime", "restart"), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--nist", type=Path, required=True)
    parser.add_argument("--mask", action="append", dest="mask_list")
    parser.add_argument("--osr", type=int, default=3)
    args = parser.parse_args()

    try:
        if platform.system() != "Linux":
            raise ValueError(
                "the upstream and NIST Makefiles require Linux/GCC; run this script in the "
                "pinned Ubuntu analysis container described in docs/JITTERENTROPY.md"
            )
        if args.osr <= 0:
            raise ValueError("OSR must be positive")
        threshold = 1.0 / args.osr
        selected_masks = masks(args.mask_list or ["FF:8"])
        upstream_revision = git_revision(args.upstream)
        nist_revision = git_revision(args.nist)
        if upstream_revision != UPSTREAM_370:
            raise ValueError(
                f"upstream revision is {upstream_revision}, expected Jitterentropy v3.7.0 "
                f"commit {UPSTREAM_370}"
            )

        validation = args.upstream / "tests" / "raw-entropy" / f"validation-{args.mode}"
        nist_cpp = args.nist / "cpp"
        args.output.mkdir(parents=True, exist_ok=True)
        input_path, inputs = prepare_input(args.mode, args.input, args.output)

        extract = validation / "extractlsb"
        run(["make", "clean"], cwd=validation)
        run(["make"], cwd=validation)
        nist_target = "non_iid" if args.mode == "runtime" else "restart"
        run(["make", nist_target], cwd=nist_cpp)
        estimator = nist_cpp / ("ea_non_iid" if args.mode == "runtime" else "ea_restart")

        results = []
        for mask, bits in selected_masks:
            binary = args.output / f"{args.mode}-{mask}-{bits}bits.data"
            binary.unlink(missing_ok=True)
            extract_log = run(
                [str(extract), str(input_path), str(binary), str(RUNTIME_SAMPLES), mask]
            )
            if binary.stat().st_size != RUNTIME_SAMPLES:
                raise ValueError(
                    f"{binary}: upstream extractor emitted {binary.stat().st_size} bytes, "
                    f"expected {RUNTIME_SAMPLES}"
            )
            if args.mode == "runtime":
                estimator_rc, estimate_log = run_estimator(
                    [str(estimator), "-i", "-a", "-v", str(binary), str(bits)]
                )
                match = MIN_ENTROPY_RE.search(estimate_log)
                estimate = float(match.group(1)) if match is not None else None
                detail = {"min_entropy_per_delta": estimate}
                passed = estimator_rc == 0 and estimate is not None and estimate > threshold
            else:
                estimator_rc, estimate_log = run_estimator(
                    [str(estimator), "-n", "-v", str(binary), str(bits), f"{threshold:.17g}"]
                )
                row = H_R_RE.search(estimate_log)
                column = H_C_RE.search(estimate_log)
                h_r = float(row.group(1)) if row is not None else None
                h_c = float(column.group(1)) if column is not None else None
                detail = {
                    "H_r": h_r,
                    "H_c": h_c,
                    "min_entropy_per_delta": min(h_r, h_c)
                    if h_r is not None and h_c is not None
                    else None,
                }
                passed = (
                    estimator_rc == 0
                    and h_r is not None
                    and h_c is not None
                    and h_r > threshold
                    and h_c > threshold
                )

            log_path = args.output / f"{args.mode}-{mask}-{bits}bits.nist.txt"
            log_path.write_text(extract_log + "\n" + estimate_log, encoding="utf-8")
            results.append(
                {
                    "mask": mask,
                    "bits_per_symbol": bits,
                    "binary_sha256": sha256(binary),
                    "nist_exit_code": estimator_rc,
                    **detail,
                    "threshold": threshold,
                    "pass_strictly_greater": passed,
                    "log": str(log_path.resolve()),
                }
            )

        report = {
            "mode": args.mode,
            "osr": args.osr,
            "required_min_entropy_per_delta": threshold,
            "comparison": "strictly greater than 1/OSR",
            "upstream_jitterentropy_revision": upstream_revision,
            "nist_entropy_assessment_revision": nist_revision,
            "inputs": inputs,
            "results": results,
            "pass": all(result["pass_strictly_greater"] for result in results),
        }
        report_path = args.output / f"{args.mode}-assessment.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 0 if report["pass"] else 1
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
        return 2


if __name__ == "__main__":
    sys.exit(main())
