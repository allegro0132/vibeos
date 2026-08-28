#!/usr/bin/env python3
"""Verify the C8.4 private single-cold-boot 24-sample collector closure."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass, replace
from functools import lru_cache
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
import tomllib
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
TRUSTED_VERIFIER_PATH = ROOT / "scripts/verify-c84-ssh-managed-child-trusted-sample.py"
PUBLISHER_VERIFIER_PATH = ROOT / "scripts/verify-c84-profile-publisher.py"
CRATE_MANIFEST = ROOT / "wasm-aot-profile/Cargo.toml"
CRATE_LIB = ROOT / "wasm-aot-profile/src/lib.rs"
COLLECTOR_SOURCE = ROOT / "wasm-aot-profile/src/collector.rs"
SLOT_SOURCE = ROOT / "kernel/src/wasm_aot_profile_slot.rs"
SSH_SOURCE = ROOT / "kernel/src/ssh_platform.rs"
SSHD_SOURCE = ROOT / "components/sshd/src/lib.rs"
TTY_SOURCE = ROOT / "kernel/src/tty.rs"
UART_SOURCE = ROOT / "kernel/src/uart.rs"
KERNEL_ROOT_SOURCE = ROOT / "kernel/src/lib.rs"
KERNEL_MANIFEST = ROOT / "kernel/Cargo.toml"
QEMU_MANIFEST = ROOT / "firmware/qemu-virt/Cargo.toml"
MILKV_MANIFEST = ROOT / "firmware/milkv-duo/Cargo.toml"
TESTING = ROOT / "TESTING.md"
DECISION_DOC = ROOT / "docs/WASM_AOT_DECISION.md"
ROADMAP = ROOT / "docs/WASM_ROADMAP.md"
CI = ROOT / ".github/workflows/ci.yml"
QEMU_SCRIPT = ROOT / "scripts/qemu-c84-ssh-managed-child-single-boot-collector-test.sh"
PEER_SCRIPT = ROOT / "scripts/c84-ssh-managed-child-single-boot-collector-peer.py"
MILKV_BUILD_SCRIPT = ROOT / "scripts/build-milkv-duo.sh"

FEATURE = "wasm-c84-ssh-managed-child-single-boot-collector"
QEMU_FEATURE = f"{FEATURE}-qemu-acceptance"
QEMU_DECISION_FEATURE = "wasm-c84-qemu-aot-decision"
QEMU_DECISION_SMOKE_FEATURE = f"{QEMU_DECISION_FEATURE}-smoke"
QEMU_PROFILE_FEATURE = "qemu-decision-v1"
QEMU_PROFILE_SMOKE_FEATURE = f"{QEMU_PROFILE_FEATURE}-smoke"
TRUSTED_FEATURE = "wasm-c84-ssh-managed-child-trusted-sample"
TRUSTED_QEMU_FEATURE = f"{TRUSTED_FEATURE}-qemu-acceptance"
FINISH_QEMU_FEATURE = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance"
FAMILY = "WASM_C84_SSH_MANAGED_CHILD_SINGLE_BOOT_COLLECTOR"
FORMAL_PREFIXES = (
    "VIBE_WASM_AOT_META ",
    "VIBE_WASM_AOT_SAMPLE ",
    "VIBE_WASM_AOT_END ",
)
COMMAND = (
    "python3 -B scripts/verify-c84-ssh-managed-child-single-boot-collector.py "
    "--selftest --check-source"
)
QEMU_COMMAND = "./scripts/qemu-c84-ssh-managed-child-single-boot-collector-test.sh"
PEER_COMMAND = "python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py --selftest"
PEER_SCRIPT_SHA256 = "ea942d9676d21f9ce0025cf0940b1b5f3838511f5405cd42a4b714e91c3217ca"
QEMU_SCRIPT_SHA256 = "b48a0048551bb90f144e5a4dbc66c938e9692a57931b324c1f03dc3a3647ef21"
KNOWN_TRANSCRIPT_BYTES = 34_386
KNOWN_TRANSCRIPT_SHA256 = "10df3a084b5817ee998c11e3eab0326fc2f16bdeba6644ce7e29e57c7bbc9da2"
QEMU_KNOWN_TRANSCRIPT_BYTES = 34_532
QEMU_KNOWN_TRANSCRIPT_SHA256 = "ee94947964ea80cdbfd4df6abdcaac1bcfe65a6e397348e6728bddada64d3cdd"
QEMU_SMOKE_KNOWN_TRANSCRIPT_BYTES = 34_542
QEMU_SMOKE_KNOWN_TRANSCRIPT_SHA256 = "6f5dee3156f8950defd10e17a163a7919afbe90ec0249bfac17e74b498b33b69"
QEMU_TEST_RUN_ID = "778d0d6347155998628068092e55ce527fe2049b01082a0099f61d62138e047c"
QEMU_SMOKE_TEST_RUN_ID = "8e196b877e4dcf562e6788ab0516c218b53959862b3b0b0bab4de758cf78d906"

MANIFEST_SHA256 = "87026895f2207d85a04f5c04f11420530f1c8f922391f71915f173b18dcfd9d8"
SCHEMA_SHA256 = "b608aa3de46aac1a73fb321babdcd4ad18ec43c60b54760f53b9e5e8d317bf3a"
QEMU_MANIFEST_SHA256 = "339bb27af9a4d24cf5440349777a2113c7ac815bc0289c2fc233426aac3402ef"
QEMU_SCHEMA_SHA256 = "0df879bea905ac1967685fdb411f017acf0136a69999ee031f71af76509eb520"
ARTIFACT_SHA256 = "180ed444de8b6c9ecd828b369d4c8b9f783758ef22c0b17170682d71f2fd0e72"
INPUT_SHA256 = "6b6054d492e00e68a93bc9b657a69577c7c44f5a48f169adb4124df0a50f6b3c"
OUTPUT_SHA256 = "791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TRUSTED = load_module(TRUSTED_VERIFIER_PATH, "vibeos_c84_collector_trusted_verifier")
PUBLISHER = load_module(PUBLISHER_VERIFIER_PATH, "vibeos_c84_collector_publisher_verifier")
PHASE = TRUSTED.PHASE


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


_RAW_STRING_START = re.compile(r'r(#+)?"')
_CHAR_LITERAL = re.compile(r"'(?:\\.|[^\\'\r\n])'")


@lru_cache(maxsize=256)
def rust_mask(source: str, *, literals: bool = True) -> str:
    """Mask Rust comments and optionally literals while preserving offsets."""

    output = list(source)
    index = 0
    block_depth = 0
    state = "code"
    raw_hashes = 0

    def blank(start: int, end: int) -> None:
        for cursor in range(start, end):
            if output[cursor] not in "\r\n":
                output[cursor] = " "

    while index < len(source):
        if state == "line-comment":
            if source[index] in "\r\n":
                state = "code"
            else:
                blank(index, index + 1)
            index += 1
            continue
        if state == "block-comment":
            if source.startswith("/*", index):
                blank(index, index + 2)
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                blank(index, index + 2)
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                blank(index, index + 1)
                index += 1
            continue
        if state in ("string", "char"):
            quote = '"' if state == "string" else "'"
            if source[index] == "\\":
                if literals:
                    blank(index, min(index + 2, len(source)))
                index += 2
            elif source[index] == quote:
                if literals:
                    blank(index, index + 1)
                index += 1
                state = "code"
            else:
                if literals:
                    blank(index, index + 1)
                index += 1
            continue
        if state == "raw-string":
            ending = '"' + "#" * raw_hashes
            if source.startswith(ending, index):
                if literals:
                    blank(index, index + len(ending))
                index += len(ending)
                state = "code"
            else:
                if literals:
                    blank(index, index + 1)
                index += 1
            continue

        if source.startswith("//", index):
            blank(index, index + 2)
            index += 2
            state = "line-comment"
            continue
        if source.startswith("/*", index):
            blank(index, index + 2)
            index += 2
            block_depth = 1
            state = "block-comment"
            continue
        raw = _RAW_STRING_START.match(source, index)
        if raw is not None:
            raw_hashes = len(raw.group(1) or "")
            if literals:
                blank(index, raw.end())
            index = raw.end()
            state = "raw-string"
            continue
        if source[index] == '"':
            if literals:
                blank(index, index + 1)
            index += 1
            state = "string"
            continue
        if source[index] == "'" and _CHAR_LITERAL.match(source, index) is not None:
            if literals:
                blank(index, index + 1)
            index += 1
            state = "char"
            continue
        index += 1

    require(state not in ("block-comment", "string", "char", "raw-string"), "unterminated Rust lexical item")
    return "".join(output)


def semantic(value: str) -> str:
    return re.sub(r"\s+", "", rust_mask(value, literals=False))


def comment_masked(value: str) -> str:
    return rust_mask(value, literals=False)


@dataclass(frozen=True)
class Scope:
    raw: str
    code: str
    start: int
    end: int


def find_scope(source: str, header: str, label: str, *, match_literals: bool = False) -> Scope:
    masked = rust_mask(source)
    searchable = rust_mask(source, literals=False) if match_literals else masked
    matches = list(re.finditer(header, searchable))
    require(len(matches) == 1, f"{label} count differs: {len(matches)}")
    match = matches[0]
    opening = masked.find("{", match.end())
    require(opening >= 0, f"{label} has no body")
    depth = 0
    for cursor in range(opening, len(masked)):
        if masked[cursor] == "{":
            depth += 1
        elif masked[cursor] == "}":
            depth -= 1
            if depth == 0:
                return Scope(source[match.start() : cursor + 1], masked[match.start() : cursor + 1], match.start(), cursor + 1)
    raise VerificationError(f"{label} body is unbalanced")


def find_function(scope: Scope, name: str, label: str) -> Scope:
    return find_scope(
        scope.raw,
        rf"\b(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?fn\s+{re.escape(name)}\b",
        label,
    )


def direct_feature_units(source: str, feature: str) -> list[str]:
    """Extract units guarded by one direct exact cfg without quadratic slicing."""

    masked = rust_mask(source, literals=False)
    assignment = rf'feature\s*=\s*"{re.escape(feature)}"'
    attribute = re.compile(rf'#\s*\[\s*cfg\s*\(\s*{assignment}\s*\)\s*\]')

    def matching(opening: int, left: str, right: str) -> int:
        depth = 0
        for cursor in range(opening, len(masked)):
            if masked[cursor] == left:
                depth += 1
            elif masked[cursor] == right:
                depth -= 1
                if depth == 0:
                    return cursor + 1
        raise VerificationError(f"unbalanced {left}{right} after direct {feature} cfg")

    units: list[str] = []
    for match in attribute.finditer(masked):
        cursor = match.end()
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        require(cursor < len(masked), f"direct {feature} cfg has no syntax unit")
        while masked.startswith("#[", cursor):
            cursor = matching(cursor + 1, "[", "]")
            while cursor < len(masked) and masked[cursor].isspace():
                cursor += 1

        parens = brackets = braces = 0
        first_brace = -1
        end = -1
        index = cursor
        while index < len(masked):
            character = masked[index]
            if character == "(":
                parens += 1
            elif character == ")":
                parens -= 1
            elif character == "[":
                brackets += 1
            elif character == "]":
                brackets -= 1
            elif character == "{":
                if parens == 0 and brackets == 0 and braces == 0 and first_brace < 0:
                    first_brace = index
                braces += 1
            elif character == "}":
                braces -= 1
                if braces == 0 and first_brace >= 0 and parens == 0 and brackets == 0:
                    end = index + 1
                    probe = end
                    while probe < len(masked) and masked[probe].isspace():
                        probe += 1
                    if probe < len(masked) and masked[probe] == ";":
                        end = probe + 1
                    break
            elif character in ";," and parens == 0 and brackets == 0 and braces == 0:
                end = index + 1
                break
            require(parens >= 0 and brackets >= 0 and braces >= 0, f"unbalanced direct {feature} cfg unit")
            index += 1
        require(end >= 0, f"direct {feature} cfg syntax unit is unterminated")
        units.append(source[match.start() : end])
    return units


def exact_semantic(source: str, snippet: str, label: str, *, count: int = 1) -> None:
    observed = semantic(source).count(semantic(snippet))
    require(observed == count, f"{label} semantic count differs: {observed}")


def ordered_semantic(source: str, snippets: tuple[str, ...], label: str) -> None:
    code = semantic(source)
    positions: list[int] = []
    for snippet in snippets:
        needle = semantic(snippet)
        matches: list[int] = []
        cursor = 0
        while True:
            position = code.find(needle, cursor)
            if position < 0:
                break
            matches.append(position)
            cursor = position + 1
        require(len(matches) == 1, f"{label}: {snippet!r} count differs: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} order differs")


def visible_methods(source: str) -> tuple[str, ...]:
    return tuple(
        re.findall(
            r'\bpub(?:\([^)]*\))?\s+(?:(?:const|async|unsafe)\s+|extern(?:\s+"[^"]*")?\s+)*fn\s+([A-Za-z_]\w*)\b',
            comment_masked(source),
        )
    )


def production(source: str, label: str) -> str:
    marker = "\n#[cfg(test)]\nmod tests"
    require(source.count(marker) == 1, f"{label} cfg(test) boundary differs")
    return source.split(marker, 1)[0]


@dataclass(frozen=True)
class Inputs:
    trusted_predecessor: Any
    publisher_predecessor: Any
    crate_manifest: bytes
    crate_lib: str
    collector: str
    slot: str
    ssh: str
    sshd: str
    tty: str
    uart: str
    kernel_root: str
    kernel_manifest: bytes
    qemu_manifest: bytes
    milkv_manifest: bytes
    testing: str
    decision_doc: str
    roadmap: str
    ci: str
    qemu_script: bytes
    peer_script: bytes
    milkv_build_script: bytes


def load_inputs() -> Inputs:
    return Inputs(
        trusted_predecessor=TRUSTED.load_inputs(),
        publisher_predecessor=PUBLISHER.load_inputs(),
        crate_manifest=CRATE_MANIFEST.read_bytes(),
        crate_lib=CRATE_LIB.read_text(encoding="utf-8"),
        collector=COLLECTOR_SOURCE.read_text(encoding="utf-8"),
        slot=SLOT_SOURCE.read_text(encoding="utf-8"),
        ssh=SSH_SOURCE.read_text(encoding="utf-8"),
        sshd=SSHD_SOURCE.read_text(encoding="utf-8"),
        tty=TTY_SOURCE.read_text(encoding="utf-8"),
        uart=UART_SOURCE.read_text(encoding="utf-8"),
        kernel_root=KERNEL_ROOT_SOURCE.read_text(encoding="utf-8"),
        kernel_manifest=KERNEL_MANIFEST.read_bytes(),
        qemu_manifest=QEMU_MANIFEST.read_bytes(),
        milkv_manifest=MILKV_MANIFEST.read_bytes(),
        testing=TESTING.read_text(encoding="utf-8"),
        decision_doc=DECISION_DOC.read_text(encoding="utf-8"),
        roadmap=ROADMAP.read_text(encoding="utf-8"),
        ci=CI.read_text(encoding="utf-8"),
        qemu_script=QEMU_SCRIPT.read_bytes(),
        peer_script=PEER_SCRIPT.read_bytes(),
        milkv_build_script=MILKV_BUILD_SCRIPT.read_bytes(),
    )


def verify_manifest(raw: bytes) -> None:
    try:
        manifest = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"collector crate manifest is invalid: {error}") from error
    require(manifest.get("package", {}).get("name") == "vibeos-wasm-aot-profile", "collector crate name differs")
    require(
        manifest.get("dependencies")
        == {"sha2": {"version": "=0.11.0", "default-features": False}},
        "collector dependency set is not exact no_std sha2 0.11.0",
    )
    require(
        manifest.get("features")
        == {
            "default": [],
            QEMU_PROFILE_FEATURE: [],
            QEMU_PROFILE_SMOKE_FEATURE: [QEMU_PROFILE_FEATURE],
        },
        "collector crate feature table is not the exact default Duo/formal-QEMU/smoke selector",
    )
    require("build" not in manifest.get("package", {}), "collector gained a build script")
    require(not (ROOT / "wasm-aot-profile/build.rs").exists(), "collector has an ambient build.rs")


def verify_lib(source: str) -> None:
    code = semantic(source)
    docs = " ".join(
        line.removeprefix("//!").strip()
        for line in source.splitlines()
        if line.startswith("//!")
    )
    require(code.count("modcollector;") == 1, "collector module declaration differs")
    require(code.count("pubusecollector::{") == 1, "collector re-export group differs")
    for name in (
        "BootCollector",
        "BootReceipt",
        "Campaign",
        "CampaignError",
        "CollectionFailure",
        "CollectionProgress",
        "CollectorAbort",
        "CollectorFault",
        "CollectorReady",
        "CompletedTerminal",
        "PendingEnd",
        "PendingTerminal",
        "PoisonedTerminal",
        "PoisonedTranscript",
        "ProfileRecordSinkFactory",
        "RecordStage",
        "BOOT_RETAINED",
        "BOOT_SAMPLES",
        "BOOT_WARMUPS",
    ):
        require(name in code, f"collector export {name} is missing")
    require(
        "build-bound META + 24 SAMPLE prefix" in docs
        and "sole [`PendingEnd`] authority" in docs
        and "append END only after its remaining acceptance checks pass" in docs,
        "crate docs omit the deferred 26-record closure",
    )
    require(
        "default record contract is Duo-v1" in docs
        and "`qemu-decision-v1` feature selects a disjoint emulator-scoped" in docs,
        "crate docs do not separate the default Duo and formal-QEMU record contracts",
    )


def verify_collector_types(source: str) -> str:
    code = production(source, "collector")
    masked = comment_masked(code)
    for forbidden in (
        "extern crate alloc",
        "alloc::",
        "Vec<",
        "String",
        "Box<",
        "serde",
        "format!(",
        "to_string(",
        "unsafe ",
        "unsafe{",
        "std::",
    ):
        require(forbidden not in code, f"collector production uses forbidden {forbidden!r}")
    exact_semantic(code, "pub const BOOT_SAMPLES: u8 = 24;", "sample count")
    exact_semantic(code, "pub const BOOT_WARMUPS: u8 = 3;", "warmup count")
    exact_semantic(code, "pub const BOOT_RETAINED: usize = 21;", "retained count")
    exact_semantic(code, 'const META_PREFIX: &[u8] = b"VIBE_WASM_AOT_META ";', "META prefix")
    exact_semantic(code, 'const END_PREFIX: &[u8] = b"VIBE_WASM_AOT_END ";', "END prefix")
    for digest in (MANIFEST_SHA256, SCHEMA_SHA256, ARTIFACT_SHA256, INPUT_SHA256, OUTPUT_SHA256):
        require(masked.count(digest) == 1, f"frozen collector digest {digest} count differs")
    for digest in (QEMU_MANIFEST_SHA256, QEMU_SCHEMA_SHA256):
        require(masked.count(digest) == 1, f"formal-QEMU collector digest {digest} count differs")
    for exact, label in (
        (
            '#[cfg(not(feature="qemu-decision-v1"))]constRUN_ID_DOMAIN:&[u8]='
            'b"vibeos.c84.aot-decision.run-id.v1";',
            "default Duo run-id domain",
        ),
        (
            '#[cfg(all(feature="qemu-decision-v1",not(feature="qemu-decision-v1-smoke")))]'
            'constRUN_ID_DOMAIN:&[u8]='
            'b"vibeos.c84.qemu-aot-decision.run-id.v1";',
            "formal-QEMU run-id domain",
        ),
        (
            '#[cfg(feature="qemu-decision-v1-smoke")]constRUN_ID_DOMAIN:&[u8]='
            'b"vibeos.c84.qemu-aot-decision.smoke.run-id.v1";',
            "dirty-smoke QEMU run-id domain",
        ),
        (
            f'#[cfg(not(feature="qemu-decision-v1"))]constMANIFEST_SHA256:&str="{MANIFEST_SHA256}";',
            "default Duo manifest identity",
        ),
        (
            f'#[cfg(feature="qemu-decision-v1")]constMANIFEST_SHA256:&str="{QEMU_MANIFEST_SHA256}";',
            "formal-QEMU manifest identity",
        ),
        (
            f'#[cfg(not(feature="qemu-decision-v1"))]constTRANSCRIPT_SCHEMA_SHA256:&str="{SCHEMA_SHA256}";',
            "default Duo schema identity",
        ),
        (
            f'#[cfg(feature="qemu-decision-v1")]constTRANSCRIPT_SCHEMA_SHA256:&str="{QEMU_SCHEMA_SHA256}";',
            "formal-QEMU schema identity",
        ),
        (
            '#[cfg(not(feature="qemu-decision-v1"))]constSTABILITY_PERCENT:u128=150;',
            "default Duo stability ceiling",
        ),
        (
            '#[cfg(feature="qemu-decision-v1")]constSTABILITY_PERCENT:u128=110;',
            "formal-QEMU stability ceiling",
        ),
        (
            '#[cfg(all(feature="qemu-decision-v1",not(feature="qemu-decision-v1-smoke")))]'
            'constCAPTURE_MODE:&[u8]=b"formal-publication";',
            "formal-QEMU capture mode",
        ),
        (
            '#[cfg(all(feature="qemu-decision-v1",not(feature="qemu-decision-v1-smoke")))]'
            'constDECISION_ELIGIBLE:&[u8]=b"true";',
            "formal-QEMU decision eligibility",
        ),
        (
            '#[cfg(feature="qemu-decision-v1-smoke")]constCAPTURE_MODE:&[u8]='
            'b"dirty-smoke-not-publication";',
            "dirty-smoke capture mode",
        ),
        (
            '#[cfg(feature="qemu-decision-v1-smoke")]constDECISION_ELIGIBLE:&[u8]=b"false";',
            "dirty-smoke decision eligibility",
        ),
    ):
        require(exact in semantic(code), f"{label} differs")

    exact_semantic(
        code,
        """
        pub trait ProfileRecordSinkFactory {
            type Error;
            type Record: ProfileRecordSink<Error = Self::Error>;
            fn begin_record(&mut self) -> Result<Self::Record, Self::Error>;
        }
        """,
        "record factory surface",
    )
    campaign = find_scope(code, r"\bimpl\s+Campaign\b", "Campaign impl")
    require(visible_methods(campaign.raw) == ("from_bound_build", "begin"), "Campaign public surface differs")
    require("fnfrom_values(" in semantic(campaign.raw) and "pubfnfrom_values(" not in semantic(campaign.raw), "raw campaign constructor is exposed")
    for environment in ("VIBEOS_C84_SOURCE_COMMIT", "VIBEOS_C84_CHALLENGE"):
        exact_semantic(campaign.raw, f'option_env!("{environment}")', f"{environment} binding")
    ordered_semantic(
        campaign.raw,
        (
            "decode_hex::<20>(source_commit)",
            "source_commit_bytes.iter().all(|byte| *byte == 0)",
            "decode_hex::<32>(challenge_text)",
            "Challenge::new(challenge_bytes)",
            "let mut run_id = Sha256::new()",
            "run_id.update(RUN_ID_DOMAIN)",
            "RunId::new(run_id.finalize().into())",
        ),
        "build-bound identity validation",
    )
    exact_semantic(
        campaign.raw,
        """
        for field in [
            source_commit,
            challenge_text,
            ARTIFACT_SHA256,
            INPUT_SHA256,
            OUTPUT_SHA256,
            MANIFEST_SHA256,
            TRANSCRIPT_SCHEMA_SHA256,
        ] {
            run_id.update(b"\\0");
            run_id.update(field.as_bytes());
        }
        """,
        "run-id field order",
    )
    exact_semantic(
        code,
        """
        const fn hex_nibble(value: u8) -> Option<u8> {
            match value {
                b'0'..=b'9' => Some(value - b'0'),
                b'a'..=b'f' => Some(value - b'a' + 10),
                _ => None,
            }
        }
        """,
        "canonical lowercase build identity decoder",
    )

    collector = find_scope(code, r"\bpub\s+struct\s+BootCollector\b", "BootCollector")
    collector_code = semantic(collector.raw)
    for field in (
        "factory:ManuallyDrop<F>",
        "campaign:Campaign",
        "next_sample:u8",
        "expected_epoch:u64",
        "accumulator:u64",
        "retained_ticks:[u64;BOOT_RETAINED]",
        "retained_count:u8",
        "not_sync:PhantomData<Cell<()>>",
    ):
        require(field in collector_code, f"private collector field {field!r} differs")
    require("pubfactory:" not in collector_code and "pubnext_sample:" not in collector_code, "collector internals are public")
    collector_impl = find_scope(code, r"\bimpl<F:\s*ProfileRecordSinkFactory>\s+BootCollector<F>", "BootCollector impl")
    require(visible_methods(collector_impl.raw) == ("collect", "quarantine_attempt"), "collector public method surface differs")
    for forbidden_method in ("finish", "reset", "retry", "rollback", "skip", "sink", "factory", "set_index", "set_accumulator"):
        require(not re.search(rf"\bpub(?:\([^)]*\))?\s+fn\s+{forbidden_method}\b", masked), f"collector exposes {forbidden_method}")
    for type_name in (
        "Campaign",
        "BootCollector",
        "CollectorReady",
        "PendingTerminal",
        "PendingEnd",
        "CompletedTerminal",
        "PoisonedTerminal",
        "PoisonedTranscript",
    ):
        require(
            not re.search(rf"#\s*\[\s*derive[^]]*(Clone|Copy)[^]]*\]\s*pub\s+struct\s+{type_name}\b", masked),
            f"linear collector type became Clone/Copy: {type_name}",
        )
    ready_impl = find_scope(code, r"\bimpl<'a,\s*F:\s*ProfileRecordSinkFactory>\s+CollectorReady", "CollectorReady impl")
    require(visible_methods(ready_impl.raw) == ("ready_next_epoch", "into_next"), "CollectorReady leaks index/factory state")
    pending_impl = find_scope(code, r"\bimpl<'a,\s*F:\s*ProfileRecordSinkFactory>\s+PendingTerminal", "PendingTerminal impl")
    require(
        visible_methods(pending_impl.raw) == ("ready_next_epoch", "receipt", "into_parts"),
        "pending terminal leaks or omits Ready/END authority",
    )
    pending_end_impl = find_scope(
        code,
        r"\bimpl<F:\s*ProfileRecordSinkFactory>\s+PendingEnd",
        "PendingEnd impl",
    )
    require(
        visible_methods(pending_end_impl.raw)
        == ("receipt", "commit_terminal", "discard_terminal"),
        "pending END exposes retry/factory state or omits explicit disposal",
    )
    complete_impl = find_scope(
        code,
        r"\bimpl<F:\s*ProfileRecordSinkFactory>\s+CompletedTerminal",
        "CompletedTerminal impl",
    )
    require(visible_methods(complete_impl.raw) == ("receipt",), "completed terminal surface differs")
    terminal_poison_impl = find_scope(
        code,
        r"\bimpl<F:\s*ProfileRecordSinkFactory>\s+PoisonedTerminal",
        "PoisonedTerminal impl",
    )
    require(
        visible_methods(terminal_poison_impl.raw)
        == ("stage", "committed_records", "failure", "receipt"),
        "terminal poison exposes retry/factory state",
    )
    poison_impl = find_scope(code, r"\bimpl<'a,\s*F:\s*ProfileRecordSinkFactory>\s+PoisonedTranscript", "PoisonedTranscript impl")
    require(
        visible_methods(poison_impl.raw) == ("stage", "committed_records", "failure", "ready_next_epoch", "into_ready"),
        "poison surface exposes retry/factory/END",
    )
    require(
        "factory:ManuallyDrop<F>" in semantic(code)
        and "_factory:ManuallyDrop<F>" in semantic(code),
        "pending/closed factory is not quarantined",
    )
    for type_name in (
        "BootCollector",
        "CollectorReady",
        "PendingTerminal",
        "PendingEnd",
        "CompletedTerminal",
        "PoisonedTerminal",
        "PoisonedTranscript",
    ):
        require(
            not re.search(rf"\bimpl(?:<[^{{}};]*>)?\s+Drop\s+for\s+{type_name}\b", masked),
            f"linear collector type gained a recovery Drop impl: {type_name}",
        )
    receipt = find_scope(code, r"\bpub\s+struct\s+BootReceipt\b", "boot receipt")
    require(
        semantic(receipt.raw)
        == (
            "pubstructBootReceipt{samples:u8,warmups:u8,retained:u8,accumulator:u64,"
            "retained_p50:u64,retained_p95:u64,}"
        ),
        "closed receipt field surface differs",
    )
    progress = find_scope(code, r"\bpub\s+enum\s+CollectionProgress\b", "collection progress")
    require(
        semantic(progress.raw)
        == (
            "pubenumCollectionProgress<'a,F:ProfileRecordSinkFactory>{"
            "More(CollectorReady<'a,F>),PendingTerminal(PendingTerminal<'a,F>),}"
        ),
        "collector progress does not expose exactly More or PendingTerminal",
    )
    return code


def verify_campaign_begin(code: str) -> None:
    campaign = find_scope(code, r"\bimpl\s+Campaign\b", "Campaign impl")
    begin = find_function(campaign, "begin", "Campaign begin")
    begin_code = semantic(begin.raw)
    ordered_semantic(
        begin.raw,
        (
            "let mut factory = ManuallyDrop::new(factory)",
            "let Some(first_epoch) = ready.next_epoch() else",
            "if first_epoch > u64::MAX - last_epoch_delta",
            "(&mut *factory).begin_record()",
            "let mut record = ManuallyDrop::new(record)",
            "write_meta(&mut *record, &self)",
            "record.commit_record()",
            "next_sample: 0",
            "expected_epoch: first_epoch",
            "accumulator: 0",
            "retained_ticks: [0; BOOT_RETAINED]",
            "retained_count: 0",
        ),
        "META-before-collector transition",
    )
    require(begin_code.count("begin_record()") == 1, "Campaign begin can emit another META")
    require(begin_code.count("write_meta(") == 1 and begin_code.count("commit_record()") == 1, "META record path differs")
    require("wrapping_" not in begin_code and "saturating_" not in begin_code, "epoch budget uses lossy arithmetic")


def verify_collect_flow(code: str) -> None:
    impl = find_scope(code, r"\bimpl<F:\s*ProfileRecordSinkFactory>\s+BootCollector<F>", "BootCollector impl")
    collect = find_function(impl, "collect", "collector collect")
    collect_code = semantic(collect.raw)
    require(
        semantic("verified: TargetVerified<'a>, terminal: EligibleTerminalEvidence") in collect_code,
        "collector does not consume both verified authorities by value",
    )
    require("sample_index:" not in semantic(collect.raw.split("->", 1)[0]), "caller supplies the sample index")
    ordered_semantic(
        collect.raw,
        (
            "let sample_index = self.next_sample",
            "if self.next_sample >= BOOT_SAMPLES",
            "let actual_epoch = verified.token().epoch()",
            "if actual_epoch != self.expected_epoch",
            "let total_ticks = verified.summary().total_ticks()",
            "let record = match (&mut *self.factory).begin_record()",
            "ProfilePublisher::new(record, self.campaign.binding, self.accumulator)",
            "publisher.publish_profile(verified, self.next_sample, terminal)",
            "ready.next_epoch() != expected_next_epoch",
            "if self.next_sample >= BOOT_WARMUPS",
            "self.retained_ticks[retained_index] = total_ticks",
            "self.retained_count += 1",
            "self.accumulator = accumulator",
            "self.next_sample += 1",
            "self.expected_epoch = expected_next_epoch.unwrap_or(u64::MAX)",
            "if self.next_sample < BOOT_SAMPLES",
            "retained_percentiles(self.retained_ticks)",
            "u128::from(p95) * 100 > u128::from(p50) * STABILITY_PERCENT",
            "let receipt = BootReceipt",
            "CollectionProgress::PendingTerminal",
            "pending_end: Some(PendingEnd",
        ),
        "checked SAMPLE chain and pending-END handoff",
    )
    for forbidden in ("wrapping_add", "saturating_add", "wrapping_sub", "saturating_sub"):
        require(forbidden not in collect_code, f"collector uses lossy sequence arithmetic {forbidden}")
    require(collect_code.count("ProfilePublisher::new(") == 1, "collector bypasses or duplicates publisher")
    require(collect_code.count("publish_profile(") == 1, "collector bypasses or duplicates SAMPLE publication")
    require(
        "write_end(" not in collect_code
        and "commit_terminal(" not in collect_code
        and collect_code.count("CollectionProgress::PendingTerminal(") == 1,
        "SAMPLE collection can commit END or duplicate the pending terminal",
    )
    require("ManuallyDrop::new(record)" in collect_code, "successful SAMPLE record destructor is not suppressed")
    require("ManuallyDrop::new(publisher)" in collect_code, "preflight-acquired record is not quarantined")
    exact_semantic(
        collect.raw,
        """
        let receipt = BootReceipt {
            samples: BOOT_SAMPLES,
            warmups: BOOT_WARMUPS,
            retained: BOOT_RETAINED as u8,
            accumulator: self.accumulator,
            retained_p50: p50,
            retained_p95: p95,
        };
        """,
        "closed receipt values",
    )

    pending_terminal_impl = find_scope(
        code,
        r"\bimpl<'a,\s*F:\s*ProfileRecordSinkFactory>\s+PendingTerminal",
        "pending terminal split",
    )
    into_parts = find_function(pending_terminal_impl, "into_parts", "pending terminal split")
    ordered_semantic(
        into_parts.raw,
        (
            'self.ready.take().expect("pending terminal Ready consumed once")',
            'self.pending_end.take().expect("pending END consumed once")',
            "(ready, pending_end)",
        ),
        "Ready/pending-END authority split",
    )

    pending_end_impl = find_scope(
        code,
        r"\bimpl<F:\s*ProfileRecordSinkFactory>\s+PendingEnd",
        "pending END impl",
    )
    commit_terminal = find_function(pending_end_impl, "commit_terminal", "terminal END commit")
    ordered_semantic(
        commit_terminal.raw,
        (
            "(&mut *self.factory).begin_record()",
            "let mut end_record = ManuallyDrop::new(end_record)",
            "write_end(&mut *end_record, self.binding, self.receipt.accumulator)",
            "end_record.commit_record()",
            "Ok(CompletedTerminal",
        ),
        "sole deferred END commit",
    )
    terminal_code = semantic(commit_terminal.raw)
    require(
        terminal_code.count("begin_record()") == 1
        and terminal_code.count("write_end(") == 1
        and terminal_code.count("commit_record()") == 1,
        "pending END can acquire, write, or commit more than one record",
    )
    discard_terminal = find_function(pending_end_impl, "discard_terminal", "terminal END discard")
    require(
        not any(
            operation in semantic(discard_terminal.raw)
            for operation in ("begin_record(", "write_end(", "commit_record(")
        ),
        "discarding pending END can touch the sink",
    )

    quarantine = find_function(impl, "quarantine_attempt", "collector attempt quarantine")
    ordered_semantic(
        quarantine.raw,
        (
            "let expected = self.expected_epoch.checked_add(1)",
            "let actual = ready.next_epoch()",
            "if actual != expected",
            "CollectorAbort::TerminalRejected",
            "CollectorAbort::TargetRejected",
            "CollectorAbort::OwnerMismatch",
            "self.poison(",
        ),
        "failed-attempt quarantine",
    )
    require("write_end(" not in semantic(quarantine.raw), "failed attempt can emit END")
    require(
        semantic(quarantine.raw).count("letstage=RecordStage::Sample(self.next_sample);") == 1
        and "RecordStage::End" not in semantic(quarantine.raw)
        and "write_end" not in semantic(quarantine.raw),
        "failed attempt can claim or emit END",
    )

    percentiles = find_scope(code, r"\bfn\s+retained_percentiles\b", "retained percentile helper")
    percentile_code = semantic(percentiles.raw)
    require("ticks[10]" in percentile_code and "ticks[19]" in percentile_code, "nearest-rank p50/p95 indices differ")
    require("sort_unstable" not in percentile_code and "alloc" not in percentile_code, "retained percentile path allocates")


def verify_serializers(code: str) -> None:
    serializers = semantic(code)
    require(
        serializers.count("fnwrite_meta<") == 2
        and '#[cfg(not(feature="qemu-decision-v1"))]fnwrite_meta<' in serializers
        and '#[cfg(feature="qemu-decision-v1")]fnwrite_meta<' in serializers,
        "default Duo and formal-QEMU META serializers are not exactly disjoint",
    )
    meta = find_scope(
        code,
        r'#\[cfg\(not\(feature\s*=\s*"qemu-decision-v1"\)\)\]\s*fn\s+write_meta\b',
        "default Duo META serializer",
        match_literals=True,
    )
    qemu_meta = find_scope(
        code,
        r'#\[cfg\(feature\s*=\s*"qemu-decision-v1"\)\]\s*fn\s+write_meta\b',
        "formal-QEMU META serializer",
        match_literals=True,
    )
    end = find_scope(code, r"\bfn\s+write_end\b", "END serializer")
    meta_code = semantic(meta.raw)
    qemu_meta_code = semantic(qemu_meta.raw)
    end_code = semantic(end.raw)
    require(meta_code.count("sink.write_all(") == 15, "default Duo META serializer fragment count differs")
    require(qemu_meta_code.count("sink.write_all(") == 19, "formal-QEMU META serializer fragment count differs")
    require(end_code.count("sink.write_all(") == 5, "END serializer fragment count differs")
    for required in (
        '"artifact_bytes":2012',
        '"budget_ticks":2500000',
        '"clock":"riscv.rdtime"',
        '"decision_eligible":true',
        '"hart_count":1',
        '"hart_id":0',
        '"input_bytes":12325',
        '"output_bytes":12325',
        '"platform":"milkv-duo-cv1800b"',
        '"required_cold_boots":3',
        '"retained_per_boot":21',
        '"samples_per_boot":24',
        '"schema":"vibeos.wasm-aot-decision.meta"',
        '"suite_id":"vibeos.c84.aot-decision"',
        '"timebase_hz":25000000',
        '"transcript_scope":"single-cold-boot"',
        '"version":1',
        '"warmup_per_boot":3',
        '"workload_id":"ssh-case-filter-12k-v1"',
        '"workload_revision":1',
    ):
        require(required.replace('"', '\\"') in meta.raw, f"META frozen field differs: {required}")
    for required in (
        '"artifact_bytes":2012',
        '"budget_ticks":1000000',
        '"capture_mode":"',
        '"clock":"riscv.rdtime"',
        '"decision_eligible":',
        '"hart_count":1',
        '"hart_id":0',
        '"input_bytes":12325',
        '"output_bytes":12325',
        '"physical_provenance":"not-claimed"',
        '"platform":"qemu-virt-rv64-tcg-icount-v1"',
        '"platform_class":"emulator"',
        '"required_qemu_boots":1',
        '"retained_per_boot":21',
        '"samples_per_boot":24',
        '"schema":"vibeos.wasm-aot-decision.meta"',
        '"suite_id":"vibeos.c84.qemu-aot-decision"',
        '"timebase_hz":10000000',
        '"transcript_scope":"one-fresh-fixed-qemu-process-no-physical-claim"',
        '"version":1',
        '"warmup_per_boot":3',
        '"workload_id":"ssh-case-filter-12k-v1"',
        '"workload_revision":1',
    ):
        require(required.replace('"', '\\"') in qemu_meta.raw, f"formal-QEMU META frozen field differs: {required}")
    require(
        qemu_meta_code.count("sink.write_all(CAPTURE_MODE)") == 1
        and qemu_meta_code.count("sink.write_all(DECISION_ELIGIBLE)") == 1,
        "formal-QEMU META does not source its capture/eligibility fields exactly once",
    )
    for required in (
        '"retained":21',
        '"samples":24',
        '"schema":"vibeos.wasm-aot-decision.end"',
        '"version":1',
        '"warmups":3',
    ):
        require(required.replace('"', '\\"') in end.raw, f"END frozen field differs: {required}")
    require(
        "commit_record" not in meta_code
        and "commit_record" not in qemu_meta_code
        and "commit_record" not in end_code,
        "serializer independently commits a record",
    )
    require(
        meta_code.endswith('\\n")}')
        and qemu_meta_code.endswith('\\n")}')
        and end_code.endswith('\\n")}'),
        "META/END do not terminate with one raw LF",
    )
    require(
        "\\r" not in meta.raw and "\\r" not in qemu_meta.raw and "\\r" not in end.raw,
        "META/END serializer can emit carriage return bytes",
    )
    write_hex = find_scope(code, r"\bfn\s+write_hex\b", "canonical lowercase hex serializer")
    exact_semantic(
        write_hex.raw,
        """
        fn write_hex<S: ProfileRecordSink>(sink: &mut S, bytes: &[u8]) -> Result<(), S::Error> {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut encoded = [0_u8; 64];
            if bytes.len() > encoded.len() / 2 {
                unreachable!("formal identity exceeds fixed hex scratch");
            }
            for (index, byte) in bytes.iter().copied().enumerate() {
                encoded[index * 2] = HEX[usize::from(byte >> 4)];
                encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
            }
            sink.write_all(&encoded[..bytes.len() * 2])
        }
        """,
        "canonical lowercase hex serializer",
    )
    write_u64 = find_scope(code, r"\bfn\s+write_u64\b", "canonical decimal serializer")
    exact_semantic(
        write_u64.raw,
        """
        fn write_u64<S: ProfileRecordSink>(sink: &mut S, mut value: u64) -> Result<(), S::Error> {
            let mut encoded = [0_u8; 20];
            let mut cursor = encoded.len();
            loop {
                cursor -= 1;
                encoded[cursor] = b'0' + (value % 10) as u8;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            sink.write_all(&encoded[cursor..])
        }
        """,
        "canonical decimal serializer",
    )


def verify_portable_tests(source: str) -> None:
    for name in (
        "campaign_validation_and_run_id_are_exact",
        "complete_boot_emits_one_meta_twenty_four_samples_and_one_end",
        "final_sample_defers_end_until_explicit_terminal_commit",
        "discarding_or_dropping_pending_terminal_never_writes_end",
        "stability_uses_only_twenty_one_retained_nearest_rank_samples",
        "meta_acquire_write_and_commit_failures_quarantine_without_drop",
        "sample_and_end_failures_never_retry_or_run_destructors",
        "epoch_mismatch_and_terminal_abort_touch_no_sample_record",
        "dropping_live_collector_leaves_meta_only_and_never_drops_factory",
        "panics_fail_stop_without_running_factory_or_record_destructors",
    ):
        require(source.count(f"fn {name}()") == 1, f"collector regression {name} is missing")
    require(source.count("#[ignore]") == 0 and source.count("#[should_panic]") == 0, "collector regression is disabled")
    require("34_386" in source, "collector known-answer transcript byte count differs")
    require(KNOWN_TRANSCRIPT_SHA256 in source, "collector known-answer transcript SHA-256 differs")
    tests = semantic(source)
    for exact, label in (
        (
            '#[cfg(all(feature="qemu-decision-v1",not(feature="qemu-decision-v1-smoke")))]'
            f'constTEST_RUN_ID:&str="{QEMU_TEST_RUN_ID}";',
            "formal-QEMU known-answer run-id",
        ),
        (
            '#[cfg(feature="qemu-decision-v1-smoke")]'
            f'constTEST_RUN_ID:&str="{QEMU_SMOKE_TEST_RUN_ID}";',
            "dirty-smoke known-answer run-id",
        ),
        (
            '#[cfg(all(feature="qemu-decision-v1",not(feature="qemu-decision-v1-smoke")))]'
            f'constTEST_TRANSCRIPT_BYTES:usize={QEMU_KNOWN_TRANSCRIPT_BYTES:_};',
            "formal-QEMU known-answer transcript byte count",
        ),
        (
            '#[cfg(feature="qemu-decision-v1-smoke")]'
            f'constTEST_TRANSCRIPT_BYTES:usize={QEMU_SMOKE_KNOWN_TRANSCRIPT_BYTES:_};',
            "dirty-smoke known-answer transcript byte count",
        ),
        (
            '#[cfg(all(feature="qemu-decision-v1",not(feature="qemu-decision-v1-smoke")))]'
            f'constTEST_TRANSCRIPT_SHA256:&str="{QEMU_KNOWN_TRANSCRIPT_SHA256}";',
            "formal-QEMU known-answer transcript SHA-256",
        ),
        (
            '#[cfg(feature="qemu-decision-v1-smoke")]'
            f'constTEST_TRANSCRIPT_SHA256:&str="{QEMU_SMOKE_KNOWN_TRANSCRIPT_SHA256}";',
            "dirty-smoke known-answer transcript SHA-256",
        ),
    ):
        require(exact in tests, f"{label} differs")
    for compile_fail_probe in (
        "require_sync::<BootCollector<Factory>>()",
        "collector.clone()",
        "collector.sink()",
        "collector.finish()",
        "collector.set_sample_index(23)",
        "collector.set_accumulator(0)",
    ):
        require(compile_fail_probe in source, f"collector compile-fail surface probe omits {compile_fail_probe!r}")
    for evidence in (
        "assert_eq!(observed.begin_calls, 26)",
        "assert_eq!(observed.commits, 26)",
        "assert_eq!(pending.ready_next_epoch(), Some(25))",
        "assert_eq!(observed.begin_calls, 25)",
        "assert_eq!(observed.commits, 25)",
        "let receipt = pending_end.discard_terminal()",
        "assert_eq!(poisoned.ready_next_epoch(), Some(25))",
        "assert!(!audit.bytes.windows(END_PREFIX.len()).any(|w| w == END_PREFIX))",
        "assert_eq!(observed.record_drops, 0)",
        "assert_eq!(observed.factory_drops, 0)",
    ):
        require(semantic(evidence) in semantic(source), f"collector failure/closure regression omits {evidence!r}")


def verify_raw_uart(tty: str, uart: str, kernel_root: str) -> None:
    tty_production = production(tty, "TTY") if "\n#[cfg(test)]\nmod tests" in tty else tty
    tx_state = find_scope(uart, r"\bstruct\s+TxState\b", "UART TX state")
    require("at_line_start:bool" in semantic(tx_state.raw), "UART does not retain byte-level column-zero state")
    put = find_scope(uart, r"\bfn\s+put_locked\b", "locked UART byte writer")
    ordered_semantic(put.raw, ("write_reg(THR, byte)", "tx.observe(byte)"), "UART write/line-state ordering")
    framing = find_scope(uart, r"\bimpl\s+RawRecordFraming\b", "raw record framing")
    for required in (
        "if self.line_feed_seen",
        "line_feeds > 1",
        "line_feeds == 1 && bytes.last() != Some(&b'\\n')",
        "if !self.wrote_any",
        "else if !self.line_feed_seen",
    ):
        require(semantic(required) in semantic(framing.raw), f"raw record framing omits {required!r}")
    raw_tx = find_scope(uart, r"\bimpl\s+RawTxRecord\b", "raw TX record")
    raw_tx_value = find_scope(uart, r"\bpub\(crate\)\s+struct\s+RawTxRecord\b", "raw TX record value")
    raw_tx_fields = semantic(raw_tx_value.raw)
    require("guard:Option<SpinGuard<'static,TxState>>" in raw_tx_fields, "raw TX record lost its hart-affine !Send guard")
    require("framing:RawRecordFraming" in raw_tx_fields, "raw TX record lost private framing state")
    require("unsafeimplSendforRawTxRecord" not in semantic(uart), "raw TX record gained an unsafe Send impl")
    require("implDropforRawTxRecord" not in semantic(uart), "raw TX record gained a releasing/recovery Drop impl")
    begin = find_function(raw_tx, "begin", "raw TX begin")
    require("_permit: &crate::tty::RawTxOrderPermit<'_>" in begin.raw, "TX acquisition lacks the TTY order permit")
    ordered_semantic(
        begin.raw,
        (
            "let guard = ManuallyDrop::new(TX.lock())",
            "if !guard.at_line_start",
            "guard: Some(ManuallyDrop::into_inner(guard))",
        ),
        "permanent NotAtLineStart fail-stop",
    )
    require("finish_raw_record_activity" not in begin.raw, "NotAtLineStart can clear raw activity")
    raw_release = find_function(raw_tx, "release_after_commit", "raw TX release")
    require(
        semantic(raw_release.raw)
        == "fnrelease_after_commit(&mutself){drop(self.guard.take());}",
        "raw TX release does not consume only the live TX guard",
    )
    write = find_function(raw_tx, "write_all", "raw TX write")
    ordered_semantic(
        write.raw,
        (
            "if self.guard.is_none()",
            "let next = self.framing.append(bytes)?",
            'self.guard.as_mut().expect("raw TX guard was checked above")',
            "for byte in bytes.iter().copied()",
            "put_locked(tx, byte)",
            "self.framing = next",
        ),
        "raw fragment transaction",
    )
    require("Console" not in write.raw and "write_fmt" not in write.raw, "raw sink enters CRLF/formatted console")
    require(
        semantic(write.raw).count("put_locked(tx,byte)") == 1 and "b'\\r'" not in write.raw,
        "raw sink inserts CR or duplicates a physical byte",
    )
    commit = find_function(raw_tx, "commit_record", "raw TX commit")
    ordered_semantic(
        commit.raw,
        (
            "if self.guard.is_none()",
            "self.framing.validate_commit()?",
            "wait_tx_fully_empty()",
            "self.guard.as_ref().is_some_and(|guard| guard.at_line_start)",
            "self.release_after_commit()",
        ),
        "TX drain/release ordering",
    )

    permit = find_scope(tty_production, r"\bpub\(crate\)\s+struct\s+RawTxOrderPermit\b", "TTY/TX order permit")
    require("&'guard SpinGuard<'static, ConsoleTty>" in permit.raw, "TTY/TX permit is not lifetime-bound to TTY")
    wrapper = find_scope(tty_production, r"\bpub\(crate\)\s+struct\s+RawUartRecord\b", "raw UART wrapper")
    require(
        semantic(wrapper.raw)
        == "pub(crate)structRawUartRecord{tx:Option<uart::RawTxRecord>,tty:Option<SpinGuard<'static,ConsoleTty>>,}",
        "raw UART guard field set/order differs",
    )
    wrapper_impl = find_scope(tty_production, r"\bimpl\s+RawUartRecord\b", "raw UART wrapper impl")
    require("unsafeimplSendforRawUartRecord" not in semantic(tty_production), "raw UART record gained an unsafe Send impl")
    release = find_function(wrapper_impl, "release_after_commit", "raw UART release")
    ordered_semantic(release.raw, ("drop(self.tx.take())", "drop(self.tty.take())"), "TX-before-TTY release")
    wrapper_commit = find_function(wrapper_impl, "commit_record", "raw UART commit")
    ordered_semantic(
        wrapper_commit.raw,
        (
            "tx.commit_record()",
            "if result.is_ok()",
            "uart::finish_raw_record_activity()",
            "self.release_after_commit()",
        ),
        "drain/TX-release/activity-clear/TTY-release order",
    )
    acquire = find_scope(tty_production, r"\bpub\(crate\)\s+fn\s+begin_raw_uart_record\b", "raw UART acquisition")
    ordered_semantic(
        acquire.raw,
        (
            "let tty = ManuallyDrop::new(TTY.lock())",
            "uart::begin_raw_record_activity()",
            "let permit = RawTxOrderPermit",
            "uart::RawTxRecord::begin(&permit)?",
            "tty: Some(ManuallyDrop::into_inner(tty))",
        ),
        "TTY-guard/activity-arm/TX-guard acquisition",
    )
    require("drop(" not in semantic(wrapper_impl.raw).replace(semantic(release.raw), ""), "raw wrapper has another explicit release")

    wrapper_drop = find_scope(tty_production, r"\bimpl\s+Drop\s+for\s+RawUartRecord\b", "raw UART fail-stop Drop")
    require(
        semantic(wrapper_drop.raw)
        == (
            "implDropforRawUartRecord{fndrop(&mutself){ifuart::raw_record_active(){"
            "ifletSome(tx)=self.tx.take(){core::mem::forget(tx);}"
            "ifletSome(tty)=self.tty.take(){core::mem::forget(tty);}}}}"
        ),
        "raw UART Drop can recover output after a partial record",
    )

    uart_code = semantic(uart)
    require(
        "staticRAW_RECORD_ACTIVE:core::sync::atomic::AtomicBool="
        "core::sync::atomic::AtomicBool::new(false);" in uart_code,
        "raw-record panic gate is not a private false-initialized AtomicBool",
    )
    activity_begin = find_scope(uart, r"\bpub\(crate\)\s+fn\s+begin_raw_record_activity\b", "raw activity arm")
    require(
        semantic(activity_begin.raw)
        == (
            "pub(crate)fnbegin_raw_record_activity(){"
            "letwas_active=RAW_RECORD_ACTIVE.swap(true,Ordering::AcqRel);"
            'debug_assert!(!was_active,"rawUARTrecordactivitycannotnest");}'
        ),
        "raw activity arm is not one checked AcqRel false-to-true transition",
    )
    activity_read = find_scope(uart, r"\bpub\(crate\)\s+fn\s+raw_record_active\b", "raw activity read")
    require(
        semantic(activity_read.raw)
        == "pub(crate)fnraw_record_active()->bool{RAW_RECORD_ACTIVE.load(Ordering::Acquire)}",
        "panic/OOM raw activity read is not Acquire",
    )
    activity_finish = find_scope(uart, r"\bpub\(crate\)\s+fn\s+finish_raw_record_activity\b", "raw activity clear")
    require(
        semantic(activity_finish.raw)
        == (
            "pub(crate)fnfinish_raw_record_activity(){"
            'debug_assert!(RAW_RECORD_ACTIVE.load(Ordering::Acquire),"rawUARTrecordactivitymustbearmeduntilcommit");'
            "RAW_RECORD_ACTIVE.store(false,Ordering::Release);}"
        ),
        "raw activity clear is not a checked Release transition",
    )
    require(semantic(tty_production).count("uart::begin_raw_record_activity()") == 1, "raw activity can be armed outside TTY-first acquisition")
    require(semantic(tty_production).count("uart::finish_raw_record_activity()") == 1, "raw activity can be cleared outside successful commit")
    require(semantic(acquire.raw).count("uart::RawTxRecord::begin(&permit)") == 1, "raw wrapper can acquire another TX record")

    panic_handler = find_scope(kernel_root, r"\bfn\s+panic\s*\(", "kernel panic handler")
    panic_code = semantic(panic_handler.raw)
    silence_gate = (
        f'#[cfg(feature="{FEATURE}")]'
        "ifuart::raw_record_active(){sbi::shutdown(true);}"
    )
    require(silence_gate in panic_code, "panic raw-record silence gate differs")
    require(panic_code.count("uart::raw_record_active()") == 1, "panic raw-record gate count differs")
    panic_gate = panic_code.find("uart::raw_record_active()")
    for bypass in ("SbiWriter", "core::fmt::write(", "sbi::legacy_putchar(", "uart::early_write("):
        for match in re.finditer(re.escape(bypass), panic_code):
            require(panic_gate < match.start(), f"panic reaches {bypass} before checking raw activity")
    oom_handler = find_scope(kernel_root, r"\bfn\s+oom\s*\(", "global OOM handler")
    oom_code = semantic(oom_handler.raw)
    require(silence_gate in oom_code, "OOM raw-record silence gate differs")
    require(oom_code.count("uart::raw_record_active()") == 1, "OOM raw-record gate count differs")
    require(
        oom_code.find("uart::raw_record_active()") < oom_code.find("matchHEAP.take_last_failure()"),
        "OOM examines allocator state before fail-stopping an active raw record",
    )
    oom_gate = oom_code.find("uart::raw_record_active()")
    for bypass in ("SbiWriter", "core::fmt::write(", "sbi::legacy_putchar(", "uart::early_write("):
        for match in re.finditer(re.escape(bypass), oom_code):
            require(oom_gate < match.start(), f"OOM reaches {bypass} before checking raw activity")


def verify_features(inputs: Inputs) -> None:
    kernel = PHASE.parse_features(inputs.kernel_manifest, "kernel")
    qemu = PHASE.parse_features(inputs.qemu_manifest, "QEMU firmware")
    milkv = PHASE.parse_features(inputs.milkv_manifest, "Milk-V firmware")
    require(kernel.get(FEATURE) == [TRUSTED_FEATURE], "collector base is not the exact trusted-sample successor")
    require(kernel.get(QEMU_FEATURE) == [FEATURE, FINISH_QEMU_FEATURE, "dep:sha2"], "kernel collector QEMU closure differs")
    require(
        kernel.get(QEMU_DECISION_FEATURE)
        == ["ssh-test", FEATURE, f"vibeos-wasm-aot-profile/{QEMU_PROFILE_FEATURE}"],
        "kernel formal-QEMU decision closure differs",
    )
    require(
        kernel.get(QEMU_DECISION_SMOKE_FEATURE)
        == [
            QEMU_DECISION_FEATURE,
            f"vibeos-wasm-aot-profile/{QEMU_PROFILE_SMOKE_FEATURE}",
        ],
        "kernel dirty-smoke QEMU decision closure differs",
    )
    require(qemu.get(QEMU_FEATURE) == [FINISH_QEMU_FEATURE, f"vibeos-kernel/{QEMU_FEATURE}"], "QEMU collector forwarding differs")
    require(
        qemu.get(QEMU_DECISION_FEATURE)
        == [f"vibeos-kernel/{QEMU_DECISION_FEATURE}"],
        "QEMU firmware formal-decision forwarding differs",
    )
    require(
        qemu.get(QEMU_DECISION_SMOKE_FEATURE)
        == [QEMU_DECISION_FEATURE, f"vibeos-kernel/{QEMU_DECISION_SMOKE_FEATURE}"],
        "QEMU firmware dirty-smoke forwarding differs",
    )
    require(milkv.get(FEATURE) == ["milkv-ssh", f"vibeos-kernel/{FEATURE}"], "Milk-V collector forwarding differs")
    require(QEMU_FEATURE not in milkv, "Milk-V exposes the audit-only QEMU gate")
    require(QEMU_DECISION_FEATURE not in milkv, "Milk-V exposes the formal-QEMU decision gate")
    require(QEMU_DECISION_SMOKE_FEATURE not in milkv, "Milk-V exposes the dirty-smoke QEMU gate")
    for label, features, name in (
        ("kernel", kernel, FEATURE),
        ("kernel", kernel, QEMU_FEATURE),
        ("kernel", kernel, QEMU_DECISION_FEATURE),
        ("kernel", kernel, QEMU_DECISION_SMOKE_FEATURE),
        ("QEMU firmware", qemu, QEMU_FEATURE),
        ("QEMU firmware", qemu, QEMU_DECISION_FEATURE),
        ("QEMU firmware", qemu, QEMU_DECISION_SMOKE_FEATURE),
        ("Milk-V firmware", milkv, FEATURE),
    ):
        require(name not in PHASE.local_feature_closure(features, features.get("default", [])), f"{label} enables {name} by default")
    physical = PHASE.local_feature_closure(kernel, [FEATURE])
    require(TRUSTED_FEATURE in physical, "physical collector omits trusted live-sample predecessor")
    require(not any(name.endswith("-qemu-acceptance") for name in physical), "physical collector selects QEMU audit")
    qemu_closure = PHASE.local_feature_closure(kernel, [QEMU_FEATURE])
    require(FEATURE in qemu_closure and FINISH_QEMU_FEATURE in qemu_closure, "QEMU collector omits base/finish predecessor")
    require(TRUSTED_QEMU_FEATURE not in qemu_closure, "QEMU collector inherits the discard-only trusted-sample transcript")
    formal_qemu_closure = PHASE.local_feature_closure(kernel, [QEMU_DECISION_FEATURE])
    require(
        FEATURE in formal_qemu_closure
        and "ssh-test" in formal_qemu_closure
        and FINISH_QEMU_FEATURE not in formal_qemu_closure
        and QEMU_FEATURE not in formal_qemu_closure
        and TRUSTED_QEMU_FEATURE not in formal_qemu_closure,
        "formal-QEMU decision inherits diagnostic QEMU telemetry or omits its narrow SSH fixture",
    )
    smoke_qemu_closure = PHASE.local_feature_closure(kernel, [QEMU_DECISION_SMOKE_FEATURE])
    require(
        QEMU_DECISION_FEATURE in smoke_qemu_closure
        and FEATURE in smoke_qemu_closure
        and "ssh-test" in smoke_qemu_closure
        and FINISH_QEMU_FEATURE not in smoke_qemu_closure
        and QEMU_FEATURE not in smoke_qemu_closure
        and TRUSTED_QEMU_FEATURE not in smoke_qemu_closure,
        "dirty-smoke QEMU decision does not layer exactly on the formal image",
    )
    try:
        kernel_toml = tomllib.loads(inputs.kernel_manifest.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"kernel manifest is invalid: {error}") from error
    require(
        kernel_toml.get("dependencies", {}).get("sha2")
        == {"version": "=0.11.0", "default-features": False, "optional": True},
        "kernel QEMU audit sha2 dependency is not exact/pinned/optional/no_std",
    )

    root = semantic(inputs.kernel_root)
    qemu_only = f'#[cfg(all(feature="{QEMU_FEATURE}",not(feature="qemu-virt")))]compile_error!("feature`{QEMU_FEATURE}`isQEMU-only");'
    require(qemu_only in root, "collector acceptance lacks its QEMU-only guard")
    physical_qemu = (
        f'#[cfg(all(feature="{FEATURE}",feature="qemu-virt",not(any('
        f'feature="{QEMU_FEATURE}",feature="{QEMU_DECISION_FEATURE}"))))]'
        f'compile_error!("feature`{FEATURE}`cannotexposephysicalformalrecordsonQEMU");'
    )
    require(physical_qemu in root, "physical formal collector can run on QEMU outside the absorbing audit gate")
    physical_platform = (
        f'#[cfg(all(feature="{FEATURE}",not(any(feature="milkv-duo",'
        f'feature="{QEMU_FEATURE}",feature="{QEMU_DECISION_FEATURE}"))))]'
        f'compile_error!("feature`{FEATURE}`requiresMilk-VDuo,itsabsorbingQEMUacceptance,'
        'ortheformalQEMUcontract");'
    )
    require(physical_platform in root, "physical formal collector can run outside Milk-V Duo")
    formal_qemu_only = (
        f'#[cfg(all(feature="{QEMU_DECISION_FEATURE}",not(feature="qemu-virt")))]'
        f'compile_error!("feature`{QEMU_DECISION_FEATURE}`isQEMU-only");'
    )
    require(formal_qemu_only in root, "formal-QEMU decision lacks its QEMU-only guard")
    formal_no_milkv = (
        f'#[cfg(all(feature="{QEMU_DECISION_FEATURE}",feature="milkv-duo"))]'
        f'compile_error!("feature`{QEMU_DECISION_FEATURE}`cannotclaimMilk-VDuoprovenance");'
    )
    require(formal_no_milkv in root, "formal-QEMU decision can claim Milk-V provenance")
    smoke_layer = (
        f'#[cfg(all(feature="{QEMU_DECISION_SMOKE_FEATURE}",'
        f'not(feature="{QEMU_DECISION_FEATURE}")))]'
        f'compile_error!("feature`{QEMU_DECISION_SMOKE_FEATURE}`mustlayerontheformalQEMUimage");'
    )
    require(smoke_layer in root, "dirty-smoke marker need not layer on the formal QEMU image")
    formal_audit_mutual = (
        f'#[cfg(all(feature="{QEMU_DECISION_FEATURE}",feature="{QEMU_FEATURE}"))]'
        'compile_error!("formalandabsorbingC8.4QEMUcollectorsaremutuallyexclusive");'
    )
    require(formal_audit_mutual in root, "formal and absorbing QEMU collectors can be combined")
    legacy_shell = (
        f'#[cfg(all(feature="{FEATURE}",feature="legacy-shell"))]'
        f'compile_error!("feature`{FEATURE}`excludesthelocallegacyshell");'
    )
    require(legacy_shell in root, "physical collector can re-enable the local legacy shell")
    pairing = (
        f'#[cfg(all(feature="{FEATURE}",feature="{FINISH_QEMU_FEATURE}",not(any('
        f'feature="{QEMU_FEATURE}",feature="{QEMU_DECISION_FEATURE}"))))]'
        f'compile_error!("feature`{FEATURE}`cannotreusethediscard-onlyfinish/verifyQEMUtranscript");'
    )
    require(pairing in root, "collector base can reuse predecessor QEMU telemetry")
    mutual = (
        f'#[cfg(all(feature="{FEATURE}",feature="wasm-c84-ssh-managed-child-verified-stream"))]'
        f'compile_error!("features`{FEATURE}`and`wasm-c84-ssh-managed-child-verified-stream`aremutuallyexclusivetrusted-sampleconsumers");'
    )
    require(mutual in root, "collector and verified-stream consumers are not mutually exclusive")
    trusted_exemption = (
        f'feature="{TRUSTED_FEATURE}",feature="{FINISH_QEMU_FEATURE}",'
        f'not(feature="{TRUSTED_QEMU_FEATURE}"),not(feature="{QEMU_FEATURE}"),'
        f'not(feature="{QEMU_DECISION_FEATURE}")'
    )
    require(trusted_exemption in root, "trusted predecessor does not narrowly exempt collector QEMU")
    require(
        f'feature="{QEMU_FEATURE}"' in root and "C8.4QEMUacceptancesareisolatedimages" in root,
        "collector QEMU isolation guard is missing",
    )
    absorbing_isolation = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",any('
        'feature="wasm-c48-qemu-acceptance",'
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        'feature="wasm-c84-profile-irq-overlay-qemu-acceptance",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance",'
        f'feature="{TRUSTED_QEMU_FEATURE}",'
        'feature="wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance",'
        f'feature="{QEMU_DECISION_FEATURE}")))]'
        'compile_error!("C8.4QEMUacceptancesareisolatedimages");'
    )
    require(absorbing_isolation in root, "absorbing QEMU collector isolation set differs")


def verify_irq_long_run(inputs: Inputs) -> None:
    """Freeze the predecessor IRQ gate extension needed by all 24 samples."""

    terminal = find_scope(
        inputs.slot,
        r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
        "collector 24-epoch terminal IRQ gate",
    )
    terminal_code = semantic(terminal.raw)
    collector_range = semantic(
        f"""
        #[cfg(feature = "{QEMU_FEATURE}")]
        if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch) {{
            return Err(ProfileError::StateMismatch);
        }}
        """
    )
    predecessor_range = semantic(
        f"""
        #[cfg(not(feature = "{QEMU_FEATURE}"))]
        if !(1..=4).contains(&epoch) {{
            return Err(ProfileError::StateMismatch);
        }}
        """
    )
    require(
        terminal_code.count(collector_range) == 1,
        "collector IRQ gate is not bounded by the exact portable 24-sample count",
    )
    require(
        terminal_code.count(predecessor_range) == 1,
        "collector IRQ extension changed the predecessor four-epoch gate",
    )
    require(
        terminal_code.count("if!(1..=") == 2 and "cfg!(" not in terminal_code,
        "terminal IRQ range has an extra, runtime-selected, or missing bound",
    )
    require(
        f'feature="{FEATURE}"' not in terminal_code,
        "24-epoch IRQ range is exposed by the reusable physical/base collector",
    )
    require(
        f'feature="{QEMU_DECISION_FEATURE}"' not in terminal_code,
        "formal-QEMU image inherits diagnostic IRQ range selection",
    )
    ordered_semantic(
        terminal.raw,
        (
            collector_range,
            predecessor_range,
            """
            if ready_epoch != epoch.checked_add(1).ok_or(ProfileError::StateMismatch)?
                || MANAGED_IRQ_ACCEPTANCE_STAGE.load(Ordering::Acquire) != 4
                || status()
                    != (SlotStatus::Ready {
                        next_epoch: Some(ready_epoch),
                    })
            """,
            """
            let before = managed_irq_acceptance_observation();
            if before.paired != 2 || before.inactive != epoch - 1 || before.active_epoch != 0
            """,
            """
            MANAGED_IRQ_ACCEPTANCE_TERMINAL_EPOCH
                .compare_exchange(epoch, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| ProfileError::StateMismatch)?;
            """,
            "force_boot_self_ssip(false)?;",
            """
            let observation = managed_irq_acceptance_observation();
            if observation
                != (ManagedIrqObservation {
                    paired: 2,
                    inactive: epoch,
                    active_epoch: 0,
                })
                || status()
                    != (SlotStatus::Ready {
                        next_epoch: Some(ready_epoch),
                    })
            """,
            "MANAGED_IRQ_ACCEPTANCE_TERMINAL_EPOCH.store(ready_epoch, Ordering::Release);",
            "Ok(observation)",
        ),
        "collector 24-epoch terminal IRQ lineage",
    )
    require(
        terminal_code.count("force_boot_self_ssip(false)?;") == 1
        and terminal_code.count("managed_irq_acceptance_observation()") == 2,
        "terminal IRQ gate does not perform exactly one inactive observation transition",
    )
    require(
        not any(word in terminal_code for word in ("wrapping_", "saturating_", ".store(u64::MAX")),
        "terminal IRQ lineage uses an unchecked/resetting counter transition",
    )

    response = find_scope(inputs.ssh, r"\bfn\s+managed_irq_response\b", "collector IRQ response marker")
    require(
        semantic(response.raw).count("letcausal_pair=u8::from(epoch==1);") == 1,
        "collector IRQ response does not isolate its two causal markers to epoch 1",
    )
    exact_semantic(
        response.raw,
        f"""
        #[cfg(feature = "{QEMU_FEATURE}")]
        crate::println!(
            "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY RESPONSE epoch={{}} status={{}} parent_pair={{}} child_pair={{}} terminal_inactive=1 paired={{}} inactive={{}} active_epoch={{}} finish=1 verify=1 bundle=trusted collector=consumed ack=0 ready_epoch={{}}",
            epoch,
            status,
            causal_pair,
            causal_pair,
            observation.paired,
            observation.inactive,
            observation.active_epoch,
            ready_epoch,
        );
        """,
        "collector IRQ response marker schema",
    )
    response_success = find_scope(
        inputs.ssh,
        r"Ok\(\(ready_epoch,\s*_terminal_evidence\)\)\s+if\s+terminal_prerequisite_exact\s*=>",
        "collector successful response IRQ chain",
    )
    response_success_code = semantic(response_success.raw)
    require(
        response_success_code.count("managed_irq_acceptance_terminal_gate(epoch,ready_epoch,") == 1
        and response_success_code.count("managed_irq_response(epoch,status,ready_epoch,irq_observation);") == 1,
        "collector response does not invoke exactly one terminal gate and IRQ marker",
    )
    ordered_semantic(
        response_success.raw,
        (
            "managed_irq_acceptance_terminal_gate(epoch, ready_epoch,)",
            'profile_request_failure("irq-response-terminal", Some(epoch))',
            "profile_request_response(epoch, status, ready_epoch);",
            "managed_irq_response(epoch, status, ready_epoch, irq_observation);",
            "finish_verify_response(epoch, status, ready_epoch);",
            "collector_trusted_sample_response(epoch, &_terminal_evidence)?;",
        ),
        "collector terminal gate and predecessor marker order",
    )


def verify_sshd_terminal_reject(inputs: Inputs) -> None:
    source = inputs.sshd
    error = find_scope(source, r"\bpub\s+enum\s+SshExecProfilePrepareError\b", "SSHD profile prepare error")
    require(
        semantic(error.raw) == "pubenumSshExecProfilePrepareError{Failed,Reject,}",
        "SSHD no longer distinguishes fatal prepare failure from terminal pre-start rejection",
    )
    exact_semantic(
        source,
        """
        #[cfg(feature = "c84-profile-request-parent")]
        const SSH_EXEC_PRESTART_REJECT_STATUS: u32 = 126;
        """,
        "SSHD fixed terminal reject status",
    )

    prepared = find_scope(source, r"\benum\s+PreparedExec\b", "SSHD prepared exec")
    require(
        semantic(prepared.raw)
        == (
            "enumPreparedExec{Execute{command:String,component:Option<SshExecComponentSessionPolicy>,"
            '#[cfg(feature="c84-profile-request-parent")]profile:Option<SshExecProfilePermit>,},'
            '#[cfg(feature="c84-profile-request-parent")]Reject,}'
        ),
        "pre-start Reject carries a command, component, or permit",
    )
    accepted = find_scope(source, r"\benum\s+AcceptedExec\b", "SSHD accepted exec")
    require(
        semantic(accepted.raw)
        == (
            "enumAcceptedExec{Execute{command:String,component:Option<SshExecComponentSessionPolicy>,"
            '#[cfg(feature="c84-profile-request-parent")]profile:Option<SshExecProfileRun>,},'
            '#[cfg(feature="c84-profile-request-parent")]Reject{status:u32},}'
        ),
        "accepted Reject gained a command/component/profile execution surface",
    )

    prepared_impl = find_scope(source, r"\bimpl\s+PreparedExec\b", "SSHD prepared exec impl")
    prepare = find_function(prepared_impl, "prepare", "SSHD exec prepare")
    ordered_semantic(
        prepare.raw,
        (
            "space.prepare_ssh_exec_profile(SshExecProfileTarget::new(&command, policy))",
            "Err(SshExecProfilePrepareError::Failed)",
            'return Err("SSH exec profile preparation failed")',
            "Err(SshExecProfilePrepareError::Reject) => return Ok(Self::Reject)",
            "Ok(Self::Execute",
        ),
        "SSHD prepare failure/reject split",
    )
    accept = find_function(prepared_impl, "accept", "SSHD exec acceptance")
    ordered_semantic(
        accept.raw,
        (
            "succeed()?",
            "match self",
            "Self::Execute",
            "SshExecProfilePermit::start",
            "Self::Reject",
            "status: SSH_EXEC_PRESTART_REJECT_STATUS",
        ),
        "SSHD succeed-before-start/reject mapping",
    )

    protocol = find_scope(source, r"\bfn\s+progress_protocol\b", "SSHD protocol progress")
    exec_event = find_scope(
        protocol.raw,
        r"Event::Serv\(ServEvent::SessionExec\(event\)\)\s*=>",
        "SSHD exec request event",
    )
    ordered_semantic(
        exec_event.raw,
        (
            "PreparedExec::prepare(space, value, accepted_component)?",
            "prepared.accept(||",
            "event.succeed()",
            "ProtocolSignal::Exec(accepted)",
        ),
        "SSHD prepare/succeed/accept boundary",
    )

    serve = find_scope(source, r"\basync\s+fn\s+serve_connection\b", "SSHD connection service")
    serve_code = re.sub(r"\s+", "", serve.code)
    require(
        serve_code.count("AcceptedExec::Reject") == 1,
        "terminal Reject has an additional early or duplicate handling path",
    )
    reject = find_scope(
        serve.raw,
        r"\bif\s+let\s+AcceptedExec::Reject\s*\{\s*status\s*\}\s*=\s*&accepted",
        "SSHD terminal Reject drain",
    )
    reject_code = semantic(reject.raw)
    require(
        reject_code
        == (
            "ifletAcceptedExec::Reject{status}=&accepted{letstatus=*status;letmutprofile_run=None;"
            "returnmatchfinish_exec(&mutrunner,&mutsigner,space,control,bound_epoch,policy,stack,"
            "&mutbridge,&mutprotocol,&mutprofile_run,&[],status,require_carrier,).await{"
            "Ok(())=>ConnectionEnd::ExecComplete(status),"
            "Err(ConnectionEnd::Reset(reason))=>reset_connection(stack,reason),Err(other)=>other,};}"
        ),
        "terminal Reject does not use the existing empty-output completion drain",
    )
    for forbidden in (
        "command",
        "component",
        "profile.start",
        "execute_with_network",
        "execute_stream_with_network",
        "ssh_exec_component_completed",
    ):
        require(forbidden not in reject.raw, f"terminal Reject enters execution via {forbidden!r}")
    require(
        semantic(serve.raw).find("ifletAcceptedExec::Reject")
        < semantic(serve.raw).find("letAcceptedExec::Execute"),
        "terminal Reject is destructured as an executable command first",
    )
    for regression in (
        "profile_prepare_reject_accepts_only_a_fixed_terminal_126",
        "profile_prepare_failure_remains_fatal_before_exec_acceptance",
    ):
        require(source.count(f"fn {regression}()") == 1, f"SSHD terminal reject regression {regression} is missing")


def verify_kernel_integration(inputs: Inputs) -> None:
    slot = inputs.slot
    slot_code = semantic(slot)
    require(f'#[cfg(feature="{FEATURE}")]' in slot_code, "collector slot integration is not feature-isolated")
    for state in (
        "Uninitialized",
        "Initializing",
        "Ready",
        "Bound",
        "Publishing",
        "PendingAcceptance",
        "PendingTerminal",
        "FinalizingTerminal",
        "Complete",
        "Failed",
    ):
        require(state in slot, f"collector slot state {state} is missing")
    require("SpinLock" in slot and "COLLECTOR" in slot, "collector is not retained behind a kernel SpinLock")
    require("OwnerSeal" in slot, "collector binding does not retain the exact owner seal")
    require("ProfileRecordSinkFactory" in slot and "begin_raw_uart_record" in slot, "physical UART factory adapter is missing")
    require("AuditCommit" in slot, "QEMU audit lacks its private post-commit capability")
    require("decision_eligible=0" in slot and "formal_uart=0" in slot, "audit markers do not deny evidence eligibility")
    for prefix in FORMAL_PREFIXES:
        # Portable serializer literals live in another crate. Kernel QEMU code
        # must not contain or reconstruct one for UART output.
        require(slot.count(prefix) == 0, f"kernel collector contains formal UART prefix {prefix!r}")

    owner = find_scope(slot, r"\bstruct\s+OwnerSeal\b", "exact collector owner seal")
    require(
        semantic(owner.raw) == "structOwnerSeal{epoch:u64,detach:CurrentTaskDetachLease,}",
        "collector owner seal stores copied/ambient lineage",
    )
    owner_impl = find_scope(slot, r"\bimpl\s+OwnerSeal\b", "collector owner seal impl")
    require(
        "self.epoch==epoch&&self.detach.matches_exact(detach)" in semantic(owner_impl.raw),
        "collector owner seal does not require exact epoch/detach lineage",
    )
    collector_state = find_scope(slot, r"\benum\s+CollectorState\b", "collector state")
    require(
        semantic(collector_state.raw)
        == (
            "enumCollectorState{Uninitialized,Initializing,Ready(KernelBootCollector),"
            "Bound{collector:KernelBootCollector,owner:OwnerSeal,},Publishing{owner:OwnerSeal,},"
            "PendingAcceptance{collector:KernelBootCollector,epoch:u64,ready_epoch:u64,"
            "committed_records:u8,},PendingTerminal{pending_end:KernelPendingEnd,epoch:u64,"
            "ready_epoch:u64,committed_records:u8,},FinalizingTerminal{epoch:u64,"
            "ready_epoch:u64,committed_records:u8,},"
            "Complete{receipt:BootReceipt,ready_epoch:u64,audit_commits:u8,},"
            "Failed(CollectorFailureReceipt),}"
        ),
        "collector state graph or terminal receipts differ",
    )
    failure_receipt = find_scope(slot, r"\bstruct\s+CollectorFailureReceipt\b", "collector failure receipt")
    require(
        semantic(failure_receipt.raw)
        == (
            "structCollectorFailureReceipt{epoch:u64,sequence:u8,ready_epoch:u64,audit_commits:u8,"
            "reason:CollectorFailureReason,marker_pending:bool,}"
        ),
        "collector Failed state does not retain its exact absorbing receipt",
    )
    next_sequence = find_scope(slot, r"\bconst\s+fn\s+collector_next_sequence\b", "collector next-sequence mapping")
    exact_semantic(
        next_sequence.raw,
        """
        const fn collector_next_sequence(committed_records: u8) -> u8 {
            let committed_samples = committed_records.saturating_sub(1);
            if committed_samples > BOOT_SAMPLES {
                BOOT_SAMPLES
            } else {
                committed_samples
            }
        }
        """,
        "META-excluding clamped collector next-sequence mapping",
    )
    failure_receipt_impl = find_scope(slot, r"\bimpl\s+CollectorFailureReceipt\b", "collector failure receipt impl")
    exact_semantic(
        failure_receipt_impl.raw,
        "sequence: collector_next_sequence(committed_records),",
        "failure receipt next sequence",
    )
    exact_semantic(
        failure_receipt_impl.raw,
        """
        fn absorb_committed_records(&mut self, committed_records: u8) {
            let committed_records = if committed_records > self.audit_commits {
                committed_records
            } else {
                self.audit_commits
            };
            self.sequence = collector_next_sequence(committed_records);
            self.audit_commits = committed_records;
        }
        """,
        "absorbing failure committed-record update",
    )
    require("epoch.checked_sub" not in semantic(failure_receipt_impl.raw), "failure receipt regressed to epoch-derived sequence")
    fail_state = find_scope(slot, r"\bfn\s+fail_collector_state\b", "absorbing collector failure transition")
    fail_state_code = semantic(fail_state.raw)
    require(
        "CollectorState::Failed(_)|CollectorState::FinalizingTerminal{..}|CollectorState::Complete{..}"
        in fail_state_code
        and fail_state_code.find(
            "CollectorState::Failed(_)|CollectorState::FinalizingTerminal{..}|CollectorState::Complete{..}"
        )
        < fail_state_code.find("mem::replace(state,CollectorState::Failed(failure))"),
        "Failed/finalizing/Complete collector state can be reset or overwritten",
    )

    physical_factory = find_scope(slot, r"\bstruct\s+AtomicUartRecordFactory\b", "atomic UART record factory")
    require(
        semantic(physical_factory.raw) == "structAtomicUartRecordFactory{not_sync:PhantomData<Cell<()>>,}",
        "persistent atomic UART factory is not guard-free Send + !Sync",
    )
    physical_impl = find_scope(
        slot,
        r"\bimpl\s+ProfileRecordSinkFactory\s+for\s+AtomicUartRecordFactory\b",
        "atomic UART record factory impl",
    )
    require(
        semantic(physical_impl.raw)
        == (
            "implProfileRecordSinkFactoryforAtomicUartRecordFactory{"
            "typeError=crate::tty::RawUartRecordError;typeRecord=crate::tty::RawUartRecord;"
            "fnbegin_record(&mutself)->Result<Self::Record,Self::Error>{crate::tty::begin_raw_uart_record()}}"
        ),
        "atomic UART factory no longer acquires exactly one temporary raw record",
    )
    require("unsafeimplSyncforAtomicUartRecordFactory" not in slot_code, "atomic UART factory gained an unsafe Sync impl")
    require("unsafeimplSendforcrate::tty::RawUartRecord" not in slot_code, "physical record gained an unsafe Send impl")
    physical_sink = find_scope(
        slot,
        r"\bimpl\s+ProfileRecordSink\s+for\s+crate::tty::RawUartRecord\b",
        "physical raw UART sink impl",
    )
    require(
        semantic(physical_sink.raw)
        == (
            "implProfileRecordSinkforcrate::tty::RawUartRecord{"
            "typeError=crate::tty::RawUartRecordError;"
            "fnwrite_all(&mutself,bytes:&[u8])->Result<(),Self::Error>{"
            "crate::tty::RawUartRecord::write_all(self,bytes)}"
            "fncommit_record(&mutself)->Result<(),Self::Error>{"
            "crate::tty::RawUartRecord::commit_record(self)}}"
        ),
        "physical sink bypasses or wraps the raw TTY/TX record",
    )
    physical_cfg = (
        f'#[cfg(all(feature="{FEATURE}",not(feature="{QEMU_FEATURE}")))]'
    )
    prefix = semantic(slot[max(0, physical_factory.start - 640) : physical_factory.start])
    require(prefix.endswith(physical_cfg), "atomic UART factory is not excluded from QEMU audit images")
    require(
        "typeCollectorFactory=AtomicUartRecordFactory;" in slot_code,
        "non-absorbing collector no longer selects the atomic UART factory",
    )
    factory_constructor = find_scope(
        slot,
        rf'#\[cfg\(all\(\s*feature\s*=\s*"{FEATURE}",\s*'
        rf'not\(feature\s*=\s*"{QEMU_FEATURE}"\)\s*\)\)\]\s*'
        r'fn\s+collector_factory\b',
        "atomic UART collector factory constructor",
        match_literals=True,
    )
    require(
        semantic(factory_constructor.raw)
        == physical_cfg + "fncollector_factory()->CollectorFactory{AtomicUartRecordFactory::new()}",
        "non-absorbing collector factory constructor differs",
    )

    initialize = find_scope(slot, r"\bfn\s+init_collector\b", "collector initialization")
    initialize_code = semantic(initialize.raw)
    initial_positions = [
        initialize_code.find(semantic(fragment))
        for fragment in (
            "let mut slot = SLOT.lock()",
            "let mut collector_slot = COLLECTOR.lock()",
            "*slot = SlotState::CollectorInitializing",
            "*collector_slot = CollectorState::Initializing",
            "Campaign::from_bound_build()",
            "campaign.begin(collector_factory(), ready)",
        )
    ]
    require(all(position >= 0 for position in initial_positions) and initial_positions == sorted(initial_positions), "collector initialization tombstone/META order differs")
    success = find_scope(initialize.raw, r"Ok\(next\)\s*=>", "successful collector META reinstall")
    ordered_semantic(
        success.raw,
        (
            "let audit = match collector_take_audit(1)",
            "let mut slot = SLOT.lock()",
            "let mut collector_slot = COLLECTOR.lock()",
            "*slot = SlotState::Ready(ready)",
            "*collector_slot = CollectorState::Ready(collector)",
            "collector_audit_meta(audit)",
        ),
        "single META success reinstall",
    )
    exact_semantic(
        success.raw,
        """
        Err(_) => {
            quarantine_collector_initialization(
                collector,
                ready,
                CollectorFailureReason::MetaRecord,
            );
            return;
        }
        """,
        "META audit-token failure quarantine",
    )
    require("collector_take_audit(1).expect" not in semantic(success.raw), "missing META audit token can panic/retry after META")
    require(
        semantic(success.raw).count("quarantine_collector_initialization(") == 2,
        "META audit/reinstall failures do not both absorb the campaign and restore Ready",
    )
    success_code = semantic(success.raw)
    require(
        success_code.rfind("drop(collector_slot)")
        < success_code.rfind("drop(slot)")
        < success_code.find("collector_audit_meta(audit)"),
        "META audit marker can run while SLOT/COLLECTOR is locked",
    )
    require(initialize_code.count("campaign.begin(") == 1, "kernel can begin a second META campaign")
    require(initialize_code.count("collector_audit_meta(") == 1, "kernel can emit a second META audit marker")
    initial_failure = find_scope(slot, r"\bfn\s+install_collector_initial_failure\b", "collector initial failure install")
    ordered_semantic(
        initial_failure.raw,
        (
            "let ready_epoch = ready.next_epoch().unwrap_or(epoch)",
            "let mut slot = SLOT.lock()",
            "let mut collector_slot = COLLECTOR.lock()",
            "mem::replace(&mut *slot, SlotState::Ready(ready))",
            "CollectorState::Failed(CollectorFailureReceipt::new(",
        ),
        "collector initial failure Ready/Failed reinstall",
    )
    init_quarantine = find_scope(slot, r"\bfn\s+quarantine_collector_initialization\b", "collector META quarantine")
    ordered_semantic(
        init_quarantine.raw,
        (
            "collector.quarantine_attempt(ready, CollectorAbort::TerminalRejected)",
            "poisoned.committed_records()",
            "poisoned.into_ready()",
            "install_collector_initial_failure(",
        ),
        "collector META audit/reinstall quarantine",
    )

    # The exact adapter names are intentionally allowed to evolve, but the
    # source ordering must show both state tombstones before external work and
    # owner detachment before the first record factory acquisition.
    require(slot_code.count("CollectorState::Publishing") >= 1, "collector lacks a Publishing tombstone")
    require(slot_code.count("CollectorState::PendingAcceptance") >= 4, "collector lacks a sealed post-SAMPLE acceptance state")
    require(slot_code.count("CollectorState::PendingTerminal") >= 4, "collector lacks a sealed pending-END state")
    require(slot_code.count("CollectorState::FinalizingTerminal") >= 3, "collector lacks an END-commit tombstone")
    require(slot_code.count("CollectorState::Failed") >= 2, "collector failure is not absorbing")
    require(slot_code.count("CollectorState::Complete") >= 2, "collector completion is not absorbing")
    require("CollectorAbort::TerminalRejected" in slot and "quarantine_attempt(" in slot, "terminal rejection can escape without collector poison")
    require("CollectorAbort::OwnerMismatch" in slot, "owner mismatch is not collector-fatal")
    collect = find_scope(slot, r"\bpub\(crate\)\s+fn\s+collect_trusted_sample\b", "trusted collector consume")
    collect_code = semantic(collect.raw)
    ordered_semantic(
        collect.raw,
        (
            "let previous_collector = mem::replace(&mut *collector_slot, CollectorState::Publishing { owner })",
            "*slot = SlotState::CollectorPublishing { owner }",
            "if !owner.detach.is_current_running_exact()",
            "if owner.detach.disarm() != TaskDetachDisarm::Disarmed",
            "match collector.collect(sample, evidence)",
        ),
        "Publishing/disarm/first-sink order",
    )
    require(collect_code.count("collector.collect(sample,evidence)") == 1, "collector SAMPLE call count differs")
    require("begin_record(" not in collect_code, "kernel adapter directly acquires a sink around the portable collector")
    require(slot_code.count("collector.collect(") == 1, "another kernel path can publish a SAMPLE")
    publishing = collect.raw.index("*slot = SlotState::CollectorPublishing { owner };")
    require("?" not in collect.raw[publishing:], "collector can early-return after Publishing without quarantine")
    require("return Err(" not in collect.raw[publishing:], "collector can leave a Publishing tombstone directly")
    require(
        "owner.epoch.checked_sub(1)" in collect_code
        and "u8::try_from(value).ok()" in collect_code
        and "sequence.checked_add(2)" in collect_code,
        "kernel audit derives sequence/commit order with unchecked or caller-supplied arithmetic",
    )
    require(
        collect_code.count("quarantine_ready_for_collector(") >= 3
        and collect_code.count("quarantine_verified_for_collector(") >= 3,
        "post-Publishing failure paths do not all restore Ready and absorb Failed",
    )
    more = find_scope(collect.raw, r"Ok\(CollectionProgress::More\(next\)\)\s*=>", "collector More reinstall")
    ordered_semantic(
        more.raw,
        (
            "collector_take_audit(expected_commit)",
            "*slot = SlotState::Ready(ready)",
            "*collector_slot = CollectorState::PendingAcceptance",
            "armed: true",
        ),
        "SAMPLE audit capability before Ready/PendingAcceptance reinstall",
    )
    more_code = semantic(more.raw)
    require(
        "slot_owner.matches(owner.epoch,owner.detach)&&collector_owner.matches(owner.epoch,owner.detach)"
        in more_code
        and "if!exact||ready.next_epoch()!=Some(ready_epoch)" in more_code,
        "SAMPLE reinstall accepts stale owner lineage or a changed Ready epoch",
    )
    require(
        "CollectorState::Ready(collector)" not in more_code,
        "next collector epoch becomes reusable before SSH tail acceptance",
    )
    pending = find_scope(
        collect.raw,
        r"Ok\(CollectionProgress::PendingTerminal\(pending\)\)\s*=>",
        "collector pending-END reinstall",
    )
    ordered_semantic(
        pending.raw,
        (
            "pending.ready_next_epoch()",
            "pending.receipt()",
            "pending.into_parts()",
            "collector_take_audit(expected_commit)",
            "*slot = SlotState::Ready(ready)",
            "*collector_slot = CollectorState::PendingTerminal",
            "armed: true",
        ),
        "sample-23 capability before Ready25/pending-END reinstall",
    )
    pending_code = semantic(pending.raw)
    require(
        "slot_owner.matches(owner.epoch,owner.detach)&&collector_owner.matches(owner.epoch,owner.detach)"
        in pending_code
        and "if!exact||ready.next_epoch()!=Some(ready_epoch)" in pending_code,
        "pending-END reinstall accepts stale owner lineage or a changed Ready25",
    )
    require(
        "commit_terminal(" not in collect_code
        and "CollectorState::Complete" not in pending_code,
        "sample-23 path commits END or closes before SSH tail acceptance",
    )

    next_epoch = find_scope(
        slot,
        rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(FEATURE)}"\s*\)\s*\]\s*fn\s+next_epoch_for_prepare\b',
        "collector terminal pre-prepare gate",
        match_literals=True,
    )
    next_code = semantic(next_epoch.raw)
    require(
        "(SlotState::Ready(_),CollectorState::Complete{..})=>{Err(ProfileError::CollectorClosed)}"
        in next_code
        and "(SlotState::Ready(_),CollectorState::Failed(_))=>Err(ProfileError::CollectorFailed)"
        in next_code
        and "CollectorState::PendingAcceptance{..}" in next_code
        and "CollectorState::PendingTerminal{..}" in next_code
        and "CollectorState::FinalizingTerminal{..}" in next_code
        and next_code.count("Err(ProfileError::Busy)") >= 2,
        "pending/closed/failed states do not gate preparation against the preserved Ready slot",
    )
    prepare_current = find_scope(
        slot,
        rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(FEATURE)}"\s*\)\s*\]\s*pub\(crate\)\s+fn\s+prepare_current\b',
        "collector request preparation",
        match_literals=True,
    )
    ordered_semantic(
        prepare_current.raw,
        (
            "let epoch = next_epoch_for_prepare()?",
            "try_reserve_current_task_registrations(1)",
            "register_current_task_detach(target)",
            "detach.is_current_running_exact()",
            "reserve_ready(epoch, detach)",
        ),
        "terminal-check-before-registration/start preparation",
    )

    acknowledge = find_scope(
        slot,
        rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(FEATURE)}"\s*\)\s*\]\s*pub\(crate\)\s+fn\s+acknowledge_rejection\b',
        "collector rejection acknowledgement",
        match_literals=True,
    )
    acknowledge_code = semantic(acknowledge.raw)
    ordered_semantic(
        acknowledge.raw,
        (
            "let previous_slot = mem::replace(&mut *slot, SlotState::CollectorPublishing { owner })",
            "let previous_collector = mem::replace(&mut *collector_slot, CollectorState::Publishing { owner })",
            "CollectorFailureReason::ActiveTargetDisconnected",
            "collector.quarantine_attempt(ready, CollectorAbort::TerminalRejected)",
        ),
        "active-target disconnect to absorbing Failed",
    )
    quarantine_position = acknowledge_code.find("collector.quarantine_attempt(ready,CollectorAbort::TerminalRejected)")
    require(
        quarantine_position
        < acknowledge_code.rfind("*slot=SlotState::Ready(ready)")
        < acknowledge_code.rfind("*collector_slot=CollectorState::Failed"),
        "active disconnect does not restore Ready before installing Failed",
    )
    require("write_end" not in acknowledge_code and "collector.collect(" not in acknowledge_code, "disconnect failure can publish SAMPLE/END")

    failed_marker = find_scope(slot, r"\bpub\(crate\)\s+fn\s+collector_emit_failed_after_drop\b", "collector FAILED marker")
    ordered_semantic(
        failed_marker.raw,
        (
            "let slot = SLOT.lock()",
            "let mut collector_slot = COLLECTOR.lock()",
            "receipt.sequence == 0",
            "receipt.audit_commits == 1",
            "receipt.reason == CollectorFailureReason::ActiveTargetDisconnected",
            "&& receipt.marker_pending =>",
            "receipt.marker_pending = false",
            "drop(collector_slot)",
            "drop(slot)",
            "crate::println!(",
        ),
        "one-shot FAILED marker after active disconnect",
    )
    terminal_reject = find_scope(slot, r"\bpub\(crate\)\s+fn\s+collector_terminal_reject\b", "collector terminal rejection")
    terminal_code = semantic(terminal_reject.raw)
    require(
        "ready.next_epoch()==Some(*ready_epoch)" in terminal_code
        and "ready.next_epoch()==Some(receipt.ready_epoch)" in terminal_code
        and "receipt.samples()" in terminal_code
        and "false,receipt.ready_epoch,receipt.sequence,receipt.audit_commits" in terminal_code,
        "terminal rejection does not preserve exact Ready25/Ready2 and next sequence",
    )
    failed_reject = (
        f'"{FAMILY} REJECT epoch={{}} attempt={{}} next_sequence={{}} status=126 '
        'reason=collector_failed target_started=0 audit_commits={} state=failed ready_epoch={} '
        'decision_eligible=0 formal_uart=0", ready_epoch, ready_epoch, next_sequence, '
        'audit_commits, ready_epoch,'
    )
    require(
        semantic(failed_reject) in terminal_code,
        "Failed REJECT does not print the receipt-derived next sequence",
    )
    ordered_semantic(
        terminal_reject.raw,
        ("let marker = match", "drop(collector_slot)", "drop(slot)", "let Some"),
        "terminal reject state snapshot before marker",
    )
    require(
        terminal_code.find("drop(slot)") < terminal_code.find("crate::println!("),
        "terminal reject prints while retaining SLOT/COLLECTOR",
    )

    terminal_receipt = find_scope(slot, r"\bpub\(crate\)\s+struct\s+CollectorTerminalReceipt\b", "collector terminal receipt")
    require(
        semantic(terminal_receipt.raw)
        == (
            "pub(crate)structCollectorTerminalReceipt{epoch:u64,ready_epoch:u64,committed_records:u8,"
            "armed:bool,"
            f'#[cfg(feature="{QEMU_FEATURE}")]audit:Option<CollectorAuditTerminal>,}}'
        ),
        "collector terminal receipt can be copied or dropped without an armed fail-close",
    )
    require(
        slot_code.count("armed:true") == 2 and slot_code.count("receipt.armed=false") == 4,
        "terminal receipt arm/disarm graph differs",
    )
    receipt_drop = find_scope(slot, r"\bimpl\s+Drop\s+for\s+CollectorTerminalReceipt\b", "collector terminal receipt Drop")
    ordered_semantic(
        receipt_drop.raw,
        (
            "if self.armed",
            "self.armed = false",
            "collector_fail_unfinalized_terminal(",
        ),
        "unfinalized collector terminal fail-close",
    )
    fail_unfinalized = find_scope(slot, r"\bfn\s+collector_fail_unfinalized_terminal\b", "unfinalized collector terminal failure")
    fail_unfinalized_code = semantic(fail_unfinalized.raw)
    require(
        "SlotState::Ready(ready)ifready.next_epoch()==Some(ready_epoch)" in fail_unfinalized_code
        and "CollectorState::Failed(CollectorFailureReceipt::new(" in fail_unfinalized_code
        and "CollectorFailureReason::StateMismatch" in fail_unfinalized_code
        and "receipt.absorb_committed_records(committed_records)" in fail_unfinalized_code
        and "CollectorState::PendingAcceptance" in fail_unfinalized_code
        and "CollectorState::PendingTerminal" in fail_unfinalized_code,
        "dropped terminal receipt can leave a closed campaign reusable",
    )
    install_failure = find_scope(slot, r"\bfn\s+install_collector_failure\b", "collector failure install")
    install_failure_code = semantic(install_failure.raw)
    require(
        "CollectorState::Failed(receipt)ifreceipt.epoch==owner.epoch" in install_failure_code
        and "receipt.ready_epoch=ready_epoch" in install_failure_code
        and "receipt.absorb_committed_records(committed_records)" in install_failure_code,
        "absorbing Failed reinstall can roll back or stale its next sequence",
    )
    emit_success = find_scope(slot, r"\bpub\(crate\)\s+fn\s+collector_emit_success\b", "collector success finalizer")
    emit_success_code = semantic(emit_success.raw)
    require(
        "pub(crate)fncollector_emit_success(mutreceipt:CollectorTerminalReceipt,)->Result<(),ProfileError>"
        in emit_success_code,
        "collector success finalizer cannot report a failed END commit",
    )
    ordered_semantic(
        emit_success.raw,
        (
            "receipt.audit.take()",
            "collector_audit_sample(",
            "let final_prefix_records = BOOT_SAMPLES.checked_add(1)",
            "let slot = SLOT.lock()",
            "let mut collector_slot = COLLECTOR.lock()",
            "if receipt.committed_records < final_prefix_records",
            "let CollectorState::PendingAcceptance { collector, .. } = previous else",
            "*collector_slot = CollectorState::Ready(collector)",
            "return Ok(())",
            "CollectorState::FinalizingTerminal",
            "let CollectorState::PendingTerminal { pending_end, .. } = previous else",
            "pending_end.commit_terminal()",
            "let committed_records = poisoned.committed_records()",
            "let boot = completed.receipt()",
            "collector_take_audit(committed_records)",
            "*collector_slot = CollectorState::Complete",
            "collector_audit_end(end, boot, receipt.ready_epoch)",
        ),
        "post-tail SAMPLE acceptance and sole END finalization",
    )
    require(
        emit_success_code.count("pending_end.commit_terminal()") == 1
        and slot_code.count("pending_end.commit_terminal()") == 1
        and emit_success_code.count("receipt.armed=false") == 4,
        "END authority can be committed elsewhere or a finalizer outcome stays armed",
    )

    # Every acquisition of the collector slot must have a still-live SLOT
    # acquisition earlier in the same top-level function. This admits multiple
    # mutually-exclusive match arms under one live SLOT guard, while rejecting
    # the reverse order and releasing SLOT before taking COLLECTOR.
    lines = slot.splitlines()
    function_start = 0
    last_slot = -1
    for index, line in enumerate(lines):
        if re.match(r"^(?:pub(?:\(crate\))?\s+)?fn\s+", line):
            function_start = index
            last_slot = -1
        if "SLOT.lock()" in line:
            last_slot = index
        if "COLLECTOR.lock()" in line:
            require(last_slot >= function_start, f"COLLECTOR acquired before SLOT near line {index + 1}")
            between = "\n".join(lines[last_slot : index + 1])
            require("drop(slot)" not in between, f"SLOT released before COLLECTOR near line {index + 1}")
    for forbidden in ("wrapping_add", "saturating_add"):
        require(forbidden not in collect_code, f"kernel collector consume uses lossy sequence arithmetic {forbidden}")

    ssh = semantic(inputs.ssh)
    require(FEATURE.replace("-", "") in ssh or FEATURE in inputs.ssh, "SSH collector successor is absent")
    require("finish_verify_trusted_discard_and_ack_profile" in inputs.ssh, "trusted predecessor helper was removed")
    require("discard=trusted_sample_abandoned" in inputs.ssh, "trusted predecessor marker contract drifted")
    collect_helper = find_scope(
        inputs.ssh,
        r"\bfn\s+finish_verify_trusted_collect_profile\b",
        "SSH trusted-bundle collector adapter",
    )
    ordered_semantic(
        collect_helper.raw,
        (
            "let epoch = run.token().epoch()",
            "run.finish_trusted(terminal)",
            "collect_trusted_sample(bundle)",
            "collector.ready_epoch()",
            "Ok(TrustedSampleEvidence",
        ),
        "SSH trusted-bundle consumption",
    )
    require(
        semantic(collect_helper.raw).count("collect_trusted_sample(bundle)") == 1
        and ".discard(" not in collect_helper.raw,
        "collector SSH adapter discards or duplicates the trusted bundle",
    )
    abandon = find_scope(slot, r"\bfn\s+abandon_trusted_sample_for_collector\b", "collector trusted-bundle abandon")
    ordered_semantic(
        abandon.raw,
        (
            "*slot = SlotState::CollectorPublishing { owner }",
            "CollectorState::Publishing { owner }",
            "let disarm = owner.detach.disarm()",
            "let ready = sample.recycle()",
            "collector.quarantine_attempt(ready, CollectorAbort::TerminalRejected)",
            "let committed_records = poisoned.committed_records()",
        ),
        "collector-specific trusted-bundle abandon",
    )
    require(
        "install_rejected(" not in abandon.raw and "acknowledge_rejection(" not in abandon.raw,
        "collector bundle abandon re-enters the predecessor reject/ack state machine",
    )
    require(
        semantic(abandon.raw).count("install_collector_failure(") == 2,
        "collector bundle abandon does not restore Ready/Failed with or without its live collector",
    )
    trusted_drop = find_scope(slot, r"\bimpl\s+Drop\s+for\s+TrustedVerifiedSample\b", "trusted bundle Drop")
    require(
        semantic(trusted_drop.raw).count("abandon_trusted_sample_for_collector(sample,self.owner)") == 1,
        "collector bundle Drop does not use its Ready-restoring absorbing path",
    )
    release_reservation = find_scope(
        slot,
        rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(FEATURE)}"\s*\)\s*\]\s*fn\s+release_reservation\b',
        "collector reservation recovery",
        match_literals=True,
    )
    release_code = semantic(release_reservation.raw)
    require(
        "(SlotState::Ready(ready),CollectorState::Failed(receipt))" in release_code
        and "*slot=SlotState::Ready(ready)" in release_code
        and "TaskDetachDisarm::Disarmed|TaskDetachDisarm::AlreadyDisarmed" in release_code,
        "dropped/failed start permit can consume Ready or reopen Failed",
    )
    recover_target = find_scope(slot, r"\bfn\s+recover_failed_target\b", "collector failed-start recovery")
    ordered_semantic(
        recover_target.raw,
        (
            "let disarm = owner.detach.disarm()",
            "sample.cancel(token, context)",
            "rejected.recycle()",
            "SlotState::Transit",
            "CollectorState::Failed(_)",
            "*slot = SlotState::Ready(ready)",
            "*collector_slot = CollectorState::Failed",
        ),
        "collector failed-start Ready recovery",
    )
    start_reserved = find_scope(slot, r"\bfn\s+start_reserved\b", "collector target start")
    require(
        semantic(start_reserved.raw).count("recover_failed_target(") == 2
        and semantic(start_reserved.raw).count("CollectorFailureReason::Start") >= 5,
        "start/IRQ publication failures can strand the sole Ready authority",
    )
    detached = find_scope(slot, r"\bunsafe\s+fn\s+profile_task_detached\b", "collector detach callback")
    detached_code = semantic(detached.raw)
    require(
        "SlotState::Transit{owner,..}ifowner.callback_matches(epoch,task,domain)" in detached_code
        and "SlotState::CollectorPublishing{owner}ifowner.callback_matches(epoch,task,domain)" in detached_code
        and detached_code.count("ifinstalled.is_ok(){let_=acknowledge_rejection(owner.epoch);}") == 2,
        "detach/IRQ recovery can poison a collector tombstone or fail to reinstall Ready",
    )
    prepare_ssh = find_scope(inputs.ssh, r"\bfn\s+prepare_ssh_exec_profile\b", "kernel SSH profile preparation")
    permit_match = find_scope(prepare_ssh.raw, r"\blet\s+permit\s*=\s*match\b", "kernel SSH prepare result split")
    ordered_semantic(
        permit_match.raw,
        (
            "prepare_current()",
            "Err(error) if crate::wasm_aot_profile_slot::collector_terminal_reject(error)",
            "return Err(SshExecProfilePrepareError::Reject)",
            "profile_request_failure",
            "return Err(SshExecProfilePrepareError::Failed)",
        ),
        "kernel terminal-reject-before-start mapping",
    )
    require(
        semantic(prepare_ssh.raw).find("SshExecProfilePrepareError::Reject")
        < semantic(prepare_ssh.raw).find("SshExecProfilePermit::new"),
        "terminal rejection is mapped after constructing a permit",
    )
    require("profile_request_start" not in prepare_ssh.raw, "kernel logs/starts a target before terminal rejection")
    ordered_semantic(
        inputs.ssh,
        (
            f'#[cfg(feature = "{QEMU_FEATURE}")] collector_trusted_sample_response(epoch, &_terminal_evidence)?',
            f'#[cfg(feature = "{FEATURE}")] crate::wasm_aot_profile_slot::collector_emit_success(_terminal_evidence.collector).map_err(|_| ())?;',
        ),
        "diagnostic predecessor marker before fallible collector finalization",
    )
    response_success = find_scope(
        inputs.ssh,
        r"Ok\(\(ready_epoch,\s*_terminal_evidence\)\)\s+if\s+terminal_prerequisite_exact\s*=>",
        "SSH successful terminal response",
    )
    response_code = semantic(response_success.raw)
    finalizer_position = response_code.find("collector_emit_success(")
    require(finalizer_position >= 0, "SSH success drops the armed collector terminal receipt")
    finalizer_tail = response_code[finalizer_position:]
    require(
        "collector_emit_success(_terminal_evidence.collector).map_err(|_|())?;Ok(())"
        in finalizer_tail
        and finalizer_tail.count("?") == 1
        and "returnErr" not in finalizer_tail,
        "SSH does not propagate END failure or can fail after collector finalization",
    )
    require(
        response_code.rfind("?") > finalizer_position
        and response_code.rfind("?") == response_code.find("?", finalizer_position),
        "collector finalization is not the last fallible SSH-tail operation",
    )
    qemu_failure = semantic(
        f"""
        #[cfg(feature = "{QEMU_FEATURE}")]
        {{
            trusted_sample_drop(epoch, ready_epoch);
            if crate::wasm_aot_profile_slot::collector_emit_failed_after_drop(
                epoch,
                ready_epoch,
            )
            .is_err()
            {{
                profile_request_failure("collector-drop-observation", Some(epoch));
                return;
            }}
        }}
        """
    )
    require(ssh.count(qemu_failure) == 1, "QEMU active disconnect does not emit exact DROP then FAILED")

    root = semantic(inputs.kernel_root)
    local_vsh_cfg = (
        '#[cfg(not(any(feature="legacy-shell",feature="wasm-c67-information-flow-acceptance",'
        'feature="wasm-c74-crash-safe-publication-acceptance",feature="wasm-c75-boot-revalidation-acceptance",'
        'feature="wasm-c76-graph-version-replacement-acceptance",feature="wasm-c83-runtime-costs",'
        f'feature="{FEATURE}")))]'
    )
    require(local_vsh_cfg in root, "collector image does not suppress the local VSH/prompt task")


def verify_audit_source(inputs: Inputs) -> None:
    slot = inputs.slot
    slot_code = semantic(slot)
    masked = comment_masked(slot)
    qemu_units = direct_feature_units(slot, QEMU_FEATURE)
    require(len(qemu_units) >= 12, "QEMU audit feature-unit set is unexpectedly small")
    qemu_source = "\n".join(qemu_units)
    qemu_code = semantic(qemu_source)
    for forbidden in (
        "crate::uart",
        "crate::tty",
        "uart::",
        "tty::",
        "Console",
        "Vec<",
        "String",
        "Box<",
        "alloc::",
        "from_utf8",
        "str::from",
        "format!(",
        "debug!(",
        "write_all(&mutcrate::",
    ):
        require(forbidden not in qemu_source, f"QEMU audit feature forwards/stores bytes via {forbidden!r}")
    for prefix in FORMAL_PREFIXES:
        require(prefix not in qemu_source, f"QEMU audit reconstructs formal prefix {prefix!r}")
    require("AuditCommit" in masked, "audit commit token type is missing")
    token_scope = find_scope(slot, r"\bstruct\s+AuditCommit\b", "AuditCommit token")
    token_prefix = slot[max(0, token_scope.start - 160) : token_scope.start]
    require("Copy" not in token_prefix and "Clone" not in token_prefix, "AuditCommit is duplicable")
    require("pub struct AuditCommit" not in masked and "pub(crate) struct AuditCommit" not in masked, "AuditCommit escapes the slot module")
    token_impls = re.findall(r"\bimpl\b[^{};]*\bfor\s+AuditCommit\b", masked)
    require(not token_impls, "AuditCommit gained a conversion/recovery trait")

    token_fields = semantic(token_scope.raw)
    require(
        token_fields == "structAuditCommit{ordinal:u8,bytes:u64,sha256:[u8;32],}",
        "AuditCommit field surface differs",
    )
    state = find_scope(slot, r"\bstruct\s+AuditState\b", "audit state")
    require(
        semantic(state.raw)
        == "structAuditState{commits:u8,pending_first:Option<AuditCommit>,pending_second:Option<AuditCommit>,last_sample_accumulator:u64,}",
        "audit state stores data beyond bounded commit capabilities",
    )
    state_impl = find_scope(slot, r"\bimpl\s+AuditState\b", "audit state impl")
    exact_semantic(
        state_impl.raw,
        """
        impl AuditState {
            const NEW: Self = Self {
                commits: 0,
                pending_first: None,
                pending_second: None,
                last_sample_accumulator: 0,
            };

            fn push(&mut self, commit: AuditCommit) -> Result<(), AuditError> {
                if self.pending_first.is_none() {
                    self.pending_first = Some(commit);
                    return Ok(());
                }
                if self.pending_second.is_none() {
                    self.pending_second = Some(commit);
                    return Ok(());
                }
                Err(AuditError::PendingCommitOverflow)
            }

            fn take(&mut self, expected: u8) -> Result<AuditCommit, AuditError> {
                let Some(commit) = self.pending_first.take() else {
                    return Err(AuditError::PendingCommitOverflow);
                };
                self.pending_first = self.pending_second.take();
                if commit.ordinal != expected {
                    return Err(AuditError::DuplicateCommit);
                }
                Ok(commit)
            }
        }
        """,
        "bounded audit capability queue",
    )
    factory = find_scope(slot, r"\bstruct\s+AuditRecordFactory\b", "audit factory")
    require(
        semantic(factory.raw) == "structAuditRecordFactory{not_sync:PhantomData<Cell<()>>,}",
        "persistent audit factory is not guard-free Send + !Sync",
    )
    record_value = find_scope(slot, r"\bstruct\s+AuditRecord\b", "audit record")
    require(
        semantic(record_value.raw)
        == (
            "structAuditRecord{hasher:Sha256,bytes:u64,wrote_any:bool,"
            "line_feed_seen:bool,committed:bool,not_send:PhantomData<*mut()>,}"
        ),
        "temporary audit record fields no longer enforce absorbing !Send hashing",
    )
    require("implDropforAuditRecord" not in qemu_code, "audit record gained a Drop flush/recovery path")
    require("unsafeimplSendforAuditRecord" not in qemu_code, "audit record gained an unsafe Send impl")
    require("unsafeimplSyncforAuditRecordFactory" not in qemu_code, "audit factory gained an unsafe Sync impl")
    for type_name in ("AuditCommit", "AuditState", "AuditRecordFactory", "AuditRecord"):
        require(f"implDropfor{type_name}" not in slot_code, f"{type_name} gained a Drop flush/recovery path")
    require("unsafeimplSendforAuditRecord" not in slot_code, "audit record gained an unguarded unsafe Send impl")
    require("unsafeimplSyncforAuditRecordFactory" not in slot_code, "audit factory gained an unguarded unsafe Sync impl")

    factory_impl = find_scope(
        slot,
        r"\bimpl\s+ProfileRecordSinkFactory\s+for\s+AuditRecordFactory\b",
        "audit record factory impl",
    )
    exact_semantic(
        factory_impl.raw,
        """
        impl ProfileRecordSinkFactory for AuditRecordFactory {
            type Error = AuditError;
            type Record = AuditRecord;

            fn begin_record(&mut self) -> Result<Self::Record, Self::Error> {
                if COLLECTOR_AUDIT.lock().pending_second.is_some() {
                    return Err(AuditError::PendingCommitOverflow);
                }
                Ok(AuditRecord {
                    hasher: Sha256::new(),
                    bytes: 0,
                    wrote_any: false,
                    line_feed_seen: false,
                    committed: false,
                    not_send: PhantomData,
                })
            }
        }
        """,
        "absorbing audit factory",
    )
    record_impl = find_scope(slot, r"\bimpl\s+ProfileRecordSink\s+for\s+AuditRecord\b", "audit record sink impl")
    exact_semantic(
        record_impl.raw,
        r"""
        impl ProfileRecordSink for AuditRecord {
            type Error = AuditError;

            fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
                if self.committed {
                    return Err(AuditError::DuplicateCommit);
                }
                if !bytes.is_empty() && self.line_feed_seen {
                    return Err(AuditError::BytesAfterLineFeed);
                }
                if bytes.iter().any(|byte| *byte == b'\r') {
                    return Err(AuditError::CarriageReturn);
                }
                if bytes.contains(&0) {
                    return Err(AuditError::NulByte);
                }
                let line_feeds = bytes.iter().filter(|byte| **byte == b'\n').count();
                if line_feeds > 1 {
                    return Err(AuditError::MultipleLineFeeds);
                }
                if line_feeds == 1 && bytes.last() != Some(&b'\n') {
                    return Err(AuditError::LineFeedNotFinal);
                }
                let fragment = u64::try_from(bytes.len()).map_err(|_| AuditError::ByteCountOverflow)?;
                let next = self
                    .bytes
                    .checked_add(fragment)
                    .ok_or(AuditError::ByteCountOverflow)?;
                self.hasher.update(bytes);
                self.bytes = next;
                self.wrote_any |= !bytes.is_empty();
                self.line_feed_seen |= line_feeds == 1;
                Ok(())
            }

            fn commit_record(&mut self) -> Result<(), Self::Error> {
                if self.committed {
                    return Err(AuditError::DuplicateCommit);
                }
                if !self.wrote_any {
                    return Err(AuditError::EmptyRecord);
                }
                if !self.line_feed_seen {
                    return Err(AuditError::MissingLineFeed);
                }
                let sha256: [u8; 32] = self.hasher.clone().finalize().into();
                let mut audit = COLLECTOR_AUDIT.lock();
                let ordinal = audit
                    .commits
                    .checked_add(1)
                    .ok_or(AuditError::CommitCountOverflow)?;
                audit.push(AuditCommit {
                    ordinal,
                    bytes: self.bytes,
                    sha256,
                })?;
                audit.commits = ordinal;
                self.committed = true;
                Ok(())
            }
        }
        """,
        "absorbing audit record",
    )

    audit_text = "\n".join((record_value.raw, record_impl.raw))
    audit_code = semantic(audit_text)
    for forbidden in (
        "println!(",
        "print!(",
        "tty::",
        "uart::",
        "Console",
        "String",
        "Vec<",
        "Box<",
        "alloc::",
        "from_utf8",
        "str::from",
        "format!(",
        "debug!(",
    ):
        require(forbidden not in audit_text, f"absorbing audit sink forwards/stores bytes via {forbidden!r}")
    require("Sha256" in audit_text or "sha256" in audit_text.lower(), "audit record does not hash absorbed bytes")
    require("checked_add" in audit_code, "audit byte/commit counters are not checked")
    require("commit_record" in audit_code, "audit record has no commit boundary")
    require("AuditCommit" in audit_text, "successful audit commit does not mint its private token")
    for prefix in FORMAL_PREFIXES:
        require(prefix not in audit_text, f"audit sink branches on/forwards formal prefix {prefix!r}")

    digest = find_scope(slot, r"\bimpl\s+fmt::Display\s+for\s+HexDigest", "audit lowercase digest formatter")
    exact_semantic(
        digest.raw,
        """
        impl fmt::Display for HexDigest<'_> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
        """,
        "audit lowercase digest formatter",
    )

    marker_scopes = [
        find_scope(slot, rf"\bfn\s+{name}\b", f"collector audit marker {name}")
        for name in ("collector_audit_meta", "collector_audit_sample", "collector_audit_end")
        if re.search(rf"\bfn\s+{name}\b", masked)
    ]
    require(len(marker_scopes) == 3, "META/SAMPLE/END audit marker helpers differ")
    for scope in marker_scopes:
        code = semantic(scope.raw)
        require("AuditCommit" in scope.raw, f"{scope.raw[:40]!r} does not consume AuditCommit")
        require("&AuditCommit" not in scope.raw, "audit marker borrows a reusable commit token")
        require("decision_eligible=0" in scope.raw and "formal_uart=0" in scope.raw, "audit marker flags differ")
        require("println!(" in scope.raw, "audit marker is not the sole diagnostic emitter")
        require("write_all(" not in code and "commit_record(" not in code, "audit marker writes after commit")
    expected_markers = (
        f"{FAMILY} AUDIT_META commit={{}} bytes={{}} sha256={{}} next_sequence=0 state=collecting ready_epoch=1 decision_eligible=0 formal_uart=0",
        f"{FAMILY} AUDIT_SAMPLE commit={{}} epoch={{}} sequence={{}} warmup={{}} bytes={{}} sha256={{}} accumulator={{}} next_sequence={{}} recycled_ready_epoch={{}} state=collecting decision_eligible=0 formal_uart=0",
        f"{FAMILY} AUDIT_END commit={{}} samples={{}} warmups={{}} retained={{}} bytes={{}} sha256={{}} accumulator={{}} recycled_ready_epoch={{}} state=closed decision_eligible=0 formal_uart=0",
        f"{FAMILY} FAILED epoch={{}} sequence={{}} reason=active_target_disconnected target_started=1 sample_committed=0 end_committed=0 audit_commits={{}} recycled_ready_epoch={{}} state=failed decision_eligible=0 formal_uart=0",
        f"{FAMILY} REJECT epoch={{}} attempt={{}} next_sequence={{}} status=126 reason=collector_closed target_started=0 audit_commits={{}} state=closed ready_epoch={{}} decision_eligible=0 formal_uart=0",
        f"{FAMILY} REJECT epoch={{}} attempt={{}} next_sequence={{}} status=126 reason=collector_failed target_started=0 audit_commits={{}} state=failed ready_epoch={{}} decision_eligible=0 formal_uart=0",
    )
    for marker in expected_markers:
        require(slot.count(marker) == 1, f"exact QEMU collector marker schema differs: {marker.split()[1]}")

    meta = marker_scopes[0]
    ordered_semantic(meta.raw, ("commit.ordinal", "commit.bytes", "HexDigest(&commit.sha256)"), "META post-commit token projection")
    sample = marker_scopes[1]
    ordered_semantic(
        sample.raw,
        (
            "let next_sequence = sequence.checked_add(1)",
            "let accumulator = u64::from_be_bytes",
            "COLLECTOR_AUDIT.lock().last_sample_accumulator = accumulator",
            "commit.ordinal",
            "u8::from(sequence < BOOT_WARMUPS)",
        ),
        "SAMPLE audit relations",
    )
    require(
        "u8::from(sequence<BOOT_WARMUPS),commit.bytes,HexDigest(&commit.sha256),"
        "accumulator,next_sequence,ready_epoch," in semantic(sample.raw),
        "SAMPLE marker argument relation differs",
    )
    end = marker_scopes[2]
    ordered_semantic(
        end.raw,
        (
            "let accumulator = COLLECTOR_AUDIT.lock().last_sample_accumulator",
            "commit.ordinal",
            "receipt.samples()",
            "receipt.warmups()",
            "receipt.retained()",
        ),
        "END audit relations",
    )
    require(
        "receipt.samples(),receipt.warmups(),receipt.retained(),commit.bytes,"
        "HexDigest(&commit.sha256),accumulator,ready_epoch," in semantic(end.raw),
        "END marker argument relation differs",
    )

    take = find_scope(slot, r"\bfn\s+collector_take_audit\b", "audit token take")
    require(
        semantic(take.raw)
        == "fncollector_take_audit(expected:u8)->Result<AuditCommit,AuditError>{COLLECTOR_AUDIT.lock().take(expected)}",
        "audit commit token can be forged or recovered outside the private queue",
    )
    require(slot_code.count("AuditCommit{") == 2, "AuditCommit has another constructor")
    require(slot_code.count("collector_take_audit(") == 5, "audit token take graph differs")


def verify_peer_script(raw: bytes) -> None:
    require(hashlib.sha256(raw).hexdigest() == PEER_SCRIPT_SHA256, "collector peer SHA-256 differs")
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"collector peer is not UTF-8: {error}") from error
    require(source.startswith("#!/usr/bin/env python3\n"), "collector peer shebang differs")
    require("--selftest" in source and "--verify-log-only" in source, "collector peer lacks selftest/frozen-log modes")
    require(FAMILY in source, "collector peer family differs")
    require("MAX_QEMU_LOG_BYTES = 16 * 1024 * 1024" in source, "collector peer raw-log bound differs")
    require("EXPECTED_META_BYTES = 1157" in source, "collector peer META byte KAT differs")
    require(
        'EXPECTED_META_SHA256 = "6d46aa52ca9155cfed4eae230a00175f4247d950a8a686a8bdb3657dc6954b4b"' in source,
        "collector peer META SHA-256 KAT differs",
    )
    require(
        source.count('getattr(os, "O_NOFOLLOW", 0)') == 3,
        "stable/live/source peer readers do not all reject symlinks",
    )
    require(source.count("stat.S_ISREG(") >= 3, "stable/live peer readers do not both require regular files")
    require(source.count("total <= MAX_QEMU_LOG_BYTES") == 2, "stable/live peer readers do not both enforce streaming size bounds")
    require(
        "len(set(record_digests)) == len(record_digests)" in source
        and "META, 24 ordered SAMPLE records, and END must have distinct audit digests" in source,
        "collector peer does not require 26 distinct record digests",
    )
    require("SAMPLE_COUNT = 24" in source, "collector peer sample count differs")
    require(
        'require(len(irq_markers) == 26, "success IRQ predecessor count differs")' in source
        and "*(irq_response_line(epoch) for epoch in range(1, SAMPLE_COUNT + 1))," in source,
        "collector peer does not require two causal plus 24 terminal IRQ markers",
    )
    require(
        'f"child_pair={first} terminal_inactive=1 paired=2 inactive={epoch} "' in source
        and 'f"active_epoch=0 {COLLECTOR_SUFFIX} ready_epoch={epoch + 1}"' in source,
        "collector peer does not bind each terminal IRQ marker to its epoch/Ready lineage",
    )
    for marker in ("AUDIT_META", "AUDIT_SAMPLE", "AUDIT_END", "REJECT", "FAILED"):
        require(marker in source, f"collector peer omits {marker}")
    for field in (
        "decision_eligible",
        "formal_uart",
        "commit",
        "bytes",
        "sha256",
        "ready_epoch",
        "next_sequence",
        "target_started",
        "audit_commits",
    ):
        require(field in source, f"collector peer omits relation field {field}")
    for prefix in FORMAL_PREFIXES:
        require(prefix in source, f"collector peer does not scan for leaked {prefix!r}")
    for mutation in (
        "missing META",
        "duplicate META",
        "missing sample",
        "duplicate sample",
        "sample commit",
        "sample epoch",
        "sample sequence",
        "warmup boundary",
        "next sequence",
        "Ready rollback",
        "missing END",
        "END commit",
        "sample marker before trusted terminal",
        "next request before sample audit",
        "END before sample 23",
        "failure sample committed",
        "failure END committed",
        "failure Ready epoch",
        "failure reject target",
        "failure emitted sample",
        "post-epoch-4 IRQ truncation",
        "epoch-5 terminal gate failure",
        "epoch-5 inactive counter stalled",
        "formal-prefix leak was accepted",
        "pair parser accepted different META receipts",
    ):
        require(source.count(mutation) >= 1, f"collector peer selftest lacks {mutation!r}")
    require(
        "except EXPECTED_EXCEPTIONS:\n                return" in source,
        "collector peer selftest does not require every mutation to be rejected",
    )
    require("if: ${{ false }}" not in source and "|| true" not in source, "collector peer embeds a bypass")


def verify_qemu_script(raw: bytes) -> None:
    require(hashlib.sha256(raw).hexdigest() == QEMU_SCRIPT_SHA256, "collector QEMU runner SHA-256 differs")
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"collector QEMU script is not UTF-8: {error}") from error
    require(source.startswith("#!/bin/sh\n") and source.count("\nset -eu\n") == 1, "collector QEMU script is not fail-fast")
    require("exit 0\n" not in source[:300], "collector QEMU script exits successfully before work")
    require("continue-on-error" not in source and "if: ${{ false }}" not in source, "collector QEMU script contains a bypass")
    require(source.count(COMMAND) == 1, "collector QEMU script does not run the exact source verifier once")
    require(source.count("--selftest") >= 2, "collector QEMU script omits peer/source adversarial selftests")
    require(source.count("--verify-log-only") == 1, "collector QEMU frozen-log verifier path differs")
    require(source.count("TEST_TMP=$(mktemp -d)") == 1, "collector QEMU script lacks its private workspace")
    require("VIBEOS_C84_SOURCE_COMMIT" in source and "VIBEOS_C84_CHALLENGE" in source, "QEMU build is not bound to source/challenge")
    require(QEMU_FEATURE in source, "collector QEMU script builds the wrong feature")
    for prefix in FORMAL_PREFIXES:
        require(prefix in source, f"collector QEMU script lacks full-log {prefix!r} leak scan")
    failure_scan = (
        "grep -a -E -q 'WASM_[A-Z0-9_]+ FAIL([[:space:]]|$)|"
        r"\[!\] (fatal|panic)|panicked at'"
    )
    require(
        source.count(failure_scan) == 1
        and "WASM_[A-Z0-9_]+ FAIL|" not in source,
        "collector QEMU failure scan confuses the absorbing FAILED state with a FAIL marker",
    )
    require(source.count("python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py") == 5, "collector QEMU script bypasses live/frozen/pair peer")
    for exact_count in (
        '[ "$irq" -eq 3 ] || fail "failure boot IRQ count differs: $irq"',
        '[ "$irq" -eq 26 ] || fail "success boot IRQ count differs: $irq"',
        '[ "$finish" -eq 24 ] || fail "success boot finish count differs: $finish"',
        '[ "$trusted" -eq 24 ] || fail "success boot trusted count differs: $trusted"',
    ):
        require(source.count(exact_count) == 1, f"collector predecessor count gate differs: {exact_count}")
    for invocation in (
        'start_qemu "$FAILURE_QEMU_LOG" "$FAILURE_PORT"',
        'freeze_and_verify_boot failure "$FAILURE_QEMU_LOG"',
        'start_qemu "$SUCCESS_QEMU_LOG" "$SUCCESS_PORT"',
        'freeze_and_verify_boot success "$SUCCESS_QEMU_LOG"',
        '--verify-pair --failure-log "$FAILURE_QEMU_LOG" --success-log "$SUCCESS_QEMU_LOG"',
    ):
        require(source.count(invocation) == 1, f"two-boot runner omits {invocation!r}")
    require(source.count("start_qemu \"") == 2, "collector runner does not start exactly two independent QEMU boots")
    require(
        'FAILURE_QEMU_LOG="$TEST_TMP/failure-qemu.log"' in source
        and 'SUCCESS_QEMU_LOG="$TEST_TMP/success-qemu.log"' in source,
        "collector runner aliases its two raw boot logs",
    )
    require(
        'cat "$FAILURE_QEMU_LOG"' not in source
        and 'cat "$SUCCESS_QEMU_LOG"' not in source
        and '>>"$FAILURE_QEMU_LOG"' not in source
        and '>>"$SUCCESS_QEMU_LOG"' not in source,
        "collector runner concatenates or appends independently frozen boot logs",
    )
    freeze = source[source.index("freeze_and_verify_boot() {") : source.index("\n}\n\ntrap cleanup", source.index("freeze_and_verify_boot() {"))]
    require(
        freeze.index("stop_qemu") < freeze.index("--verify-log-only"),
        "collector runner parses a supposedly frozen log before stopping QEMU",
    )
    protected_commands = (
        "verify-c84-ssh-managed-child-single-boot-collector.py",
        "c84-ssh-managed-child-single-boot-collector-peer.py --selftest",
        "cargo build --release",
        "--verify-pair",
    )
    for command in protected_commands:
        lines = [line for line in source.splitlines() if command in line]
        require(lines and all("|| true" not in line for line in lines), f"runner ignores failure from {command}")


def verify_milkv_build_script(raw: bytes) -> None:
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"Milk-V build script is not UTF-8: {error}") from error
    require(source.startswith("#!/bin/sh\n") and source.count("\nset -eu\n") == 1, "Milk-V builder is not fail-fast")
    require(
        re.search(
            r"\bset[ \t]+\+(?:[A-Za-z]*[eu][A-Za-z]*|o[ \t]+(?:errexit|nounset))\b",
            source,
        )
        is None,
        "Milk-V builder disables errexit or nounset after enabling fail-fast mode",
    )
    exit_codes = re.findall(r"\bexit\b(?:[ \t]+([0-9]+))?", source)
    require(
        exit_codes and all(code and int(code) != 0 for code in exit_codes),
        "Milk-V builder contains a successful, implicit, or dynamic early exit",
    )
    require(source.count("--wasm-aot-profile") >= 3, "Milk-V builder does not expose/document the collector mode")
    require(source.count("wasm_aot_profile=true") == 1, "Milk-V collector mode parser differs")
    require(
        source.count("require_wasm_aot_profile_identity VIBEOS_C84_SOURCE_COMMIT") == 1
        and source.count("require_wasm_aot_profile_identity VIBEOS_C84_CHALLENGE") == 1,
        "Milk-V collector build does not validate both build identities",
    )
    identity = source[source.index("require_wasm_aot_profile_identity() {") : source.index("\n}\n", source.index("require_wasm_aot_profile_identity() {"))]
    for required in (
        'if [ -z "$identity_value" ]',
        'if [ "${#identity_value}" -ne "$identity_length" ]',
        '*[!0123456789abcdef]*',
        'if [ "$identity_value" = "$zero_value" ]',
        'if [ "$identity_value" = "$test_value" ]',
    ):
        require(required in identity, f"Milk-V collector identity validation omits {required!r}")
    source_verifier = '''verify_wasm_aot_profile_source() {
  python3 -B "$script_dir/c84-source-materialization.py" verify \\
    --destination "$repo_root" \\
    --source-commit "$wasm_aot_profile_source_commit" \\
    --challenge "$wasm_aot_profile_challenge"
}'''
    source_verifier_symbol = "verify_wasm_aot_profile_source"
    source_verifier_definitions = re.findall(
        rf"(?m)^{re.escape(source_verifier_symbol)}\(\) \{{$", source
    )
    source_verifier_calls = re.findall(
        rf"(?m)^  {re.escape(source_verifier_symbol)}$", source
    )
    require(
        source.count(source_verifier) == 1
        and len(source_verifier_definitions) == 1
        and len(source_verifier_calls) == 4
        and source.count(source_verifier_symbol) == 5,
        "Milk-V collector frozen-source verifier definition/call count differs",
    )
    source_gate_contexts = (
        '''  wasm_aot_profile_source_commit=$VIBEOS_C84_SOURCE_COMMIT
  wasm_aot_profile_challenge=$VIBEOS_C84_CHALLENGE
  verify_wasm_aot_profile_source
  wasm_aot_profile_source_envelope="$repo_root/target/c84-source-materialization/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge/source-materialization-envelope.json"''',
        '''if [ ! -f "$built_elf" ]; then
  echo "build-milkv-duo.sh: kernel ELF not found after build: $built_elf" >&2
  exit 1
fi
if [ "$wasm_aot_profile" = true ]; then
  verify_wasm_aot_profile_source
fi

mkdir -p "$output_dir"''',
        '''  mv "$wasm_aot_profile_temp_envelope" "$wasm_aot_profile_build_envelope"
  verify_wasm_aot_profile_source
  python3 - "$wasm_aot_profile_build_envelope" \\''',
        '''print("build-milkv-duo.sh C8.4 build closure rehash: PASS")
PY
  verify_wasm_aot_profile_source
  if [ -e "$wasm_aot_profile_publish_dir" ] || [ -L "$wasm_aot_profile_publish_dir" ]; then''',
    )
    require(
        all(source.count(context) == 1 for context in source_gate_contexts),
        "Milk-V collector frozen-source gates are not adjacent to all four protected boundaries",
    )
    branch_start = source.index(
        'if [ "$wasm_aot_profile" = true ]; then\n'
        "  require_wasm_aot_profile_identity VIBEOS_C84_SOURCE_COMMIT"
    )
    branch_end = source.index(
        '\n\nif [ "$diagnostic" = false ]', branch_start
    )
    branch = source[branch_start:branch_end]
    for required in (
        "  verify_wasm_aot_profile_source\n",
        'wasm_aot_profile_source_envelope="$repo_root/target/c84-source-materialization/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge/source-materialization-envelope.json"',
        'wasm_aot_profile_target_dir="$repo_root/target/c84-milkv-build/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge"',
        'export VIBEOS_C84_SOURCE_COMMIT VIBEOS_C84_CHALLENGE',
    ):
        require(required in branch, f"Milk-V collector pre-build binding omits {required!r}")
    prebuild_source_order = tuple(
        branch.index(item)
        for item in (
            "  wasm_aot_profile_source_commit=$VIBEOS_C84_SOURCE_COMMIT",
            "  wasm_aot_profile_challenge=$VIBEOS_C84_CHALLENGE",
            "  verify_wasm_aot_profile_source\n",
            '  wasm_aot_profile_source_envelope="$repo_root/target/c84-source-materialization/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge/source-materialization-envelope.json"',
            '  wasm_aot_profile_target_dir="$repo_root/target/c84-milkv-build/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge"',
        )
    )
    require(
        prebuild_source_order == tuple(sorted(prebuild_source_order)),
        "Milk-V collector frozen-source pre-build binding order differs",
    )
    require(
        source.count('"$script_dir/prepare-jitterentropy-rs.sh"') == 1
        and '''if [ "$diagnostic" = false ] && [ "$ssh_acceptance" = false ] &&
   [ "$iperf3_server" = false ] && [ "$runtime_costs" = false ] &&
   [ "$wasm_aot_profile" = false ]; then
  "$script_dir/prepare-jitterentropy-rs.sh"
fi'''
        in source,
        "Milk-V collector formal build still applies the operator-tree jitterentropy patch",
    )
    require(
        '1111111111111111111111111111111111111111' in branch
        and '2222222222222222222222222222222222222222222222222222222222222222' in branch,
        "Milk-V collector build does not reject both QEMU sentinels",
    )
    require(
        source.count(
            'if [ "$wasm_aot_profile" = true ] && [ -n "$sdk_arg" ]; then'
        )
        == 1
        and
        source.count(
            "build-milkv-duo.sh: --wasm-aot-profile does not accept an SDK argument; "
            "run package-milkv-duo-sdk.sh --wasm-aot-profile separately"
        )
        == 1,
        "Milk-V collector build does not give the package script exclusive SDK ownership",
    )
    mode_start = source.index('elif [ "$wasm_aot_profile" = true ]; then', source.index("features=milkv-ssh"))
    mode_end = source.index("\nfi\noutput_bin=", mode_start)
    mode = source[mode_start:mode_end]
    for required in (
        "features=wasm-c84-ssh-managed-child-single-boot-collector",
        'output_dir="$repo_root/target/milkv-duo-wasm-aot-profile"',
        'output_elf="$output_dir/vibeos-milkv-duo-wasm-aot-profile.elf"',
    ):
        require(required in mode, f"Milk-V collector output/feature isolation omits {required!r}")
    build = source[source.index('elif [ "$wasm_aot_profile" = true ]; then', source.index('cd "$repo_root/firmware/milkv-duo"')) :]
    for required in (
        "env -i \\",
        'PATH="$wasm_aot_profile_build_path"',
        'HOME="$wasm_aot_profile_cargo_home_sandbox/home"',
        'RUSTUP_HOME="$wasm_aot_profile_rustup_home"',
        'CARGO_HOME="$wasm_aot_profile_cargo_home_sandbox"',
        'TMPDIR="$wasm_aot_profile_cargo_home_sandbox/tmp"',
        'LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$wasm_aot_profile_source_date_epoch"',
        'VIBEOS_C84_SOURCE_COMMIT="$wasm_aot_profile_source_commit"',
        'VIBEOS_C84_CHALLENGE="$wasm_aot_profile_challenge"',
        'RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc"',
        'CARGO_TARGET_DIR="$wasm_aot_profile_target_dir"',
        "CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true",
        '"$wasm_aot_profile_rustup" run "$toolchain" cargo build',
        "--release --locked --offline",
        '--no-default-features --features "$features"',
    ):
        require(required in build, f"Milk-V collector cargo invocation omits {required!r}")
    for forbidden in (
        "RUSTFLAGS=",
        "CARGO_ENCODED_RUSTFLAGS=",
        "RUSTC_WRAPPER=",
        "RUSTC_WORKSPACE_WRAPPER=",
        "CARGO_PROFILE_RELEASE_OPT_LEVEL=",
    ):
        require(forbidden not in build, f"Milk-V collector cargo whitelist admits {forbidden[:-1]}")
    for required in (
        'wasm_aot_profile_rustup=$(python3 -c',
        'wasm_aot_profile_linker=$(python3 -c',
        'wasm_aot_profile_rustc_verbose=$("$pinned_rustc" -vV)',
        'wasm_aot_profile_source_date_epoch=$(git -C "$repo_root" show -s --format=%ct "$wasm_aot_profile_source_commit")',
        'wasm_aot_profile_cargo_home_sandbox=$(mktemp -d "$wasm_aot_profile_tmpdir/vibeos-c84-cargo-home.XXXXXX")',
        'ln -s "$wasm_aot_profile_linker" "$wasm_aot_profile_cargo_home_sandbox/closed-bin/ld.lld"',
        'ln -s "$wasm_aot_profile_cache_cargo_home/registry" "$wasm_aot_profile_cargo_home_sandbox/registry"',
        'ln -s "$wasm_aot_profile_cache_cargo_home/git" "$wasm_aot_profile_cargo_home_sandbox/git"',
        '[ -e "$wasm_aot_profile_cargo_home_sandbox/config" ]',
        '[ -e "$wasm_aot_profile_cargo_home_sandbox/config.toml" ]',
        'wasm_aot_profile_build_path="$wasm_aot_profile_cargo_home_sandbox/closed-bin:/usr/bin:/bin:/usr/sbin:/sbin"',
    ):
        require(required in source, f"Milk-V collector closed build setup omits {required!r}")
    objcopy_start = source.index('elif [ "$wasm_aot_profile" = true ]; then', source.index('if [ "$runtime_costs" = true ]; then\n  runtime_costs_objcopy_os='))
    objcopy_end = source.index('\nelif [ "$(uname -s)" = Darwin ]; then', objcopy_start)
    objcopy = source[objcopy_start:objcopy_end]
    require(
        objcopy.count("env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC") == 2
        and objcopy.count('"$rust_objcopy" -O binary "$output_elf" "$output_bin"') == 2,
        "Milk-V collector objcopy is not isolated on both host branches",
    )
    built_check = source.index('if [ ! -f "$built_elf" ]; then')
    copy_start = source.index('mkdir -p "$output_dir"', built_check)
    post_build_source_check = source[built_check:copy_start]
    require(
        '''if [ "$wasm_aot_profile" = true ]; then
  verify_wasm_aot_profile_source
fi'''
        in post_build_source_check,
        "Milk-V collector does not reverify the frozen source after Cargo and before artifact copy",
    )
    post_start = source.index(
        'if [ "$wasm_aot_profile" = true ]; then\n',
        source.index('if [ -n "$sdk_root" ]; then'),
    )
    post_end = source.index('\n\nif [ "$runtime_costs" = true ]; then', post_start)
    post = source[post_start:post_end]
    require(
        'built_elf="$wasm_aot_profile_target_dir/riscv64imac-unknown-none-elf/release/vibeos-milkv-duo"' in source,
        "Milk-V collector does not consume only its identity-isolated Cargo target",
    )
    for required in (
        'for artifact in "$output_elf" "$output_bin"',
        'grep -a -F -q "$wasm_aot_profile_source_commit" "$artifact"',
        'grep -a -F -q "$wasm_aot_profile_challenge" "$artifact"',
    ):
        require(required in post, f"Milk-V collector artifact binding omits {required!r}")

    cleanup_start = source.index("cleanup_wasm_aot_profile_build() {")
    cleanup_end = source.index("\n}\n\ncleanup_build() {", cleanup_start) + len("\n}")
    cleanup = source[cleanup_start:cleanup_end]
    for required in (
        'if [ -n "$wasm_aot_profile_cargo_home_sandbox" ]',
        '"${wasm_aot_profile_tmpdir-}"/vibeos-c84-cargo-home.*)',
        'rm -rf -- "$wasm_aot_profile_cargo_home_sandbox"',
        'if [ -n "$wasm_aot_profile_stage_dir" ]',
        '"$repo_root/target/.milkv-duo-wasm-aot-profile.stage.$wasm_aot_profile_source_commit.$wasm_aot_profile_challenge")',
        'vibeos-milkv-duo-wasm-aot-profile.elf vibeos-milkv-duo.bin',
        'rm -f -- "$staged_path"',
        'rmdir -- "$wasm_aot_profile_stage_dir"',
        'if [ "$wasm_aot_profile_publish_lock_held" = true ]',
        '"$repo_root/target/.milkv-duo-wasm-aot-profile.publish.lock")',
        'rmdir -- "$wasm_aot_profile_publish_lock"',
    ):
        require(required in cleanup, f"Milk-V collector failure cleanup omits {required!r}")
    require(
        cleanup.count("rm -rf --") == 1,
        "Milk-V collector staging cleanup contains a recursive removal",
    )
    trap_lines = [
        line.strip()
        for line in source.splitlines()
        if re.match(r"^[ \t]*trap\b", line)
    ]
    require(
        source.count("trap") == 4
        and trap_lines
        == [
            "trap cleanup_build EXIT",
            "trap 'exit 129' HUP",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
        ],
        "Milk-V collector signal/EXIT trap set is not exact and unique",
    )
    for signal, code in (("HUP", "129"), ("INT", "130"), ("TERM", "143")):
        require(
            source.count(f"trap 'exit {code}' {signal}") == 1,
            f"Milk-V collector cleanup lacks its {signal} signal trap",
        )
    require(
        source.count("cleanup_wasm_aot_profile_build") == 2
        and "cleanup_runtime_costs_build\n  cleanup_wasm_aot_profile_build" in source,
        "Milk-V collector cleanup is not joined to the existing build cleanup",
    )

    for required in (
        'wasm_aot_profile_publish_dir="$repo_root/target/milkv-duo-wasm-aot-profile"',
        'wasm_aot_profile_publish_lock="$repo_root/target/.milkv-duo-wasm-aot-profile.publish.lock"',
        'case "$wasm_aot_profile_target_dir" in',
        '"$repo_root/target/c84-milkv-build/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge")',
        'if ! mkdir "$wasm_aot_profile_publish_lock"; then',
        'if [ -e "$wasm_aot_profile_publish_dir" ] || [ -L "$wasm_aot_profile_publish_dir" ]; then',
        'if [ -e "$wasm_aot_profile_target_dir" ] || [ -L "$wasm_aot_profile_target_dir" ]; then',
        'wasm_aot_profile_stage_dir="$repo_root/target/.milkv-duo-wasm-aot-profile.stage.$wasm_aot_profile_source_commit.$wasm_aot_profile_challenge"',
        '! mkdir "$wasm_aot_profile_stage_dir"; then',
    ):
        require(required in branch, f"Milk-V collector no-clobber pre-build staging omits {required!r}")
    require(
        'rm -rf -- "$wasm_aot_profile_target_dir"' not in branch
        and "mktemp -d" not in branch,
        "Milk-V collector clears or randomizes its identity-bound build/staging path",
    )
    prebuild_order = (
        branch.index('if ! mkdir "$wasm_aot_profile_publish_lock"; then'),
        branch.index('if [ -e "$wasm_aot_profile_publish_dir" ] || [ -L "$wasm_aot_profile_publish_dir" ]; then'),
        branch.index('if [ -e "$wasm_aot_profile_target_dir" ] || [ -L "$wasm_aot_profile_target_dir" ]; then'),
        branch.index('wasm_aot_profile_stage_dir="$repo_root/target/.milkv-duo-wasm-aot-profile.stage.'),
        branch.index('! mkdir "$wasm_aot_profile_stage_dir"; then'),
    )
    require(prebuild_order == tuple(sorted(prebuild_order)), "Milk-V collector pre-build cleanup/staging order differs")

    stage_select_start = source.index('if [ "$wasm_aot_profile" = true ]; then', mode_end)
    stage_select_end = source.index("\nfi\n", stage_select_start) + len("\nfi\n")
    stage_select = source[stage_select_start:stage_select_end]
    for required in (
        "output_dir=$wasm_aot_profile_stage_dir",
        'output_elf="$output_dir/vibeos-milkv-duo-wasm-aot-profile.elf"',
        'output_bin="$output_dir/vibeos-milkv-duo.bin"',
    ):
        require(required in stage_select, f"Milk-V collector staging output selection omits {required!r}")
    copy_start = source.index('mkdir -p "$output_dir"', stage_select_end)
    require(stage_select_end < copy_start, "Milk-V collector writes an artifact before selecting private staging")

    require(
        '''if [ "$wasm_aot_profile" = false ]; then
  echo "Milk-V Duo ELF: $output_elf"
  echo "Milk-V Duo binary: $output_bin"
fi'''
        in source,
        "Milk-V collector prints private staging paths before publication",
    )
    for required in (
        '[ -L "$artifact" ] || [ ! -f "$artifact" ] || [ ! -s "$artifact" ]',
        'if [ -e "$wasm_aot_profile_publish_dir" ] || [ -L "$wasm_aot_profile_publish_dir" ]; then',
        'if system == "Linux" and hasattr(libc, "renameat2"):',
        'elif system == "Darwin" and hasattr(libc, "renamex_np"):',
        '"vibeos-milkv-duo-wasm-aot-profile.elf", "vibeos-milkv-duo.bin", "build-envelope.json",',
        "wasm_aot_profile_stage_dir=",
        "output_dir=$wasm_aot_profile_publish_dir",
    ):
        require(required in post, f"Milk-V collector atomic publication closure omits {required!r}")
    require(
        post.count("  verify_wasm_aot_profile_source\n") == 2,
        "Milk-V collector does not reverify the frozen source around build-envelope closure",
    )
    publish_move = post.index('  python3 - "$wasm_aot_profile_stage_dir" "$wasm_aot_profile_publish_dir" "$repo_root/target"')
    require(
        post.count('  python3 - "$wasm_aot_profile_stage_dir" "$wasm_aot_profile_publish_dir" "$repo_root/target"') == 1
        and 'mv -- "$wasm_aot_profile_stage_dir" "$wasm_aot_profile_publish_dir"' not in post,
        "Milk-V collector no-replace publication is duplicated or bypassed",
    )
    envelope_move = post.index(
        '  mv "$wasm_aot_profile_temp_envelope" "$wasm_aot_profile_build_envelope"'
    )
    closure_start = post.index(
        '  python3 - "$wasm_aot_profile_build_envelope"', envelope_move
    )
    before_closure_verify = post.index(
        "  verify_wasm_aot_profile_source\n", envelope_move
    )
    after_closure_verify = post.index(
        "  verify_wasm_aot_profile_source\n", closure_start
    )
    publication_order = (
        post.index('  for artifact in "$output_elf" "$output_bin"; do'),
        envelope_move,
        before_closure_verify,
        closure_start,
        post.index("build-milkv-duo.sh C8.4 build closure rehash: PASS"),
        after_closure_verify,
        post.index('  if [ -e "$wasm_aot_profile_publish_dir" ] || [ -L "$wasm_aot_profile_publish_dir" ]; then'),
        publish_move,
        post.index("  wasm_aot_profile_stage_dir=", publish_move),
        post.index("  output_dir=$wasm_aot_profile_publish_dir", publish_move),
        post.index('  echo "Milk-V Duo ELF: $output_elf"', publish_move),
        post.index('  echo "Milk-V Duo binary: $output_bin"', publish_move),
    )
    require(publication_order == tuple(sorted(publication_order)), "Milk-V collector postcheck/publication/printing order differs")
    require("Milk-V Duo ELF:" not in post[:publish_move], "Milk-V collector exposes a path before atomic publication")
    require(
        'echo "Milk-V Duo FIT: $output_dir/boot.sd"' not in post[publish_move:],
        "Milk-V collector build still claims ownership of FIT packaging",
    )

    envelope_start = post.index('  python3 - \\\n    "$wasm_aot_profile_temp_envelope"')
    envelope = post[envelope_start:closure_start]
    for required in (
        '"root": "."',
        '"version": 2,',
        "if supplied != expected or expected.resolve(strict=True) != expected:",
        "before = expected.lstat()",
        "after = expected.lstat()",
        "if not isinstance(root, dict) or set(root) != {",
        "if not isinstance(content, dict) or set(content) != {",
        'source_materialization = load_source_materialization(source_materialization_envelope)',
        '"materialization": source_materialization,',
        '"source_materializer_script": identity(source_materializer_script, repository_input=True)',
        'root["schema"] != "vibeos.c84.source-materialization-envelope"',
        'root["version"] != 1',
        'content.get("source_commit") != source_commit or content.get("challenge") != challenge',
        'hashlib.sha256(canonical_content).hexdigest() != digest',
        'if raw != canonical_root:',
        '"provenance": "build-runner-self-measured; package cross-platform live rehash unavailable"',
        '"kernel_elf": identity(kernel_elf, require_build_identity=True, repository_input=True)',
        '"kernel_binary": identity(kernel_bin, require_build_identity=True, repository_input=True)',
        '"transcript_schema": identity(transcript_schema, repository_input=True)',
        'for name, value in zip(("build_started", "build_completed", "envelope_closed"), timestamp_values)',
    ):
        require(required in envelope, f"Milk-V collector build envelope omits {required!r}")
    repository_tool_inputs = {
        "build_script": "build_script",
        "source_materializer_script": "source_materializer_script",
        "jitterentropy_patch": "jitterentropy_patch",
        "gitmodules": "gitmodules",
        "firmware_manifest": "firmware_manifest",
        "firmware_build_script": "firmware_build_script",
        "firmware_linker_script": "firmware_linker_script",
        "firmware_cargo_config": "firmware_cargo_config",
        "kernel_manifest": "kernel_manifest",
        "workspace_manifest": "workspace_manifest",
        "cargo_lock": "cargo_lock",
        "workload_manifest": "workload_manifest",
        "transcript_schema": "transcript_schema",
        "toolchain_contract": "toolchain_contract",
    }
    for role, variable in repository_tool_inputs.items():
        require(
            f'"{role}": identity({variable}, repository_input=True)' in envelope,
            f"Milk-V collector build envelope does not normalize repository tool {role}",
        )
    closure = post[closure_start:publish_move]
    closure_python_marker = '    "$repo_root" <<\'PY\'\n'
    require(
        closure.count(closure_python_marker) == 1,
        "Milk-V collector closure Python heredoc boundary differs",
    )
    closure_python_start = closure.index(closure_python_marker) + len(
        closure_python_marker
    )
    closure_python_end = closure.index(
        "\nPY\n  verify_wasm_aot_profile_source", closure_python_start
    )
    closure_python = closure[closure_python_start:closure_python_end]
    try:
        closure_tree = ast.parse(closure_python)
    except SyntaxError as error:
        raise VerificationError(
            f"Milk-V collector closure Python is not valid: {error}"
        ) from error

    class ClosureReachability(ast.NodeVisitor):
        def __init__(self) -> None:
            self.forbidden: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Raise(self, node: ast.Raise) -> None:
            self.forbidden.append("raise")

        def visit_Call(self, node: ast.Call) -> None:
            function = node.func
            name = function.id if isinstance(function, ast.Name) else None
            attribute = function.attr if isinstance(function, ast.Attribute) else None
            if name in {
                "SystemExit",
                "exit",
                "quit",
                "exec",
                "eval",
                "compile",
                "__import__",
                "getattr",
            } or attribute in {"exit", "_exit"}:
                self.forbidden.append(name or attribute or "dynamic exit")
            self.generic_visit(node)

    reachability = ClosureReachability()
    reachability.visit(closure_tree)
    fail_functions = [
        node
        for node in ast.walk(closure_tree)
        if isinstance(node, ast.FunctionDef) and node.name == "fail"
    ]
    expected_fail = ast.parse(
        '''def fail(message):
    raise SystemExit(f"build-milkv-duo.sh: C8.4 closure rehash failed: {message}")
'''
    ).body[0]
    fail_rebindings = [
        node
        for node in ast.walk(closure_tree)
        if isinstance(node, ast.Name)
        and node.id == "fail"
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    final_statement = closure_tree.body[-1] if closure_tree.body else None
    require(
        len(closure_tree.body) == 60
        and len(fail_functions) == 1
        and fail_functions[0] in closure_tree.body
        and ast.dump(fail_functions[0], include_attributes=False)
        == ast.dump(expected_fail, include_attributes=False)
        and not fail_rebindings
        and isinstance(final_statement, ast.Expr)
        and isinstance(final_statement.value, ast.Call)
        and isinstance(final_statement.value.func, ast.Name)
        and final_statement.value.func.id == "print"
        and len(final_statement.value.args) == 1
        and isinstance(final_statement.value.args[0], ast.Constant)
        and final_statement.value.args[0].value
        == "build-milkv-duo.sh C8.4 build closure rehash: PASS"
        and not final_statement.value.keywords
        and not reachability.forbidden,
        "Milk-V collector closure Python has an early exit or non-terminal PASS flow",
    )
    common_source_loader_requirements = (
        "before.st_nlink != 1",
        "before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns",
        '"content", "content_sha256", "schema", "status", "version"',
        'root["schema"] != "vibeos.c84.source-materialization-envelope"',
        'root["version"] != 1',
        'root["status"] != "closed"',
        '"bundles", "challenge", "clone_git_admin", "command", "frozen", "git"',
        '"source_commit", "submodules", "timestamps_utc"',
        "hashlib.sha256(canonical_content).hexdigest() != digest",
        "if raw != canonical_root:",
    )
    for scope, label in ((envelope, "build-envelope writer"), (closure, "build closure")):
        for required in common_source_loader_requirements:
            require(
                required in scope,
                f"Milk-V collector {label} source-envelope loader omits {required!r}",
            )
    for required in (
        'envelope["version"] != 2',
        "if path.resolve(strict=True) != path:",
        "before = path.lstat()",
        "after = path.lstat()",
        "if not isinstance(root, dict) or set(root) != {",
        "if not isinstance(materialization_content, dict) or set(materialization_content) != {",
        'materialization_content.get("source_commit") != source_commit',
        'materialization_content.get("challenge") != challenge',
        'source["root"] != "."',
        '"root", "head", "materialization"',
        '/ "c84-source-materialization"',
        '/ "source-materialization-envelope.json"',
        'if source["materialization"] != load_source_materialization(source_materialization_path):',
        '"tools.source_materializer_script": "scripts/c84-source-materialization.py"',
        'toolchain["provenance"] != "build-runner-self-measured; package cross-platform live rehash unavailable"',
        'path = (source_root_path / pathlib.Path(*pure.parts)).resolve(strict=True)',
        'for name in ("build_started", "build_completed", "envelope_closed"):',
    ):
        require(required in closure, f"Milk-V collector build closure omits {required!r}")
    require(
        source.count("def load_source_materialization(path):") == 2
        and source.count('"vibeos.c84.source-materialization-envelope"') == 2,
        "Milk-V collector build/envelope closure does not deeply load the frozen source twice",
    )
    require(
        "package-envelope" not in mode,
        "collector build mode incorrectly claims a sealed package envelope",
    )


def verify_docs_ci(inputs: Inputs) -> None:
    step_name = "      - name: Verify the C8.4 private single-boot collector"
    peer_step_name = "      - name: Test the C8.4 single-boot collector transcript parser"
    qemu_step_name = "      - name: Exercise the C8.4 private single-boot collector closure"
    physical_step_name = "      - name: Type/link-check the C8.4 physical single-boot collector"
    ci_lines = inputs.ci.splitlines()
    checkout_block = [
        "      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1",
        "        with:",
        "          submodules: recursive",
        "          fetch-depth: 0",
        "          persist-credentials: false",
    ]
    host_job_header = [
        "  host-tests:",
        "    name: Host unit tests",
        "    runs-on: ubuntu-24.04",
        "    steps:",
    ]
    qemu_job_header = [
        "  qemu-tests:",
        "    name: QEMU integration",
        "    needs: differential",
        "    runs-on: ubuntu-24.04",
        "    steps:",
    ]
    ref_mutating_git_command = re.compile(
        r"\bgit\b[^\n;&|]*?\b(?:checkout|switch|reset|restore|clean|update-ref|"
        r"symbolic-ref|read-tree|merge|rebase|cherry-pick|revert|am|apply|pull|commit)\b"
    )

    def exact_checkout(
        job: str,
        next_job: str | None,
        label: str,
        job_header: list[str],
    ) -> int:
        job_index = ci_lines.index(f"  {job}:")
        job_end = (
            ci_lines.index(f"  {next_job}:", job_index + 1)
            if next_job is not None
            else len(ci_lines)
        )
        job_level_lines = [
            line
            for line in ci_lines[job_index + 1 : job_end]
            if line.startswith("    ") and not line.startswith("      ")
        ]
        require(
            ci_lines[job_index : job_index + len(job_header)] == job_header
            and job_level_lines == job_header[1:],
            f"CI {label} job header has an if, continue-on-error, or other bypass key",
        )
        job_source = "\n".join(ci_lines[job_index:job_end])
        matches = [
            index
            for index in range(job_index, job_end)
            if ci_lines[index : index + len(checkout_block)] == checkout_block
        ]
        require(
            len(matches) == 1 and job_source.count("actions/checkout@") == 1,
            f"CI {label} checkout is not the unique pinned, recursive, full-depth, credential-free checkout",
        )
        logical_job_source = job_source.replace("\\\n", " ")
        require(
            ref_mutating_git_command.search(logical_job_source) is None,
            f"CI {label} job contains a ref- or worktree-mutating Git command",
        )
        return matches[0]

    host_checkout_index = exact_checkout(
        "host-tests", "c82-preview1-corpus", "host selftest", host_job_header
    )
    qemu_checkout_index = exact_checkout(
        "qemu-tests", None, "QEMU collector", qemu_job_header
    )
    source_materializer_selftest = (
        "          python3 -B scripts/c84-source-materialization.py --selftest --check-source"
    )
    source_materializer_indices = [
        index
        for index, line in enumerate(ci_lines)
        if line == source_materializer_selftest
    ]
    require(
        len(source_materializer_indices) == 1,
        "CI host source-materializer selftest is not exact and unique",
    )
    require(
        host_checkout_index
        < source_materializer_indices[0]
        < ci_lines.index("  c82-preview1-corpus:"),
        "CI host source selftests run before their pinned full checkout",
    )

    def exact_run_step(name: str, command: str, label: str) -> int:
        require(ci_lines.count(name) == 1, f"CI {label} step count differs")
        index = ci_lines.index(name)
        require(index + 1 < len(ci_lines) and ci_lines[index + 1] == f"        run: {command}", f"CI {label} is not unconditional/exact")
        return index

    exact_run_step(step_name, COMMAND, "collector source-verifier")
    exact_run_step(peer_step_name, PEER_COMMAND, "collector peer selftest")
    qemu_index = exact_run_step(qemu_step_name, QEMU_COMMAND, "collector QEMU closure")
    require(
        inputs.ci.count(COMMAND) == 1 and inputs.ci.count(PEER_COMMAND) == 1 and inputs.ci.count(QEMU_COMMAND) == 1,
        "CI collector commands are duplicated",
    )
    require("on:\n  push:\n  pull_request:\n" in inputs.ci, "CI collector is not protected on push and pull requests")

    require(ci_lines.count(physical_step_name) == 1, "CI physical type/link step count differs")
    physical_index = ci_lines.index(physical_step_name)
    physical_block = [
        physical_step_name,
        "        run: |",
        '          source_commit="$GITHUB_SHA"',
        '          test "$(git rev-parse HEAD)" = "$source_commit"',
        '          challenge="$(openssl rand -hex 32)"',
        '          frozen="$RUNNER_TEMP/vibeos-c84-frozen-$challenge"',
        "          python3 -B scripts/c84-source-materialization.py materialize \\",
        "            --source \"$GITHUB_WORKSPACE\" \\",
        "            --destination \"$frozen\" \\",
        "            --source-commit \"$source_commit\" \\",
        '            --challenge "$challenge"',
        '          cd "$frozen"',
        '          RUSTC_WRAPPER="$(command -v false)" \\',
        "          CARGO_PROFILE_RELEASE_OPT_LEVEL=0 \\",
        "          RUSTFLAGS='--c84-ambient-rustflags-must-not-leak' \\",
        '          VIBEOS_C84_SOURCE_COMMIT="$source_commit" \\',
        '          VIBEOS_C84_CHALLENGE="$challenge" \\',
        "            ./scripts/build-milkv-duo.sh --wasm-aot-profile",
    ]
    require(
        ci_lines[physical_index : physical_index + len(physical_block)] == physical_block,
        "CI physical collector type/link command, hostile ambient proof, or non-evidence identity differs",
    )
    c83_build_index = ci_lines.index(
        "      - name: Build the isolated Milk-V Duo C8.3 sampler (CI-only identity)"
    )
    c83_index = ci_lines.index("      - name: Exercise the fixed-QEMU C8.3 publication contract")
    ordinary_duo_index = ci_lines.index("      - name: Build the Milk-V Duo kernel")
    require(
        qemu_checkout_index
        < qemu_index
        < physical_index
        < c83_build_index
        < c83_index
        < ordinary_duo_index,
        "CI frozen physical collector gate order differs",
    )
    comments = "\n".join(ci_lines[max(0, physical_index - 3) : physical_index]).lower()
    require(
        "materialize" in comments
        and "not retained or executed" in comments
        and "evidence" in comments
        and "cold boot" in comments,
        "CI physical gate overclaims or retains evidence",
    )
    next_step = next(
        (index for index in range(physical_index + 1, len(ci_lines)) if ci_lines[index].startswith("      - ")),
        len(ci_lines),
    )
    require(
        ci_lines[physical_index:next_step] == physical_block,
        "CI physical type/link step contains an extra execution, retention, or bypass command",
    )
    require("upload-artifact" not in "\n".join(ci_lines[physical_index:next_step]), "CI retains the fixed-identity collector build as evidence")

    for doc, label in ((inputs.testing, "TESTING"), (inputs.decision_doc, "decision doc"), (inputs.roadmap, "roadmap")):
        require(FEATURE in doc or "single-cold-boot" in doc, f"{label} omits the collector node")
        for phrase in ("24", "META", "SAMPLE", "END", "physical", "QEMU"):
            require(phrase in doc, f"{label} collector section omits {phrase!r}")
    for doc, label in ((inputs.testing, "TESTING"), (inputs.decision_doc, "decision doc")):
        require(COMMAND in doc and QEMU_COMMAND in doc, f"{label} omits collector validation commands")
        require("decision_eligible=0" in doc and "formal_uart=0" in doc, f"{label} overclaims QEMU audit evidence")
        require("three" in doc.lower() and "63" in doc, f"{label} does not leave three-boot/63-retained evidence open")
        normalized = re.sub(r"\s+", " ", doc.lower())
        require(
            "package" in normalized and "capture" in normalized,
            f"{label} omits the closed software-package/open physical-capture boundary",
        )
        require(
            "materializ" in normalized and "frozen" in normalized,
            f"{label} omits the independently frozen source boundary",
        )
    require(
        "./scripts/build-milkv-duo.sh --wasm-aot-profile" in inputs.decision_doc,
        "decision doc omits the frozen-source-bound Milk-V command",
    )
    for snippet in (
        "python3 -B scripts/c84-source-materialization.py materialize",
        '--source "$operator_source"',
        '--destination "$frozen"',
        '--source-commit "$prep"',
        '--challenge "$challenge"',
        'cd "$frozen"',
        'VIBEOS_C84_SOURCE_COMMIT="$prep"',
        'VIBEOS_C84_CHALLENGE="$challenge"',
    ):
        require(
            snippet in inputs.decision_doc,
            f"decision doc frozen build command omits {snippet!r}",
        )
    require(
        inputs.decision_doc.index("python3 -B scripts/c84-source-materialization.py materialize")
        < inputs.decision_doc.index('cd "$frozen"')
        < inputs.decision_doc.index("./scripts/build-milkv-duo.sh --wasm-aot-profile"),
        "decision doc materialize/frozen-build order differs",
    )
    for doc, label in ((inputs.testing, "TESTING"), (inputs.decision_doc, "decision doc")):
        normalized = re.sub(r"\s+", " ", doc.lower())
        for phrase in (
            "env -i",
            "isolated Cargo home",
            "SOURCE_DATE_EPOCH",
        ):
            require(
                phrase.lower() in normalized,
                f"{label} omits the closed physical-build fact {phrase!r}",
            )
    require(
        "hostile ambient" in inputs.testing
        and "sanitized `env -i` envelope" in inputs.decision_doc,
        "software-only closed-build environment description differs",
    )
    require(
        "34,386" in inputs.decision_doc
        and KNOWN_TRANSCRIPT_SHA256 in inputs.decision_doc
        and "34,532" in inputs.decision_doc
        and QEMU_KNOWN_TRANSCRIPT_SHA256 in inputs.decision_doc
        and "34,542" in inputs.decision_doc
        and QEMU_SMOKE_KNOWN_TRANSCRIPT_SHA256 in inputs.decision_doc,
        "decision doc known-answer transcript differs",
    )
    testing_status = re.sub(r"\s+", " ", inputs.testing.lower()).replace(
        "cold-boot", "cold boot"
    )
    require(
        "compile" in testing_status
        and "link" in testing_status
        and "freshly" in testing_status
        and "challenge" in testing_status
        and "independently materialized and verified frozen source tree" in testing_status
        and "host-observed runtime closure" in testing_status
        and "neither runs nor retains" in testing_status
        and "physical cold boot" in testing_status,
        "TESTING overclaims the CI physical type/link gate",
    )
    decision_status = re.sub(r"\s+", " ", inputs.decision_doc.lower()).replace(
        "cold-boot", "cold boot"
    )
    for phrase in (
        "ci does not package an sdk image or contact a board",
        "never open a uart",
        "no sdk, docker, network, flash, reset, or physical cold boot",
        "produce no decision-eligible evidence",
    ):
        require(
            phrase in decision_status,
            f"decision doc software-only CI boundary omits {phrase!r}",
        )
    require("implementation in progress" in inputs.roadmap, "roadmap no longer reports the remaining physical evidence work")
    roadmap_status = (
        re.sub(r"\s+", " ", inputs.roadmap.lower())
        .replace("cold-boot", "cold boot")
        .replace("`", "")
    )
    for phrase in (
        "independent frozen-source and build/package envelopes, host-observed docker runtime closure",
        "retained physical contract and tooling remain available but are no longer a c8.4 prerequisite",
        "decision-bearing replacement is the disjoint qemu-virt-rv64-tcg-icount-v1 contract",
    ):
        require(
            phrase in roadmap_status,
            f"roadmap software provenance status omits {phrase!r}",
        )
    for doc, label in (
        (inputs.testing, "TESTING"),
        (inputs.decision_doc, "decision doc"),
        (inputs.roadmap, "roadmap"),
    ):
        normalized = re.sub(r"\s+", " ", doc.lower()).replace("cold-boot", "cold boot")
        require(
            "materializ" in normalized
            and "frozen" in normalized
            and "runtime" in normalized
            and ("closure" in normalized or "custody" in normalized),
            f"{label} omits the frozen-source/runtime-custody software boundary",
        )
        require(
            "milk-v duo" in normalized
            and "paused" in normalized
            and ("physical testing" in normalized or "physical execution" in normalized),
            f"{label} omits the paused Milk-V Duo physical status",
        )
        require(
            "synthetic" in normalized
            and ("host-only" in normalized or "self-tests" in normalized),
            f"{label} omits the software-only synthetic coverage boundary",
        )
        require(
            (
                "preparation only" in normalized
                if label == "decision doc"
                else "no workload-specific aot decision" in normalized
            ),
            f"{label} overclaims a workload-specific AOT decision",
        )
    require(
        "operator request" in inputs.decision_doc.lower()
        and "operator request" in inputs.roadmap.lower(),
        "operator-paused physical status is not retained in the governing docs",
    )
    require(
        "These self-tests use local synthetic repositories, records, streams, and\n"
        "temporary files." in inputs.decision_doc,
        "decision doc no longer states the exact local-synthetic selftest boundary",
    )


def verify_collector(inputs: Inputs) -> None:
    verify_manifest(inputs.crate_manifest)
    verify_lib(inputs.crate_lib)
    code = verify_collector_types(inputs.collector)
    verify_campaign_begin(code)
    verify_collect_flow(code)
    verify_serializers(code)
    verify_portable_tests(inputs.collector)
    verify_raw_uart(inputs.tty, inputs.uart, inputs.kernel_root)
    verify_features(inputs)
    verify_irq_long_run(inputs)
    verify_sshd_terminal_reject(inputs)
    verify_kernel_integration(inputs)
    verify_audit_source(inputs)
    verify_peer_script(inputs.peer_script)
    verify_qemu_script(inputs.qemu_script)
    verify_milkv_build_script(inputs.milkv_build_script)
    verify_docs_ci(inputs)


def verify(inputs: Inputs, *, predecessors: bool = True) -> None:
    if predecessors:
        try:
            trusted = inputs.trusted_predecessor
            TRUSTED.STREAM.verify(trusted.stream_predecessor)
            TRUSTED.PUBLISHER.verify(
                trusted.publisher_predecessor,
                predecessor=False,
                contract=False,
            )
            TRUSTED.verify_features(trusted)
            TRUSTED.verify_sshd(trusted.sshd)
            TRUSTED.verify_runtime(trusted.runtime)
            TRUSTED.verify_component(trusted.component)
            TRUSTED.verify_slot(trusted.slot)
            TRUSTED.verify_ssh(trusted)
        except Exception as error:
            raise VerificationError(f"trusted-sample predecessor failed: {error}") from error
        try:
            PUBLISHER.verify(inputs.publisher_predecessor)
        except Exception as error:
            raise VerificationError(f"publisher predecessor failed: {error}") from error
    verify_collector(inputs)


def replace_once(value: str, old: str, new: str, label: str) -> str:
    count = value.count(old)
    require(count == 1, f"selftest {label} source count differs: {count}")
    return value.replace(old, new, 1)


def mutate_text(inputs: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    value = getattr(inputs, field)
    require(type(value) is str, f"selftest field {field} is not text")
    return replace(inputs, **{field: replace_once(value, old, new, label)})


def mutate_scoped_text(
    inputs: Inputs,
    field: str,
    header: str,
    old: str,
    new: str,
    label: str,
    *,
    match_literals: bool = False,
) -> Inputs:
    value = getattr(inputs, field)
    require(type(value) is str, f"selftest field {field} is not text")
    scope = find_scope(value, header, f"selftest {label} scope", match_literals=match_literals)
    mutated_scope = replace_once(scope.raw, old, new, label)
    return replace(inputs, **{field: value[: scope.start] + mutated_scope + value[scope.end :]})


def swap_text(inputs: Inputs, field: str, first: str, second: str, label: str) -> Inputs:
    value = getattr(inputs, field)
    require(type(value) is str, f"selftest field {field} is not text")
    require(value.count(first) == 1, f"selftest {label} first count differs: {value.count(first)}")
    require(value.count(second) == 1, f"selftest {label} second count differs: {value.count(second)}")
    first_at = value.index(first)
    second_at = value.index(second)
    require(first_at + len(first) <= second_at or second_at + len(second) <= first_at, f"selftest {label} blocks overlap")
    if first_at < second_at:
        mutated = value[:first_at] + second + value[first_at + len(first) : second_at] + first + value[second_at + len(second) :]
    else:
        mutated = value[:second_at] + first + value[second_at + len(second) : first_at] + second + value[first_at + len(first) :]
    return replace(inputs, **{field: mutated})


def swap_scoped_text(
    inputs: Inputs,
    field: str,
    header: str,
    first: str,
    second: str,
    label: str,
    *,
    match_literals: bool = False,
) -> Inputs:
    value = getattr(inputs, field)
    require(type(value) is str, f"selftest field {field} is not text")
    scope = find_scope(value, header, f"selftest {label} scope", match_literals=match_literals)
    scoped_inputs = replace(inputs, **{field: scope.raw})
    swapped = swap_text(scoped_inputs, field, first, second, label)
    mutated_scope = getattr(swapped, field)
    return replace(inputs, **{field: value[: scope.start] + mutated_scope + value[scope.end :]})


def mutate_bytes(inputs: Inputs, field: str, old: bytes, new: bytes, label: str) -> Inputs:
    value = getattr(inputs, field)
    require(type(value) is bytes, f"selftest field {field} is not bytes")
    require(value.count(old) == 1, f"selftest {label} byte count differs: {value.count(old)}")
    return replace(inputs, **{field: value.replace(old, new, 1)})


def expect_rejected(inputs: Inputs, mutation: Callable[[Inputs], Inputs], label: str) -> None:
    mutated = mutation(inputs)
    require(mutated != inputs, f"selftest mutation made no change: {label}")
    try:
        verify_collector(mutated)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def run_selftest(inputs: Inputs, *, predecessors: bool = True) -> int:
    verify(inputs, predecessors=predecessors)
    milkv_source_verifier = b'''verify_wasm_aot_profile_source() {
  python3 -B "$script_dir/c84-source-materialization.py" verify \\
    --destination "$repo_root" \\
    --source-commit "$wasm_aot_profile_source_commit" \\
    --challenge "$wasm_aot_profile_challenge"
}'''
    ci_host_checkout = '''  host-tests:
    name: Host unit tests
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          submodules: recursive
          fetch-depth: 0
          persist-credentials: false
      - name: Install repository toolchain'''
    ci_qemu_checkout = '''  qemu-tests:
    name: QEMU integration
    needs: differential
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          submodules: recursive
          fetch-depth: 0
          persist-credentials: false
      - name: Install repository toolchain'''
    ci_physical_block = '''      - name: Type/link-check the C8.4 physical single-boot collector
        run: |
          source_commit="$GITHUB_SHA"
          test "$(git rev-parse HEAD)" = "$source_commit"
          challenge="$(openssl rand -hex 32)"
          frozen="$RUNNER_TEMP/vibeos-c84-frozen-$challenge"
          python3 -B scripts/c84-source-materialization.py materialize \\
            --source "$GITHUB_WORKSPACE" \\
            --destination "$frozen" \\
            --source-commit "$source_commit" \\
            --challenge "$challenge"
          cd "$frozen"
          RUSTC_WRAPPER="$(command -v false)" \\
          CARGO_PROFILE_RELEASE_OPT_LEVEL=0 \\
          RUSTFLAGS='--c84-ambient-rustflags-must-not-leak' \\
          VIBEOS_C84_SOURCE_COMMIT="$source_commit" \\
          VIBEOS_C84_CHALLENGE="$challenge" \\
            ./scripts/build-milkv-duo.sh --wasm-aot-profile
'''
    ci_c83_build_block = '''      - name: Build the isolated Milk-V Duo C8.3 sampler (CI-only identity)
        run: |
          VIBEOS_C83_SOURCE_COMMIT="$(git rev-parse HEAD)" \\
          VIBEOS_C83_CHALLENGE=8383838383838383838383838383838383838383838383838383838383838383 \\
            ./scripts/build-milkv-duo.sh --runtime-costs
'''
    mutations: list[tuple[str, Callable[[Inputs], Inputs]]] = [
        (
            "collector-crate-default-selects-qemu",
            lambda data: mutate_bytes(
                data,
                "crate_manifest",
                b"default = []",
                b'default = ["qemu-decision-v1"]',
                "collector crate default feature",
            ),
        ),
        (
            "collector-crate-qemu-feature-widened",
            lambda data: mutate_bytes(
                data,
                "crate_manifest",
                b"qemu-decision-v1 = []",
                b'qemu-decision-v1 = ["sha2/asm"]',
                "collector crate formal-QEMU feature",
            ),
        ),
        (
            "collector-crate-smoke-feature-detached",
            lambda data: mutate_bytes(
                data,
                "crate_manifest",
                b'qemu-decision-v1-smoke = ["qemu-decision-v1"]',
                b"qemu-decision-v1-smoke = []",
                "collector crate dirty-smoke feature",
            ),
        ),
        (
            "collector-crate-smoke-feature-widened",
            lambda data: mutate_bytes(
                data,
                "crate_manifest",
                b'qemu-decision-v1-smoke = ["qemu-decision-v1"]',
                b'qemu-decision-v1-smoke = ["qemu-decision-v1", "sha2/asm"]',
                "collector crate dirty-smoke feature width",
            ),
        ),
        (
            "collector-crate-extra-feature",
            lambda data: mutate_bytes(
                data,
                "crate_manifest",
                b"qemu-decision-v1 = []",
                b"qemu-decision-v1 = []\nunreviewed = []",
                "collector crate extra feature",
            ),
        ),
        ("sample-count-25", lambda data: mutate_text(data, "collector", "pub const BOOT_SAMPLES: u8 = 24;", "pub const BOOT_SAMPLES: u8 = 25;", "sample count")),
        ("warmup-count-2", lambda data: mutate_text(data, "collector", "pub const BOOT_WARMUPS: u8 = 3;", "pub const BOOT_WARMUPS: u8 = 2;", "warmup count")),
        ("retained-count-20", lambda data: mutate_text(data, "collector", "pub const BOOT_RETAINED: usize = 21;", "pub const BOOT_RETAINED: usize = 20;", "retained count")),
        ("caller-supplied-index", lambda data: mutate_text(data, "collector", "terminal: EligibleTerminalEvidence,", "terminal: EligibleTerminalEvidence, sample_index: u8,", "caller index")),
        ("sequence-wrapping", lambda data: mutate_text(data, "collector", "self.next_sample += 1;", "self.next_sample = self.next_sample.wrapping_add(1);", "wrapping sequence")),
        ("sequence-reset", lambda data: mutate_text(data, "collector", "self.next_sample += 1;", "self.next_sample = 0;", "sequence reset")),
        ("prior-reset", lambda data: mutate_text(data, "collector", "self.accumulator = accumulator;", "self.accumulator = 0;", "prior reset")),
        ("warmup-off-by-one", lambda data: mutate_text(data, "collector", "self.next_sample >= BOOT_WARMUPS", "self.next_sample > BOOT_WARMUPS", "warmup split")),
        ("p50-index-9", lambda data: mutate_text(data, "collector", "(ticks[10], ticks[19])", "(ticks[9], ticks[19])", "p50 index")),
        ("p95-index-20", lambda data: mutate_text(data, "collector", "(ticks[10], ticks[19])", "(ticks[10], ticks[20])", "p95 index")),
        ("stability-overflow", lambda data: mutate_text(data, "collector", "u128::from(p95) * 100 > u128::from(p50) * STABILITY_PERCENT", "p95 * 100 > p50 * STABILITY_PERCENT", "stability width")),
        ("end-before-stability", lambda data: mutate_text(data, "collector", "let (p50, p95) = retained_percentiles(self.retained_ticks);", "let (p50, p95) = (0, 0);", "stability bypass")),
        ("extra-meta", lambda data: mutate_text(data, "collector", "write_meta(&mut *record, &self)", "write_meta(&mut *record, &self).and_then(|()| write_meta(&mut *record, &self))", "extra META")),
        ("meta-retry-surface", lambda data: mutate_text(data, "collector", "    pub fn begin<'a, F: ProfileRecordSinkFactory>(", "    pub fn retry_meta(&self) {}\n\n    pub fn begin<'a, F: ProfileRecordSinkFactory>(", "META retry surface")),
        ("failed-end", lambda data: mutate_text(data, "collector", "let stage = RecordStage::Sample(self.next_sample);", "let _ = write_end; let stage = RecordStage::End;", "failure END")),
        ("collector-index-getter", lambda data: mutate_text(data, "collector", "pub fn into_next(mut self)", "pub const fn next_sample_index(&self) -> u8 { 0 }\n\n    pub fn into_next(mut self)", "index getter")),
        ("poison-factory-recovery", lambda data: mutate_text(data, "collector", "impl<'a, F: ProfileRecordSinkFactory> PoisonedTranscript<'a, F> {", "impl<'a, F: ProfileRecordSinkFactory> PoisonedTranscript<'a, F> {\n    pub fn recover_factory(self) -> F { ManuallyDrop::into_inner(self.factory) }", "factory recovery")),
        ("uppercase-build-id", lambda data: mutate_text(data, "collector", "b'a'..=b'f' => Some(value - b'a' + 10),", "b'a'..=b'f' => Some(value - b'a' + 10), b'A'..=b'F' => Some(value - b'A' + 10),", "uppercase build identity")),
        ("run-id-field-swap", lambda data: mutate_text(data, "collector", "source_commit,\n            challenge_text,", "challenge_text,\n            source_commit,", "run-id fields")),
        (
            "formal-qemu-manifest-digest-drift",
            lambda data: mutate_text(
                data,
                "collector",
                QEMU_MANIFEST_SHA256,
                "0" + QEMU_MANIFEST_SHA256[1:],
                "formal QEMU manifest digest",
            ),
        ),
        (
            "formal-qemu-schema-digest-drift",
            lambda data: mutate_text(
                data,
                "collector",
                QEMU_SCHEMA_SHA256,
                "1" + QEMU_SCHEMA_SHA256[1:],
                "formal QEMU schema digest",
            ),
        ),
        (
            "formal-qemu-run-domain-includes-smoke",
            lambda data: mutate_text(
                data,
                "collector",
                '#[cfg(all(feature = "qemu-decision-v1", not(feature = "qemu-decision-v1-smoke")))]\n'
                'const RUN_ID_DOMAIN: &[u8] = b"vibeos.c84.qemu-aot-decision.run-id.v1";',
                '#[cfg(feature = "qemu-decision-v1")]\n'
                'const RUN_ID_DOMAIN: &[u8] = b"vibeos.c84.qemu-aot-decision.run-id.v1";',
                "formal QEMU run-id smoke exclusion",
            ),
        ),
        (
            "smoke-qemu-run-domain-collides-formal",
            lambda data: mutate_text(
                data,
                "collector",
                'b"vibeos.c84.qemu-aot-decision.smoke.run-id.v1"',
                'b"vibeos.c84.qemu-aot-decision.run-id.v1"',
                "dirty-smoke QEMU run-id domain",
            ),
        ),
        (
            "formal-qemu-capture-made-dirty",
            lambda data: mutate_text(
                data,
                "collector",
                'const CAPTURE_MODE: &[u8] = b"formal-publication";',
                'const CAPTURE_MODE: &[u8] = b"dirty-smoke-not-publication";',
                "formal QEMU capture mode",
            ),
        ),
        (
            "formal-qemu-made-ineligible",
            lambda data: mutate_text(
                data,
                "collector",
                'const DECISION_ELIGIBLE: &[u8] = b"true";',
                'const DECISION_ELIGIBLE: &[u8] = b"false";',
                "formal QEMU eligibility",
            ),
        ),
        (
            "smoke-qemu-made-eligible",
            lambda data: mutate_text(
                data,
                "collector",
                '#[cfg(feature = "qemu-decision-v1-smoke")]\nconst DECISION_ELIGIBLE: &[u8] = b"false";',
                '#[cfg(feature = "qemu-decision-v1-smoke")]\nconst DECISION_ELIGIBLE: &[u8] = b"true";',
                "dirty-smoke QEMU eligibility",
            ),
        ),
        (
            "formal-qemu-run-id-answer-drift",
            lambda data: mutate_text(
                data,
                "collector",
                QEMU_TEST_RUN_ID,
                "0" + QEMU_TEST_RUN_ID[1:],
                "formal QEMU run-id known answer",
            ),
        ),
        (
            "smoke-qemu-run-id-answer-drift",
            lambda data: mutate_text(
                data,
                "collector",
                QEMU_SMOKE_TEST_RUN_ID,
                "0" + QEMU_SMOKE_TEST_RUN_ID[1:],
                "dirty-smoke QEMU run-id known answer",
            ),
        ),
        (
            "formal-qemu-transcript-answer-drift",
            lambda data: mutate_text(
                data,
                "collector",
                QEMU_KNOWN_TRANSCRIPT_SHA256,
                "0" + QEMU_KNOWN_TRANSCRIPT_SHA256[1:],
                "formal QEMU transcript known answer",
            ),
        ),
        (
            "smoke-qemu-transcript-answer-drift",
            lambda data: mutate_text(
                data,
                "collector",
                QEMU_SMOKE_KNOWN_TRANSCRIPT_SHA256,
                "0" + QEMU_SMOKE_KNOWN_TRANSCRIPT_SHA256[1:],
                "dirty-smoke QEMU transcript known answer",
            ),
        ),
        (
            "retained-counter-wrapping",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bpub\s+fn\s+collect\b",
                "self.retained_count += 1;",
                "self.retained_count = self.retained_count.wrapping_add(1);",
                "retained counter wrapping",
            ),
        ),
        (
            "expected-epoch-rollback",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bpub\s+fn\s+collect\b",
                "self.expected_epoch = expected_next_epoch.unwrap_or(u64::MAX);",
                "self.expected_epoch = actual_epoch;",
                "expected epoch rollback",
            ),
        ),
        (
            "early-end-at-sample-22",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bpub\s+fn\s+collect\b",
                "if self.next_sample < BOOT_SAMPLES {",
                "if self.next_sample + 1 < BOOT_SAMPLES {",
                "early END",
            ),
        ),
        (
            "end-commit-omitted",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bpub\s+fn\s+commit_terminal\b",
                ".and_then(|()| end_record.commit_record());",
                ";",
                "END commit omitted",
            ),
        ),
        (
            "receipt-samples-23",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bpub\s+fn\s+collect\b",
                "samples: BOOT_SAMPLES,",
                "samples: BOOT_SAMPLES - 1,",
                "receipt sample count",
            ),
        ),
        (
            "retained-tick-substitution",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bpub\s+fn\s+collect\b",
                "self.retained_ticks[retained_index] = total_ticks;",
                "self.retained_ticks[retained_index] = self.accumulator;",
                "retained tick source",
            ),
        ),
        (
            "epoch-budget-saturating",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bpub\s+fn\s+begin\b",
                "let last_epoch_delta = u64::from(BOOT_SAMPLES - 1);",
                "let last_epoch_delta = u64::from(BOOT_SAMPLES.saturating_sub(1));",
                "epoch budget saturation",
            ),
        ),
        (
            "collector-factory-public",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bpub\s+struct\s+BootCollector\b",
                "    factory: ManuallyDrop<F>,",
                "    pub factory: ManuallyDrop<F>,",
                "public collector factory",
            ),
        ),
        (
            "completed-factory-recovery",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bimpl<F:\s*ProfileRecordSinkFactory>\s+CompletedTerminal",
                "    pub const fn receipt(&self) -> BootReceipt {",
                "    pub fn into_factory(self) -> F { ManuallyDrop::into_inner(self._factory) }\n\n    pub const fn receipt(&self) -> BootReceipt {",
                "completed factory recovery",
            ),
        ),
        (
            "uppercase-record-hex",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bfn\s+write_hex\b",
                'b"0123456789abcdef"',
                'b"0123456789ABCDEF"',
                "uppercase record hex",
            ),
        ),
        (
            "hexadecimal-accumulator",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bfn\s+write_u64\b",
                "value % 10",
                "value % 16",
                "non-decimal accumulator",
            ),
        ),
        (
            "meta-crlf",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r'#\[cfg\(not\(feature\s*=\s*"qemu-decision-v1"\)\)\]\s*fn\s+write_meta\b',
                '"workload_revision\\\":1}\\n")',
                '"workload_revision\\\":1}\\r\\n")',
                "META CRLF",
                match_literals=True,
            ),
        ),
        (
            "end-missing-lf",
            lambda data: mutate_text(
                data,
                "collector",
                '"warmups\\\":3}\\n")',
                '"warmups\\\":3}")',
                "END missing LF",
            ),
        ),
        (
            "campaign-runtime-source",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bimpl\s+Campaign\b",
                'option_env!("VIBEOS_C84_SOURCE_COMMIT")',
                'Some("1111111111111111111111111111111111111111")',
                "runtime source binding",
            ),
        ),
        (
            "campaign-raw-constructor-public",
            lambda data: mutate_scoped_text(
                data,
                "collector",
                r"\bimpl\s+Campaign\b",
                "    fn from_values(source_commit: &str, challenge_text: &str)",
                "    pub fn from_values(source_commit: &str, challenge_text: &str)",
                "public raw campaign constructor",
            ),
        ),
        (
            "portable-test-disabled",
            lambda data: mutate_text(
                data,
                "collector",
                "    fn complete_boot_emits_one_meta_twenty_four_samples_and_one_end() {",
                "    #[ignore]\n    fn complete_boot_emits_one_meta_twenty_four_samples_and_one_end() {",
                "disabled portable regression",
            ),
        ),
        (
            "portable-extra-dependency",
            lambda data: mutate_bytes(
                data,
                "crate_manifest",
                b'sha2 = { version = "=0.11.0", default-features = false }',
                b'sha2 = { version = "=0.11.0", default-features = false }\nserde = "1"',
                "portable extra dependency",
            ),
        ),
        ("raw-crlf", lambda data: mutate_text(data, "uart", "put_locked(tx, byte);", "if byte == b'\\n' { put_locked(tx, b'\\r'); } put_locked(tx, byte);", "raw CRLF")),
        (
            "activity-before-tty",
            lambda data: mutate_text(
                data,
                "tty",
                "    let tty = ManuallyDrop::new(TTY.lock());\n    uart::begin_raw_record_activity();\n    let tx = {\n        let permit = RawTxOrderPermit { _tty: &tty };\n        uart::RawTxRecord::begin(&permit)?\n    };",
                "    uart::begin_raw_record_activity();\n    let tty = ManuallyDrop::new(TTY.lock());\n    let tx = {\n        let permit = RawTxOrderPermit { _tty: &tty };\n        uart::RawTxRecord::begin(&permit)?\n    };",
                "TTY/activity arm order",
            ),
        ),
        ("commit-no-drain", lambda data: mutate_text(data, "uart", "wait_tx_fully_empty();", "core::hint::spin_loop();", "TX drain")),
        ("release-on-error", lambda data: mutate_text(data, "tty", "if result.is_ok() {", "if result.is_err() {", "successful release")),
        ("record-send-widening", lambda data: mutate_text(data, "uart", "guard: Option<SpinGuard<'static, TxState>>", "guard: Option<()>", "record Send widening")),
        (
            "activity-arm-removed",
            lambda data: mutate_scoped_text(
                data,
                "tty",
                r"\bpub\(crate\)\s+fn\s+begin_raw_uart_record\b",
                "    uart::begin_raw_record_activity();",
                "    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);",
                "raw activity arm removed",
            ),
        ),
        (
            "tx-before-activity-arm",
            lambda data: mutate_scoped_text(
                data,
                "tty",
                r"\bpub\(crate\)\s+fn\s+begin_raw_uart_record\b",
                "    uart::begin_raw_record_activity();\n    let tx = {\n        let permit = RawTxOrderPermit { _tty: &tty };\n        uart::RawTxRecord::begin(&permit)?\n    };",
                "    let tx = {\n        let permit = RawTxOrderPermit { _tty: &tty };\n        uart::RawTxRecord::begin(&permit)?\n    };\n    uart::begin_raw_record_activity();",
                "TX before activity arm",
            ),
        ),
        (
            "not-at-line-start-releases-tx",
            lambda data: mutate_scoped_text(
                data,
                "uart",
                r"\bpub\(crate\)\s+fn\s+begin\b",
                "let guard = ManuallyDrop::new(TX.lock());",
                "let guard = TX.lock();",
                "NotAtLineStart TX release",
            ),
        ),
        (
            "not-at-line-start-clears-activity",
            lambda data: mutate_scoped_text(
                data,
                "uart",
                r"\bpub\(crate\)\s+fn\s+begin\b",
                "        if !guard.at_line_start {\n            return Err(RawTxRecordError::NotAtLineStart);",
                "        if !guard.at_line_start {\n            finish_raw_record_activity();\n            return Err(RawTxRecordError::NotAtLineStart);",
                "NotAtLineStart activity clear",
            ),
        ),
        (
            "tx-release-before-drain",
            lambda data: mutate_scoped_text(
                data,
                "uart",
                r"\bpub\(crate\)\s+fn\s+commit_record\b",
                "        wait_tx_fully_empty();",
                "        self.release_after_commit();\n        wait_tx_fully_empty();",
                "TX release before drain",
            ),
        ),
        (
            "commit-framing-bypass",
            lambda data: mutate_scoped_text(
                data,
                "uart",
                r"\bpub\(crate\)\s+fn\s+commit_record\b",
                "        self.framing.validate_commit()?;",
                "        let _ = self.framing;",
                "commit framing bypass",
            ),
        ),
        (
            "raw-drop-releases-tx",
            lambda data: mutate_scoped_text(
                data,
                "tty",
                r"\bimpl\s+Drop\s+for\s+RawUartRecord\b",
                "core::mem::forget(tx);",
                "drop(tx);",
                "raw Drop TX recovery",
            ),
        ),
        (
            "raw-drop-clears-activity",
            lambda data: mutate_scoped_text(
                data,
                "tty",
                r"\bimpl\s+Drop\s+for\s+RawUartRecord\b",
                "        if uart::raw_record_active() {",
                "        if uart::raw_record_active() { uart::finish_raw_record_activity();",
                "raw Drop activity recovery",
            ),
        ),
        (
            "activity-read-relaxed",
            lambda data: mutate_scoped_text(
                data,
                "uart",
                r"\bpub\(crate\)\s+fn\s+raw_record_active\b",
                "Ordering::Acquire",
                "Ordering::Relaxed",
                "raw activity relaxed read",
            ),
        ),
        (
            "activity-clear-relaxed",
            lambda data: mutate_scoped_text(
                data,
                "uart",
                r"\bpub\(crate\)\s+fn\s+finish_raw_record_activity\b",
                "RAW_RECORD_ACTIVE.store(false, Ordering::Release);",
                "RAW_RECORD_ACTIVE.store(false, Ordering::Relaxed);",
                "raw activity relaxed clear",
            ),
        ),
        (
            "activity-arm-unchecked-store",
            lambda data: mutate_scoped_text(
                data,
                "uart",
                r"\bpub\(crate\)\s+fn\s+begin_raw_record_activity\b",
                "let was_active = RAW_RECORD_ACTIVE.swap(true, Ordering::AcqRel);",
                "let was_active = RAW_RECORD_ACTIVE.load(Ordering::Relaxed); RAW_RECORD_ACTIVE.store(true, Ordering::Relaxed);",
                "raw activity unchecked arm",
            ),
        ),
        (
            "panic-raw-gate-removed",
            lambda data: mutate_scoped_text(
                data,
                "kernel_root",
                r"\bfn\s+panic\s*\(",
                f'    #[cfg(feature = "{FEATURE}")]\n    if uart::raw_record_active() {{\n        // A physical formal record may already own TTY/TX and have emitted a\n        // prefix. SBI console output bypasses both locks, so the only framing-\n        // safe panic path is a silent machine stop.\n        sbi::shutdown(true);\n    }}',
                "",
                "panic raw gate removal",
            ),
        ),
        (
            "oom-raw-gate-removed",
            lambda data: mutate_scoped_text(
                data,
                "kernel_root",
                r"\bfn\s+oom\s*\(",
                f'    #[cfg(feature = "{FEATURE}")]\n    if uart::raw_record_active() {{\n        // This check precedes both quota diagnostics and the fatal allocator\n        // writer: neither may splice bytes into an in-flight formal record.\n        sbi::shutdown(true);\n    }}',
                "",
                "OOM raw gate removal",
            ),
        ),
        (
            "panic-sbi-before-gate",
            lambda data: mutate_scoped_text(
                data,
                "kernel_root",
                r"\bfn\s+panic\s*\(",
                "fn panic(info: &PanicInfo) -> ! {",
                "fn panic(info: &PanicInfo) -> ! { sbi::legacy_putchar(b'!');",
                "panic SBI bypass before gate",
            ),
        ),
        (
            "oom-sbi-before-gate",
            lambda data: mutate_scoped_text(
                data,
                "kernel_root",
                r"\bfn\s+oom\s*\(",
                "fn oom(layout: core::alloc::Layout) -> ! {",
                "fn oom(layout: core::alloc::Layout) -> ! { sbi::legacy_putchar(b'!');",
                "OOM SBI bypass before gate",
            ),
        ),
        (
            "raw-tx-unsafe-send",
            lambda data: mutate_text(
                data,
                "uart",
                "pub(crate) struct RawTxRecord {\n    guard: Option<SpinGuard<'static, TxState>>,\n    framing: RawRecordFraming,\n}",
                "pub(crate) struct RawTxRecord {\n    guard: Option<SpinGuard<'static, TxState>>,\n    framing: RawRecordFraming,\n}\nunsafe impl Send for RawTxRecord {}",
                "raw TX unsafe Send",
            ),
        ),
        (
            "owner-seal-or",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bimpl\s+OwnerSeal\b",
                "self.epoch == epoch && self.detach.matches_exact(detach)",
                "self.epoch == epoch || self.detach.matches_exact(detach)",
                "owner seal OR",
            ),
        ),
        (
            "terminal-state-overwrite",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+fail_collector_state\b",
                "CollectorState::Failed(_)\n            | CollectorState::FinalizingTerminal { .. }\n            | CollectorState::Complete { .. }",
                "CollectorState::Failed(_)",
                "finalizing/Complete overwrite",
            ),
        ),
        (
            "collector-irq-terminal-cap-four",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                "if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)",
                "if !(1..=4).contains(&epoch)",
                "collector IRQ four-epoch cap",
            ),
        ),
        (
            "collector-irq-terminal-cap-23",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                "if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)",
                "if !(1..=23).contains(&epoch)",
                "collector IRQ 23-epoch cap",
            ),
        ),
        (
            "collector-irq-terminal-cap-25",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                "if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)",
                "if !(1..=25).contains(&epoch)",
                "collector IRQ 25-epoch cap",
            ),
        ),
        (
            "collector-irq-range-cfg-removed",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                f'    #[cfg(feature = "{QEMU_FEATURE}")]\n    if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)',
                "    if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)",
                "collector IRQ range cfg removal",
            ),
        ),
        (
            "collector-irq-range-inherits-formal-policy",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                f'#[cfg(feature = "{QEMU_FEATURE}")]\n    if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)',
                f'#[cfg(any(\n        feature = "{QEMU_FEATURE}",\n        feature = "{QEMU_DECISION_FEATURE}"\n    ))]\n    if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)',
                "collector IRQ formal-policy inheritance",
            ),
        ),
        (
            "collector-irq-range-formal-policy-only",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                f'#[cfg(feature = "{QEMU_FEATURE}")]\n    if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)',
                f'#[cfg(feature = "{QEMU_DECISION_FEATURE}")]\n    if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)',
                "collector IRQ formal-policy coupling",
            ),
        ),
        (
            "collector-irq-range-names-smoke-policy",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                f'#[cfg(feature = "{QEMU_FEATURE}")]\n    if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)',
                f'#[cfg(any(\n        feature = "{QEMU_FEATURE}",\n        feature = "{QEMU_DECISION_SMOKE_FEATURE}"\n    ))]\n    if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)',
                "collector IRQ smoke-policy coupling",
            ),
        ),
        (
            "collector-irq-predecessor-formal-exemption-added",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                f'#[cfg(not(feature = "{QEMU_FEATURE}"))]\n    if !(1..=4).contains(&epoch)',
                f'#[cfg(not(any(\n        feature = "{QEMU_FEATURE}",\n        feature = "{QEMU_DECISION_FEATURE}"\n    )))]\n    if !(1..=4).contains(&epoch)',
                "collector IRQ predecessor formal-QEMU exemption",
            ),
        ),
        (
            "collector-irq-predecessor-cap-widened",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                "if !(1..=4).contains(&epoch)",
                "if !(1..=u64::from(BOOT_SAMPLES)).contains(&epoch)",
                "predecessor IRQ four-epoch cap",
            ),
        ),
        (
            "collector-irq-terminal-cas-removed",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                "MANAGED_IRQ_ACCEPTANCE_TERMINAL_EPOCH\n        .compare_exchange(epoch, u64::MAX, Ordering::AcqRel, Ordering::Acquire)\n        .map_err(|_| ProfileError::StateMismatch)?;",
                "MANAGED_IRQ_ACCEPTANCE_TERMINAL_EPOCH.store(u64::MAX, Ordering::Release);",
                "collector IRQ terminal CAS",
            ),
        ),
        (
            "collector-irq-terminal-cas-relaxed",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                ".compare_exchange(epoch, u64::MAX, Ordering::AcqRel, Ordering::Acquire)",
                ".compare_exchange(epoch, u64::MAX, Ordering::Relaxed, Ordering::Relaxed)",
                "collector IRQ terminal CAS ordering",
            ),
        ),
        (
            "collector-irq-inactive-off-by-one",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                "before.inactive != epoch - 1",
                "before.inactive != epoch",
                "collector IRQ predecessor inactive count",
            ),
        ),
        (
            "collector-irq-next-epoch-not-published",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
                "MANAGED_IRQ_ACCEPTANCE_TERMINAL_EPOCH.store(ready_epoch, Ordering::Release);",
                "let _ = ready_epoch;",
                "collector IRQ next terminal epoch publish",
            ),
        ),
        (
            "collector-peer-only-four-terminal-irqs",
            lambda data: mutate_bytes(
                data,
                "peer_script",
                b"*(irq_response_line(epoch) for epoch in range(1, SAMPLE_COUNT + 1)),",
                b"*(irq_response_line(epoch) for epoch in range(1, 5)),",
                "peer 24 terminal IRQ sequence",
            ),
        ),
        (
            "collector-runner-six-irq-success-count",
            lambda data: mutate_bytes(
                data,
                "qemu_script",
                b'[ "$irq" -eq 26 ] || fail "success boot IRQ count differs: $irq"',
                b'[ "$irq" -eq 6 ] || fail "success boot IRQ count differs: $irq"',
                "runner 26 IRQ marker count",
            ),
        ),
        (
            "failure-sequence-from-epoch",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bimpl\s+CollectorFailureReceipt\b",
                "sequence: collector_next_sequence(committed_records),",
                "sequence: epoch.saturating_sub(1).min(u64::from(BOOT_SAMPLES)) as u8,",
                "epoch-derived failure sequence",
            ),
        ),
        (
            "failure-sequence-counts-meta",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bconst\s+fn\s+collector_next_sequence\b",
                "committed_records.saturating_sub(1)",
                "committed_records.saturating_sub(0)",
                "failure sequence META off-by-one",
            ),
        ),
        (
            "failure-sequence-unchecked-subtraction",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bconst\s+fn\s+collector_next_sequence\b",
                "committed_records.saturating_sub(1)",
                "committed_records - 1",
                "failure sequence unchecked META subtraction",
            ),
        ),
        (
            "failure-sequence-unclamped",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bconst\s+fn\s+collector_next_sequence\b",
                "if committed_samples > BOOT_SAMPLES {\n        BOOT_SAMPLES\n    } else {\n        committed_samples\n    }",
                "committed_samples",
                "failure sequence BOOT_SAMPLES clamp",
            ),
        ),
        (
            "failure-update-stale-sequence",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bimpl\s+CollectorFailureReceipt\b",
                "self.sequence = collector_next_sequence(committed_records);",
                "let _ = collector_next_sequence(committed_records);",
                "Failed update sequence refresh",
            ),
        ),
        (
            "failure-update-rolls-back-commits",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bimpl\s+CollectorFailureReceipt\b",
                "let committed_records = if committed_records > self.audit_commits {\n            committed_records\n        } else {\n            self.audit_commits\n        };",
                "let committed_records = committed_records;",
                "Failed committed-record rollback",
            ),
        ),
        (
            "failure-install-skips-sequence-refresh",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+install_collector_failure\b",
                "receipt.absorb_committed_records(committed_records);",
                "receipt.audit_commits = committed_records;",
                "Failed install sequence refresh",
            ),
        ),
        (
            "failure-finalizer-skips-sequence-refresh",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+collector_fail_unfinalized_terminal\b",
                "receipt.absorb_committed_records(committed_records);",
                "receipt.audit_commits = committed_records;",
                "Failed finalizer sequence refresh",
            ),
        ),
        (
            "failed-reject-recomputes-epoch-sequence",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+collector_terminal_reject\b",
                "receipt.sequence,",
                "receipt.epoch.saturating_sub(1) as u8,",
                "Failed REJECT next sequence",
            ),
        ),
        (
            "meta-audit-panic",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+init_collector\b",
                "let audit = match collector_take_audit(1) {",
                'let audit = collector_take_audit(1).expect("META"); match Ok::<(), ()>(()) {',
                "META audit panic",
            ),
        ),
        (
            "meta-marker-before-reinstall",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+init_collector\b",
                "            let mut slot = SLOT.lock();",
                "            collector_audit_meta(audit);\n            let mut slot = SLOT.lock();",
                "early META marker",
            ),
        ),
        (
            "publishing-question-mark-escape",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+collect_trusted_sample\b",
                "    if !owner.detach.is_current_running_exact() {",
                "    ensure_not_poisoned()?;\n    if !owner.detach.is_current_running_exact() {",
                "post-Publishing question-mark escape",
            ),
        ),
        (
            "detach-disarm-bypassed",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+collect_trusted_sample\b",
                "if owner.detach.disarm() != TaskDetachDisarm::Disarmed {",
                "if matches!(owner.detach.disarm(), TaskDetachDisarm::Disarmed | TaskDetachDisarm::AlreadyDisarmed) && false {",
                "collector detach disarm bypass",
            ),
        ),
        (
            "sample-reinstall-owner-or",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"Ok\(CollectionProgress::More\(next\)\)\s*=>",
                "slot_owner.matches(owner.epoch, owner.detach)\n                    && collector_owner.matches(owner.epoch, owner.detach)",
                "slot_owner.matches(owner.epoch, owner.detach)\n                    || collector_owner.matches(owner.epoch, owner.detach)",
                "SAMPLE reinstall owner OR",
            ),
        ),
        (
            "pending-end-ready-check-weakened",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"Ok\(CollectionProgress::PendingTerminal\(pending\)\)\s*=>",
                "if !exact || ready.next_epoch() != Some(ready_epoch) {",
                "if !exact && ready.next_epoch() != Some(ready_epoch) {",
                "pending-END Ready check",
            ),
        ),
        (
            "audit-commit-saturating",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"Ok\(CollectionProgress::PendingTerminal\(pending\)\)\s*=>",
                "sequence.checked_add(2)",
                "sequence.saturating_add(2).into()",
                "audit commit saturation",
            ),
        ),
        (
            "end-audit-commit-uses-prefix-count",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+collector_emit_success\b",
                "collector_take_audit(committed_records)",
                "collector_take_audit(final_prefix_records)",
                "END audit commit",
            ),
        ),
        (
            "terminal-receipt-born-disarmed",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"Ok\(CollectionProgress::PendingTerminal\(pending\)\)\s*=>",
                "armed: true,",
                "armed: false,",
                "terminal receipt arm",
            ),
        ),
        (
            "terminal-drop-no-fail-close",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bimpl\s+Drop\s+for\s+CollectorTerminalReceipt\b",
                "collector_fail_unfinalized_terminal(\n                self.epoch,\n                self.ready_epoch,\n                self.committed_records,\n            );",
                "let _ = (self.epoch, self.ready_epoch, self.committed_records);",
                "terminal Drop fail-close",
            ),
        ),
        (
            "terminal-disarm-before-audit",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+collector_emit_success\b",
                "    #[cfg(feature = \"wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance\")]\n    let audit = receipt",
                "    receipt.armed = false;\n    #[cfg(feature = \"wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance\")]\n    let audit = receipt",
                "terminal disarm before audit",
            ),
        ),
        (
            "failed-marker-replay",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+collector_emit_failed_after_drop\b",
                "receipt.marker_pending = false;",
                "receipt.marker_pending = true;",
                "FAILED marker replay",
            ),
        ),
        (
            "closed-ready-mismatch-accepted",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+collector_terminal_reject\b",
                "ready.next_epoch() == Some(*ready_epoch)",
                "ready.next_epoch() != Some(*ready_epoch)",
                "closed Ready mismatch",
            ),
        ),
        (
            "closed-reject-started",
            lambda data: mutate_text(
                data,
                "slot",
                "reason=collector_closed target_started=0",
                "reason=collector_closed target_started=1",
                "closed reject target start",
            ),
        ),
        (
            "terminal-check-allows-closed",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(FEATURE)}"\s*\)\s*\]\s*fn\s+next_epoch_for_prepare\b',
                "(SlotState::Ready(_), CollectorState::Complete { .. }) => {\n            Err(ProfileError::CollectorClosed)\n        }",
                "(SlotState::Ready(ready), CollectorState::Complete { .. }) => ready.next_epoch().ok_or(ProfileError::Exhausted)",
                "closed next epoch",
                match_literals=True,
            ),
        ),
        (
            "prepare-registers-before-terminal-check",
            lambda data: swap_scoped_text(
                data,
                "slot",
                rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(FEATURE)}"\s*\)\s*\]\s*pub\(crate\)\s+fn\s+prepare_current\b',
                "    let epoch = next_epoch_for_prepare()?;",
                "    if !crate::exec::try_reserve_current_task_registrations(1) {",
                "prepare registration before terminal check",
                match_literals=True,
            ),
        ),
        (
            "active-disconnect-misclassified",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(FEATURE)}"\s*\)\s*\]\s*pub\(crate\)\s+fn\s+acknowledge_rejection\b',
                "CollectorFailureReason::ActiveTargetDisconnected",
                "CollectorFailureReason::TerminalRejected",
                "active disconnect reason",
                match_literals=True,
            ),
        ),
        (
            "collector-abandon-predecessor-ack",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+abandon_trusted_sample_for_collector\b",
                "    match installed {",
                "    let _ = acknowledge_rejection(owner.epoch);\n    match installed {",
                "collector abandon predecessor ack",
            ),
        ),
        (
            "reservation-drops-ready",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(FEATURE)}"\s*\)\s*\]\s*fn\s+release_reservation\b',
                "*slot = SlotState::Ready(ready);",
                "drop(ready);",
                "reservation Ready recovery",
                match_literals=True,
            ),
        ),
        (
            "failed-start-drops-ready",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+recover_failed_target\b",
                "*slot = SlotState::Ready(ready);",
                "drop(ready);",
                "failed-start Ready recovery",
            ),
        ),
        (
            "detach-skips-recovery-ack",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bunsafe\s+fn\s+profile_task_detached\b",
                "let installed = install_rejected(owner, TransitKind::Cancel, ready, report);\n            #[cfg(feature = \"wasm-c84-ssh-managed-child-single-boot-collector\")]\n            if installed.is_ok() {\n                let _ = acknowledge_rejection(owner.epoch);\n            }",
                "let installed = install_rejected(owner, TransitKind::Cancel, ready, report);\n            #[cfg(feature = \"wasm-c84-ssh-managed-child-single-boot-collector\")]\n            if installed.is_ok() { let _ = owner.epoch; }",
                "detach Ready recovery ack",
            ),
        ),
        (
            "sshd-reject-status-zero",
            lambda data: mutate_text(
                data,
                "sshd",
                "const SSH_EXEC_PRESTART_REJECT_STATUS: u32 = 126;",
                "const SSH_EXEC_PRESTART_REJECT_STATUS: u32 = 0;",
                "SSHD reject status",
            ),
        ),
        (
            "sshd-prepared-reject-carries-command",
            lambda data: mutate_scoped_text(
                data,
                "sshd",
                r"\benum\s+PreparedExec\b",
                "    Reject,",
                "    Reject { command: String },",
                "Prepared Reject command",
            ),
        ),
        (
            "sshd-accepted-reject-carries-profile",
            lambda data: mutate_scoped_text(
                data,
                "sshd",
                r"\benum\s+AcceptedExec\b",
                "    Reject { status: u32 },",
                "    Reject { status: u32, profile: Option<SshExecProfileRun> },",
                "Accepted Reject profile",
            ),
        ),
        (
            "sshd-reject-event-fails",
            lambda data: mutate_scoped_text(
                data,
                "sshd",
                r"Event::Serv\(ServEvent::SessionExec\(event\)\)\s*=>",
                "event\n                            .succeed()",
                "event\n                            .fail()",
                "Reject event failure",
            ),
        ),
        (
            "sshd-reject-nonempty-output",
            lambda data: mutate_scoped_text(
                data,
                "sshd",
                r"\bif\s+let\s+AcceptedExec::Reject\s*\{\s*status\s*\}\s*=\s*&accepted",
                "&[],",
                'b"rejected",',
                "Reject output",
            ),
        ),
        (
            "sshd-reject-falls-through",
            lambda data: mutate_scoped_text(
                data,
                "sshd",
                r"\bif\s+let\s+AcceptedExec::Reject\s*\{\s*status\s*\}\s*=\s*&accepted",
                "return match finish_exec(",
                "match finish_exec(",
                "Reject fallthrough",
            ),
        ),
        (
            "sshd-reject-executes",
            lambda data: mutate_scoped_text(
                data,
                "sshd",
                r"\bif\s+let\s+AcceptedExec::Reject\s*\{\s*status\s*\}\s*=\s*&accepted",
                "let status = *status;",
                "let status = *status; let _ = execute_with_network;",
                "Reject execution",
            ),
        ),
        (
            "sshd-reject-early-bypass",
            lambda data: mutate_scoped_text(
                data,
                "sshd",
                r"\basync\s+fn\s+serve_connection\b",
                "        SessionStart::Exec(accepted) => {\n",
                '''        SessionStart::Exec(accepted) => {
            #[cfg(feature = "c84-profile-request-parent")]
            if matches!(&accepted, AcceptedExec::Reject { .. }) {
                return ConnectionEnd::ExecComplete(SSH_EXEC_PRESTART_REJECT_STATUS);
            }
''',
                "Reject early bypass",
            ),
        ),
        ("audit-uart-forward", lambda data: mutate_text(data, "slot", "        self.hasher.update(bytes);", "        crate::uart::early_write(core::str::from_utf8(bytes).unwrap());\n        self.hasher.update(bytes);", "audit UART forwarding")),
        ("audit-buffer-store", lambda data: mutate_text(data, "slot", "struct AuditRecord {\n    hasher: Sha256,", "struct AuditRecord {\n    leaked: alloc::vec::Vec<u8>,\n    hasher: Sha256,", "audit buffer storage")),
        ("audit-token-copy", lambda data: mutate_text(data, "slot", "struct AuditCommit", "#[derive(Clone, Copy)]\nstruct AuditCommit", "AuditCommit Copy")),
        ("atomic-uart-factory-alias-replaced", lambda data: mutate_text(data, "slot", "type CollectorFactory = AtomicUartRecordFactory;", "type CollectorFactory = AuditRecordFactory;", "atomic UART factory alias")),
        ("audit-borrowed-token", lambda data: mutate_text(data, "slot", "fn collector_audit_meta(commit: AuditCommit)", "fn collector_audit_meta(commit: &AuditCommit)", "borrowed AuditCommit")),
        ("qemu-formal-prefix", lambda data: mutate_text(data, "slot", "next_sequence=0 state=collecting ready_epoch=1 decision_eligible=0 formal_uart=0", "next_sequence=0 state=collecting ready_epoch=1 VIBE_WASM_AOT_SAMPLE decision_eligible=0 formal_uart=0", "formal UART leak")),
        ("qemu-eligible", lambda data: mutate_text(data, "slot", "next_sequence=0 state=collecting ready_epoch=1 decision_eligible=0 formal_uart=0", "next_sequence=0 state=collecting ready_epoch=1 decision_eligible=1 formal_uart=0", "QEMU eligibility")),
        ("qemu-formal-uart", lambda data: mutate_text(data, "slot", "next_sequence=0 state=collecting ready_epoch=1 decision_eligible=0 formal_uart=0", "next_sequence=0 state=collecting ready_epoch=1 decision_eligible=0 formal_uart=1", "QEMU formal UART")),
        (
            "audit-println-whole-value",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bimpl\s+ProfileRecordSink\s+for\s+AuditRecord\b",
                "        self.hasher.update(bytes);",
                '        crate::println!("{:?}", bytes);\n        self.hasher.update(bytes);',
                "audit whole-value println",
            ),
        ),
        (
            "audit-record-drop-flush",
            lambda data: mutate_text(
                data,
                "slot",
                "struct AuditRecord {\n    hasher: Sha256,\n    bytes: u64,\n    wrote_any: bool,\n    line_feed_seen: bool,\n    committed: bool,\n    not_send: PhantomData<*mut ()>,\n}",
                "struct AuditRecord {\n    hasher: Sha256,\n    bytes: u64,\n    wrote_any: bool,\n    line_feed_seen: bool,\n    committed: bool,\n    not_send: PhantomData<*mut ()>,\n}\nimpl Drop for AuditRecord { fn drop(&mut self) { crate::println!(\"flush\"); } }",
                "audit Drop flush",
            ),
        ),
        (
            "audit-record-unsafe-send",
            lambda data: mutate_text(
                data,
                "slot",
                "struct AuditRecord {\n    hasher: Sha256,",
                "unsafe impl Send for AuditRecord {}\nstruct AuditRecord {\n    hasher: Sha256,",
                "audit unsafe Send",
            ),
        ),
        (
            "audit-factory-unsafe-sync",
            lambda data: mutate_text(
                data,
                "slot",
                "struct AuditRecordFactory {\n    not_sync: PhantomData<Cell<()>>,\n}",
                "struct AuditRecordFactory {\n    not_sync: PhantomData<Cell<()>>,\n}\nunsafe impl Sync for AuditRecordFactory {}",
                "audit factory unsafe Sync",
            ),
        ),
        (
            "audit-byte-count-wrapping",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bimpl\s+ProfileRecordSink\s+for\s+AuditRecord\b",
                ".checked_add(fragment)\n            .ok_or(AuditError::ByteCountOverflow)?;",
                ".wrapping_add(fragment);",
                "audit byte count wrapping",
            ),
        ),
        (
            "audit-commit-count-wrapping",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bimpl\s+ProfileRecordSink\s+for\s+AuditRecord\b",
                ".checked_add(1)\n            .ok_or(AuditError::CommitCountOverflow)?;",
                ".wrapping_add(1);",
                "audit commit count wrapping",
            ),
        ),
        (
            "audit-committed-before-queue",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bimpl\s+ProfileRecordSink\s+for\s+AuditRecord\b",
                "        audit.push(AuditCommit {",
                "        self.committed = true;\n        audit.push(AuditCommit {",
                "audit early committed flag",
            ),
        ),
        (
            "audit-token-public",
            lambda data: mutate_text(
                data,
                "slot",
                "struct AuditCommit {\n    ordinal: u8,",
                "pub(crate) struct AuditCommit {\n    ordinal: u8,",
                "public AuditCommit",
            ),
        ),
        (
            "audit-extra-token-constructor",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+collector_audit_meta\b",
                "fn collector_audit_meta(commit: AuditCommit) {",
                "fn collector_audit_meta(commit: AuditCommit) { let _forged = AuditCommit { ordinal: 1, bytes: 1, sha256: [0; 32] };",
                "extra AuditCommit constructor",
            ),
        ),
        (
            "audit-marker-raw-integer",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+collector_audit_meta\b",
                "commit: AuditCommit",
                "commit: u8",
                "raw audit marker authority",
            ),
        ),
        (
            "audit-marker-write-after-commit",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+collector_audit_meta\b",
                "fn collector_audit_meta(commit: AuditCommit) {",
                "fn collector_audit_meta(commit: AuditCommit) { let _ = commit_record(&commit);",
                "audit write after commit",
            ),
        ),
        (
            "audit-sample-saturating-sequence",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+collector_audit_sample\b",
                ".checked_add(1)\n        .expect(\"C8.4 collector sequence remains within 24 samples\")",
                ".saturating_add(1)",
                "audit sample saturating sequence",
            ),
        ),
        (
            "audit-warmup-boundary",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+collector_audit_sample\b",
                "u8::from(sequence < BOOT_WARMUPS)",
                "u8::from(sequence <= BOOT_WARMUPS)",
                "audit warmup boundary",
            ),
        ),
        (
            "audit-end-accumulator-reset",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+collector_audit_end\b",
                "let accumulator = COLLECTOR_AUDIT.lock().last_sample_accumulator;",
                "let accumulator = 0_u64;",
                "audit END accumulator",
            ),
        ),
        (
            "audit-take-ignores-expected",
            lambda data: mutate_scoped_text(
                data,
                "slot",
                r"\bfn\s+collector_take_audit\b",
                "COLLECTOR_AUDIT.lock().take(expected)",
                "COLLECTOR_AUDIT.lock().take(1)",
                "audit expected ordinal",
            ),
        ),
        (
            "audit-state-unbounded-buffer",
            lambda data: mutate_text(
                data,
                "slot",
                "struct AuditState {\n    commits: u8,",
                "struct AuditState {\n    leaked: alloc::vec::Vec<u8>,\n    commits: u8,",
                "audit state buffer",
            ),
        ),
        ("base-inherits-qemu", lambda data: mutate_bytes(data, "kernel_manifest", f'{FEATURE} = [\n    "{TRUSTED_FEATURE}",\n]'.encode(), f'{FEATURE} = [\n    "{TRUSTED_QEMU_FEATURE}",\n]'.encode(), "physical QEMU inheritance")),
        ("qemu-inherits-trusted-transcript", lambda data: mutate_bytes(data, "kernel_manifest", f'{QEMU_FEATURE} = [\n    "{FEATURE}",\n    "{FINISH_QEMU_FEATURE}",\n    "dep:sha2",\n]'.encode(), f'{QEMU_FEATURE} = [\n    "{FEATURE}",\n    "{TRUSTED_QEMU_FEATURE}",\n    "dep:sha2",\n]'.encode(), "collector QEMU predecessor")),
        ("formal-qemu-profile-selector-removed", lambda data: mutate_bytes(data, "kernel_manifest", f'    "vibeos-wasm-aot-profile/{QEMU_PROFILE_FEATURE}",\n'.encode(), b"", "formal QEMU profile selector")),
        ("formal-qemu-firmware-inherits-diagnostic-finish", lambda data: mutate_bytes(data, "qemu_manifest", f'{QEMU_DECISION_FEATURE} = [\n    "vibeos-kernel/{QEMU_DECISION_FEATURE}",\n]'.encode(), f'{QEMU_DECISION_FEATURE} = [\n    "{FINISH_QEMU_FEATURE}",\n    "vibeos-kernel/{QEMU_DECISION_FEATURE}",\n]'.encode(), "formal QEMU firmware diagnostic finish predecessor")),
        (
            "smoke-qemu-kernel-formal-layer-removed",
            lambda data: mutate_bytes(
                data,
                "kernel_manifest",
                f'{QEMU_DECISION_SMOKE_FEATURE} = [\n    "{QEMU_DECISION_FEATURE}",\n    "vibeos-wasm-aot-profile/{QEMU_PROFILE_SMOKE_FEATURE}",\n]'.encode(),
                f'{QEMU_DECISION_SMOKE_FEATURE} = [\n    "vibeos-wasm-aot-profile/{QEMU_PROFILE_SMOKE_FEATURE}",\n]'.encode(),
                "kernel dirty-smoke formal layer",
            ),
        ),
        (
            "smoke-qemu-kernel-profile-selector-removed",
            lambda data: mutate_bytes(
                data,
                "kernel_manifest",
                f'    "vibeos-wasm-aot-profile/{QEMU_PROFILE_SMOKE_FEATURE}",\n'.encode(),
                b"",
                "kernel dirty-smoke profile selector",
            ),
        ),
        (
            "smoke-qemu-firmware-formal-layer-removed",
            lambda data: mutate_bytes(
                data,
                "qemu_manifest",
                f'{QEMU_DECISION_SMOKE_FEATURE} = [\n    "{QEMU_DECISION_FEATURE}",\n    "vibeos-kernel/{QEMU_DECISION_SMOKE_FEATURE}",\n]'.encode(),
                f'{QEMU_DECISION_SMOKE_FEATURE} = [\n    "vibeos-kernel/{QEMU_DECISION_SMOKE_FEATURE}",\n]'.encode(),
                "firmware dirty-smoke formal layer",
            ),
        ),
        ("formal-qemu-default-on", lambda data: mutate_bytes(data, "qemu_manifest", b"default = []", f'default = ["{QEMU_DECISION_FEATURE}"]'.encode(), "formal QEMU default")),
        ("smoke-qemu-default-on", lambda data: mutate_bytes(data, "qemu_manifest", b"default = []", f'default = ["{QEMU_DECISION_SMOKE_FEATURE}"]'.encode(), "dirty-smoke QEMU default")),
        ("milkv-audit-feature", lambda data: mutate_bytes(data, "milkv_manifest", f'    "vibeos-kernel/{FEATURE}",'.encode(), f'    "vibeos-kernel/{QEMU_FEATURE}",'.encode(), "Milk-V audit")),
        ("milkv-formal-qemu-feature", lambda data: mutate_bytes(data, "milkv_manifest", f'    "vibeos-kernel/{FEATURE}",'.encode(), f'    "vibeos-kernel/{QEMU_DECISION_FEATURE}",'.encode(), "Milk-V formal QEMU")),
        ("milkv-smoke-qemu-feature", lambda data: mutate_bytes(data, "milkv_manifest", f'    "vibeos-kernel/{FEATURE}",'.encode(), f'    "vibeos-kernel/{QEMU_DECISION_SMOKE_FEATURE}",'.encode(), "Milk-V dirty-smoke QEMU")),
        ("collector-qemu-exemption-removed", lambda data: mutate_text(data, "kernel_root", f'    not(feature = "{TRUSTED_QEMU_FEATURE}"),\n    not(feature = "{QEMU_FEATURE}"),\n    not(feature = "{QEMU_DECISION_FEATURE}")', f'    not(feature = "{TRUSTED_QEMU_FEATURE}"),\n    not(feature = "{QEMU_DECISION_FEATURE}")', "trusted collector exemption")),
        ("collector-qemu-exemption-widened", lambda data: mutate_text(data, "kernel_root", f'    not(feature = "{TRUSTED_QEMU_FEATURE}"),\n    not(feature = "{QEMU_FEATURE}"),\n    not(feature = "{QEMU_DECISION_FEATURE}")', f'    not(feature = "{TRUSTED_QEMU_FEATURE}"),\n    not(any(feature = "{QEMU_FEATURE}", feature = "wasm-c84-profile-slot-qemu-acceptance")),\n    not(feature = "{QEMU_DECISION_FEATURE}")', "trusted collector exemption width")),
        ("absorbing-isolation-loses-formal-qemu", lambda data: mutate_text(data, "kernel_root", f'        feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance",\n        feature = "{QEMU_DECISION_FEATURE}"', '        feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance"', "absorbing/formal QEMU isolation")),
        (
            "firmware-qemu-inherits-trusted-transcript",
            lambda data: mutate_bytes(
                data,
                "qemu_manifest",
                f'{QEMU_FEATURE} = [\n    "{FINISH_QEMU_FEATURE}",\n    "vibeos-kernel/{QEMU_FEATURE}",\n]'.encode(),
                f'{QEMU_FEATURE} = [\n    "{FINISH_QEMU_FEATURE}",\n    "vibeos-kernel/{TRUSTED_QEMU_FEATURE}",\n    "vibeos-kernel/{QEMU_FEATURE}",\n]'.encode(),
                "firmware trusted transcript inheritance",
            ),
        ),
        (
            "qemu-collector-default-on",
            lambda data: mutate_bytes(
                data,
                "qemu_manifest",
                b"default = []",
                f'default = ["{QEMU_FEATURE}"]'.encode(),
                "QEMU collector default",
            ),
        ),
        (
            "milkv-collector-default-on",
            lambda data: mutate_bytes(
                data,
                "milkv_manifest",
                b'default = ["milkv-ssh"]',
                f'default = ["milkv-ssh", "{FEATURE}"]'.encode(),
                "Milk-V collector default",
            ),
        ),
        (
            "kernel-audit-sha-defaults",
            lambda data: mutate_bytes(
                data,
                "kernel_manifest",
                b'sha2 = { version = "=0.11.0", default-features = false, optional = true }',
                b'sha2 = { version = "=0.11.0", default-features = true, optional = true }',
                "kernel audit sha2 defaults",
            ),
        ),
        (
            "qemu-only-guard-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    feature = "{QEMU_FEATURE}",\n    not(feature = "qemu-virt")',
                f'    feature = "{QEMU_FEATURE}",\n    not(feature = "milkv-duo")',
                "collector QEMU-only guard",
            ),
        ),
        (
            "formal-qemu-only-guard-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'#[cfg(all(feature = "{QEMU_DECISION_FEATURE}", not(feature = "qemu-virt")))]',
                f'#[cfg(all(feature = "{QEMU_DECISION_FEATURE}", feature = "qemu-virt"))]',
                "formal QEMU-only guard",
            ),
        ),
        (
            "formal-qemu-milkv-guard-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'#[cfg(all(feature = "{QEMU_DECISION_FEATURE}", feature = "milkv-duo"))]',
                f'#[cfg(all(feature = "{QEMU_DECISION_FEATURE}", not(feature = "milkv-duo")))]',
                "formal QEMU Milk-V exclusion",
            ),
        ),
        (
            "smoke-qemu-layer-guard-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    feature = "{QEMU_DECISION_SMOKE_FEATURE}",\n    not(feature = "{QEMU_DECISION_FEATURE}")',
                f'    feature = "{QEMU_DECISION_SMOKE_FEATURE}",\n    not(feature = "qemu-virt")',
                "dirty-smoke formal layer guard",
            ),
        ),
        (
            "formal-absorbing-mutual-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    feature = "{QEMU_DECISION_FEATURE}",\n    feature = "{QEMU_FEATURE}"',
                f'    feature = "{QEMU_DECISION_FEATURE}",\n    feature = "{FEATURE}"',
                "formal/absorbing mutual exclusion",
            ),
        ),
        (
            "physical-qemu-guard-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    feature = "{FEATURE}",\n    feature = "qemu-virt",\n    not(any(\n        feature = "{QEMU_FEATURE}",\n        feature = "{QEMU_DECISION_FEATURE}"\n    ))',
                f'    feature = "{FEATURE}",\n    feature = "qemu-virt",\n    not(any(\n        feature = "qemu-virt",\n        feature = "{QEMU_DECISION_FEATURE}"\n    ))',
                "physical QEMU guard",
            ),
        ),
        (
            "physical-qemu-exemption-widened",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    not(any(\n        feature = "{QEMU_FEATURE}",\n        feature = "{QEMU_DECISION_FEATURE}"\n    ))\n))]\ncompile_error!(\n    "feature `{FEATURE}` cannot expose physical formal records on QEMU"',
                f'    not(any(\n        feature = "{QEMU_FEATURE}",\n        feature = "{FINISH_QEMU_FEATURE}"\n    ))\n))]\ncompile_error!(\n    "feature `{FEATURE}` cannot expose physical formal records on QEMU"',
                "physical QEMU exemption width",
            ),
        ),
        (
            "physical-platform-guard-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'        feature = "milkv-duo",\n        feature = "{QEMU_FEATURE}"',
                f'        feature = "qemu-virt",\n        feature = "{QEMU_FEATURE}"',
                "physical platform guard",
            ),
        ),
        (
            "collector-legacy-shell-enabled",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    feature = "{FEATURE}",\n    feature = "legacy-shell"',
                f'    feature = "{FEATURE}",\n    feature = "nonexistent-shell"',
                "collector legacy shell exclusion",
            ),
        ),
        (
            "collector-finish-pairing-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    feature = "{FEATURE}",\n    feature = "{FINISH_QEMU_FEATURE}",\n    not(any(\n        feature = "{QEMU_FEATURE}",\n        feature = "{QEMU_DECISION_FEATURE}"\n    ))',
                f'    feature = "{FEATURE}",\n    feature = "{FINISH_QEMU_FEATURE}",\n    not(any(\n        feature = "{FINISH_QEMU_FEATURE}",\n        feature = "{QEMU_DECISION_FEATURE}"\n    ))',
                "collector finish pairing guard",
            ),
        ),
        (
            "collector-verified-stream-coenabled",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    feature = "{FEATURE}",\n    feature = "wasm-c84-ssh-managed-child-verified-stream"',
                f'    feature = "{FEATURE}",\n    feature = "wasm-c84-ssh-managed-child-verified-stream-disabled"',
                "collector consumer mutual exclusion",
            ),
        ),
        ("peer-selftest-weakened", lambda data: mutate_bytes(data, "peer_script", b'raise DriverError(f"success selftest mutation was accepted: {label}")', b"return", "peer mutation guard")),
        (
            "peer-log-bound-raised",
            lambda data: mutate_bytes(
                data,
                "peer_script",
                b"MAX_QEMU_LOG_BYTES = 16 * 1024 * 1024",
                b"MAX_QEMU_LOG_BYTES = 32 * 1024 * 1024",
                "peer log bound",
            ),
        ),
        (
            "peer-meta-bytes-drift",
            lambda data: mutate_bytes(
                data,
                "peer_script",
                b"EXPECTED_META_BYTES = 1157",
                b"EXPECTED_META_BYTES = 1158",
                "peer META bytes",
            ),
        ),
        (
            "peer-meta-digest-drift",
            lambda data: mutate_bytes(
                data,
                "peer_script",
                b'EXPECTED_META_SHA256 = "6d46aa52ca9155cfed4eae230a00175f4247d950a8a686a8bdb3657dc6954b4b"',
                b'EXPECTED_META_SHA256 = "0d46aa52ca9155cfed4eae230a00175f4247d950a8a686a8bdb3657dc6954b4b"',
                "peer META digest",
            ),
        ),
        (
            "peer-stable-reader-follows-symlink",
            lambda data: mutate_bytes(
                data,
                "peer_script",
                b'def stable_regular_file_bytes(path: Path) -> bytes:\n    """Read one immutable regular-file snapshot without following a symlink."""',
                b'def stable_regular_file_bytes(path: Path) -> bytes:\n    """Read one mutable path while following a symlink."""',
                "peer stable reader contract",
            ),
        ),
        (
            "peer-live-reader-no-nofollow",
            lambda data: mutate_bytes(
                data,
                "peer_script",
                b'def live_regular_file_bytes(path: Path) -> bytes:\n    """Read one bounded append-in-progress UART snapshot without symlinks."""\n\n    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)',
                b'def live_regular_file_bytes(path: Path) -> bytes:\n    """Read one bounded append-in-progress UART snapshot without symlinks."""\n\n    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)',
                "peer live O_NOFOLLOW",
            ),
        ),
        (
            "peer-digest-distinctness-weakened",
            lambda data: mutate_bytes(
                data,
                "peer_script",
                b"len(set(record_digests)) == len(record_digests)",
                b"len(set(record_digests)) >= 1",
                "peer digest distinctness",
            ),
        ),
        ("qemu-early-success", lambda data: mutate_bytes(data, "qemu_script", b"set -eu\n", b"set -eu\nexit 0\n", "QEMU early success")),
        ("qemu-ignore-failure", lambda data: mutate_bytes(data, "qemu_script", COMMAND.encode(), COMMAND.encode() + b" || true", "QEMU failure bypass")),
        (
            "qemu-same-boot-log",
            lambda data: mutate_bytes(
                data,
                "qemu_script",
                b'SUCCESS_QEMU_LOG="$TEST_TMP/success-qemu.log"',
                b'SUCCESS_QEMU_LOG="$TEST_TMP/failure-qemu.log"',
                "QEMU boot log alias",
            ),
        ),
        (
            "qemu-second-boot-omitted",
            lambda data: mutate_bytes(
                data,
                "qemu_script",
                b'start_qemu "$SUCCESS_QEMU_LOG" "$SUCCESS_PORT"',
                b': # second QEMU boot omitted',
                "QEMU second boot",
            ),
        ),
        (
            "qemu-boot-logs-concatenated",
            lambda data: mutate_bytes(
                data,
                "qemu_script",
                b'freeze_and_verify_boot success "$SUCCESS_QEMU_LOG"',
                b'cat "$FAILURE_QEMU_LOG" >>"$SUCCESS_QEMU_LOG"\nfreeze_and_verify_boot success "$SUCCESS_QEMU_LOG"',
                "QEMU boot log concatenation",
            ),
        ),
        (
            "qemu-formal-scan-removed",
            lambda data: mutate_bytes(
                data,
                "qemu_script",
                b"for prefix in 'VIBE_WASM_AOT_META ' 'VIBE_WASM_AOT_SAMPLE ' 'VIBE_WASM_AOT_END '; do",
                b"for prefix in 'UNRELATED_PREFIX '; do",
                "QEMU formal prefix scan",
            ),
        ),
        (
            "qemu-failed-terminal-misclassified",
            lambda data: mutate_bytes(
                data,
                "qemu_script",
                b"WASM_[A-Z0-9_]+ FAIL([[:space:]]|$)|",
                b"WASM_[A-Z0-9_]+ FAIL|",
                "QEMU FAIL versus FAILED scan boundary",
            ),
        ),
        (
            "qemu-pair-reuses-failure-log",
            lambda data: mutate_bytes(
                data,
                "qemu_script",
                b'--verify-pair --failure-log "$FAILURE_QEMU_LOG" --success-log "$SUCCESS_QEMU_LOG"',
                b'--verify-pair --failure-log "$FAILURE_QEMU_LOG" --success-log "$FAILURE_QEMU_LOG"',
                "QEMU pair log identity",
            ),
        ),
        (
            "qemu-physical-feature",
            lambda data: mutate_bytes(
                data,
                "qemu_script",
                f"FEATURE={QEMU_FEATURE}".encode(),
                f"FEATURE={FEATURE}".encode(),
                "QEMU physical feature",
            ),
        ),
        (
            "qemu-zero-source-binding",
            lambda data: mutate_bytes(
                data,
                "qemu_script",
                b"SOURCE_SENTINEL=1111111111111111111111111111111111111111",
                b"SOURCE_SENTINEL=0000000000000000000000000000000000000000",
                "QEMU zero source",
            ),
        ),
        (
            "milkv-source-verifier-materializes",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'  python3 -B "$script_dir/c84-source-materialization.py" verify \\\n',
                b'  python3 -B "$script_dir/c84-source-materialization.py" materialize \\\n',
                "Milk-V frozen-source verifier mode",
            ),
        ),
        (
            "milkv-source-verifier-override",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                milkv_source_verifier,
                milkv_source_verifier
                + b'''\n\nverify_wasm_aot_profile_source() {
  :
}''',
                "Milk-V frozen-source verifier override",
            ),
        ),
        (
            "milkv-source-verifier-comment-decoy",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                milkv_source_verifier,
                milkv_source_verifier + b"\n# verify_wasm_aot_profile_source",
                "Milk-V frozen-source verifier comment decoy",
            ),
        ),
        (
            "milkv-source-verifier-string-decoy",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                milkv_source_verifier,
                milkv_source_verifier
                + b"\nsource_verifier_decoy='verify_wasm_aot_profile_source'",
                "Milk-V frozen-source verifier string decoy",
            ),
        ),
        (
            "milkv-source-verifier-destination-unbound",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'    --destination "$repo_root" \\\n',
                b'    --destination "$repo_root/target" \\\n',
                "Milk-V frozen-source verifier destination",
            ),
        ),
        (
            "milkv-fail-fast-disabled",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b"set -eu\n",
                b"set -eu\nset +e\n",
                "Milk-V fail-fast option continuity",
            ),
        ),
        (
            "milkv-formal-early-success",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''    2222222222222222222222222222222222222222222222222222222222222222
  wasm_aot_profile_source_commit=$VIBEOS_C84_SOURCE_COMMIT''',
                b'''    2222222222222222222222222222222222222222222222222222222222222222
  if [ "$wasm_aot_profile" = true ]; then
    exit 0
  fi
  wasm_aot_profile_source_commit=$VIBEOS_C84_SOURCE_COMMIT''',
                "Milk-V formal early success",
            ),
        ),
        (
            "milkv-prebuild-source-gate-removed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''  wasm_aot_profile_source_commit=$VIBEOS_C84_SOURCE_COMMIT
  wasm_aot_profile_challenge=$VIBEOS_C84_CHALLENGE
  verify_wasm_aot_profile_source
  wasm_aot_profile_source_envelope=''',
                b'''  wasm_aot_profile_source_commit=$VIBEOS_C84_SOURCE_COMMIT
  wasm_aot_profile_challenge=$VIBEOS_C84_CHALLENGE
  : # frozen-source pre-build gate bypassed
  wasm_aot_profile_source_envelope=''',
                "Milk-V pre-build frozen-source gate",
            ),
        ),
        (
            "milkv-ambient-environment-inherited",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'  elif [ "$wasm_aot_profile" = true ]; then\n    env -i \\\n      PATH="$wasm_aot_profile_build_path"',
                b'  elif [ "$wasm_aot_profile" = true ]; then\n    env \\\n      PATH="$wasm_aot_profile_build_path"',
                "Milk-V closed Cargo environment",
            ),
        ),
        (
            "milkv-ambient-cargo-home-restored",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'      CARGO_HOME="$wasm_aot_profile_cargo_home_sandbox" \\\n',
                b'      CARGO_HOME="$wasm_aot_profile_cache_cargo_home" \\\n',
                "Milk-V isolated Cargo home",
            ),
        ),
        (
            "milkv-rustflags-admitted",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'      RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \\\n      CARGO_TARGET_DIR="$wasm_aot_profile_target_dir"',
                b'      RUSTC="$pinned_rustc" RUSTDOC="$pinned_rustdoc" \\\n      RUSTFLAGS="$RUSTFLAGS" \\\n      CARGO_TARGET_DIR="$wasm_aot_profile_target_dir"',
                "Milk-V Rust flags whitelist",
            ),
        ),
        (
            "milkv-objcopy-ambient-environment",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'elif [ "$wasm_aot_profile" = true ]; then\n  wasm_aot_profile_objcopy_os=$(uname -s)\n  if [ "$wasm_aot_profile_objcopy_os" = Darwin ]; then\n    env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC',
                b'elif [ "$wasm_aot_profile" = true ]; then\n  wasm_aot_profile_objcopy_os=$(uname -s)\n  if [ "$wasm_aot_profile_objcopy_os" = Darwin ]; then\n    env PATH=/usr/bin:/bin LC_ALL=C TZ=UTC',
                "Milk-V isolated objcopy",
            ),
        ),
        (
            "milkv-cargo-home-cleanup-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'rm -rf -- "$wasm_aot_profile_cargo_home_sandbox"',
                b": # isolated Cargo home retained",
                "Milk-V Cargo home cleanup",
            ),
        ),
        ("milkv-online-build", lambda data: mutate_bytes(data, "milkv_build_script", b"        --release --locked --offline \\\n        --no-default-features --features", b"        --release --locked \\\n        --no-default-features --features", "Milk-V offline build")),
        ("milkv-shared-target", lambda data: mutate_bytes(data, "milkv_build_script", b'CARGO_TARGET_DIR="$wasm_aot_profile_target_dir"', b'CARGO_TARGET_DIR="$repo_root/target"', "Milk-V isolated target")),
        ("milkv-incremental", lambda data: mutate_bytes(data, "milkv_build_script", b'CARGO_TARGET_DIR="$wasm_aot_profile_target_dir" \\\n      CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true', b'CARGO_TARGET_DIR="$wasm_aot_profile_target_dir" \\\n      CARGO_INCREMENTAL=1 CARGO_NET_OFFLINE=true', "Milk-V incremental build")),
        ("milkv-qemu-sentinel-allowed", lambda data: mutate_bytes(data, "milkv_build_script", b'if [ "$identity_value" = "$test_value" ]; then', b"if false; then", "Milk-V QEMU sentinel")),
        ("milkv-artifact-binding-removed", lambda data: mutate_bytes(data, "milkv_build_script", b'grep -a -F -q "$wasm_aot_profile_source_commit" "$artifact"', b"true", "Milk-V artifact binding")),
        (
            "milkv-unlocked-build",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b"        --release --locked --offline \\\n        --no-default-features --features",
                b"        --release --offline \\\n        --no-default-features --features",
                "Milk-V locked build",
            ),
        ),
        (
            "milkv-challenge-not-passed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'      VIBEOS_C84_CHALLENGE="$wasm_aot_profile_challenge" \\\n      RUSTC=',
                b"      RUSTC=",
                "Milk-V challenge cargo binding",
            ),
        ),
        (
            "milkv-source-not-passed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'      VIBEOS_C84_SOURCE_COMMIT="$wasm_aot_profile_source_commit" \\\n      VIBEOS_C84_CHALLENGE=',
                b"      VIBEOS_C84_CHALLENGE=",
                "Milk-V source cargo binding",
            ),
        ),
        (
            "milkv-target-omits-challenge",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'wasm_aot_profile_target_dir="$repo_root/target/c84-milkv-build/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge"',
                b'wasm_aot_profile_target_dir="$repo_root/target/c84-milkv-build/$wasm_aot_profile_source_commit"',
                "Milk-V target challenge",
            ),
        ),
        (
            "milkv-post-cargo-source-gate-removed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''if [ "$wasm_aot_profile" = true ]; then
  verify_wasm_aot_profile_source
fi

mkdir -p "$output_dir"''',
                b'''if [ "$wasm_aot_profile" = true ]; then
  : # post-Cargo frozen-source gate bypassed
fi

mkdir -p "$output_dir"''',
                "Milk-V post-Cargo frozen-source gate",
            ),
        ),
        (
            "milkv-pre-closure-source-gate-removed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''  mv "$wasm_aot_profile_temp_envelope" "$wasm_aot_profile_build_envelope"
  verify_wasm_aot_profile_source
  python3 - "$wasm_aot_profile_build_envelope" \\''',
                b'''  mv "$wasm_aot_profile_temp_envelope" "$wasm_aot_profile_build_envelope"
  : # pre-closure frozen-source gate bypassed
  python3 - "$wasm_aot_profile_build_envelope" \\''',
                "Milk-V pre-closure frozen-source gate",
            ),
        ),
        (
            "milkv-only-elf-bound",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'for artifact in "$output_elf" "$output_bin"; do',
                b'for artifact in "$output_elf"; do',
                "Milk-V ELF/BIN binding",
            ),
        ),
        (
            "milkv-challenge-artifact-unbound",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'grep -a -F -q "$wasm_aot_profile_challenge" "$artifact"',
                b"true",
                "Milk-V challenge artifact binding",
            ),
        ),
        (
            "milkv-output-collides",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'output_dir="$repo_root/target/milkv-duo-wasm-aot-profile"',
                b'output_dir="$repo_root/target/milkv-duo"',
                "Milk-V collector output isolation",
            ),
        ),
        (
            "milkv-stage-cleanup-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'rm -f -- "$staged_path"',
                b": # staged failure artifacts retained",
                "Milk-V staging failure cleanup",
            ),
        ),
        (
            "milkv-stage-cleanup-broadened",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'"$repo_root/target/.milkv-duo-wasm-aot-profile.stage.$wasm_aot_profile_source_commit.$wasm_aot_profile_challenge")',
                b'"$repo_root/target"/*)',
                "Milk-V narrow staging cleanup",
            ),
        ),
        (
            "milkv-exit-cleanup-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b"trap cleanup_build EXIT",
                b"trap cleanup_runtime_costs_build EXIT",
                "Milk-V EXIT cleanup",
            ),
        ),
        (
            "milkv-exit-trap-overridden",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b"trap cleanup_build EXIT\ntrap 'exit 129' HUP",
                b'''trap cleanup_build EXIT
trap "exit 0" EXIT
trap 'exit 129' HUP''',
                "Milk-V unique EXIT trap",
            ),
        ),
        (
            "milkv-sdk-positional-accepted",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'if [ "$wasm_aot_profile" = true ] && [ -n "$sdk_arg" ]; then',
                b"if false; then",
                "Milk-V exclusive SDK packaging ownership",
            ),
        ),
        (
            "milkv-target-clobber-restored",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'if [ -e "$wasm_aot_profile_target_dir" ] || [ -L "$wasm_aot_profile_target_dir" ]; then\n    echo "build-milkv-duo.sh: WebAssembly AOT profile target is no-clobber:',
                b'if false; then\n    echo "build-milkv-duo.sh: WebAssembly AOT profile target is no-clobber:',
                "Milk-V identity target no-clobber gate",
            ),
        ),
        (
            "milkv-stage-no-clobber-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'! mkdir "$wasm_aot_profile_stage_dir"; then',
                b'mkdir -p "$wasm_aot_profile_stage_dir"; then',
                "Milk-V staging no-clobber gate",
            ),
        ),
        (
            "milkv-staging-omits-challenge",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'wasm_aot_profile_stage_dir="$repo_root/target/.milkv-duo-wasm-aot-profile.stage.$wasm_aot_profile_source_commit.$wasm_aot_profile_challenge"',
                b'wasm_aot_profile_stage_dir="$repo_root/target/.milkv-duo-wasm-aot-profile.stage.$wasm_aot_profile_source_commit"',
                "Milk-V identity-keyed staging",
            ),
        ),
        (
            "milkv-staging-writes-fixed-output",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b"  output_dir=$wasm_aot_profile_stage_dir\n",
                b"  output_dir=$wasm_aot_profile_publish_dir\n",
                "Milk-V private staging selection",
            ),
        ),
        (
            "milkv-envelope-source-root-absolute",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'        "root": ".",',
                b'        "root": str(source_root_path),',
                "Milk-V portable build source role",
            ),
        ),
        (
            "milkv-envelope-artifact-host-path",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'"kernel_binary": identity(kernel_bin, require_build_identity=True, repository_input=True)',
                b'"kernel_binary": identity(kernel_bin, require_build_identity=True)',
                "Milk-V portable artifact role",
            ),
        ),
        (
            "milkv-toolchain-provenance-removed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'    "provenance": "build-runner-self-measured; package cross-platform live rehash unavailable",\n',
                b"",
                "Milk-V build-runner tool provenance",
            ),
        ),
        (
            "milkv-timestamp-order-genericized",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'for name, value in zip(("build_started", "build_completed", "envelope_closed"), timestamp_values):',
                b"for name, value in zip(sorted((\"build_started\", \"build_completed\", \"envelope_closed\")), timestamp_values):",
                "Milk-V semantic timestamp order",
            ),
        ),
        (
            "milkv-source-envelope-path-omits-challenge",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'wasm_aot_profile_source_envelope="$repo_root/target/c84-source-materialization/$wasm_aot_profile_source_commit/$wasm_aot_profile_challenge/source-materialization-envelope.json"',
                b'wasm_aot_profile_source_envelope="$repo_root/target/c84-source-materialization/$wasm_aot_profile_source_commit/source-materialization-envelope.json"',
                "Milk-V source-envelope challenge path",
            ),
        ),
        (
            "milkv-envelope-materialization-omitted",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'        "materialization": source_materialization,',
                b'        "materialization": source_materialization["content"],',
                "Milk-V embedded source materialization",
            ),
        ),
        (
            "milkv-final-source-gate-wrapper-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''print("build-milkv-duo.sh C8.4 build closure rehash: PASS")
PY
  verify_wasm_aot_profile_source
  if [ -e "$wasm_aot_profile_publish_dir" ] || [ -L "$wasm_aot_profile_publish_dir" ]; then''',
                b'''print("build-milkv-duo.sh C8.4 build closure rehash: PASS")
PY
  if false; then
    verify_wasm_aot_profile_source
  fi
  if [ -e "$wasm_aot_profile_publish_dir" ] || [ -L "$wasm_aot_profile_publish_dir" ]; then''',
                "Milk-V pre-publication frozen-source gate wrapper",
            ),
        ),
        (
            "milkv-build-envelope-version-regressed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'    "version": 2,\n',
                b'    "version": 1,\n',
                "Milk-V build-envelope v2",
            ),
        ),
        (
            "milkv-source-materializer-tool-swapped",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'    "source_materializer_script": identity(source_materializer_script, repository_input=True),',
                b'    "source_materializer_script": identity(jitterentropy_patch, repository_input=True),',
                "Milk-V source-materializer tool identity",
            ),
        ),
        (
            "milkv-source-envelope-single-link-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''before = expected.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > 16_777_216
        or before.st_nlink != 1''',
                b'''before = expected.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > 16_777_216
        or False''',
                "Milk-V source-envelope single-link gate",
            ),
        ),
        (
            "milkv-source-envelope-lstat-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b"before = expected.lstat()",
                b"before = expected.stat()",
                "Milk-V source-envelope lstat snapshot",
            ),
        ),
        (
            "milkv-source-envelope-identity-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''    if content.get("source_commit") != source_commit or content.get("challenge") != challenge:
        fail("source materialization identity differs")''',
                b'''    if False:
        fail("source materialization identity differs")''',
                "Milk-V source-envelope identity gate",
            ),
        ),
        (
            "milkv-closure-source-content-opened",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b"if not isinstance(materialization_content, dict) or set(materialization_content) != {",
                b"if not isinstance(materialization_content, dict) or set(materialization_content) >= {",
                "Milk-V closure source-envelope content keys",
            ),
        ),
        (
            "milkv-closure-early-success",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''source_root_path = pathlib.Path(sys.argv[4]).resolve(strict=True)


def fail(message):''',
                b'''source_root_path = pathlib.Path(sys.argv[4]).resolve(strict=True)
raise SystemExit(0)


def fail(message):''',
                "Milk-V closure Python early success",
            ),
        ),
        (
            "milkv-closure-fail-success",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''raise SystemExit(f"build-milkv-duo.sh: C8.4 closure rehash failed: {message}")''',
                b"raise SystemExit(0)",
                "Milk-V closure failure success status",
            ),
        ),
        (
            "milkv-closure-source-identity-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''    if (
        materialization_content.get("source_commit") != source_commit
        or materialization_content.get("challenge") != challenge
    ):
        fail("source materialization identity differs")''',
                b'''    if False:
        fail("source materialization identity differs")''',
                "Milk-V closure source-envelope identity",
            ),
        ),
        (
            "milkv-source-envelope-canonical-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''    if raw != canonical_root:
        fail("source materialization envelope is not canonical JSON")
    return root


artifacts = {''',
                b'''    if False:
        fail("source materialization envelope is not canonical JSON")
    return root


artifacts = {''',
                "Milk-V source-envelope canonical encoding",
            ),
        ),
        (
            "milkv-closure-materialization-equality-bypassed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''if source["materialization"] != load_source_materialization(source_materialization_path):
    fail("embedded source materialization envelope differs from the live closure")''',
                b'''if False:
    fail("embedded source materialization envelope differs from the live closure")''',
                "Milk-V live source-materialization equality",
            ),
        ),
        (
            "milkv-nonatomic-publication",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'if system == "Linux" and hasattr(libc, "renameat2"):',
                b'if system == "Linux" and False:',
                "Milk-V Linux atomic no-replace publication",
            ),
        ),
        (
            "milkv-darwin-noreplace-removed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'elif system == "Darwin" and hasattr(libc, "renamex_np"):',
                b'elif system == "Darwin" and False:',
                "Milk-V Darwin atomic no-replace publication",
            ),
        ),
        (
            "milkv-publication-before-postchecks",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'  for artifact in "$output_elf" "$output_bin"; do',
                b'  mv -- "$wasm_aot_profile_stage_dir" "$wasm_aot_profile_publish_dir"\n'
                b'  for artifact in "$output_elf" "$output_bin"; do',
                "Milk-V postcheck/publication order",
            ),
        ),
        (
            "milkv-staging-path-printed",
            lambda data: mutate_bytes(
                data,
                "milkv_build_script",
                b'''if [ "$wasm_aot_profile" = false ]; then
  echo "Milk-V Duo ELF: $output_elf"
  echo "Milk-V Duo binary: $output_bin"
fi''',
                b'''echo "Milk-V Duo ELF: $output_elf"
echo "Milk-V Duo binary: $output_bin"''',
                "Milk-V deferred publication path",
            ),
        ),
        ("ci-source-disabled", lambda data: mutate_text(data, "ci", "      - name: Verify the C8.4 private single-boot collector\n        run:", "      - name: Verify the C8.4 private single-boot collector\n        if: ${{ false }}\n        run:", "CI source disabled")),
        ("ci-peer-disabled", lambda data: mutate_text(data, "ci", "      - name: Test the C8.4 single-boot collector transcript parser\n        run:", "      - name: Test the C8.4 single-boot collector transcript parser\n        if: ${{ false }}\n        run:", "CI peer disabled")),
        ("ci-qemu-disabled", lambda data: mutate_text(data, "ci", "      - name: Exercise the C8.4 private single-boot collector closure\n        run:", "      - name: Exercise the C8.4 private single-boot collector closure\n        if: ${{ false }}\n        run:", "CI QEMU disabled")),
        ("ci-source-ignored", lambda data: mutate_text(data, "ci", f"        run: {COMMAND}\n", f"        run: {COMMAND} || true\n", "CI source ignored")),
        ("ci-peer-ignored", lambda data: mutate_text(data, "ci", f"        run: {PEER_COMMAND}\n", f"        run: {PEER_COMMAND} || true\n", "CI peer ignored")),
        ("ci-qemu-ignored", lambda data: mutate_text(data, "ci", f"        run: {QEMU_COMMAND}\n", f"        run: {QEMU_COMMAND} || true\n", "CI QEMU ignored")),
        (
            "ci-host-job-continue-on-error",
            lambda data: mutate_text(
                data,
                "ci",
                ci_host_checkout,
                ci_host_checkout.replace(
                    "    runs-on: ubuntu-24.04\n    steps:",
                    "    runs-on: ubuntu-24.04\n    continue-on-error: true\n    steps:",
                ),
                "CI host job continue-on-error bypass",
            ),
        ),
        (
            "ci-host-job-if-false",
            lambda data: mutate_text(
                data,
                "ci",
                ci_host_checkout,
                ci_host_checkout.replace(
                    "    runs-on: ubuntu-24.04\n    steps:",
                    "    runs-on: ubuntu-24.04\n    if: false\n    steps:",
                ),
                "CI host job if:false bypass",
            ),
        ),
        (
            "ci-qemu-job-continue-on-error",
            lambda data: mutate_text(
                data,
                "ci",
                ci_qemu_checkout,
                ci_qemu_checkout.replace(
                    "    runs-on: ubuntu-24.04\n    steps:",
                    "    runs-on: ubuntu-24.04\n    continue-on-error: true\n    steps:",
                ),
                "CI QEMU job continue-on-error bypass",
            ),
        ),
        (
            "ci-qemu-job-if-false",
            lambda data: mutate_text(
                data,
                "ci",
                ci_qemu_checkout,
                ci_qemu_checkout.replace(
                    "    runs-on: ubuntu-24.04\n    steps:",
                    "    runs-on: ubuntu-24.04\n    if: false\n    steps:",
                ),
                "CI QEMU job if:false bypass",
            ),
        ),
        (
            "ci-host-second-checkout",
            lambda data: mutate_text(
                data,
                "ci",
                ci_host_checkout,
                ci_host_checkout.replace(
                    "      - name: Install repository toolchain",
                    '''      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          ref: main
      - name: Install repository toolchain''',
                ),
                "CI host second checkout",
            ),
        ),
        (
            "ci-qemu-second-checkout",
            lambda data: mutate_text(
                data,
                "ci",
                ci_qemu_checkout,
                ci_qemu_checkout.replace(
                    "      - name: Install repository toolchain",
                    '''      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          ref: main
      - name: Install repository toolchain''',
                ),
                "CI QEMU second checkout",
            ),
        ),
        (
            "ci-host-git-checkout",
            lambda data: mutate_text(
                data,
                "ci",
                ci_host_checkout,
                ci_host_checkout.replace(
                    "      - name: Install repository toolchain",
                    '''      - name: Mutate the protected host ref
        run: git checkout main
      - name: Install repository toolchain''',
                ),
                "CI host Git checkout",
            ),
        ),
        (
            "ci-qemu-git-checkout",
            lambda data: mutate_text(
                data,
                "ci",
                ci_qemu_checkout,
                ci_qemu_checkout.replace(
                    "      - name: Install repository toolchain",
                    '''      - name: Mutate the protected QEMU ref
        run: git checkout main
      - name: Install repository toolchain''',
                ),
                "CI QEMU Git checkout",
            ),
        ),
        (
            "ci-host-checkout-shallow",
            lambda data: mutate_text(
                data,
                "ci",
                ci_host_checkout,
                ci_host_checkout.replace("          fetch-depth: 0", "          fetch-depth: 1"),
                "CI host full-depth checkout",
            ),
        ),
        (
            "ci-host-checkout-persists-credentials",
            lambda data: mutate_text(
                data,
                "ci",
                ci_host_checkout,
                ci_host_checkout.replace(
                    "          persist-credentials: false",
                    "          persist-credentials: true",
                ),
                "CI host credential-free checkout",
            ),
        ),
        (
            "ci-qemu-checkout-shallow",
            lambda data: mutate_text(
                data,
                "ci",
                ci_qemu_checkout,
                ci_qemu_checkout.replace("          fetch-depth: 0", "          fetch-depth: 1"),
                "CI QEMU full-depth checkout",
            ),
        ),
        (
            "ci-qemu-checkout-persists-credentials",
            lambda data: mutate_text(
                data,
                "ci",
                ci_qemu_checkout,
                ci_qemu_checkout.replace(
                    "          persist-credentials: false",
                    "          persist-credentials: true",
                ),
                "CI QEMU credential-free checkout",
            ),
        ),
        (
            "ci-host-source-materializer-selftest-removed",
            lambda data: mutate_text(
                data,
                "ci",
                "          python3 -B scripts/c84-source-materialization.py --selftest --check-source",
                "          python3 -B scripts/c84-source-materialization.py --check-source",
                "CI host source-materializer selftest",
            ),
        ),
        (
            "ci-physical-disabled",
            lambda data: mutate_text(
                data,
                "ci",
                "      - name: Type/link-check the C8.4 physical single-boot collector\n        run: |",
                "      - name: Type/link-check the C8.4 physical single-boot collector\n        if: ${{ false }}\n        run: |",
                "CI physical disabled",
            ),
        ),
        (
            "ci-physical-fixed-challenge",
            lambda data: mutate_text(
                data,
                "ci",
                '          challenge="$(openssl rand -hex 32)"',
                "          challenge=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "CI fresh physical challenge",
            ),
        ),
        (
            "ci-physical-live-head-self-binding",
            lambda data: mutate_text(
                data,
                "ci",
                '''          source_commit="$GITHUB_SHA"
          test "$(git rev-parse HEAD)" = "$source_commit"''',
                '          source_commit="$(git rev-parse HEAD)"',
                "CI physical workflow-SHA binding",
            ),
        ),
        (
            "ci-physical-head-equality-bypassed",
            lambda data: mutate_text(
                data,
                "ci",
                '          test "$(git rev-parse HEAD)" = "$source_commit"',
                "          true # live HEAD equality bypassed",
                "CI physical live-HEAD equality",
            ),
        ),
        (
            "ci-physical-materialization-bypassed",
            lambda data: mutate_text(
                data,
                "ci",
                "          python3 -B scripts/c84-source-materialization.py materialize \\\n",
                "          true \\\n",
                "CI physical source materialization",
            ),
        ),
        (
            "ci-physical-materialization-destination-unbound",
            lambda data: mutate_text(
                data,
                "ci",
                '            --destination "$frozen" \\\n',
                '            --destination "$GITHUB_WORKSPACE" \\\n',
                "CI physical frozen destination",
            ),
        ),
        (
            "ci-physical-materialization-source-unbound",
            lambda data: mutate_text(
                data,
                "ci",
                '            --source-commit "$source_commit" \\\n',
                "            --source-commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\\n",
                "CI physical materialization source identity",
            ),
        ),
        (
            "ci-physical-materialization-challenge-unbound",
            lambda data: mutate_text(
                data,
                "ci",
                '            --challenge "$challenge"',
                "            --challenge aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "CI physical materialization challenge identity",
            ),
        ),
        (
            "ci-physical-build-outside-frozen-source",
            lambda data: mutate_text(
                data,
                "ci",
                '          cd "$frozen"',
                '          cd "$GITHUB_WORKSPACE"',
                "CI physical frozen build root",
            ),
        ),
        (
            "ci-physical-hostile-env-proof-removed",
            lambda data: mutate_text(
                data,
                "ci",
                '          RUSTC_WRAPPER="$(command -v false)" \\\n',
                "",
                "CI hostile ambient build proof",
            ),
        ),
        (
            "ci-physical-source-unbound",
            lambda data: mutate_text(
                data,
                "ci",
                '          VIBEOS_C84_SOURCE_COMMIT="$source_commit" \\',
                "          VIBEOS_C84_SOURCE_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\",
                "CI physical build source binding",
            ),
        ),
        (
            "ci-physical-challenge-unbound",
            lambda data: mutate_text(
                data,
                "ci",
                '          VIBEOS_C84_CHALLENGE="$challenge" \\',
                "          VIBEOS_C84_CHALLENGE=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\",
                "CI physical challenge binding",
            ),
        ),
        (
            "ci-physical-ignored",
            lambda data: mutate_text(
                data,
                "ci",
                "            ./scripts/build-milkv-duo.sh --wasm-aot-profile",
                "            ./scripts/build-milkv-duo.sh --wasm-aot-profile || true",
                "CI physical failure bypass",
            ),
        ),
        (
            "ci-physical-uploads-artifact",
            lambda data: mutate_text(
                data,
                "ci",
                "            ./scripts/build-milkv-duo.sh --wasm-aot-profile\n      - name: Build the isolated Milk-V Duo C8.3 sampler (CI-only identity)",
                "            ./scripts/build-milkv-duo.sh --wasm-aot-profile\n        uses: actions/upload-artifact@v4\n      - name: Build the isolated Milk-V Duo C8.3 sampler (CI-only identity)",
                "CI physical artifact retention",
            ),
        ),
        (
            "ci-physical-after-c83-build",
            lambda data: swap_text(
                data,
                "ci",
                ci_physical_block,
                ci_c83_build_block,
                "CI physical step order",
            ),
        ),
        (
            "testing-overclaims-ci-evidence",
            lambda data: mutate_text(
                data,
                "testing",
                "It neither runs\nnor retains that artifact.",
                "It runs and retains that artifact.",
                "TESTING CI evidence claim",
            ),
        ),
        (
            "decision-overclaims-ci-evidence",
            lambda data: mutate_text(
                data,
                "decision_doc",
                "They never open a UART; the commands also require no SDK,\n"
                "Docker, network, flash, reset, or physical cold boot and produce no\n"
                "decision-eligible evidence.",
                "They open a UART and produce decision-eligible physical evidence.",
                "decision CI evidence claim",
            ),
        ),
        (
            "roadmap-physical-pause-removed",
            lambda data: mutate_text(
                data,
                "roadmap",
                "Milk-V Duo physical testing is paused at operator request.",
                "Milk-V Duo physical testing is complete.",
                "roadmap operator-paused physical status",
            ),
        ),
        (
            "testing-aot-decision-overclaimed",
            lambda data: mutate_text(
                data,
                "testing",
                "No workload-specific AOT decision\nis claimed yet.",
                "A complete workload-specific AOT decision\nis claimed.",
                "TESTING incomplete AOT decision status",
            ),
        ),
        (
            "decision-synthetic-boundary-removed",
            lambda data: mutate_text(
                data,
                "decision_doc",
                "These self-tests use local synthetic repositories, records, streams, and\n"
                "temporary files.",
                "These self-tests use no synthetic repositories, records, streams, or files.",
                "decision software-only synthetic boundary",
            ),
        ),
        (
            "testing-frozen-build-boundary-removed",
            lambda data: mutate_text(
                data,
                "testing",
                "independently materialized and verified frozen\nsource tree",
                "operator checkout",
                "TESTING frozen build boundary",
            ),
        ),
        (
            "decision-materialization-command-removed",
            lambda data: mutate_text(
                data,
                "decision_doc",
                "python3 -B scripts/c84-source-materialization.py materialize",
                "python3 -B scripts/c84-source-materialization.py verify",
                "decision materialization command",
            ),
        ),
        (
            "roadmap-frozen-source-boundary-removed",
            lambda data: mutate_text(
                data,
                "roadmap",
                "independent frozen-source and build/package envelopes, host-observed Docker\n"
                "runtime closure",
                "operator-source assertion and build/package envelopes, Docker runtime\n"
                "record",
                "roadmap frozen-source/runtime closure",
            ),
        ),
    ]
    for label, mutation in mutations:
        expect_rejected(inputs, mutation, label)
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-source", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()
    if not arguments.check_source and not arguments.selftest:
        parser.error("select --check-source and/or --selftest")
    try:
        inputs = load_inputs()
        mutations = run_selftest(inputs) if arguments.selftest else 0
        if arguments.check_source and not arguments.selftest:
            verify(inputs)
        suffix = f" mutations={mutations}" if arguments.selftest else ""
        print(
            "PASS verify-c84-ssh-managed-child-single-boot-collector: build-bound private "
            "META+24 SAMPLE+END, absorbing physical UART records, exact owner lineage, "
            f"and non-evidence two-boot QEMU audit are closed{suffix}"
        )
        return 0
    except (
        OSError,
        RuntimeError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        VerificationError,
    ) as error:
        print(f"FAIL verify-c84-ssh-managed-child-single-boot-collector: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
