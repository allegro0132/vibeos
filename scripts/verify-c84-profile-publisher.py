#!/usr/bin/env python3
"""Verify the portable C8.4 formal single-SAMPLE publisher foundation."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
STREAM_VERIFIER_PATH = ROOT / "scripts/verify-c84-ssh-managed-child-verified-stream.py"
AOT_VERIFIER_PATH = ROOT / "scripts/verify-c84-aot-decision.py"
CRATE_MANIFEST_PATH = ROOT / "wasm-aot-profile/Cargo.toml"
LIB_PATH = ROOT / "wasm-aot-profile/src/lib.rs"
PUBLISHER_PATH = ROOT / "wasm-aot-profile/src/publisher.rs"
GOLDEN_TEST_PATH = ROOT / "wasm-aot-profile/tests/profile_publisher_golden.rs"
GOLDEN_PATH = ROOT / "wasm-aot-profile/tests/fixtures/publisher-sample-v1.jsonl"
TESTING_PATH = ROOT / "TESTING.md"
DECISION_DOC_PATH = ROOT / "docs/WASM_AOT_DECISION.md"
CI_PATH = ROOT / ".github/workflows/ci.yml"

SAMPLE_PREFIX = b"VIBE_WASM_AOT_SAMPLE "
EXPECTED_PAYLOAD_BYTES = 1_370
EXPECTED_RECORD_BYTES = 1_392
EXPECTED_PAYLOAD_SHA256 = "f6e4ccc1dec079996bbd6715da8589788cf478eb061e59e8e6f933969ee3032c"
EXPECTED_RECORD_SHA256 = "dc0aafe23554862c3941a06440ff404aebf19aaf2ce5358694625beb0bdf8955"
EXPECTED_ZERO_ACCUMULATOR = 0x7B3F_96C2_1D6F_6C20
EXPECTED_PRIOR = 0x0123_4567_89AB_CDEF
EXPECTED_PRIOR_ACCUMULATOR = 0x0CE2_4A87_0336_63A1
EXPECTED_RUN_ID = bytes(range(32)).hex()
EXPECTED_CHALLENGE = bytes(range(32, 64)).hex()
COMMAND = "python3 -B scripts/verify-c84-profile-publisher.py --selftest --check-source"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


STREAM = load_module(STREAM_VERIFIER_PATH, "vibeos_c84_publisher_stream_verifier")
AOT = load_module(AOT_VERIFIER_PATH, "vibeos_c84_publisher_aot_verifier")


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def semantic(value: str) -> str:
    return STREAM.semantic(value)


def comment_masked(value: str) -> str:
    return STREAM.comment_masked(value)


def find_scope(source: str, header: str, label: str):
    try:
        return STREAM.find_scope(source, header, label)
    except Exception as error:
        raise VerificationError(str(error)) from error


def find_function(scope, name: str, label: str):
    try:
        return STREAM.find_function(scope, name, label)
    except Exception as error:
        raise VerificationError(str(error)) from error


def exact_semantic(source: str, snippet: str, label: str, *, count: int = 1) -> None:
    observed = semantic(source).count(semantic(snippet))
    require(observed == count, f"{label} semantic count differs: {observed}")


def ordered_semantic(source: str, snippets: tuple[str, ...], label: str) -> None:
    value = semantic(source)
    positions: list[int] = []
    for snippet in snippets:
        needle = semantic(snippet)
        matches: list[int] = []
        cursor = 0
        while True:
            position = value.find(needle, cursor)
            if position < 0:
                break
            matches.append(position)
            cursor = position + 1
        require(len(matches) == 1, f"{label}: {snippet!r} count differs: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} order differs")


def visible_methods(source: str) -> tuple[str, ...]:
    """Return every method with visibility outside its defining impl."""
    return tuple(
        re.findall(
            r'\bpub(?:\([^)]*\))?\s+(?:(?:const|async|unsafe)\s+|extern(?:\s+"[^"]*")?\s+)*fn\s+([A-Za-z_][A-Za-z0-9_]*)\b',
            comment_masked(source),
        )
    )


def keyword_count(source: str, keyword: str) -> int:
    return len(re.findall(rf"\b{re.escape(keyword)}\b", comment_masked(source)))


def visibility_count(source: str) -> int:
    return len(re.findall(r"\bpub(?:\([^)]*\))?(?=\s)", comment_masked(source)))


@dataclass(frozen=True)
class Inputs:
    predecessor: Any
    cargo_manifest: bytes
    lib: str
    publisher: str
    golden_test: str
    golden: bytes
    testing: str
    decision_doc: str
    ci: str


def load_inputs() -> Inputs:
    return Inputs(
        predecessor=STREAM.load_inputs(),
        cargo_manifest=CRATE_MANIFEST_PATH.read_bytes(),
        lib=LIB_PATH.read_text(encoding="utf-8"),
        publisher=PUBLISHER_PATH.read_text(encoding="utf-8"),
        golden_test=GOLDEN_TEST_PATH.read_text(encoding="utf-8"),
        golden=GOLDEN_PATH.read_bytes(),
        testing=TESTING_PATH.read_text(encoding="utf-8"),
        decision_doc=DECISION_DOC_PATH.read_text(encoding="utf-8"),
        ci=CI_PATH.read_text(encoding="utf-8"),
    )


def verify_contract() -> None:
    try:
        manifest, schema = AOT.load_contract_files()
        AOT.validate_manifest(manifest)
        AOT.validate_schema(schema)
    except Exception as error:
        raise VerificationError(f"frozen AOT contract failed: {error}") from error


def accumulator_from_prior(sample: dict[str, Any], prior: int) -> tuple[int, int]:
    accumulator = prior
    words = [
        AOT.SAMPLE_DOMAIN_WORD,
        sample["sequence"],
        sample["sample_index"],
        int(sample["warmup"]),
        sample["total_ticks"],
        *(sample["phase_ticks"][phase] for phase in AOT.PHASE_IDS),
        sample["interval_capacity"],
        sample["interval_count"],
        int(sample["intervals_complete"]),
    ]
    for interval in sample["intervals"]:
        words.extend(
            (
                AOT.INTERVAL_DOMAIN_WORD,
                interval["sequence"],
                AOT.PHASE_CODES[interval["phase"]],
                interval["start_offset_ticks"],
                interval["end_offset_ticks"],
            )
        )
    words.extend(
        (
            sample["read_chunks"],
            sample["write_chunks"],
            sample["fuel_consumed"],
            sample["poll_quanta"],
            1,
            sample["logical_live_after"],
            int(sample["timed_out"]),
            0,
            sample["exit_status"],
            sample["stdout_bytes"],
            *AOT.stdout_digest_words(sample["stdout_sha256"]),
            sample["stderr_bytes"],
        )
    )
    for word in words:
        accumulator = AOT.fold_word(accumulator, word)
    return accumulator, len(words)


def verify_golden(raw: bytes) -> dict[str, Any]:
    require(len(raw) == EXPECTED_RECORD_BYTES, "publisher golden byte length differs")
    require(b"\r" not in raw, "publisher golden contains CR")
    require(raw.endswith(b"\n") and raw.count(b"\n") == 1, "publisher golden is not one LF line")
    require(raw.startswith(SAMPLE_PREFIX), "publisher golden SAMPLE prefix differs")
    require(raw.count(SAMPLE_PREFIX) == 1, "publisher golden SAMPLE prefix count differs")
    require(b"VIBE_WASM_AOT_META " not in raw, "publisher golden contains META")
    require(b"VIBE_WASM_AOT_END " not in raw, "publisher golden contains END")
    payload = raw[len(SAMPLE_PREFIX) : -1]
    require(len(payload) == EXPECTED_PAYLOAD_BYTES, "publisher golden payload length differs")
    require(hashlib.sha256(payload).hexdigest() == EXPECTED_PAYLOAD_SHA256, "payload SHA-256 differs")
    require(hashlib.sha256(raw).hexdigest() == EXPECTED_RECORD_SHA256, "record SHA-256 differs")
    try:
        sample = AOT.strict_json_bytes(payload, "publisher golden")
    except Exception as error:
        raise VerificationError(f"publisher golden JSON failed: {error}") from error
    require(type(sample) is dict, "publisher golden payload is not an object")
    require(tuple(sample) == tuple(sorted(sample)), "publisher top-level keys are not ASCII sorted")
    require(
        tuple(sample["phase_ticks"]) == tuple(sorted(sample["phase_ticks"])),
        "publisher phase_ticks keys are not ASCII sorted",
    )
    for index, interval in enumerate(sample["intervals"]):
        require(type(interval) is dict, f"publisher interval {index} is not an object")
        require(tuple(interval) == tuple(sorted(interval)), f"publisher interval {index} keys are not ASCII sorted")
    canonical = SAMPLE_PREFIX + json.dumps(
        sample,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    require(raw == canonical, "publisher golden is not recursively canonical compact JSON")
    require(sample["run_id"] == EXPECTED_RUN_ID, "publisher golden run_id differs")
    require(sample["challenge"] == EXPECTED_CHALLENGE, "publisher golden challenge differs")
    try:
        AOT.verify_transcript_sample(
            sample,
            position=3,
            meta={"run_id": EXPECTED_RUN_ID, "challenge": EXPECTED_CHALLENGE},
        )
    except Exception as error:
        raise VerificationError(f"publisher golden schema semantics failed: {error}") from error
    zero, zero_words = accumulator_from_prior(sample, 0)
    prior, prior_words = accumulator_from_prior(sample, EXPECTED_PRIOR)
    require(zero_words == prior_words == 65, "publisher accumulator word count differs")
    require(zero == EXPECTED_ZERO_ACCUMULATOR, "publisher zero-prior accumulator differs")
    require(prior == EXPECTED_PRIOR_ACCUMULATOR, "publisher prior accumulator differs")
    require(AOT.transcript_accumulator([sample]) == zero, "AOT verifier accumulator disagrees")
    return sample


def production_source(source: str) -> str:
    marker = "\n#[cfg(test)]\nmod tests"
    require(source.count(marker) == 1, "publisher cfg(test) module boundary differs")
    production, tests = source.split(marker, 1)
    require("fn public_api_emits_the_frozen_canonical_sample" not in production, "golden test leaked into production")
    require("ProfileAccess for FakeProfile" in tests, "relational fake-profile tests are missing")
    return production


def verify_manifest(raw: bytes) -> None:
    try:
        manifest = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"publisher crate manifest is invalid: {error}") from error
    require(manifest.get("package", {}).get("name") == "vibeos-wasm-aot-profile", "publisher crate name differs")
    require(manifest.get("dependencies") == {}, "publisher crate gained a dependency")
    require("dev-dependencies" not in manifest, "publisher crate gained a dev dependency")


def verify_lib(source: str) -> None:
    code = semantic(source)
    require(code.count("modpublisher;") == 1, "publisher module declaration differs")
    for name in (
        "Challenge",
        "EligibleTerminalEvidence",
        "PoisonedPublisher",
        "PreflightFailure",
        "ProfilePublisher",
        "ProfileRecordSink",
        "PublishFailure",
        "Published",
        "RunId",
        "SinkFailure",
        "TerminalObservation",
        "TranscriptBinding",
    ):
        require(name in code, f"publisher export {name} is missing")
    require(
        "The allocation-free [`ProfilePublisher`] implemented here accepts only" in source
        and "[`TargetVerified`]" in source,
        "crate publisher authority documentation differs",
    )


def verify_types(production: str) -> None:
    for forbidden in (
        "unsafe ",
        "unsafe{",
        "extern crate alloc",
        "alloc::",
        "Vec<",
        "String",
        "Box<",
        "serde",
        "format!(",
        "to_string(",
        "include_bytes!(",
        "publisher-sample-v1",
        "GOLDEN_",
    ):
        require(forbidden not in production, f"publisher production uses forbidden {forbidden!r}")
    exact_semantic(
        production,
        """
        pub trait ProfileRecordSink {
            type Error;
            fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
            fn commit_record(&mut self) -> Result<(), Self::Error>;
        }
        """,
        "sink contract",
    )
    exact_semantic(production, "pub struct RunId([u8; 32]);", "RunId brand")
    exact_semantic(production, "pub struct Challenge([u8; 32]);", "Challenge brand")
    exact_semantic(production, "if bytes.iter().all(|byte| *byte == 0) { Err(BindingError::ZeroRunId) }", "RunId zero rejection")
    exact_semantic(production, "if bytes.iter().all(|byte| *byte == 0) { Err(BindingError::ZeroChallenge) }", "challenge zero rejection")
    exact_semantic(production, "pub const fn new(run_id: RunId, challenge: Challenge) -> Self", "branded binding constructor")
    exact_semantic(production, "pub struct EligibleTerminalEvidence", "eligible evidence type")
    exact_semantic(production, "pub struct ProfilePublisher<S>", "publisher type")
    exact_semantic(production, "pub struct Published<'a, S>", "published type")
    exact_semantic(production, "pub struct PoisonedPublisher<S>", "poison type")
    exact_semantic(production, "_sink: ManuallyDrop<S>", "poison sink quarantine")
    require("impl<S> Drop for PoisonedPublisher" not in production, "poison runs a Drop implementation")
    require("fn sink(" not in production and "fn into_sink(" not in production, "poison exposes its sink")

    evidence_impl = find_scope(production, "impl EligibleTerminalEvidence", "eligible evidence impl")
    require(
        visible_methods(evidence_impl.raw)
        == ("validate", "fuel_consumed", "poll_quanta", "poll_quanta_is_exact"),
        "eligible evidence public method surface differs",
    )
    require(visibility_count(evidence_impl.raw) == 4, "eligible evidence exposes a non-method public item")
    require(semantic(production).count("implEligibleTerminalEvidence") == 1, "eligible evidence impl count differs")

    publisher_impl = find_scope(production, "impl<S> ProfilePublisher<S>", "publisher value impl")
    require(
        visible_methods(publisher_impl.raw) == ("new", "binding", "prior_accumulator"),
        "publisher value public method surface differs",
    )
    require(visibility_count(publisher_impl.raw) == 3, "publisher value exposes a non-method public item")

    poison_impl = find_scope(production, "impl<S> PoisonedPublisher<S>", "poison impl")
    require(
        visible_methods(poison_impl.raw) == ("failed_sample_index", "prior_accumulator"),
        "poison public method surface differs",
    )
    require(visibility_count(poison_impl.raw) == 2, "poison exposes a non-method public item")
    require(semantic(production).count("impl<S>PoisonedPublisher<S>") == 1, "poison impl count differs")
    code = semantic(production)
    for type_name in ("EligibleTerminalEvidence", "ProfilePublisher", "Published", "PoisonedPublisher"):
        require(f"for{type_name}" not in code, f"linear publisher type gained a trait impl: {type_name}")
        require(
            re.search(rf"#\s*\[\s*derive[^\]]*\]\s*pub\s+struct\s+{type_name}\b", comment_masked(production))
            is None,
            f"linear publisher type gained a derive: {type_name}",
        )


def verify_terminal(production: str) -> None:
    scope = find_scope(production, "impl EligibleTerminalEvidence", "terminal evidence impl")
    function = find_function(scope, "validate", "terminal evidence validator")
    checks = (
        "if observation.read_chunks != FORMAL_READ_CHUNKS",
        "if observation.write_chunks != FORMAL_WRITE_CHUNKS",
        "if !(1..=MAX_FORMAL_FUEL).contains(&observation.fuel_consumed)",
        "if observation.poll_quanta == 0",
        "if !observation.poll_quanta_exact",
        "if !observation.succeeded",
        "if observation.logical_live_after != 0",
        "if observation.timed_out",
        "if observation.timeout_phase.is_some()",
        "if observation.exit_status != 0",
        "if observation.stdout_bytes != FORMAL_STDOUT_BYTES",
        "if observation.stdout_sha256 != FORMAL_STDOUT_SHA256",
        "if observation.stderr_bytes != 0",
    )
    ordered_semantic(function.raw, checks, "terminal eligibility checks")
    assignments = (
        "read_chunks: observation.read_chunks",
        "write_chunks: observation.write_chunks",
        "fuel_consumed: observation.fuel_consumed",
        "poll_quanta: observation.poll_quanta",
        "poll_quanta_exact: observation.poll_quanta_exact",
        "succeeded: observation.succeeded",
        "logical_live_after: observation.logical_live_after",
        "timed_out: observation.timed_out",
        "timeout_phase: observation.timeout_phase",
        "exit_status: observation.exit_status",
        "stdout_bytes: observation.stdout_bytes",
        "stdout_sha256: observation.stdout_sha256",
        "stderr_bytes: observation.stderr_bytes",
    )
    ordered_semantic(function.raw, assignments, "terminal retained evidence")
    require(semantic(function.raw).count("returnErr(TerminalEvidenceError::") == 13, "terminal rejection branch count differs")


def verify_preflight(production: str) -> None:
    require(semantic(production).count("implProfileAccessforTargetVerified<'_>") == 1, "TargetVerified profile access impl differs")
    require(semantic(production).count("implProfileAccessfor") == 1, "production has another profile authority impl")
    function = find_scope(production, "fn preflight_profile", "publisher preflight")
    ordered_semantic(
        function.raw,
        (
            "if sample_index > MAX_SAMPLE_INDEX",
            "let summary = verified.profile_summary()",
            "if total_ticks == 0",
            "if summary.interval_capacity() != INTERVAL_CAPACITY",
            "if !summary.intervals_complete()",
            "if !(1..=INTERVAL_CAPACITY).contains(&interval_count)",
            "if interval_count as u64 > total_ticks",
            "let Some(declared_total) = declared_phase_ticks.checked_total() else",
            "if declared_total != total_ticks",
            "let mut accumulator = prior_accumulator",
            "for phase in Phase::ALL",
            "for sequence in 0..interval_count",
            "let Some(interval) = verified.profile_interval(sequence) else",
            "if interval.sequence() != sequence",
            "if interval.start_offset_ticks() != previous_end",
            "if interval.end_offset_ticks() <= interval.start_offset_ticks()",
            "if interval.end_offset_ticks() > total_ticks",
            "if previous_phase == Some(interval.phase())",
            "rescanned[phase_index].checked_add(duration)",
            "if verified.profile_interval(interval_count).is_some()",
            "if previous_end != total_ticks",
            "if rescanned != declared_phase_ticks",
            "for chunk in terminal.stdout_sha256.chunks_exact(8)",
            "u64::from_be_bytes(bytes)",
            "accumulator = fold_word(accumulator, terminal.stderr_bytes)",
            "Ok(Candidate { summary, accumulator, })",
        ),
        "publisher full preflight",
    )
    exact_semantic(
        function.raw,
        """
        for word in [
            SAMPLE_DOMAIN_WORD,
            u64::from(sample_index),
            u64::from(sample_index),
            bool_word(warmup),
            total_ticks,
        ] { accumulator = fold_word(accumulator, word); }
        """,
        "accumulator sample prefix",
    )
    exact_semantic(
        function.raw,
        "for phase in Phase::ALL { accumulator = fold_word(accumulator, declared_phase_ticks.get(phase)); }",
        "accumulator phase order",
    )
    exact_semantic(
        function.raw,
        """
        for word in [
            INTERVAL_DOMAIN_WORD,
            interval.sequence() as u64,
            u64::from(interval.phase().code()),
            interval.start_offset_ticks(),
            interval.end_offset_ticks(),
        ] { accumulator = fold_word(accumulator, word); }
        """,
        "accumulator interval words",
    )
    exact_semantic(
        function.raw,
        """
        for word in [
            terminal.read_chunks,
            terminal.write_chunks,
            terminal.fuel_consumed,
            terminal.poll_quanta,
            bool_word(terminal.succeeded),
            terminal.logical_live_after,
            bool_word(terminal.timed_out),
            timeout_phase_word(terminal.timeout_phase),
            u64::from(terminal.exit_status),
            terminal.stdout_bytes,
        ] { accumulator = fold_word(accumulator, word); }
        """,
        "accumulator sample suffix",
    )
    exact_semantic(production, "const SAMPLE_DOMAIN_WORD: u64 = 4_843_678_931_419_484_236;", "sample domain")
    exact_semantic(production, "const INTERVAL_DOMAIN_WORD: u64 = 4_843_678_888_688_374_358;", "interval domain")
    exact_semantic(
        production,
        "fn fold_word(accumulator: u64, word: u64) -> u64 { accumulator.rotate_left(7).wrapping_add(word) }",
        "accumulator fold",
    )
    exact_semantic(
        function.raw,
        """
        accumulator = fold_word(accumulator, terminal.stderr_bytes);
        Ok(Candidate { summary, accumulator, })
        """,
        "accumulator finalization",
    )


def verify_publish_flow(production: str) -> None:
    scope = find_scope(production, "impl<S: ProfileRecordSink> ProfilePublisher<S>", "publisher impl")
    require(visible_methods(scope.raw) == ("publish_profile",), "publisher authority public method surface differs")
    require(visibility_count(scope.raw) == 1, "publisher authority exposes a non-method public item")
    function = find_function(scope, "publish_profile", "publish_profile")
    exact_semantic(
        function.raw,
        """
        pub fn publish_profile<'a>(
            self,
            verified: TargetVerified<'a>,
            sample_index: u8,
            terminal: EligibleTerminalEvidence,
        ) -> Result<Published<'a, S>, PublishFailure<'a, S>>
        """,
        "publisher authority signature",
    )
    code = semantic(function.raw)
    required_prefix = semantic(
        """
        pub fn publish_profile<'a>(
            self,
            verified: TargetVerified<'a>,
            sample_index: u8,
            terminal: EligibleTerminalEvidence,
        ) -> Result<Published<'a, S>, PublishFailure<'a, S>> {
            let candidate = match preflight_profile(
                &verified,
                sample_index,
                &terminal,
                self.prior_accumulator
            )
        """
    )
    require(code.startswith(required_prefix), "publisher does work before full preflight")
    require(code.count("write_all(") == 0, "publisher bypasses the quarantined serializer with a sink write")
    require(code.count("commit_record(") == 0, "publisher bypasses the quarantined serializer with a commit")
    ordered_semantic(
        function.raw,
        (
            "preflight_profile(&verified, sample_index, &terminal, self.prior_accumulator)",
            "let ProfilePublisher { sink, binding, prior_accumulator, } = self",
            "let mut sink = ManuallyDrop::new(sink)",
            "let write_result = write_sample(&mut *sink, binding, sample_index, &terminal, candidate.summary, &verified,)",
            "match write_result",
            "let sink = ManuallyDrop::into_inner(sink)",
            "accumulator: candidate.accumulator",
            "publisher: PoisonedPublisher",
            "_sink: sink",
            "failed_sample_index: sample_index",
        ),
        "publisher transaction",
    )
    require(code.count("verified.recycle()") == 3, "publisher recycle path count differs")
    require(code.count("write_sample(") == 1, "publisher write call count differs")
    require(code.count("ManuallyDrop::new(sink)") == 1, "publisher quarantine count differs")
    require(code.count("ManuallyDrop::into_inner(sink)") == 1, "publisher sink recovery count differs")


def verify_serializer(production: str) -> None:
    function = find_scope(production, "fn write_sample", "sample serializer")
    exact_semantic(production, 'const SAMPLE_PREFIX: &[u8] = b"VIBE_WASM_AOT_SAMPLE ";', "SAMPLE prefix")
    exact_semantic(function.raw, "sink.write_all(SAMPLE_PREFIX)?;", "SAMPLE prefix write")
    code = semantic(function.raw)
    require(code.count("write_all(") == 42, "serializer write call surface differs")
    require(code.count("sink.write_all(") == 42, "serializer uses a non-canonical write receiver")
    require(code.count("commit_record(") == 1, "serializer commit call surface differs")
    require(code.count("sink.commit_record(") == 1, "serializer uses a non-canonical commit receiver")
    require(code.count("write_u64(") == 23, "serializer u64 field call count differs")
    require(code.count("write_hex(") == 3, "serializer hex field call count differs")
    require(code.count("write_bool(") == 3, "serializer boolean field call count differs")
    require(code.count("verified.intervals().enumerate()") == 1, "serializer interval iteration differs")
    for keyword, expected in (("if", 2), ("match", 1), ("for", 1)):
        require(keyword_count(function.raw, keyword) == expected, f"serializer {keyword} control-flow count differs")
    for keyword in ("return", "while", "loop", "break", "continue"):
        require(keyword_count(function.raw, keyword) == 0, f"serializer contains forbidden {keyword} control flow")
    require("br\"" not in function.raw and "br#" not in function.raw, "serializer contains a raw byte string")
    exact_semantic(
        function.raw,
        'sink.write_all(b",\\"schema\\":\\"vibeos.wasm-aot-decision.sample\\",\\"sequence\\":")',
        "sample schema literal",
    )
    exact_semantic(
        function.raw,
        'sink.write_all(b",\\"version\\":1,\\"warmup\\":")',
        "sample version literal",
    )
    exact_semantic(
        function.raw,
        'sink.write_all(b",\\"workload_id\\":\\"ssh-case-filter-12k-v1\\",\\"write_chunks\\":")',
        "sample workload literal",
    )
    raw = comment_masked(function.raw)
    keys = (
        '\\"challenge\\"',
        '\\"exit_status\\"',
        '\\"fuel_consumed\\"',
        '\\"interval_capacity\\"',
        '\\"interval_count\\"',
        '\\"intervals\\"',
        '\\"intervals_complete\\"',
        '\\"logical_live_after\\"',
        '\\"phase_ticks\\"',
        '\\"poll_quanta\\"',
        '\\"read_chunks\\"',
        '\\"run_id\\"',
        '\\"sample_index\\"',
        '\\"schema\\"',
        '\\"sequence\\"',
        '\\"stderr_bytes\\"',
        '\\"stdout_bytes\\"',
        '\\"stdout_sha256\\"',
        '\\"terminal\\"',
        '\\"timed_out\\"',
        '\\"timeout_phase\\"',
        '\\"total_ticks\\"',
        '\\"version\\"',
        '\\"warmup\\"',
        '\\"workload_id\\"',
        '\\"write_chunks\\"',
    )
    positions: list[int] = []
    for key in keys:
        matches = [index for index in range(len(raw)) if raw.startswith(key, index)]
        expected_count = 2 if key == '\\"sequence\\"' else 1
        require(len(matches) == expected_count, f"serializer key {key} count differs: {len(matches)}")
        positions.append(matches[-1])
    require(positions == sorted(positions), "serializer top-level key order differs")
    ordered_semantic(
        function.raw,
        (
            'sink.write_all(b"{\\"end_offset_ticks\\":")',
            "write_u64(sink, interval.end_offset_ticks())",
            'sink.write_all(b",\\"phase\\":\\"")',
            "sink.write_all(interval.phase().as_str().as_bytes())",
            'sink.write_all(b"\\",\\"sequence\\":")',
            "write_u64(sink, interval.sequence() as u64)",
            'sink.write_all(b",\\"start_offset_ticks\\":")',
            "write_u64(sink, interval.start_offset_ticks())",
        ),
        "serializer interval order",
    )
    ordered_semantic(
        function.raw,
        (
            'sink.write_all(b",\\"phase_ticks\\":{\\"abi\\":")',
            "write_u64(sink, phase_ticks.abi)",
            'sink.write_all(b",\\"cleanup\\":")',
            "write_u64(sink, phase_ticks.cleanup)",
            'sink.write_all(b",\\"host\\":")',
            "write_u64(sink, phase_ticks.host)",
            'sink.write_all(b",\\"instantiation\\":")',
            "write_u64(sink, phase_ticks.instantiation)",
            'sink.write_all(b",\\"interpretation\\":")',
            "write_u64(sink, phase_ticks.interpretation)",
            'sink.write_all(b",\\"validation\\":")',
            "write_u64(sink, phase_ticks.validation)",
            'sink.write_all(b",\\"wait\\":")',
            "write_u64(sink, phase_ticks.wait)",
        ),
        "serializer phase_ticks ASCII order",
    )
    exact_semantic(function.raw, "write_hex(sink, &binding.challenge().bytes())", "challenge field source")
    exact_semantic(function.raw, "write_hex(sink, &binding.run_id().bytes())", "run-id field source")
    for field in (
        "exit_status",
        "fuel_consumed",
        "logical_live_after",
        "poll_quanta",
        "read_chunks",
        "stderr_bytes",
        "stdout_bytes",
        "stdout_sha256",
        "succeeded",
        "timed_out",
        "timeout_phase",
        "write_chunks",
    ):
        require(f"terminal.{field}" in semantic(function.raw), f"serializer does not use terminal evidence {field}")
    tail = semantic('sink.write_all(b"}")?; sink.write_all(b"\\n")?; sink.commit_record()')
    require(semantic(function.raw).endswith(tail + "}"), "serializer does not end with one LF then commit")
    require(semantic(function.raw).count("sink.commit_record()") == 1, "serializer commit count differs")
    exact_semantic(
        production,
        """
        fn write_u64<S: ProfileRecordSink>(sink: &mut S, mut value: u64) -> Result<(), S::Error> {
            let mut encoded = [0_u8; 20];
            let mut cursor = encoded.len();
            loop {
                cursor -= 1;
                encoded[cursor] = b'0' + (value % 10) as u8;
                value /= 10;
                if value == 0 { break; }
            }
            sink.write_all(&encoded[cursor..])
        }
        """,
        "strict decimal u64 encoder",
    )
    exact_semantic(production, 'const HEX: &[u8; 16] = b"0123456789abcdef";', "lowercase hex encoder")


def verify_golden_test(source: str) -> None:
    require(source.count('#[test]\nfn public_api_emits_the_frozen_canonical_sample()') == 1, "public golden test attribute differs")
    require("#[ignore]" not in source and "#[should_panic]" not in source, "public golden test is disabled")
    require(source.count('include_bytes!("fixtures/publisher-sample-v1.jsonl")') == 1, "golden fixture include differs")
    require("struct ProfilePublisher" not in source and "fn publish_profile" not in source, "golden test shadows publisher API")
    function = find_scope(source, "fn public_api_emits_the_frozen_canonical_sample", "public golden test")
    for keyword in ("if", "match", "for", "while", "loop", "return", "break", "continue"):
        require(keyword_count(function.raw, keyword) == 0, f"public golden test contains {keyword} control flow")
    ordered_semantic(
        function.raw,
        (
            "let ready = TargetReady::new(Storage::new(&mut endpoints, &mut phases).unwrap())",
            "ProfilePublisher::new",
            ".publish_profile(verified_from_ready(ready), 3, terminal())",
            "assert_eq!(published.accumulator(), EXPECTED_ACCUMULATOR)",
            "let (ready, sink, observed_binding, accumulator) = published.into_parts()",
            "assert_eq!(ready.next_epoch(), Some(2))",
            "assert_eq!(sink.commits, 1)",
            "assert_eq!(sink.bytes.as_slice(), FIXTURE)",
            "assert_eq!(sha256(&sink.bytes), RECORD_SHA256)",
        ),
        "public golden test binding",
    )
    code = semantic(function.raw)
    for forbidden in ("sink.bytes.clear(", "sink.bytes.extend_from_slice(FIXTURE", "FIXTURE.to_vec("):
        require(forbidden not in code, f"golden test overwrites publisher output via {forbidden}")


def verify_docs(inputs: Inputs) -> None:
    ci_lines = inputs.ci.splitlines()
    step_name = "      - name: Verify the C8.4 formal single-SAMPLE publisher"
    require(ci_lines.count(step_name) == 1, "CI publisher step count differs")
    step_start = ci_lines.index(step_name)
    step_end = next(
        (index for index in range(step_start + 1, len(ci_lines)) if ci_lines[index].startswith("      - ")),
        len(ci_lines),
    )
    require(
        ci_lines[step_start:step_end] == [step_name, f"        run: {COMMAND}"],
        "CI publisher step is not an unconditional exact command",
    )
    require(inputs.ci.count(COMMAND) == 1, "CI publisher verifier command count differs")
    require(inputs.testing.count(COMMAND) == 2, "TESTING publisher verifier command count differs")
    require(inputs.decision_doc.count(COMMAND) == 2, "decision doc publisher verifier command count differs")
    for source, label in ((inputs.testing, "TESTING"), (inputs.decision_doc, "decision doc")):
        require(
            "single-SAMPLE" in source or "single-record" in source,
            f"{label} publisher single-record scope is missing",
        )
        for text in (
            "TargetVerified",
            "ManuallyDrop",
            "no META or END",
            "physical-Duo",
            "AOT decision",
        ):
            require(text in source, f"{label} publisher boundary is missing {text!r}")


def verify_publisher(inputs: Inputs) -> None:
    verify_manifest(inputs.cargo_manifest)
    verify_lib(inputs.lib)
    production = production_source(inputs.publisher)
    verify_types(production)
    verify_terminal(production)
    verify_preflight(production)
    verify_publish_flow(production)
    verify_serializer(production)
    verify_golden_test(inputs.golden_test)
    verify_golden(inputs.golden)
    verify_docs(inputs)


def verify(inputs: Inputs, *, predecessor: bool = True, contract: bool = True) -> None:
    if predecessor:
        try:
            STREAM.verify(inputs.predecessor)
        except Exception as error:
            raise VerificationError(f"verified-stream predecessor failed: {error}") from error
    if contract:
        verify_contract()
    verify_publisher(inputs)


def replace_once(value: str, old: str, new: str, label: str) -> str:
    count = value.count(old)
    require(count == 1, f"selftest {label} source count differs: {count}")
    return value.replace(old, new, 1)


def mutate_text(inputs: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    value = getattr(inputs, field)
    require(type(value) is str, f"selftest field {field} is not text")
    return replace(inputs, **{field: replace_once(value, old, new, label)})


def mutate_golden(inputs: Inputs, mutation: Callable[[dict[str, Any]], None]) -> Inputs:
    payload = inputs.golden[len(SAMPLE_PREFIX) : -1]
    value = json.loads(payload)
    mutation(value)
    raw = SAMPLE_PREFIX + json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    return replace(inputs, golden=raw)


def expect_rejected(inputs: Inputs, label: str) -> None:
    try:
        verify(inputs, predecessor=False, contract=False)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation was accepted: {label}")


def run_selftest(inputs: Inputs) -> int:
    verify(inputs, predecessor=True, contract=True)
    mutations: list[tuple[str, Inputs]] = []
    add = mutations.append
    add(("authority-by-reference", mutate_text(inputs, "publisher", "verified: TargetVerified<'a>,", "verified: &TargetVerified<'a>,", "authority-by-reference")))
    add(("authority-summary", mutate_text(inputs, "publisher", "verified: TargetVerified<'a>,", "verified: Summary,", "authority-summary")))
    add(("sample-index-bypass", mutate_text(inputs, "publisher", "if sample_index > MAX_SAMPLE_INDEX {", "if false {", "sample-index-bypass")))
    add(("read-validation-inverted", mutate_text(inputs, "publisher", "if observation.read_chunks != FORMAL_READ_CHUNKS {", "if observation.read_chunks == FORMAL_READ_CHUNKS {", "read-validation")))
    add(("poll-exactness-inverted", mutate_text(inputs, "publisher", "if !observation.poll_quanta_exact {", "if observation.poll_quanta_exact {", "poll-exactness")))
    add(("success-validation-removed", mutate_text(inputs, "publisher", "if !observation.succeeded {", "if false && !observation.succeeded {", "success-validation")))
    add(("success-evidence-hardcoded", mutate_text(inputs, "publisher", "succeeded: observation.succeeded,", "succeeded: true,", "success-evidence")))
    add(("rotate-six", mutate_text(inputs, "publisher", "accumulator.rotate_left(7).wrapping_add(word)", "accumulator.rotate_left(6).wrapping_add(word)", "rotate-six")))
    add(("saturating-add", mutate_text(inputs, "publisher", "accumulator.rotate_left(7).wrapping_add(word)", "accumulator.rotate_left(7).saturating_add(word)", "saturating-add")))
    add(("sample-domain", mutate_text(inputs, "publisher", "4_843_678_931_419_484_236", "4_843_678_931_419_484_237", "sample-domain")))
    add(("interval-domain", mutate_text(inputs, "publisher", "4_843_678_888_688_374_358", "4_843_678_888_688_374_359", "interval-domain")))
    add(("phase-fold-order", mutate_text(inputs, "publisher", "for phase in Phase::ALL {", "for phase in Phase::ALL.into_iter().rev() {", "phase-fold-order")))
    add(("skip-first-interval", mutate_text(inputs, "publisher", "verified.profile_interval(sequence)", "verified.profile_interval(sequence + 1)", "skip-first-interval")))
    add(("trailing-interval-bypass", mutate_text(inputs, "publisher", "if verified.profile_interval(interval_count).is_some() {", "if false && verified.profile_interval(interval_count).is_some() {", "trailing-interval")))
    add(("empty-interval-accepted", mutate_text(inputs, "publisher", "interval.end_offset_ticks() <= interval.start_offset_ticks()", "interval.end_offset_ticks() < interval.start_offset_ticks()", "empty-interval")))
    add(("adjacent-phase-inverted", mutate_text(inputs, "publisher", "previous_phase == Some(interval.phase())", "previous_phase != Some(interval.phase())", "adjacent-phase")))
    add(("digest-little-endian", mutate_text(inputs, "publisher", "u64::from_be_bytes(bytes)", "u64::from_le_bytes(bytes)", "digest-endian")))
    add(("prior-zeroed", mutate_text(inputs, "publisher", "let mut accumulator = prior_accumulator;", "let mut accumulator = 0;", "prior-zeroed")))
    add(("quarantine-removed", mutate_text(inputs, "publisher", "let mut sink = ManuallyDrop::new(sink);", "let mut sink = ManuallyDrop::new(ManuallyDrop::into_inner(ManuallyDrop::new(sink)));", "quarantine")))
    add(("recycle-removed", mutate_text(
        inputs,
        "publisher",
        "let ready = verified.recycle();\n                    return Err(PublishFailure::Preflight",
        "let ready = { drop(verified); panic!(\"no recycle\") };\n                    return Err(PublishFailure::Preflight",
        "recycle",
    )))
    add(("success-old-accumulator", mutate_text(inputs, "publisher", "accumulator: candidate.accumulator,", "accumulator: prior_accumulator,", "success-accumulator")))
    add(("challenge-from-run-id", mutate_text(inputs, "publisher", "write_hex(sink, &binding.challenge().bytes())?;", "write_hex(sink, &binding.run_id().bytes())?;", "challenge-source")))
    add(("line-feed-omitted", mutate_text(inputs, "publisher", 'sink.write_all(b"\\n")?;', 'sink.write_all(b"")?;', "line-feed")))
    add(("commit-omitted", mutate_text(inputs, "publisher", "sink.commit_record()", "Ok(())", "commit")))
    add(("decimal-hex", mutate_text(inputs, "publisher", "value % 10", "value % 16", "decimal")))
    add(("uppercase-hex", mutate_text(inputs, "publisher", 'b"0123456789abcdef"', 'b"0123456789ABCDEF"', "hex")))
    add(("schema-drift", mutate_text(inputs, "publisher", "vibeos.wasm-aot-decision.sample", "vibeos.wasm-aot-decision.sample-v2", "schema")))
    add(("version-drift", mutate_text(inputs, "publisher", '\\"version\\":1', '\\"version\\":2', "version")))
    add(("workload-drift", mutate_text(inputs, "publisher", "ssh-case-filter-12k-v1", "ssh-case-filter-12k-v2", "workload")))
    add(("golden-test-disabled", mutate_text(inputs, "golden_test", "#[test]\nfn public_api_emits", "#[ignore]\n#[test]\nfn public_api_emits", "golden-disabled")))
    add(("golden-self-compare", mutate_text(inputs, "golden_test", "assert_eq!(sink.bytes.as_slice(), FIXTURE);", "assert_eq!(FIXTURE, FIXTURE);", "golden-self-compare")))
    add(("ci-command-drift", mutate_text(inputs, "ci", COMMAND, COMMAND.replace("--check-source", "--check-docs"), "ci-command")))
    add(("testing-command-drift", mutate_text(
        inputs,
        "testing",
        "python3 -B scripts/verify-c84-aot-decision.py --selftest --check-manifest\n" + COMMAND,
        "python3 -B scripts/verify-c84-aot-decision.py --selftest --check-manifest\n" + COMMAND.replace("--check-source", "--check-docs"),
        "testing-command",
    )))
    add(("record-leading-noise", replace(inputs, golden=b"noise " + inputs.golden)))
    add(("record-padding", replace(inputs, golden=inputs.golden[:-1] + b" \n")))
    add(("record-second-line", replace(inputs, golden=inputs.golden + inputs.golden)))
    add(("record-no-lf", replace(inputs, golden=inputs.golden[:-1])))
    add(("record-meta-prefix", replace(inputs, golden=inputs.golden.replace(SAMPLE_PREFIX, b"VIBE_WASM_AOT_META ", 1))))
    add(("golden-run-id", mutate_golden(inputs, lambda value: value.update(run_id="f" * 64))))
    add(("golden-challenge", mutate_golden(inputs, lambda value: value.update(challenge="e" * 64))))
    add(("golden-sequence", mutate_golden(inputs, lambda value: value.update(sequence=2))))
    add(("golden-phase-sum", mutate_golden(inputs, lambda value: value["phase_ticks"].update(validation=2))))
    add(("golden-gap", mutate_golden(inputs, lambda value: value["intervals"][1].update(start_offset_ticks=0))))
    add(("comment-decoy", replace(inputs, publisher=replace_once(inputs.publisher, "accumulator.rotate_left(7).wrapping_add(word)", "accumulator.rotate_left(6).wrapping_add(word)", "comment-decoy") + "\n// accumulator.rotate_left(7).wrapping_add(word)\n")))
    add(("dead-code-decoy", replace(inputs, publisher=replace_once(inputs.publisher, "accumulator.rotate_left(7).wrapping_add(word)", "accumulator.rotate_left(6).wrapping_add(word)", "dead-decoy").replace("fn fold_word", "fn unused_fold_decoy() { if false { let _ = 0_u64.rotate_left(7).wrapping_add(0); } }\n\nfn fold_word", 1))))
    add(("write-control-flow", mutate_text(inputs, "publisher", "sink.write_all(SAMPLE_PREFIX)?;", "sink.write_all({ return Ok(()); SAMPLE_PREFIX })?;", "write-control-flow")))
    add(("conditional-ufcs-serializer", mutate_text(
        inputs,
        "publisher",
        """) -> Result<(), S::Error> {
    sink.write_all(SAMPLE_PREFIX)?;""",
        """) -> Result<(), S::Error> {
    if sample_index == 23 {
        ProfileRecordSink::write_all(sink, br#"{"sequence":23}"#)?;
        ProfileRecordSink::commit_record(sink)?;
        return Ok(());
    }
    sink.write_all(SAMPLE_PREFIX)?;""",
        "conditional-ufcs-serializer",
    )))
    add(("borrowed-unchecked-publisher", mutate_text(
        inputs,
        "publisher",
        """        }
    }
}

/// Successful single-record publication.""",
        """        }
    }

    pub fn publish_borrowed_unchecked(
        &mut self,
        verified: &TargetVerified<'_>,
        sample_index: u8,
        terminal: &EligibleTerminalEvidence,
    ) -> Result<(), S::Error> {
        write_sample(
            &mut self.sink,
            self.binding,
            sample_index,
            terminal,
            verified.summary(),
            verified,
        )
    }
}

/// Successful single-record publication.""",
        "borrowed-unchecked-publisher",
    )))
    add(("poison-sink-recovery", mutate_text(
        inputs,
        "publisher",
        """    pub const fn prior_accumulator(&self) -> u64 {
        self.prior_accumulator
    }
}

/// Non-forgeable zero-write preflight failure.""",
        """    pub const fn prior_accumulator(&self) -> u64 {
        self.prior_accumulator
    }

    pub fn recover(self) -> S {
        ManuallyDrop::into_inner(self._sink)
    }
}

/// Non-forgeable zero-write preflight failure.""",
        "poison-sink-recovery",
    )))
    add(("poison-extern-sink-recovery", mutate_text(
        inputs,
        "publisher",
        """    pub const fn prior_accumulator(&self) -> u64 {
        self.prior_accumulator
    }
}

/// Non-forgeable zero-write preflight failure.""",
        """    pub const fn prior_accumulator(&self) -> u64 {
        self.prior_accumulator
    }

    pub extern "Rust" fn recover(value: Self) -> S {
        ManuallyDrop::into_inner(value._sink)
    }
}

/// Non-forgeable zero-write preflight failure.""",
        "poison-extern-sink-recovery",
    )))
    add(("poison-associated-recovery", mutate_text(
        inputs,
        "publisher",
        """    pub const fn prior_accumulator(&self) -> u64 {
        self.prior_accumulator
    }
}

/// Non-forgeable zero-write preflight failure.""",
        """    pub const fn prior_accumulator(&self) -> u64 {
        self.prior_accumulator
    }

    pub const RECOVER: fn(Self) -> S = |value| ManuallyDrop::into_inner(value._sink);
}

/// Non-forgeable zero-write preflight failure.""",
        "poison-associated-recovery",
    )))
    add(("poison-trait-recovery", mutate_text(
        inputs,
        "publisher",
        """}

/// Non-forgeable zero-write preflight failure.""",
        """}

impl<S> AsMut<S> for PoisonedPublisher<S> {
    fn as_mut(&mut self) -> &mut S {
        &mut self._sink
    }
}

/// Non-forgeable zero-write preflight failure.""",
        "poison-trait-recovery",
    )))
    add(("poison-derived-clone", mutate_text(
        inputs,
        "publisher",
        "pub struct PoisonedPublisher<S> {",
        "#[derive(Clone)]\npub struct PoisonedPublisher<S> {",
        "poison-derived-clone",
    )))
    add(("io-before-preflight", mutate_text(
        inputs,
        "publisher",
        """    ) -> Result<Published<'a, S>, PublishFailure<'a, S>> {
        let candidate =""",
        """    ) -> Result<Published<'a, S>, PublishFailure<'a, S>> {
        let mut publisher = self;
        if sample_index == 23 {
            let _ = ProfileRecordSink::write_all(&mut publisher.sink, b"BAD");
        }
        let self = publisher;
        let candidate =""",
        "io-before-preflight",
    )))
    add(("conditional-accumulator-adjustment", mutate_text(
        inputs,
        "publisher",
        """    accumulator = fold_word(accumulator, terminal.stderr_bytes);

    Ok(Candidate {""",
        """    accumulator = fold_word(accumulator, terminal.stderr_bytes);
    if sample_index == 23 {
        accumulator = accumulator.wrapping_add(1);
    }

    Ok(Candidate {""",
        "conditional-accumulator-adjustment",
    )))
    add(("eligible-evidence-mutator", mutate_text(
        inputs,
        "publisher",
        """    pub const fn poll_quanta_is_exact(&self) -> bool {
        self.poll_quanta_exact
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightError""",
        """    pub const fn poll_quanta_is_exact(&self) -> bool {
        self.poll_quanta_exact
    }

    pub fn with_succeeded(mut self, succeeded: bool) -> Self {
        self.succeeded = succeeded;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightError""",
        "eligible-evidence-mutator",
    )))
    add(("golden-early-return", mutate_text(
        inputs,
        "golden_test",
        "fn public_api_emits_the_frozen_canonical_sample() {",
        "fn public_api_emits_the_frozen_canonical_sample() {\n    if true { return; }",
        "golden-early-return",
    )))
    add(("ci-step-disabled", mutate_text(
        inputs,
        "ci",
        "      - name: Verify the C8.4 formal single-SAMPLE publisher\n        run: " + COMMAND,
        "      - name: Verify the C8.4 formal single-SAMPLE publisher\n        if: ${{ false }}\n        run: " + COMMAND,
        "ci-step-disabled",
    )))

    for label, mutated in mutations:
        expect_rejected(mutated, label)
    print(f"verify-c84-profile-publisher.py selftest: PASS ({len(mutations)} mutations rejected)")
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--check-source", action="store_true")
    arguments = parser.parse_args()
    if not arguments.selftest and not arguments.check_source:
        parser.error("at least one of --selftest or --check-source is required")
    try:
        inputs = load_inputs()
        if arguments.selftest:
            run_selftest(inputs)
        if arguments.check_source:
            verify(inputs, predecessor=not arguments.selftest, contract=not arguments.selftest)
            print(
                "PASS C8.4 formal SAMPLE publisher "
                f"record_bytes={EXPECTED_RECORD_BYTES} record_sha256={EXPECTED_RECORD_SHA256} "
                f"accumulator=0x{EXPECTED_PRIOR_ACCUMULATOR:016x}"
            )
    except (VerificationError, OSError) as error:
        print(f"FAIL C8.4 formal SAMPLE publisher: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
