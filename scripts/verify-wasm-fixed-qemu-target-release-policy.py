#!/usr/bin/env python3
"""Verify the prospective fixed-QEMU WASM target/release gate policy.

This checker validates a governance policy, not target evidence.  It never
boots QEMU, touches a Milk-V Duo, satisfies a target/release gate, allocates a
successor, or grants implementation, execution, admission, or release
authority.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass, replace
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable, NoReturn


SCRIPT_PATH = pathlib.Path(os.path.abspath(__file__))
ROOT = SCRIPT_PATH.parent.parent
CONTRACT_PATH = (
    ROOT / "acceptance/wasm-roadmap/artifacts/"
    "fixed-qemu-target-release-policy-v1-contract.json"
)

EXPECTED_CONTRACT_BYTES = 28_536
EXPECTED_CONTRACT_SHA256 = (
    "0fd814ef8645c91d77d8e2d23b812a0b8ac071c98f62e6076f96fcd2a05a149f"
)
MAX_CONTRACT_BYTES = 64 * 1024
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_GIT_BLOB_BYTES = 512 * 1024
MAX_JSON_INTEGER_DIGITS = 20
READ_CHUNK_BYTES = 64 * 1024

ROOT_KEYS = {
    "application_status",
    "authority",
    "code5_boundary",
    "contract_verifier",
    "duo_observation",
    "effectivity",
    "evidence_non_promotion",
    "fixed_qemu_gate",
    "historical_boundaries",
    "limitations",
    "policy_basis",
    "policy_checkpoint",
    "repository_integration",
    "roadmap_position",
    "schema",
    "scope",
    "status",
    "successor_boundary",
    "unrelated_hardware_gates",
    "version",
}

EXPECTED_APPLICATION_STATUS = {
    "allocation_contract_path": (
        "acceptance/wasm-float-target/artifacts/"
        "c89-float-successor-design-v1-contract.json"
    ),
    "allocation_contract_schema": "vibeos.c89.float-successor-design-v1.contract",
    "current_roadmap_position": "c813-e3-qualified-sealed-reference-runtime-released",
    "design_node": "C8.9-S1",
    "design_node_complete": True,
    "implementation_node": "C8.9-S2",
    "implementation_contract_path": (
        "acceptance/wasm-float-target/artifacts/"
        "c89-float-successor-implementation-v1-contract.json"
    ),
    "implementation_contract_schema": "vibeos.c89.float-successor-implementation-v1.contract",
    "implementation_node_complete": True,
    "next_successor_design_contract_path": (
        "acceptance/wasm-simd-target/artifacts/"
        "c811-simd-successor-design-v1-contract.json"
    ),
    "next_successor_design_contract_schema": (
        "vibeos.c811.simd-successor-design-v1.contract"
    ),
    "next_successor_design_node": "C8.11-S1",
    "next_successor_design_node_complete": True,
    "next_successor_implementation_contract_path": (
        "acceptance/wasm-simd-target/artifacts/"
        "c811-simd-successor-implementation-v1-contract.json"
    ),
    "next_successor_implementation_contract_schema": (
        "vibeos.c811.simd-successor-implementation-v1.contract"
    ),
    "next_successor_implementation_node": "C8.11-S2",
    "next_successor_implementation_node_complete": True,
    "next_successor_qualification_node": "C8.11-S3",
    "next_successor_qualification_node_complete": True,
    "next_widening_contract_path": (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-widening-design-v1-contract.json"
    ),
    "next_widening_contract_schema": "vibeos.c810.simd-widening-design-v1.contract",
    "next_widening_design_node": "C8.10-S1",
    "next_widening_design_node_complete": True,
    "next_widening_first_feature": "simd",
    "next_widening_implementation_node": "C8.10-S2",
    "next_widening_implementation_node_complete": True,
    "next_widening_qualification_contract_path": (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-s5-fixed-qemu-qualification-v1-contract.json"
    ),
    "next_widening_qualification_contract_schema": (
        "vibeos.c810.s5.fixed-qemu-qualification-v1.contract"
    ),
    "next_widening_qualification_node": "C8.10-S5",
    "next_widening_qualification_node_complete": True,
    "next_widening_successor_design_review_eligible": True,
    "next_widening_containment_contract_path": (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-containment-corpus-v1-contract.json"
    ),
    "next_widening_containment_contract_schema": (
        "vibeos.c810.simd-containment-corpus-v1.contract"
    ),
    "next_widening_containment_node": "C8.10-S3",
    "next_widening_containment_node_complete": True,
    "next_widening_admission_contract_path": (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-admission-lifecycle-v1-contract.json"
    ),
    "next_widening_admission_contract_schema": (
        "vibeos.c810.simd-admission-lifecycle-v1.contract"
    ),
    "next_widening_admission_node": "C8.10-S4",
    "next_widening_admission_node_complete": True,
    "policy_checkpoint_remains_nonallocating": True,
    "qualification_contract_path": (
        "acceptance/wasm-float-target/artifacts/"
        "c89-s3-fixed-qemu-qualification-v1-contract.json"
    ),
    "qualification_contract_schema": (
        "vibeos.c89.s3.fixed-qemu-qualification-v1.contract"
    ),
    "qualification_node": "C8.9-S3",
    "qualification_node_complete": True,
    "release_decision_path": (
        "acceptance/wasm-float-target/artifacts/c89-s3-release-decision.json"
    ),
    "release_decision_schema": "vibeos.c89.s3.float-executable.release-decision",
    "successor_design_review_passed": True,
    "target_policy_applies_to_qualification": True,
}

EXPECTED_AUTHORITY = {
    "admission_authorized": False,
    "aot_authorized": False,
    "command_authorized": False,
    "current_engine_authorized": False,
    "design_authorized": False,
    "durable_publication_authorized": False,
    "execution_authorized": False,
    "implementation_authorized": False,
    "in_place_promotion_authorized": False,
    "jit_authorized": False,
    "migration_authorized": False,
    "native_bytes_authorized": False,
    "production_authorized": False,
    "prototype_authorized": False,
    "release_authorized": False,
    "rwx_authorized": False,
}

EXPECTED_CODE5_BOUNDARY = {
    "activation_authorized": False,
    "admission_authorized": False,
    "artifact_profile_code": 5,
    "current_engine": False,
    "durable_publication_authorized": False,
    "executable": False,
    "execution_authorized": False,
    "in_place_promotion_authorized": False,
    "inert": True,
    "migration_authorized": False,
    "permanent": True,
    "production_authorized": False,
    "stage": "validation-only",
}

EXPECTED_CONTRACT_VERIFIER = {
    "check_modes": ["--check-contract", "--selftest"],
    "contract_identity_binding": "one-way-sha256-and-bytes-pin-in-verifier",
    "optimized_python_required": True,
    "path": "scripts/verify-wasm-fixed-qemu-target-release-policy.py",
    "runs_duo": False,
    "runs_qemu": False,
    "success_only_means": (
        "prospective-policy-integrity-not-target-evidence-not-gate-"
        "satisfaction-not-release-authorization"
    ),
    "writes_repository_outputs": False,
}

EXPECTED_DUO_OBSERVATION = {
    "automatic_resume": False,
    "completion_effect": False,
    "contracts_retained": True,
    "current_physical_evidence_present": False,
    "current_physical_inputs": 0,
    "current_physical_provenance": "not-claimed",
    "formal_gate_input_permitted": False,
    "future_valid_observation_may_be_reported_separately": True,
    "gate_effect": False,
    "operator_authorization_required_to_resume": True,
    "release_effect": False,
    "status": "paused-retained-optional-separate-non-gating",
    "tooling_retained": True,
}

EXPECTED_EFFECTIVITY = {
    "contract_is_target_evidence": False,
    "contract_satisfies_target_release_gate": False,
    "current_target_release_gate_satisfied": False,
    "policy_effective": True,
    "policy_effective_condition": (
        "exact-contract-verifier-docs-testing-and-ci-integrated-on-codex-wasm"
    ),
    "release_authorized": False,
    "retroactive_evidence_reclassification": False,
    "successor_review_passed_by_policy": False,
}

EXPECTED_EVIDENCE_NON_PROMOTION = {
    "baseline_specification_may_be_referenced": True,
    "c83_historical_members_eligible_for_future_gate": False,
    "c84_decision_or_bundle_eligible_for_future_gate": False,
    "c88_f5_contract_decision_or_receipts_eligible_for_future_gate": False,
    "fresh_capture_required": True,
    "fresh_challenge_required": True,
    "fresh_evidence_required": True,
    "fresh_node_specific_contract_required": True,
    "fresh_run_id_required": True,
    "fresh_source_commit_and_tree_required": True,
    "fresh_suite_and_domain_required": True,
    "historical_contract_semantics_may_be_referenced_only": True,
    "historical_evidence_may_satisfy_only_its_original_scope": True,
    "historical_evidence_relabeling_forbidden": True,
    "ineligible_historical_ids": [
        "a22f28ef7aab11de5c4858e9a4e4c5b5b4e6e763c43a126ad84d4ac80b9f500f",
        "1841ae06e4c8bef4842a59bbc65362fa860e37d6d8a1d79cc68e3fc5a87004f9",
        "53c9f7ed099c371724867d060c3994cb4b3ad93d46404156f40914d7f3b30254",
        "4d70865a6a665829457ee0e9ec34c9fa38de51ed6ee2bcb2be1356d752355c1a",
        "4f95fcd2b4d2524b1d27fce7bbf77846f4f7d0030da8ebe277ffc062e53550e0",
    ],
    "policy_contract_is_evidence": False,
    "predecessor_source_commits_eligible_as_fresh_source": False,
}

EXPECTED_FIXED_QEMU_GATE = {
    "additional_emulated_scenarios_must_be_node_specific_and_frozen": True,
    "applies_to": "prospective-generic-wasm-target-and-release-completion",
    "baseline": {
        "argv_semantics": [
            "-no-user-config",
            "-machine=virt",
            "-cpu=rv64",
            "-smp=1",
            "-m=128M",
            "-accel=tcg,thread=single",
            "-icount=shift=0,align=off,sleep=off",
            "-nographic",
            "-nic=none",
            "-bios=pinned-opensbi",
            "-kernel=measured-kernel",
        ],
        "class": "emulator",
        "id": "qemu-virt-rv64-tcg-icount-v1",
        "opensbi": {
            "bytes": 273_048,
            "sha256": (
                "49bdf7b939bda11321132d1042bf99d7324fb190f1feef423171fed3573f8705"
            ),
        },
        "physical_provenance": "not-claimed",
        "qemu": {
            "bytes": 13_511_488,
            "sha256": (
                "ef5c714232320c22561daa0998546b73672e21a2801404714dfbd4982ac7b3c0"
            ),
            "version": "QEMU emulator version 11.0.3",
        },
        "target": "riscv64imac-unknown-none-elf",
    },
    "baseline_alone_claims_multicore_network_or_storage_coverage": False,
    "baseline_evidence_reusable": False,
    "baseline_specification_reusable": True,
    "canonical_environment_required": True,
    "exact_binary_and_opensbi_identity_required": True,
    "fresh_capture_required": True,
    "fresh_challenge_required": True,
    "fresh_evidence_required": True,
    "fresh_node_specific_acceptance_predicates_required": True,
    "fresh_node_specific_contract_required": True,
    "fresh_run_id_required": True,
    "fresh_source_commit_and_tree_required": True,
    "fresh_suite_and_run_id_domain_required": True,
    "normal_and_optimized_verification_required": True,
    "normative_gate": "fresh-source-bound-fixed-qemu",
    "physical_equivalence_claimed": False,
    "physical_inputs_permitted": 0,
    "physical_inputs_required": 0,
    "physical_provenance": "not-claimed",
    "successful_policy_check_satisfies_gate": False,
}

EXPECTED_POLICY_BASIS = {
    "branch": "codex/wasm",
    "commit": "adb2c6abedba24e4cb13f262de37931fd0913080",
    "must_be_ancestor_of_checked_head": True,
    "role": "last-pushed-pre-policy-strengthening-basis",
    "self_binding_claimed": False,
    "tree": "8016339f6a11c725652e02a819dc14a70da0d083",
}

EXPECTED_POLICY_CHECKPOINT = {
    "c_number_allocated": False,
    "identity": "wasm-fixed-qemu-target-release-policy-v1",
    "kind": "roadmap-governance-policy-checkpoint",
    "product_roadmap_node": False,
    "resolves_successor_review_question": False,
    "successor_roadmap_node": False,
}

VERIFICATION_COMMANDS = [
    "python3 -B scripts/verify-wasm-fixed-qemu-target-release-policy.py --check-contract",
    "python3 -O -B scripts/verify-wasm-fixed-qemu-target-release-policy.py --check-contract",
    "python3 -B scripts/verify-wasm-fixed-qemu-target-release-policy.py --selftest",
    "python3 -O -B scripts/verify-wasm-fixed-qemu-target-release-policy.py --selftest",
]

EXPECTED_REPOSITORY_FILES = {
    ".github/workflows/ci.yml": {
        "bytes": 37_005,
        "sha256": "c56c4a497b1a846c98d5adf0bddd5c8f0a6cc37c2d27db7ffdd79c1a89af36ad",
    },
    "TESTING.md": {
        "bytes": 148_093,
        "sha256": "818217aea7667a3efc6572109095d0575971f0dfcdca9a43a4f27947745db45c",
    },
    (
        "acceptance/wasm-float-target/artifacts/"
        "c89-s3-fixed-qemu-qualification-v1-contract.json"
    ): {
        "bytes": 4_457,
        "sha256": "f105699b87c4f05eb90c2afe22a2a46002b7f5a1d32a1bac7cc46878a81edbb8",
    },
    "acceptance/wasm-float-target/artifacts/c89-s3-release-decision.json": {
        "bytes": 2_117,
        "sha256": "67bc213ddfc0d9044cd347c0f7aa3792909de4e7ae0074e6f546f0e4905d8593",
    },
    (
    "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-widening-design-v1-contract.json"
    ): {
        "bytes": 8_228,
        "sha256": "6e0728ed4d9c0452a5c895b17a87bb8c90a1fa30fee0eb751dbfb8b52f995be1",
    },
    (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-widening-implementation-v1-contract.json"
    ): {
        "bytes": 5_053,
        "sha256": "6083c0d132df4c2027dd826601dd9ad351ecebe844edf52290fd139a150e7c26",
    },
    (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-containment-corpus-v1-contract.json"
    ): {
        "bytes": 3_635,
        "sha256": "56bfce66eac664e0a28671f3f0b8adb36e1817e09c94519f6bc7edff13051e74",
    },
    (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-s5-fixed-qemu-qualification-v1-contract.json"
    ): {
        "bytes": 5_518,
        "sha256": "824bfe30eca3fb923ea5eeecd96963aa134364f0acc56a3db43cb26eb52ad6c8",
    },
    "acceptance/wasm-simd-target/artifacts/c810-s5-normal-receipt.json": {
        "bytes": 1_277,
        "sha256": "398a415afa8e0fa8ee66f3c94aa574879a3b8d516d066d01c1417216c39162a7",
    },
    "acceptance/wasm-simd-target/artifacts/c810-s5-optimized-receipt.json": {
        "bytes": 1_280,
        "sha256": "ff11d50409d0e4daabf41132ae04b4435530eaaf912a8fadc0649ece6cef2c48",
    },
    "acceptance/wasm-simd-target/artifacts/c810-s5-review-decision.json": {
        "bytes": 2_174,
        "sha256": "f20f68bdf0e86e99d0024e6b008903c6bfdbcc4b9e210d6d56f65646ef24b6e0",
    },
    (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-admission-lifecycle-v1-contract.json"
    ): {
        "bytes": 3_694,
        "sha256": "217c1eb45d78d7cc4a267ae9b1c3e0b366f281e4b8048a86b6ce4f5a0990186f",
    },
    (
        "acceptance/wasm-simd-target/artifacts/"
        "c811-simd-successor-design-v1-contract.json"
    ): {
        "bytes": 8_267,
        "sha256": "5995b8513f182d891c30d95530d31f6b571c14b0649c39c438f99990f58133ee",
    },
    (
        "acceptance/wasm-simd-target/artifacts/"
        "c811-simd-successor-implementation-v1-contract.json"
    ): {
        "bytes": 3_842,
        "sha256": "7b85b9324409d7cc4484ca9e661a44fce2275e70407338a4f4326f71809a40a1",
    },
    "acceptance/wasm-simd-target/artifacts/c811-s3-fixed-qemu-qualification-v1-contract.json": {"bytes": 3_309, "sha256": "68b2e3933784f1b81f2f45fb173a24131797c6b86e305ee12ccbc78b2ecb677b"},
    "acceptance/wasm-simd-target/artifacts/c811-s3-normal-receipt.json": {"bytes": 1_046, "sha256": "95201058962dcc5602149ed5f1dbd2564f3bc0c7757f11a914b5a7945044b253"},
    "acceptance/wasm-simd-target/artifacts/c811-s3-optimized-receipt.json": {"bytes": 1_049, "sha256": "da74242e314b1bdcccc5d57b73ee4dd76c0cecbaf76c45d9f8bb6fc0fe8bee8b"},
    "acceptance/wasm-simd-target/artifacts/c811-s3-release-decision.json": {"bytes": 2_200, "sha256": "b4f0f757292039a44f28f103691b8976d25986ece1012b9c7204451f929a7e3a"},
    "benchmarks/wasm-aot-decision/README.md": {
        "bytes": 16_851,
        "sha256": "c78c82a990b8b54601cf00fd5b74ce41ae0af0f6ced92244814d4d219128cd0f",
    },
    "benchmarks/wasm-runtime/README.md": {
        "bytes": 1_200,
        "sha256": "5e1e1bd8c21dc2f1badecc2f29dc52209cfa4682744c0677abdba604df1dd5b1",
    },
    "docs/WASM_AOT_DECISION.md": {
        "bytes": 84_354,
        "sha256": "12eb42d3a1d62b9a683903007b82e05d9d7b9e8a82cf127624ec6c01317f966d",
    },
    "docs/WASM_FLOAT_PROFILE.md": {
        "bytes": 36_555,
        "sha256": "8df5b0ca82cac499653cce706b49e9d07e9428481ebaaacf49ea54fb8fedc77c",
    },
    "docs/WASM_ROADMAP.md": {
        "bytes": 109_798,
        "sha256": "9fa50c86c2d0b3b9c592881664c3e047b73d66c9bdf1b0d4760977a21d070447",
    },
    "docs/WASM_RUNTIME_COSTS.md": {
        "bytes": 12_908,
        "sha256": "3eb717ad1d6681ae073b1ba10f872cc05830911ae7204a078ec64ad87b7534ac",
    },
    "docs/WASM_SIMD_EXECUTABLE_PROFILE.md": {
        "bytes": 6_089,
        "sha256": "b51aafcf526ed5b42ea01ef1ec1c57918505d4f287f8fa8d433678ff6313eece",
    },
    "docs/WASM_SIMD_PROFILE.md": {
        "bytes": 8_688,
        "sha256": "9262770df160b1bf6ad4969cd536f6897660e21f43bc0b2cba28698a9b045ded",
    },
}

EXPECTED_REPOSITORY_INTEGRATION = {
    "aot_decision_doc": "docs/WASM_AOT_DECISION.md",
    "aot_readme": "benchmarks/wasm-aot-decision/README.md",
    "ci": ".github/workflows/ci.yml",
    "ci_step_name": "Verify the prospective fixed-QEMU WASM target/release policy",
    "float_profile_doc": "docs/WASM_FLOAT_PROFILE.md",
    "qualification_contract": (
        "acceptance/wasm-float-target/artifacts/"
        "c89-s3-fixed-qemu-qualification-v1-contract.json"
    ),
    "release_decision": (
        "acceptance/wasm-float-target/artifacts/c89-s3-release-decision.json"
    ),
    "pinned_files": EXPECTED_REPOSITORY_FILES,
    "roadmap": "docs/WASM_ROADMAP.md",
    "runtime_costs_doc": "docs/WASM_RUNTIME_COSTS.md",
    "runtime_costs_readme": "benchmarks/wasm-runtime/README.md",
    "simd_design_contract": (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-widening-design-v1-contract.json"
    ),
    "simd_executable_profile_doc": "docs/WASM_SIMD_EXECUTABLE_PROFILE.md",
    "simd_implementation_contract": (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-widening-implementation-v1-contract.json"
    ),
    "simd_containment_contract": (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-containment-corpus-v1-contract.json"
    ),
    "simd_admission_contract": (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-simd-admission-lifecycle-v1-contract.json"
    ),
    "simd_profile_doc": "docs/WASM_SIMD_PROFILE.md",
    "simd_qualification_contract": (
        "acceptance/wasm-simd-target/artifacts/"
        "c810-s5-fixed-qemu-qualification-v1-contract.json"
    ),
    "simd_review_decision": (
        "acceptance/wasm-simd-target/artifacts/c810-s5-review-decision.json"
    ),
    "simd_successor_design_contract": (
        "acceptance/wasm-simd-target/artifacts/"
        "c811-simd-successor-design-v1-contract.json"
    ),
    "simd_successor_implementation_contract": (
        "acceptance/wasm-simd-target/artifacts/"
        "c811-simd-successor-implementation-v1-contract.json"
    ),
    "simd_successor_qualification_contract": "acceptance/wasm-simd-target/artifacts/c811-s3-fixed-qemu-qualification-v1-contract.json",
    "simd_successor_release_decision": "acceptance/wasm-simd-target/artifacts/c811-s3-release-decision.json",
    "testing": "TESTING.md",
    "verification_commands": VERIFICATION_COMMANDS,
}

EXPECTED_SUCCESSOR_BOUNDARY = {
    "artifact_abi_allocated": False,
    "component_model_revision_selected": False,
    "core_wasm_revision_selected": False,
    "engine_identity_selected": False,
    "engine_supply_chain_selected": False,
    "execution_stage_selected": False,
    "global_policy_constrains_future_answer": True,
    "implementation_gate_open": False,
    "profile_code_allocated": False,
    "review_passed": False,
    "roadmap_node_allocated": False,
    "runtime_abi_allocated": False,
    "scope": "policy-checkpoint-effect-not-current-repository-state",
    "selects_successor_target_policy": False,
    "state": "unallocated",
    "successor_gate_selected": False,
    "target_release_evidence_question": "unresolved-blocking",
    "wit_world_selected": False,
}

EXPECTED_UNRELATED_HARDWARE_GATES = {
    "coverage_not_claimed": {
        "cache_dma_irq_or_device_reset": True,
        "dwc2_usb_hid_or_mass_storage": True,
        "dwmac_dhcp_tcp_or_ssh": True,
        "jitterentropy_or_device_host_key": True,
        "native_microsd_sdhci_or_storage": True,
        "physical_security_or_certification": True,
        "thermal_electrical_or_physical_soak": True,
    },
    "excluded_gate_classes": [
        "milkv-duo-board-bringup-and-boot",
        "native-microsd-sdhci-storage",
        "dwmac-dhcp-tcp-ssh-network",
        "dwc2-usb-hid-mass-storage",
        "jitterentropy-entropy-and-host-key",
        "cache-dma-irq-and-device-reset",
        "thermal-electrical-long-duration",
        "physical-security-and-certification",
    ],
    "fixed_qemu_may_satisfy_excluded_gates": False,
    "unchanged": True,
}

EXPECTED_LIMITATIONS = [
    (
        "This is an effective prospective gate policy, not target evidence, "
        "gate satisfaction, release authorization, or a physical-equivalence "
        "claim."
    ),
    (
        "The fixed baseline is emulator-scoped and by itself claims no "
        "multicore, network, storage, physical cache, DMA, entropy, thermal, "
        "electrical, or certification coverage."
    ),
    (
        "Every future allocated WASM target or release gate needs fresh "
        "node-specific source, suite, challenge, run, capture, acceptance "
        "predicates, and evidence."
    ),
    (
        "C8.3, C8.4, and C8.8-F5 historical members remain frozen in their "
        "original scopes and cannot be promoted into future gate evidence."
    ),
    (
        "Milk-V Duo testing remains paused; optional future observations are "
        "separate and have no gate, completion, or release effect."
    ),
    (
        "Unrelated board, device, entropy, physical-security, and "
        "certification gates remain unchanged."
    ),
    (
        "Artifact profile code 5 remains permanently validation-only and "
        "inert and cannot be promoted or migrated in place."
    ),
    (
        "This policy checkpoint itself allocates no successor identity, "
        "roadmap number, profile, ABI, engine, "
        "implementation, execution, admission, release, or production "
        "authority."
    ),
]

CHECK_OUTPUT = (
    "PASS verify-wasm-fixed-qemu-target-release-policy\n"
    "check_scope=prospective-wasm-roadmap-target-and-release-gates\n"
    "policy_effective=true\n"
    "contract_is_target_evidence=false\n"
    "current_target_release_gate_satisfied=false\n"
    "policy_checkpoint_successor_state=unallocated\n"
    "current_roadmap_position=c813-e3-qualified-sealed-reference-runtime-released\n"
    "physical_inputs_required=0\n"
    "physical_inputs_permitted=0\n"
    "duo_gate_effect=false\n"
)


class VerificationError(RuntimeError):
    """A fail-closed policy, integration, or provenance violation."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_integer(text: str) -> int:
    digits = text[1:] if text.startswith("-") else text
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        fail("JSON integer exceeds digit limit")
    return int(text)


def _reject_float(text: str) -> NoReturn:
    fail(f"JSON floating-point number is forbidden: {text}")


def _reject_constant(text: str) -> NoReturn:
    fail(f"non-finite JSON constant is forbidden: {text}")


def strict_json_loads(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not UTF-8: {exc}")
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except VerificationError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        fail(f"{label} is not strict JSON: {exc}")


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def strict_equal(actual: Any, expected: Any, label: str) -> None:
    if type(actual) is not type(expected):
        fail(
            f"{label} has type {type(actual).__name__}, expected "
            f"{type(expected).__name__}"
        )
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            fail(f"{label} keys differ: missing={missing}, extra={extra}")
        for key in expected:
            strict_equal(actual[key], expected[key], f"{label}.{key}")
        return
    if isinstance(expected, list):
        if len(actual) != len(expected):
            fail(f"{label} length differs")
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            strict_equal(actual_item, expected_item, f"{label}[{index}]")
        return
    if actual != expected:
        fail(f"{label} differs")


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _verify_direct_parent_chain(
    path: pathlib.Path, root: pathlib.Path, label: str
) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        fail(f"{label} escapes the repository root")
    cursor = root
    components = relative.parts[:-1]
    for component in components:
        cursor = cursor / component
        try:
            metadata = os.lstat(cursor)
        except OSError as exc:
            fail(f"cannot lstat {label} parent: {exc}")
        if not stat.S_ISDIR(metadata.st_mode):
            fail(f"{label} parent path component must be a real directory")


def stable_single_link_read(path: pathlib.Path, maximum: int, label: str) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        fail(f"cannot lstat {label}: {exc}")
    if not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be a regular file")
    if before.st_nlink != 1:
        fail(f"{label} must have exactly one hard link")
    if before.st_size > maximum:
        fail(f"{label} exceeds byte limit")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot securely open {label}: {exc}")
    try:
        opened = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(before):
            fail(f"{label} changed before open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                fail(f"{label} exceeds byte limit")
            chunks.append(chunk)
        after_fd = os.fstat(descriptor)
        if _stat_identity(after_fd) != _stat_identity(opened):
            fail(f"{label} changed while read")
    finally:
        os.close(descriptor)
    try:
        after_path = os.lstat(path)
    except OSError as exc:
        fail(f"cannot re-lstat {label}: {exc}")
    if _stat_identity(after_path) != _stat_identity(before):
        fail(f"{label} changed after read")
    return b"".join(chunks)


def stable_direct_read(
    path: pathlib.Path,
    maximum: int,
    label: str,
    *,
    root: pathlib.Path = ROOT,
) -> bytes:
    _verify_direct_parent_chain(path, root, label)
    return stable_single_link_read(path, maximum, label)


def decode_utf8(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not UTF-8: {exc}")


EXPECTED_C83_MEMBERS = {
    "duo_collector": {
        "bytes": 72_450,
        "git_blob": "ec31216a03f1ddfbdbd6228f5f07ee594cb3cc47",
        "git_mode": "100755",
        "path": "scripts/capture-c83-duo-runtime-costs.py",
        "sha256": "76000ef404a99e794d5175ea6119ef4b6c9bb825a0184c3b61e30e39d50611fe",
    },
    "evidence_verifier": {
        "bytes": 80_249,
        "git_blob": "2a563b2be545baa1f792230f4817e622d6665443",
        "git_mode": "100644",
        "path": "scripts/verify-c83-evidence.py",
        "sha256": "1f21ec3ce2f1fca326d109d60749c3adba5dfebddbecba9381483bff42206b3a",
    },
    "qemu_runner": {
        "bytes": 38_965,
        "git_blob": "5da6567ebd5cd8ac4b82f48018feebb3a5a013c4",
        "git_mode": "100755",
        "path": "scripts/qemu-c83-runtime-costs.py",
        "sha256": "588a9762f2da6cf419220921ad9481b696c11281183b6a3b65357b0db963cdc8",
    },
    "schema": {
        "bytes": 6_088,
        "git_blob": "1da588bd3c8c3f6b1572b3c1a73eef3c9167c8d4",
        "git_mode": "100644",
        "path": "benchmarks/wasm-runtime/schema-v1.json",
        "sha256": "4d36975acde2de015ef75e6ed402201da3d70f516d6d9f620adde08f3e11ed8d",
    },
    "source_verifier": {
        "bytes": 43_006,
        "git_blob": "7f8a62def8d0d9e856b017c1e47dbfe02a1ab639",
        "git_mode": "100644",
        "path": "scripts/verify-c83-runtime-costs.py",
        "sha256": "ee7efeabe9b2f2a85d3d5ccc665c378a542195540a40cac0912f80e08f77458d",
    },
    "workloads": {
        "bytes": 5_994,
        "git_blob": "61feee3a19dd394db1abcfef7e7dabfa5e9d1a58",
        "git_mode": "100644",
        "path": "benchmarks/wasm-runtime/workloads-v1.json",
        "sha256": "8b5bec7eacd2fd706b716b005af3a5a085730afdeb20839e905cf9177e70aeb4",
    },
}

EXPECTED_C84_AUDIT_MEMBERS = {
    "integrity_contract": {
        "bytes": 6_017,
        "git_blob": "d25bec68a27c88f5f67f0e79ef29e0f3232a0725",
        "git_mode": "100644",
        "path": (
            "benchmarks/wasm-aot-decision/qemu-v1-publication-integrity-contract.json"
        ),
        "sha256": "bb93cc7d72ff9d2e0425b1a7a105de9243b5ae0e3f08a232d35ea0c2eec6d745",
    },
    "integrity_verifier": {
        "bytes": 49_741,
        "git_blob": "2f1a236bf1dd0e4c5c39a3feb42a2389d5e3d330",
        "git_mode": "100644",
        "path": "scripts/verify-c84-qemu-published-evidence.py",
        "sha256": "ab7021d1451d5fecd6a85e490d402baf290917f35874972fbadea9323cae66c7",
    },
}

EXPECTED_F5_MEMBERS = {
    "contract": {
        "bytes": 14_364,
        "git_blob": "c8751d541269b485ea0786a66ced506d2902caf1",
        "git_mode": "100644",
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-qemu-target-gate-v1-contract.json"
        ),
        "sha256": "93b10e8311ce7794a923425018f834b3cc8b62eddf664285e8dc2a29aaedd1d9",
    },
    "decision": {
        "bytes": 16_608,
        "git_blob": "1f43528cbb95c5f5d9d3731db7aa19997bee3ca8",
        "git_mode": "100644",
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-qemu-target-gate-v1-decision.json"
        ),
        "sha256": "1d118cdb4f5709f4ce93331b1cd6b60435e6c530eb800e9c21e0a3e8569030d4",
    },
    "normal_receipt": {
        "bytes": 2_991,
        "git_blob": "9c130c15dfaaab29000f5bfbf64598d87fe86b99",
        "git_mode": "100644",
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-qemu-target-gate-v1-normal-receipt.json"
        ),
        "sha256": "4d70865a6a665829457ee0e9ec34c9fa38de51ed6ee2bcb2be1356d752355c1a",
    },
    "optimized_receipt": {
        "bytes": 3_000,
        "git_blob": "970cbaf51c5960c374654a78d6051da6efe4ce44",
        "git_mode": "100644",
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "qualification-qemu-target-gate-v1-optimized-receipt.json"
        ),
        "sha256": "4f95fcd2b4d2524b1d27fce7bbf77846f4f7d0030da8ebe277ffc062e53550e0",
    },
    "verifier": {
        "bytes": 164_132,
        "git_blob": "6a41c789612a1ba9136b85ba488f1eed941eaabb",
        "git_mode": "100644",
        "path": "scripts/verify-c88-f5-qemu-target-gate.py",
        "sha256": "cc3c486dfe4cb13d7cb0767dbce9f97f005e976bbeed05dc66a17dee405a9a87",
    },
}

EXPECTED_SUCCESSOR_MEMBERS = {
    "contract": {
        "bytes": 9_885,
        "git_blob": "52937bdac374f5cb852f88a5faae3ad27e7e47fb",
        "git_mode": "100644",
        "path": (
            "acceptance/wasm-float-target/artifacts/"
            "float-successor-review-boundary-v1-contract.json"
        ),
        "sha256": "963c776ec5c1e6a7fa60f97b89b52a78a1857c6154718fbff906c5e59d8b2fe8",
    },
    "verifier": {
        "bytes": 42_675,
        "git_blob": "1a2aa19b6eadeb48192418eb6234a5f6ff32dd51",
        "git_mode": "100644",
        "path": "scripts/verify-c88-float-successor-review-boundary.py",
        "sha256": "ecc7f661b9ca4789a33a23f8bef8615d6c3fa810a1955f4dec3de21f99339b45",
    },
}


def validate_history(history: Any) -> None:
    require(type(history) is dict, "historical_boundaries must be an object")
    require(
        set(history)
        == {"c1_through_c82", "c83", "c84", "c88_f5", "successor_charter"},
        "historical_boundaries keys differ",
    )

    strict_equal(
        history["c1_through_c82"],
        {
            "current_policy_reopens_nodes": False,
            "individual_node_rewalk_required": False,
            "rerun_required": False,
            "retroactive_rewrite": False,
            "status": "accepted-complete-by-historical-evidence-policy",
        },
        "historical_boundaries.c1_through_c82",
    )

    c83 = history["c83"]
    require(type(c83) is dict, "historical_boundaries.c83 must be an object")
    strict_equal(
        c83.get("status"),
        "accepted-complete-by-historical-evidence-policy",
        "historical_boundaries.c83.status",
    )
    strict_equal(
        c83.get("rerun_required"), False, "historical_boundaries.c83.rerun_required"
    )
    strict_equal(
        c83.get("retroactive_rewrite"),
        False,
        "historical_boundaries.c83.retroactive_rewrite",
    )
    strict_equal(
        c83.get("current_policy_reclassifies_historical_evidence"),
        False,
        "historical_boundaries.c83.current_policy_reclassifies_historical_evidence",
    )
    strict_equal(
        c83.get("original_contract_physical_requirements_remain_historical"),
        True,
        "historical_boundaries.c83.original_contract_physical_requirements_remain_historical",
    )
    strict_equal(
        c83.get("preparation"),
        {
            "commit": "1a65ce75ef46210f89268a74ed8afc4e7c6b79fd",
            "must_be_ancestor_of_checked_head": True,
            "tree": "b07c7fbcf4a2672264cf6c5a65e52dece81aa2d7",
        },
        "historical_boundaries.c83.preparation",
    )
    strict_equal(
        c83.get("pinned_preparation_members"),
        EXPECTED_C83_MEMBERS,
        "historical_boundaries.c83.pinned_preparation_members",
    )
    require(
        set(c83)
        == {
            "current_policy_reclassifies_historical_evidence",
            "original_contract_physical_requirements_remain_historical",
            "pinned_preparation_members",
            "preparation",
            "rerun_required",
            "retroactive_rewrite",
            "status",
        },
        "historical_boundaries.c83 keys differ",
    )

    c84 = history["c84"]
    require(type(c84) is dict, "historical_boundaries.c84 must be an object")
    expected_c84 = {
        "aot_authorized": False,
        "audit": {
            "commit": "25111e04d3d1aa55e52bb29d05b66d0bfde087a3",
            "must_be_ancestor_of_checked_head": True,
            "pinned_members": EXPECTED_C84_AUDIT_MEMBERS,
            "tree": "800952738c5d2a0a547163cfa7e77acd48656479",
        },
        "historical_next_node": "C8.8-skip-or-defer-C8.5-C8.7",
        "native_code_accepted": False,
        "outcome": "aot-not-justified-on-fixed-qemu",
        "publication": {
            "commit": "cbb1d0fb0261377b848b218c9a31f862f7ec42ed",
            "tree": "72a21b59dc563e193185aa8a2d60f4ee0c6df850",
        },
        "replacement_scope": "c84-only",
        "run_id": "a22f28ef7aab11de5c4858e9a4e4c5b5b4e6e763c43a126ad84d4ac80b9f500f",
        "source": {
            "commit": "e950a2facb6a6c230e67becb186bddf34a5924bb",
            "tree": "235541126f0e8445ee5a884985db4ccd9bb24104",
        },
        "status": "complete-for-selected-workload-by-formal-fixed-qemu-evidence",
    }
    strict_equal(c84, expected_c84, "historical_boundaries.c84")

    f5 = history["c88_f5"]
    require(type(f5) is dict, "historical_boundaries.c88_f5 must be an object")
    expected_f5 = {
        "completion_scope": "c88-f5-float-widening-only",
        "contract_member_required_at_source_and_publication": True,
        "decision_id": "1841ae06e4c8bef4842a59bbc65362fa860e37d6d8a1d79cc68e3fc5a87004f9",
        "pinned_publication_members": EXPECTED_F5_MEMBERS,
        "publication": {
            "commit": "5a6e88407056fdfed0974586479b42b5bd1470fb",
            "must_be_ancestor_of_checked_head": True,
            "tree": "d296000b1ba170aaafcbd7e8ca4f689c119b9921",
        },
        "replacement_scope": "c88-f5-only",
        "run_id": "53c9f7ed099c371724867d060c3994cb4b3ad93d46404156f40914d7f3b30254",
        "semantic_sha256": "51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1",
        "source": {
            "commit": "0f06212f890077b2a3d1b4405a128058cb07c55e",
            "tree": "a3a3ef403b80eb51e60dd3cb6a2a5b5a6d3aed6d",
        },
        "status": "complete-by-formal-fixed-qemu-evidence",
    }
    strict_equal(f5, expected_f5, "historical_boundaries.c88_f5")

    successor = history["successor_charter"]
    expected_successor = {
        "pinned_publication_members": EXPECTED_SUCCESSOR_MEMBERS,
        "publication": {
            "commit": "180393e53eff1be66b2d3be1ff26779d831c8865",
            "must_be_ancestor_of_checked_head": True,
            "tree": "9a6d2ec94d8785bdda6f985b882cc90e239641bd",
        },
        "roadmap_position": "post-c88-f5-pre-allocation",
        "state": "unallocated",
        "status": "review-charter-not-design-decision-not-evidence",
    }
    strict_equal(
        successor,
        expected_successor,
        "historical_boundaries.successor_charter",
    )


def validate_contract_object(contract: Any) -> None:
    require(type(contract) is dict, "contract root must be an object")
    if set(contract) != ROOT_KEYS:
        missing = sorted(ROOT_KEYS - set(contract))
        extra = sorted(set(contract) - ROOT_KEYS)
        fail(f"contract root keys differ: missing={missing}, extra={extra}")
    strict_equal(
        contract["schema"],
        "vibeos.wasm.fixed-qemu-target-release-policy-v1.contract",
        "contract.schema",
    )
    strict_equal(contract["version"], 1, "contract.version")
    strict_equal(
        contract["scope"],
        "prospective-wasm-roadmap-target-and-release-gates",
        "contract.scope",
    )
    strict_equal(
        contract["status"],
        "effective-policy-not-target-evidence-not-release-authorization",
        "contract.status",
    )
    strict_equal(
        contract["roadmap_position"],
        "post-c88-f5-pre-allocation",
        "contract.roadmap_position",
    )
    strict_equal(
        contract["application_status"],
        EXPECTED_APPLICATION_STATUS,
        "application_status",
    )
    strict_equal(contract["authority"], EXPECTED_AUTHORITY, "authority")
    strict_equal(contract["code5_boundary"], EXPECTED_CODE5_BOUNDARY, "code5_boundary")
    strict_equal(
        contract["contract_verifier"],
        EXPECTED_CONTRACT_VERIFIER,
        "contract_verifier",
    )
    strict_equal(
        contract["duo_observation"], EXPECTED_DUO_OBSERVATION, "duo_observation"
    )
    strict_equal(contract["effectivity"], EXPECTED_EFFECTIVITY, "effectivity")
    strict_equal(
        contract["evidence_non_promotion"],
        EXPECTED_EVIDENCE_NON_PROMOTION,
        "evidence_non_promotion",
    )
    strict_equal(
        contract["fixed_qemu_gate"], EXPECTED_FIXED_QEMU_GATE, "fixed_qemu_gate"
    )
    validate_history(contract["historical_boundaries"])
    strict_equal(contract["limitations"], EXPECTED_LIMITATIONS, "limitations")
    strict_equal(contract["policy_basis"], EXPECTED_POLICY_BASIS, "policy_basis")
    strict_equal(
        contract["policy_checkpoint"],
        EXPECTED_POLICY_CHECKPOINT,
        "policy_checkpoint",
    )
    strict_equal(
        contract["repository_integration"],
        EXPECTED_REPOSITORY_INTEGRATION,
        "repository_integration",
    )
    strict_equal(
        contract["successor_boundary"],
        EXPECTED_SUCCESSOR_BOUNDARY,
        "successor_boundary",
    )
    strict_equal(
        contract["unrelated_hardware_gates"],
        EXPECTED_UNRELATED_HARDWARE_GATES,
        "unrelated_hardware_gates",
    )
    semantic_hash = hashlib.sha256(canonical_json_bytes(contract)).hexdigest()
    if semantic_hash != EXPECTED_CONTRACT_SHA256:
        fail("contract semantic content differs from verifier pin")


def decode_contract_bytes(data: bytes, *, require_identity: bool) -> dict[str, Any]:
    if require_identity:
        if len(data) != EXPECTED_CONTRACT_BYTES:
            fail("contract byte count differs from verifier pin")
        if hashlib.sha256(data).hexdigest() != EXPECTED_CONTRACT_SHA256:
            fail("contract SHA-256 differs from verifier pin")
    contract = strict_json_loads(data, "contract")
    validate_contract_object(contract)
    if canonical_json_bytes(contract) != data:
        fail("contract is not canonical sorted indented JSON")
    return contract


def _git_environment() -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    if "PATH" in os.environ:
        environment["PATH"] = os.environ["PATH"]
    if "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return environment


def git_run(
    arguments: list[str],
    *,
    allowed_codes: set[int] | None = None,
    maximum_stdout: int = MAX_GIT_BLOB_BYTES,
) -> tuple[int, bytes]:
    if allowed_codes is None:
        allowed_codes = {0}
    git = shutil.which("git", path=os.environ.get("PATH"))
    if git is None:
        fail("git executable not found")
    command = [
        git,
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-C",
        str(ROOT),
        *arguments,
    ]
    with (
        tempfile.TemporaryFile() as stdout_file,
        tempfile.TemporaryFile() as stderr_file,
    ):
        try:
            completed = subprocess.run(
                command,
                check=False,
                env=_git_environment(),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            fail(f"Git command failed to execute: {exc}")
        stdout_size = stdout_file.tell()
        stderr_size = stderr_file.tell()
        if stdout_size > maximum_stdout:
            fail("Git stdout exceeds byte limit")
        if stderr_size > 64 * 1024:
            fail("Git stderr exceeds byte limit")
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read()
        stderr = stderr_file.read()
    if completed.returncode not in allowed_codes:
        detail = stderr.decode("utf-8", "replace").strip()
        fail(
            f"Git command exited {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    return completed.returncode, stdout


def git_line(arguments: list[str], label: str) -> str:
    _, output = git_run(arguments, maximum_stdout=4096)
    try:
        text = output.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{label} Git output is not ASCII")
    if not text.endswith("\n") or text.count("\n") != 1:
        fail(f"{label} Git output is not one line")
    return text[:-1]


def verify_commit_tree(commit: str, expected_tree: str, label: str) -> None:
    resolved_commit = git_line(
        ["rev-parse", "--verify", f"{commit}^{{commit}}"], f"{label} commit"
    )
    if resolved_commit != commit:
        fail(f"{label} commit identity differs")
    resolved_tree = git_line(
        ["rev-parse", "--verify", f"{commit}^{{tree}}"], f"{label} tree"
    )
    if resolved_tree != expected_tree:
        fail(f"{label} tree identity differs")


def verify_ancestor(ancestor: str, descendant: str, label: str) -> None:
    code, output = git_run(
        ["merge-base", "--is-ancestor", ancestor, descendant],
        allowed_codes={0, 1},
        maximum_stdout=0,
    )
    if output:
        fail(f"{label} ancestry check produced stdout")
    if code != 0:
        fail(f"{label} is not an ancestor of checked HEAD")


def git_blob_at_commit(commit: str, identity: dict[str, Any], label: str) -> bytes:
    path = identity["path"]
    _, tree_entry = git_run(["ls-tree", "-z", commit, "--", path], maximum_stdout=4096)
    expected_entry = (
        f"{identity['git_mode']} blob {identity['git_blob']}\t{path}\0"
    ).encode("utf-8")
    if tree_entry != expected_entry:
        fail(f"{label} Git mode/blob membership differs")
    blob = git_line(["rev-parse", "--verify", f"{commit}:{path}"], f"{label} blob")
    if blob != identity["git_blob"]:
        fail(f"{label} Git blob identity differs")
    object_type = git_line(["cat-file", "-t", blob], f"{label} object type")
    if object_type != "blob":
        fail(f"{label} object is not a blob")
    _, data = git_run(["cat-file", "blob", blob], maximum_stdout=identity["bytes"] + 1)
    if len(data) != identity["bytes"]:
        fail(f"{label} byte count differs")
    if hashlib.sha256(data).hexdigest() != identity["sha256"]:
        fail(f"{label} SHA-256 differs")
    return data


def verify_historical_git(contract: dict[str, Any]) -> None:
    head = git_line(["rev-parse", "--verify", "HEAD^{commit}"], "checked HEAD")
    history = contract["historical_boundaries"]

    c83 = history["c83"]
    c83_commit = c83["preparation"]["commit"]
    verify_commit_tree(c83_commit, c83["preparation"]["tree"], "C8.3 preparation")
    verify_ancestor(c83_commit, head, "C8.3 preparation")
    for name, identity in c83["pinned_preparation_members"].items():
        git_blob_at_commit(c83_commit, identity, f"C8.3 {name}")

    c84 = history["c84"]
    for name in ("source", "publication", "audit"):
        identity = c84[name]
        verify_commit_tree(identity["commit"], identity["tree"], f"C8.4 {name}")
        verify_ancestor(identity["commit"], head, f"C8.4 {name}")
    for name, identity in c84["audit"]["pinned_members"].items():
        git_blob_at_commit(c84["audit"]["commit"], identity, f"C8.4 {name}")

    f5 = history["c88_f5"]
    for name in ("source", "publication"):
        identity = f5[name]
        verify_commit_tree(identity["commit"], identity["tree"], f"F5 {name}")
        verify_ancestor(identity["commit"], head, f"F5 {name}")
    for name, identity in f5["pinned_publication_members"].items():
        git_blob_at_commit(f5["publication"]["commit"], identity, f"F5 {name}")
    git_blob_at_commit(
        f5["source"]["commit"],
        f5["pinned_publication_members"]["contract"],
        "F5 source contract",
    )

    successor = history["successor_charter"]
    successor_commit = successor["publication"]["commit"]
    verify_commit_tree(
        successor_commit,
        successor["publication"]["tree"],
        "successor charter publication",
    )
    verify_ancestor(successor_commit, head, "successor charter publication")
    for name, identity in successor["pinned_publication_members"].items():
        git_blob_at_commit(successor_commit, identity, f"successor charter {name}")

    basis = contract["policy_basis"]
    verify_commit_tree(basis["commit"], basis["tree"], "policy basis")
    verify_ancestor(basis["commit"], head, "policy basis")


POLICY_HEADING = (
    "### Fixed-QEMU target/release policy v1 "
    "(policy checkpoint; not a roadmap implementation node)"
)
POLICY_CONTRACT_LINK = (
    "[`fixed-qemu-target-release-policy-v1-contract.json`]"
    "(../acceptance/wasm-roadmap/artifacts/"
    "fixed-qemu-target-release-policy-v1-contract.json)"
)
ROADMAP_STATUS = "**Status (2026-08-30): implementation in progress.**"
ROADMAP_STATUS_PREFIX = (
    "# Component Model admitted-code roadmap\n\n"
    "This document defines the dependency order, security invariants, acceptance\n"
    "gates, and compatibility boundaries for admitting WebAssembly components into\n"
    "VibeOS. It complements [BLUEPRINT.md](BLUEPRINT.md),\n"
    "[CAPABILITY_SHELL.md](CAPABILITY_SHELL.md), and\n"
    "[PROGRAM_PERSISTENCE.md](PROGRAM_PERSISTENCE.md).\n\n"
    + ROADMAP_STATUS
)
EXPECTED_POLICY_SECTION_BYTES = 2_296
EXPECTED_POLICY_SECTION_SHA256 = (
    "0e9a24bbe393c3008d7c5541d26a1d6de81976b8188eb83312104af6c8a51cd5"
)
ROADMAP_POLICY_MARKERS = (
    (
        "The policy checkpoint roadmap position is "
        "`post-c88-f5-pre-allocation`."
    ),
    "The policy scope is `prospective-wasm-roadmap-target-and-release-gates`.",
    "The policy contract is not target evidence and satisfies no target or release gate.",
    (
        "The normative generic WASM target/release gate is fresh, source-bound "
        "fixed QEMU on `qemu-virt-rv64-tcg-icount-v1`."
    ),
    (
        "Fresh node-specific source, suite, challenge, run, capture, acceptance "
        "predicates, and evidence remain mandatory."
    ),
    "Historical C8.4 and C8.8-F5 QEMU evidence cannot satisfy a future gate.",
    (
        "Milk-V Duo remains paused and optional; any later observation is "
        "separate and has no gate, completion, or release effect."
    ),
    "Code 5 remains permanently `ValidationOnly` and inert.",
    (
        "No successor identity, roadmap number, profile, ABI, engine, "
        "implementation, execution, admission, release, or production authority "
        "is allocated by this policy."
    ),
    (
        "Unrelated board, device, entropy, physical-security, and certification "
        "gates remain unchanged."
    ),
)
ROADMAP_C83_ROW = (
    "| C8.3 | Publish runtime costs | Report validation, startup, lift/lower, "
    "async, composition, host-call, memory, fuel and cancellation/revocation "
    "costs on fixed QEMU and physical-Duo baselines |"
)
ROADMAP_F5_ROW = (
    "| C8.8-F5 | Qualify targets and review activation | Host and the formal "
    "fixed-QEMU normal/optimized matrix pass 1,176 exact-bit/fuel records; fixed "
    "QEMU replaces the physical-Duo exit requirement for this gate only, and "
    "completion opens only design review for a separately numbered, unallocated "
    "successor |"
)
FIXED_QEMU_MATRIX_ROW = (
    "| Formal fixed-QEMU WASM target/release gate | Fresh source-bound, "
    "node-specific validation, execution, lifecycle, quota, fault, restart, and "
    "soak evidence on pinned emulator profiles | Physical cache/DMA, native "
    "microSD/DWMAC/USB/entropy, thermal/electrical behavior, physical security, "
    "and certification |"
)
OPTIONAL_DUO_MATRIX_ROW = (
    "| Optional Milk-V Duo observation (paused) | Separately scoped observations "
    "only; never a target/release gate input or completion condition | No generic "
    "WASM gate, completion, or release effect |"
)
FIXED_QEMU_METRIC = "- fixed-QEMU target/release soak duration, restart count, and exact baseline identity;"
OPTIONAL_DUO_METRIC = (
    "- optional physical-Duo observations, if collected, reported separately "
    "with no gate effect;"
)
FIXED_QEMU_DOD = (
    "fuzzers, self-tests, four-hart QEMU gates, and every applicable fresh "
    "fixed-QEMU target/release gate are green on pinned tools."
)

TESTING_POLICY_COMMENT_1 = (
    "# Prospective fixed-QEMU WASM target/release policy; static contract checks only."
)
TESTING_POLICY_COMMENT_2 = (
    "# These commands run no QEMU or Duo, satisfy no target or release gate, "
    "and allocate no successor."
)
TESTING_POLICY_HEADING = "## Fixed-QEMU target/release policy v1"
TESTING_RETAINED_HEADING = "## Retained C8.4 implementation notes"
TESTING_NORMATIVE_MARKER = (
    "This section and the canonical contract are normative for this policy; "
    "no other prose in `TESTING.md` can override them."
)
EXPECTED_TESTING_POLICY_SECTION_BYTES = 1_927
EXPECTED_TESTING_POLICY_SECTION_SHA256 = (
    "73ed19176541159ca498516b20c208058dd80dcd80253cc1391212e15fef55fd"
)
TESTING_POLICY_BLOCK = (
    TESTING_POLICY_COMMENT_1
    + "\n"
    + TESTING_POLICY_COMMENT_2
    + "\n"
    + "\n".join(VERIFICATION_COMMANDS)
    + "\n"
)

CI_STEP_NAME = "Verify the prospective fixed-QEMU WASM target/release policy"
CI_POLICY_STEP = (
    f"      - name: {CI_STEP_NAME}\n"
    "        # Policy/contract integrity only: this step runs no QEMU or Duo and\n"
    "        # itself satisfies no gate. C8.9 qualification is verified separately.\n"
    "        run: |\n"
    f"          {VERIFICATION_COMMANDS[0]}\n"
    f"          {VERIFICATION_COMMANDS[1]}\n"
    f"          {VERIFICATION_COMMANDS[2]}\n"
    f"          {VERIFICATION_COMMANDS[3]}\n"
)

C83_STATUS_MARKER = (
    "C8.3 is accepted complete by historical-evidence policy and is not being rerun."
)
C1_C82_STATUS_MARKER = (
    "C1 through C8.2 remain accepted complete by historical-evidence policy; "
    "none is reopened, rerun, or individually rewalked."
)
C83_HISTORICAL_CONTRACT_MARKER = (
    "The fixed-QEMU plus three-cold-boot Duo text below is the original v1 "
    "publication contract, not a current physical prerequisite or a new "
    "publication claim."
)
C84_HISTORICAL_NEXT_MARKER = (
    "The immutable historical C8.4 `next_node` value is "
    "`C8.8-skip-or-defer-C8.5-C8.7`; it is not the repository's current position."
)
CURRENT_POSITION_MARKER = (
    "The current roadmap position is "
    "`c813-e3-qualified-sealed-reference-runtime-released`;"
)
FLOAT_NON_PROMOTION_MARKER = (
    "The C8.8-F5 replacement remains scoped to F5 only; the independent "
    "prospective fixed-QEMU target/release policy does not reclassify or promote "
    "F5 evidence."
)
STALE_CURRENT_NODE_MARKER = "current implementation node is C8.8"
C83_FORMAL_CI_STEP = "      - name: Exercise the fixed-QEMU C8.3 publication contract"
C83_QEMU_RUNNER_BASENAME = "qemu-c83-runtime-costs.py"
C83_ACTIVE_SMOKE_COMMAND = (
    "python3 -B ./scripts/qemu-c83-runtime-costs.py --allow-dirty-smoke"
)
FORBIDDEN_DOCUMENT_CLAIMS = (
    (r"\bc1 through c8\.2 are reopened\b", "C1-C8.2 reopened"),
    (
        r"\bc1 through c8\.2\b[^.]{0,120}\brequire(?:s|d)? "
        r"(?:individual )?reruns?\b",
        "C1-C8.2 rerun required",
    ),
    (r"\bc8\.3 is incomplete\b", "C8.3 reopened"),
    (r"\bc8\.3\b[^.]{0,120}\bmust be rerun\b", "C8.3 rerun required"),
    (
        r"\bc8\.3\b[^.]{0,160}\bmust be[^.]{0,80}\bbackfill(?:ed)?\b",
        "C8.3 backfill required",
    ),
    (r"\bmilk-v duo is mandatory\b", "Milk-V Duo made mandatory"),
    (
        r"\bmilk-v duo\b[^.]{0,120}\b(?<!not )(?<!never )"
        r"blocks? (?:completion|release)\b",
        "Milk-V Duo made blocking",
    ),
    (
        r"\bhistorical c8\.4 and c8\.8-f5\b[^.]{0,160}"
        r"\b(?:may|can|does|will) satisfy\b[^.]{0,100}\bfuture gates?\b",
        "historical QEMU evidence promoted",
    ),
    (
        r"\bf5 evidence satisfies every future (?:target )?gate\b",
        "F5 evidence promoted",
    ),
    (r"\bcode 5 is executable\b", "Code 5 made executable"),
    (r"\bcode 5 is current\b", "Code 5 made current"),
    (
        r"\bthis checkpoint allocates c[0-9]+(?:\.[0-9]+)*\b",
        "successor roadmap number allocated",
    ),
    (
        r"\bthis (?:checkpoint|policy) authorizes production\b",
        "production authority granted",
    ),
)


@dataclass(frozen=True)
class RepositoryInputs:
    roadmap: str
    testing: str
    ci: str
    runtime_costs_doc: str
    runtime_costs_readme: str
    aot_decision_doc: str
    aot_readme: str
    float_profile_doc: str


def _read_repository_text(relative: str, label: str) -> str:
    path = ROOT / relative
    data = stable_direct_read(path, MAX_DOCUMENT_BYTES, label)
    return decode_utf8(data, label)


def load_repository_inputs() -> RepositoryInputs:
    return RepositoryInputs(
        roadmap=_read_repository_text("docs/WASM_ROADMAP.md", "WASM roadmap"),
        testing=_read_repository_text("TESTING.md", "TESTING"),
        ci=_read_repository_text(".github/workflows/ci.yml", "CI workflow"),
        runtime_costs_doc=_read_repository_text(
            "docs/WASM_RUNTIME_COSTS.md", "runtime-costs document"
        ),
        runtime_costs_readme=_read_repository_text(
            "benchmarks/wasm-runtime/README.md", "runtime-costs README"
        ),
        aot_decision_doc=_read_repository_text(
            "docs/WASM_AOT_DECISION.md", "AOT decision document"
        ),
        aot_readme=_read_repository_text(
            "benchmarks/wasm-aot-decision/README.md", "AOT decision README"
        ),
        float_profile_doc=_read_repository_text(
            "docs/WASM_FLOAT_PROFILE.md", "Float profile document"
        ),
    )


def normalized(value: str) -> str:
    return " ".join(value.split())


def require_normalized_marker(value: str, marker: str, label: str) -> None:
    normalized_value = normalized(value)
    normalized_marker = normalized(marker)
    count = normalized_value.count(normalized_marker)
    if count != 1:
        fail(f"{label} marker count differs: {count}")


def extract_heading_section(value: str, heading: str, label: str) -> str:
    header = heading + "\n"
    if value.count(header) != 1:
        fail(f"{label} heading count differs")
    start = value.index(header)
    match = re.search(r"(?m)^## (?=[^#])", value[start + len(header) :])
    end = len(value) if match is None else start + len(header) + match.start()
    return value[start:end]


def extract_named_ci_step(ci: str, name: str) -> str:
    header = f"      - name: {name}\n"
    if ci.count(header) != 1:
        fail("CI policy step count differs")
    start = ci.index(header)
    following = re.search(r"(?m)^      - name: ", ci[start + len(header) :])
    if following is None:
        following_job = re.search(
            r"(?m)^  [a-zA-Z0-9_-]+:\n", ci[start + len(header) :]
        )
        end = (
            len(ci)
            if following_job is None
            else start + len(header) + following_job.start()
        )
    else:
        end = start + len(header) + following.start()
    return ci[start:end].rstrip("\n") + "\n"


def verify_roadmap(
    roadmap: str, *, require_policy_section_identity: bool = True
) -> None:
    require(
        roadmap.startswith(ROADMAP_STATUS_PREFIX)
        and roadmap.count(ROADMAP_STATUS) == 1,
        "roadmap top-level implementation status differs",
    )
    section = extract_heading_section(roadmap, POLICY_HEADING, "roadmap policy")
    require_normalized_marker(
        section, POLICY_CONTRACT_LINK, "roadmap policy contract link"
    )
    for marker in ROADMAP_POLICY_MARKERS:
        require_normalized_marker(section, marker, "roadmap policy")
    require_normalized_marker(roadmap, ROADMAP_C83_ROW, "roadmap historical C8.3 row")
    require_normalized_marker(roadmap, ROADMAP_F5_ROW, "roadmap historical F5 row")
    require_normalized_marker(
        roadmap, C1_C82_STATUS_MARKER, "roadmap C1-C8.2 historical status"
    )
    require_normalized_marker(
        roadmap,
        "The fixed-QEMU replacement remains scoped to C8.8-F5.",
        "roadmap historical F5 scope",
    )

    matrix_start = roadmap.find("## 10. Test and evidence matrix\n")
    metrics_start = roadmap.find("## 11. Metrics and release budgets\n")
    if matrix_start < 0 or metrics_start <= matrix_start:
        fail("roadmap test/evidence matrix boundaries differ")
    matrix = roadmap[matrix_start:metrics_start]
    if "| Physical Duo gate |" in matrix:
        fail("roadmap restores a mandatory generic Physical Duo gate")
    require_normalized_marker(
        matrix, FIXED_QEMU_MATRIX_ROW, "roadmap fixed-QEMU matrix"
    )
    require_normalized_marker(
        matrix, OPTIONAL_DUO_MATRIX_ROW, "roadmap optional-Duo matrix"
    )

    risk_start = roadmap.find("## 12. Risk register\n")
    if risk_start <= metrics_start:
        fail("roadmap metrics boundaries differ")
    metrics = roadmap[metrics_start:risk_start]
    require_normalized_marker(metrics, FIXED_QEMU_METRIC, "roadmap fixed-QEMU metric")
    require_normalized_marker(
        metrics, OPTIONAL_DUO_METRIC, "roadmap optional-Duo metric"
    )

    dod_start = roadmap.find("## 13. Definition of done for Component v1\n")
    reference_start = roadmap.find(
        "## 14. Reference specifications and candidate tooling\n"
    )
    if dod_start < 0 or reference_start <= dod_start:
        fail("roadmap definition-of-done boundaries differ")
    dod = roadmap[dod_start:reference_start]
    require_normalized_marker(
        dod, FIXED_QEMU_DOD, "roadmap fixed-QEMU definition of done"
    )
    if "physical-Duo gate are green" in dod or "physical Duo gate are green" in dod:
        fail("roadmap definition of done restores a mandatory Physical Duo gate")
    if STALE_CURRENT_NODE_MARKER.lower() in roadmap.lower():
        fail("roadmap restores stale current implementation node C8.8")
    if require_policy_section_identity:
        section_bytes = section.encode("utf-8")
        require(
            len(section_bytes) == EXPECTED_POLICY_SECTION_BYTES,
            "roadmap policy section byte count differs",
        )
        require(
            hashlib.sha256(section_bytes).hexdigest()
            == EXPECTED_POLICY_SECTION_SHA256,
            "roadmap policy section SHA-256 differs",
        )


def verify_testing(
    testing: str, *, require_policy_section_identity: bool = True
) -> None:
    section = extract_heading_section(
        testing, TESTING_POLICY_HEADING, "TESTING policy"
    )
    require_normalized_marker(
        section, TESTING_NORMATIVE_MARKER, "TESTING normative policy"
    )
    if testing.count(TESTING_RETAINED_HEADING + "\n") != 1:
        fail("TESTING retained-notes heading differs")
    if testing.count(TESTING_POLICY_BLOCK) != 1:
        fail("TESTING policy command block differs")
    for command in VERIFICATION_COMMANDS:
        count = testing.count(command)
        if count != 1:
            fail(f"TESTING policy command count differs for {command!r}: {count}")
    for marker, label in (
        (C1_C82_STATUS_MARKER, "TESTING C1-C8.2 historical status"),
        (C83_STATUS_MARKER, "TESTING C8.3 historical status"),
        (C83_HISTORICAL_CONTRACT_MARKER, "TESTING C8.3 historical contract"),
        (C84_HISTORICAL_NEXT_MARKER, "TESTING C8.4 historical next-node"),
        (CURRENT_POSITION_MARKER, "TESTING current roadmap position"),
        (FLOAT_NON_PROMOTION_MARKER, "TESTING F5 non-promotion"),
    ):
        require_normalized_marker(testing, marker, label)
    if STALE_CURRENT_NODE_MARKER.lower() in testing.lower():
        fail("TESTING restores stale current implementation node C8.8")
    if C83_QEMU_RUNNER_BASENAME in testing:
        fail("TESTING restores active C8.3 QEMU execution")
    if require_policy_section_identity:
        section_bytes = section.encode("utf-8")
        require(
            len(section_bytes) == EXPECTED_TESTING_POLICY_SECTION_BYTES,
            "TESTING policy section byte count differs",
        )
        require(
            hashlib.sha256(section_bytes).hexdigest()
            == EXPECTED_TESTING_POLICY_SECTION_SHA256,
            "TESTING policy section SHA-256 differs",
        )


def verify_ci(ci: str) -> None:
    actual = extract_named_ci_step(ci, CI_STEP_NAME)
    if actual != CI_POLICY_STEP:
        fail("CI policy step differs or can be bypassed")
    for command in VERIFICATION_COMMANDS:
        count = ci.count(command)
        if count != 1:
            fail(f"CI policy command count differs for {command!r}: {count}")
    forbidden = ("if:", "continue-on-error", "|| true", "; true", "PYTHONOPTIMIZE")
    for token in forbidden:
        if token in actual:
            fail(f"CI policy step admits bypass token {token!r}")
    if C83_FORMAL_CI_STEP in ci or C83_QEMU_RUNNER_BASENAME in ci:
        fail("CI restores the historical C8.3 formal QEMU campaign")


def verify_history_documents(inputs: RepositoryInputs) -> None:
    for value, label in (
        (inputs.runtime_costs_doc, "runtime-costs document"),
        (inputs.runtime_costs_readme, "runtime-costs README"),
        (inputs.aot_decision_doc, "AOT decision document"),
        (inputs.aot_readme, "AOT decision README"),
        (inputs.float_profile_doc, "Float profile document"),
    ):
        require_normalized_marker(
            value, C1_C82_STATUS_MARKER, f"{label} C1-C8.2 historical status"
        )

    for value, label in (
        (inputs.runtime_costs_doc, "runtime-costs document"),
        (inputs.runtime_costs_readme, "runtime-costs README"),
    ):
        require_normalized_marker(value, C83_STATUS_MARKER, f"{label} C8.3 status")
        require_normalized_marker(
            value, C83_HISTORICAL_CONTRACT_MARKER, f"{label} historical contract"
        )

    for value, label in (
        (inputs.aot_decision_doc, "AOT decision document"),
        (inputs.aot_readme, "AOT decision README"),
    ):
        require_normalized_marker(
            value, C84_HISTORICAL_NEXT_MARKER, f"{label} historical next-node"
        )
        require_normalized_marker(
            value, CURRENT_POSITION_MARKER, f"{label} current roadmap position"
        )
        if STALE_CURRENT_NODE_MARKER.lower() in value.lower():
            fail(f"{label} restores stale current implementation node C8.8")

    require_normalized_marker(
        inputs.float_profile_doc,
        FLOAT_NON_PROMOTION_MARKER,
        "Float profile F5 non-promotion",
    )


def verify_no_forbidden_document_claims(inputs: RepositoryInputs) -> None:
    for field in (
        "roadmap",
        "testing",
        "runtime_costs_doc",
        "runtime_costs_readme",
        "aot_decision_doc",
        "aot_readme",
        "float_profile_doc",
    ):
        value = normalized(getattr(inputs, field)).lower()
        for pattern, claim in FORBIDDEN_DOCUMENT_CLAIMS:
            if re.search(pattern, value):
                fail(f"{field} contains forbidden policy claim: {claim}")


def verify_repository_file_identities(inputs: RepositoryInputs) -> None:
    field_paths = (
        ("ci", ".github/workflows/ci.yml"),
        ("testing", "TESTING.md"),
        ("aot_readme", "benchmarks/wasm-aot-decision/README.md"),
        ("runtime_costs_readme", "benchmarks/wasm-runtime/README.md"),
        ("aot_decision_doc", "docs/WASM_AOT_DECISION.md"),
        ("float_profile_doc", "docs/WASM_FLOAT_PROFILE.md"),
        ("roadmap", "docs/WASM_ROADMAP.md"),
        ("runtime_costs_doc", "docs/WASM_RUNTIME_COSTS.md"),
    )
    for field, path in field_paths:
        data = getattr(inputs, field).encode("utf-8")
        identity = EXPECTED_REPOSITORY_FILES[path]
        require(
            len(data) == identity["bytes"],
            f"repository integration file byte count differs: {path}",
        )
        require(
            hashlib.sha256(data).hexdigest() == identity["sha256"],
            f"repository integration file SHA-256 differs: {path}",
        )


def verify_repository_integration(
    inputs: RepositoryInputs, *, require_policy_section_identity: bool = True
) -> None:
    verify_roadmap(
        inputs.roadmap,
        require_policy_section_identity=require_policy_section_identity,
    )
    verify_testing(
        inputs.testing,
        require_policy_section_identity=require_policy_section_identity,
    )
    verify_ci(inputs.ci)
    verify_history_documents(inputs)
    verify_no_forbidden_document_claims(inputs)
    if require_policy_section_identity:
        verify_repository_file_identities(inputs)


def synthetic_repository_inputs() -> RepositoryInputs:
    roadmap = (
        f"{ROADMAP_STATUS_PREFIX} Synthetic repository status.\n\n"
        "| # | Work item | Acceptance |\n"
        "|---|---|---|\n"
        f"{ROADMAP_C83_ROW}\n"
        f"{ROADMAP_F5_ROW}\n\n"
        f"{C1_C82_STATUS_MARKER}\n\n"
        "The fixed-QEMU replacement remains scoped to C8.8-F5.\n\n"
        f"{POLICY_HEADING}\n\n"
        f"The machine contract is {POLICY_CONTRACT_LINK}.\n\n"
        + "\n\n".join(ROADMAP_POLICY_MARKERS)
        + "\n\n"
        "## 10. Test and evidence matrix\n\n"
        "| Layer | Component responsibility | Blind spot |\n"
        "|---|---|---|\n"
        f"{FIXED_QEMU_MATRIX_ROW}\n"
        f"{OPTIONAL_DUO_MATRIX_ROW}\n\n"
        "## 11. Metrics and release budgets\n\n"
        f"{FIXED_QEMU_METRIC}\n"
        f"{OPTIONAL_DUO_METRIC}\n\n"
        "## 12. Risk register\n\n"
        "No synthetic risk entry.\n\n"
        "## 13. Definition of done for Component v1\n\n"
        f"11. {FIXED_QEMU_DOD}\n\n"
        "## 14. Reference specifications and candidate tooling\n"
    )
    testing = (
        "# Testing\n\n"
        f"{TESTING_POLICY_HEADING}\n\n"
        f"{TESTING_NORMATIVE_MARKER}\n\n"
        "```sh\n"
        f"{TESTING_POLICY_BLOCK}"
        "```\n\n"
        f"{TESTING_RETAINED_HEADING}\n\n"
        f"{C1_C82_STATUS_MARKER}\n\n"
        f"{C83_STATUS_MARKER}\n\n"
        f"{C83_HISTORICAL_CONTRACT_MARKER}\n\n"
        f"{C84_HISTORICAL_NEXT_MARKER}\n\n"
        f"{CURRENT_POSITION_MARKER}\n\n"
        f"{FLOAT_NON_PROMOTION_MARKER}\n"
    )
    ci = (
        "name: CI\n\n"
        "on:\n"
        "  push:\n\n"
        "jobs:\n"
        "  host-tests:\n"
        "    name: Host unit tests\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        f"{CI_POLICY_STEP}"
    )
    runtime_history = (
        f"{C1_C82_STATUS_MARKER}\n\n{C83_STATUS_MARKER}\n\n"
        f"{C83_HISTORICAL_CONTRACT_MARKER}\n"
    )
    aot_history = (
        f"{C1_C82_STATUS_MARKER}\n\n{C84_HISTORICAL_NEXT_MARKER}\n\n"
        f"{CURRENT_POSITION_MARKER}\n"
    )
    return RepositoryInputs(
        roadmap=roadmap,
        testing=testing,
        ci=ci,
        runtime_costs_doc=runtime_history,
        runtime_costs_readme=runtime_history,
        aot_decision_doc=aot_history,
        aot_readme=aot_history,
        float_profile_doc=(
            C1_C82_STATUS_MARKER + "\n\n" + FLOAT_NON_PROMOTION_MARKER + "\n"
        ),
    )


def expect_rejected(action: Callable[[], Any], label: str, diagnostic: str) -> None:
    try:
        action()
    except VerificationError as exc:
        message = str(exc)
        if diagnostic not in message:
            fail(
                f"selftest {label} produced diagnostic {message!r}; "
                f"expected {diagnostic!r}"
            )
        return
    fail(f"selftest {label} was accepted")


def set_nested(value: dict[str, Any], path: tuple[str, ...], replacement: Any) -> None:
    current: dict[str, Any] = value
    for key in path[:-1]:
        child = current.get(key)
        if type(child) is not dict:
            fail(f"selftest mutation path is not an object: {path!r}")
        current = child
    current[path[-1]] = replacement


def expect_contract_mutation_rejected(
    contract: dict[str, Any],
    path: tuple[str, ...],
    replacement: Any,
    label: str,
    diagnostic: str,
) -> None:
    mutant = copy.deepcopy(contract)
    set_nested(mutant, path, replacement)
    expect_rejected(lambda: validate_contract_object(mutant), label, diagnostic)


def replace_once(value: str, old: str, new: str, label: str) -> str:
    count = value.count(old)
    if count != 1:
        fail(f"selftest fixture {label} source count differs: {count}")
    return value.replace(old, new, 1)


def replace_marker_in_fields(
    inputs: RepositoryInputs,
    fields: tuple[str, ...],
    marker: str,
    replacement: str,
    label: str,
) -> RepositoryInputs:
    updates: dict[str, str] = {}
    for field in fields:
        current = getattr(inputs, field)
        if type(current) is not str:
            fail(f"selftest fixture {label} field {field} is not text")
        updates[field] = replace_once(
            current, marker, replacement, f"{label} in {field}"
        )
    return replace(inputs, **updates)


def run_contract_selftests(contract: dict[str, Any]) -> int:
    cases = 0
    mutations = (
        (("scope",), "c84-and-f5-only", "scope-shrunk", "contract.scope differs"),
        (
            ("policy_checkpoint", "c_number_allocated"),
            True,
            "c-number-allocated",
            "policy_checkpoint.c_number_allocated differs",
        ),
        (
            ("policy_checkpoint", "product_roadmap_node"),
            True,
            "policy-made-product-node",
            "policy_checkpoint.product_roadmap_node differs",
        ),
        (
            ("effectivity", "contract_is_target_evidence"),
            True,
            "contract-promoted-to-evidence",
            "effectivity.contract_is_target_evidence differs",
        ),
        (
            ("effectivity", "current_target_release_gate_satisfied"),
            True,
            "gate-falsely-satisfied",
            "effectivity.current_target_release_gate_satisfied differs",
        ),
        (
            ("fixed_qemu_gate", "baseline", "id"),
            "unfixed-qemu",
            "baseline-id-drift",
            "fixed_qemu_gate.baseline.id differs",
        ),
        (
            ("fixed_qemu_gate", "baseline", "class"),
            "physical",
            "qemu-relabeled-physical",
            "fixed_qemu_gate.baseline.class differs",
        ),
        (
            ("fixed_qemu_gate", "physical_equivalence_claimed"),
            True,
            "physical-equivalence-claimed",
            "fixed_qemu_gate.physical_equivalence_claimed differs",
        ),
        (
            ("fixed_qemu_gate", "physical_inputs_required"),
            1,
            "physical-input-required",
            "fixed_qemu_gate.physical_inputs_required differs",
        ),
        (
            ("fixed_qemu_gate", "physical_inputs_permitted"),
            1,
            "physical-input-permitted",
            "fixed_qemu_gate.physical_inputs_permitted differs",
        ),
        (
            ("fixed_qemu_gate", "fresh_source_commit_and_tree_required"),
            False,
            "fresh-source-disabled",
            "fixed_qemu_gate.fresh_source_commit_and_tree_required differs",
        ),
        (
            ("fixed_qemu_gate", "fresh_suite_and_run_id_domain_required"),
            False,
            "fresh-suite-disabled",
            "fixed_qemu_gate.fresh_suite_and_run_id_domain_required differs",
        ),
        (
            ("fixed_qemu_gate", "fresh_capture_required"),
            False,
            "fresh-capture-disabled",
            "fixed_qemu_gate.fresh_capture_required differs",
        ),
        (
            (
                "evidence_non_promotion",
                "c83_historical_members_eligible_for_future_gate",
            ),
            True,
            "c83-evidence-promoted",
            "evidence_non_promotion.c83_historical_members_eligible_for_future_gate differs",
        ),
        (
            (
                "evidence_non_promotion",
                "c84_decision_or_bundle_eligible_for_future_gate",
            ),
            True,
            "c84-evidence-promoted",
            "evidence_non_promotion.c84_decision_or_bundle_eligible_for_future_gate differs",
        ),
        (
            (
                "evidence_non_promotion",
                "c88_f5_contract_decision_or_receipts_eligible_for_future_gate",
            ),
            True,
            "f5-evidence-promoted",
            "evidence_non_promotion.c88_f5_contract_decision_or_receipts_eligible_for_future_gate differs",
        ),
        (
            ("evidence_non_promotion", "historical_evidence_relabeling_forbidden"),
            False,
            "historical-relabeling-enabled",
            "evidence_non_promotion.historical_evidence_relabeling_forbidden differs",
        ),
        (
            ("duo_observation", "formal_gate_input_permitted"),
            True,
            "duo-input-enabled",
            "duo_observation.formal_gate_input_permitted differs",
        ),
        (
            ("duo_observation", "gate_effect"),
            True,
            "duo-gate-effect-enabled",
            "duo_observation.gate_effect differs",
        ),
        (
            ("duo_observation", "completion_effect"),
            True,
            "duo-completion-effect-enabled",
            "duo_observation.completion_effect differs",
        ),
        (
            ("duo_observation", "release_effect"),
            True,
            "duo-release-effect-enabled",
            "duo_observation.release_effect differs",
        ),
        (
            ("unrelated_hardware_gates", "unchanged"),
            False,
            "hardware-gates-widened",
            "unrelated_hardware_gates.unchanged differs",
        ),
        (
            ("unrelated_hardware_gates", "fixed_qemu_may_satisfy_excluded_gates"),
            True,
            "hardware-gates-satisfied-by-qemu",
            "unrelated_hardware_gates.fixed_qemu_may_satisfy_excluded_gates differs",
        ),
        (
            ("code5_boundary", "inert"),
            False,
            "code5-made-active",
            "code5_boundary.inert differs",
        ),
        (
            ("code5_boundary", "executable"),
            True,
            "code5-made-executable",
            "code5_boundary.executable differs",
        ),
        (
            ("authority", "release_authorized"),
            True,
            "release-authority-granted",
            "authority.release_authorized differs",
        ),
        (
            ("authority", "execution_authorized"),
            True,
            "execution-authority-granted",
            "authority.execution_authorized differs",
        ),
        (
            ("successor_boundary", "roadmap_node_allocated"),
            True,
            "successor-number-allocated",
            "successor_boundary.roadmap_node_allocated differs",
        ),
        (
            ("successor_boundary", "selects_successor_target_policy"),
            True,
            "successor-target-selected",
            "successor_boundary.selects_successor_target_policy differs",
        ),
        (
            ("successor_boundary", "target_release_evidence_question"),
            "resolved",
            "successor-question-resolved",
            "successor_boundary.target_release_evidence_question differs",
        ),
        (
            ("application_status", "implementation_node_complete"),
            False,
            "c89-implementation-regressed-incomplete",
            "application_status.implementation_node_complete differs",
        ),
        (
            ("application_status", "qualification_node_complete"),
            False,
            "c89-qualification-regressed-incomplete",
            "application_status.qualification_node_complete differs",
        ),
        (
            ("application_status", "next_widening_design_node_complete"),
            False,
            "c810-design-regressed-incomplete",
            "application_status.next_widening_design_node_complete differs",
        ),
        (
            ("historical_boundaries", "c1_through_c82", "status"),
            "reopened",
            "c1-c82-status-reopened",
            "historical_boundaries.c1_through_c82.status differs",
        ),
        (
            ("historical_boundaries", "c83", "status"),
            "incomplete",
            "c83-status-reopened",
            "historical_boundaries.c83.status differs",
        ),
        (
            (
                "historical_boundaries",
                "c83",
                "pinned_preparation_members",
                "schema",
                "git_blob",
            ),
            "0" * 40,
            "c83-git-identity-drift",
            "historical_boundaries.c83.pinned_preparation_members.schema.git_blob differs",
        ),
        (
            ("historical_boundaries", "c84", "replacement_scope"),
            "all-wasm",
            "c84-scope-promoted",
            "historical_boundaries.c84.replacement_scope differs",
        ),
        (
            ("historical_boundaries", "c84", "historical_next_node"),
            "C8.5",
            "c84-next-node-rewritten",
            "historical_boundaries.c84.historical_next_node differs",
        ),
        (
            ("historical_boundaries", "c88_f5", "replacement_scope"),
            "all-wasm",
            "f5-scope-promoted",
            "historical_boundaries.c88_f5.replacement_scope differs",
        ),
        (
            ("historical_boundaries", "c88_f5", "decision_id"),
            "0" * 64,
            "f5-decision-id-drift",
            "historical_boundaries.c88_f5.decision_id differs",
        ),
        (
            ("historical_boundaries", "successor_charter", "state"),
            "allocated",
            "successor-charter-rewritten",
            "historical_boundaries.successor_charter.state differs",
        ),
        (
            ("policy_basis", "commit"),
            "0" * 40,
            "policy-basis-drift",
            "policy_basis.commit differs",
        ),
        (
            (
                "repository_integration",
                "pinned_files",
                "docs/WASM_RUNTIME_COSTS.md",
                "sha256",
            ),
            "0" * 64,
            "repository-doc-identity-drift",
            "repository_integration.pinned_files.docs/WASM_RUNTIME_COSTS.md.sha256 differs",
        ),
        (
            ("contract_verifier", "runs_qemu"),
            True,
            "verifier-runs-qemu",
            "contract_verifier.runs_qemu differs",
        ),
    )
    for path, replacement, label, diagnostic in mutations:
        expect_contract_mutation_rejected(
            contract, path, replacement, label, diagnostic
        )
        cases += 1

    extra = copy.deepcopy(contract)
    extra["unexpected"] = False
    expect_rejected(
        lambda: validate_contract_object(extra),
        "extra-root-key",
        "contract root keys differ",
    )
    cases += 1
    missing = copy.deepcopy(contract)
    del missing["scope"]
    expect_rejected(
        lambda: validate_contract_object(missing),
        "missing-root-key",
        "contract root keys differ",
    )
    cases += 1

    expect_rejected(
        lambda: strict_json_loads(b'{"x": 1, "x": 2}\n', "duplicate fixture"),
        "duplicate-json-key",
        "duplicate JSON key",
    )
    cases += 1
    expect_rejected(
        lambda: strict_json_loads(b'{"x": 1.5}\n', "float fixture"),
        "floating-json-number",
        "floating-point number is forbidden",
    )
    cases += 1
    expect_rejected(
        lambda: strict_json_loads(b'{"x": NaN}\n', "constant fixture"),
        "nonfinite-json-constant",
        "non-finite JSON constant is forbidden",
    )
    cases += 1
    compact = json.dumps(contract, ensure_ascii=True, sort_keys=True).encode("utf-8")
    expect_rejected(
        lambda: decode_contract_bytes(compact, require_identity=False),
        "noncanonical-json",
        "contract is not canonical sorted indented JSON",
    )
    cases += 1
    return cases


def run_filesystem_selftests() -> int:
    cases = 0
    with tempfile.TemporaryDirectory(prefix="vibeos-qemu-policy-selftest-") as name:
        root = pathlib.Path(name)
        regular = root / "regular.json"
        regular.write_bytes(b"{}\n")
        if stable_direct_read(regular, 16, "regular fixture", root=root) != b"{}\n":
            fail("selftest regular direct read differs")
        cases += 1

        hardlink = root / "hardlink.json"
        os.link(regular, hardlink)
        expect_rejected(
            lambda: stable_direct_read(regular, 16, "hardlink fixture", root=root),
            "hardlink-alias",
            "must have exactly one hard link",
        )
        cases += 1
        hardlink.unlink()

        symlink = root / "symlink.json"
        os.symlink(regular.name, symlink)
        expect_rejected(
            lambda: stable_direct_read(symlink, 16, "symlink fixture", root=root),
            "leaf-symlink",
            "must be a regular file",
        )
        cases += 1

        directory = root / "directory"
        directory.mkdir()
        expect_rejected(
            lambda: stable_direct_read(directory, 16, "directory fixture", root=root),
            "directory-input",
            "must be a regular file",
        )
        cases += 1

        if hasattr(os, "mkfifo"):
            fifo = root / "fifo"
            os.mkfifo(fifo)
            expect_rejected(
                lambda: stable_direct_read(fifo, 16, "fifo fixture", root=root),
                "fifo-input",
                "must be a regular file",
            )
            cases += 1

        real_parent = root / "real-parent"
        real_parent.mkdir()
        child = real_parent / "child"
        child.write_bytes(b"x")
        alias_parent = root / "alias-parent"
        os.symlink(real_parent.name, alias_parent)
        expect_rejected(
            lambda: stable_direct_read(
                alias_parent / "child", 16, "parent-symlink fixture", root=root
            ),
            "parent-symlink",
            "parent path component must be a real directory",
        )
        cases += 1
    return cases


def run_repository_selftests() -> int:
    base = synthetic_repository_inputs()
    verify_repository_integration(base, require_policy_section_identity=False)
    cases = 1

    mutations: list[tuple[str, Callable[[RepositoryInputs], RepositoryInputs], str]] = [
        (
            "roadmap-status-decoy",
            lambda value: replace(
                value,
                roadmap=(
                    replace_once(
                        value.roadmap,
                        ROADMAP_STATUS,
                        "**Status (2026-08-30): planned.**",
                        "roadmap status",
                    )
                    + "\nThe words implementation in progress are only a decoy.\n"
                ),
            ),
            "roadmap top-level implementation status differs",
        ),
        (
            "roadmap-policy-heading-removed",
            lambda value: replace(
                value,
                roadmap=replace_once(
                    value.roadmap,
                    POLICY_HEADING,
                    "### Fixed-QEMU policy",
                    "roadmap policy heading",
                ),
            ),
            "roadmap policy heading count differs",
        ),
        (
            "roadmap-position-removed",
            lambda value: replace(
                value,
                roadmap=replace_once(
                    value.roadmap,
                    ROADMAP_POLICY_MARKERS[0],
                    "The policy checkpoint roadmap position is unselected.",
                    "roadmap policy position",
                ),
            ),
            "roadmap policy marker count differs",
        ),
        (
            "roadmap-fresh-evidence-removed",
            lambda value: replace(
                value,
                roadmap=replace_once(
                    value.roadmap,
                    ROADMAP_POLICY_MARKERS[4],
                    "Historical evidence remains sufficient.",
                    "roadmap fresh evidence",
                ),
            ),
            "roadmap policy marker count differs",
        ),
        (
            "roadmap-old-evidence-promoted",
            lambda value: replace(
                value,
                roadmap=replace_once(
                    value.roadmap,
                    ROADMAP_POLICY_MARKERS[5],
                    "Historical C8.4 and C8.8-F5 QEMU evidence satisfies future gates.",
                    "roadmap evidence non-promotion",
                ),
            ),
            "roadmap policy marker count differs",
        ),
        (
            "roadmap-duo-gate-effect",
            lambda value: replace(
                value,
                roadmap=replace_once(
                    value.roadmap,
                    ROADMAP_POLICY_MARKERS[6],
                    "Milk-V Duo remains mandatory and blocks completion.",
                    "roadmap Duo effect",
                ),
            ),
            "roadmap policy marker count differs",
        ),
        (
            "roadmap-mandatory-physical-row",
            lambda value: replace(
                value,
                roadmap=replace_once(
                    value.roadmap,
                    FIXED_QEMU_MATRIX_ROW,
                    "| Physical Duo gate | Mandatory physical target evidence | QEMU |",
                    "roadmap matrix",
                ),
            ),
            "restores a mandatory generic Physical Duo gate",
        ),
        (
            "roadmap-optional-duo-row-removed",
            lambda value: replace(
                value,
                roadmap=replace_once(
                    value.roadmap,
                    OPTIONAL_DUO_MATRIX_ROW,
                    "| Duo gate | Required | None |",
                    "roadmap optional Duo row",
                ),
            ),
            "roadmap optional-Duo matrix marker count differs",
        ),
        (
            "roadmap-fixed-qemu-metric-removed",
            lambda value: replace(
                value,
                roadmap=replace_once(
                    value.roadmap,
                    FIXED_QEMU_METRIC,
                    "- physical-only soak duration;",
                    "roadmap QEMU metric",
                ),
            ),
            "roadmap fixed-QEMU metric marker count differs",
        ),
        (
            "roadmap-physical-dod-restored",
            lambda value: replace(
                value,
                roadmap=replace_once(
                    value.roadmap,
                    FIXED_QEMU_DOD,
                    "fuzzers, self-tests, and the physical-Duo gate are green on pinned tools.",
                    "roadmap definition of done",
                ),
            ),
            "roadmap fixed-QEMU definition of done marker count differs",
        ),
        (
            "all-docs-reopen-c1-c82",
            lambda value: replace_marker_in_fields(
                value,
                (
                    "roadmap",
                    "testing",
                    "runtime_costs_doc",
                    "runtime_costs_readme",
                    "aot_decision_doc",
                    "aot_readme",
                    "float_profile_doc",
                ),
                C1_C82_STATUS_MARKER,
                "C1 through C8.2 are reopened and require individual reruns.",
                "C1-C8.2 historical status",
            ),
            "roadmap C1-C8.2 historical status marker count differs",
        ),
        (
            "runtime-doc-appends-c1-c82-reopen",
            lambda value: replace(
                value,
                runtime_costs_doc=(
                    value.runtime_costs_doc
                    + "C1 through C8.2 are reopened and require individual reruns.\n"
                ),
            ),
            "runtime_costs_doc contains forbidden policy claim: C1-C8.2 reopened",
        ),
        (
            "testing-appends-c83-rerun-backfill",
            lambda value: replace(
                value,
                testing=(
                    value.testing
                    + "C8.3 is incomplete and must be rerun and backfilled before release.\n"
                ),
            ),
            "testing contains forbidden policy claim: C8.3 reopened",
        ),
        (
            "aot-doc-appends-mandatory-duo",
            lambda value: replace(
                value,
                aot_decision_doc=(
                    value.aot_decision_doc
                    + "Milk-V Duo is mandatory and blocks release.\n"
                ),
            ),
            "aot_decision_doc contains forbidden policy claim: Milk-V Duo made mandatory",
        ),
        (
            "float-doc-appends-f5-promotion",
            lambda value: replace(
                value,
                float_profile_doc=(
                    value.float_profile_doc
                    + "F5 evidence satisfies every future target gate.\n"
                ),
            ),
            "float_profile_doc contains forbidden policy claim: F5 evidence promoted",
        ),
        (
            "float-doc-appends-code5-activation",
            lambda value: replace(
                value,
                float_profile_doc=value.float_profile_doc
                + "Code 5 is executable and current.\n",
            ),
            "float_profile_doc contains forbidden policy claim: Code 5 made executable",
        ),
        (
            "testing-command-removed",
            lambda value: replace(
                value,
                testing=replace_once(
                    value.testing,
                    VERIFICATION_COMMANDS[1] + "\n",
                    "",
                    "TESTING optimized check",
                ),
            ),
            "TESTING policy command block differs",
        ),
        (
            "testing-restores-c83-qemu-smoke",
            lambda value: replace(
                value,
                testing=value.testing + C83_ACTIVE_SMOKE_COMMAND + "\n",
            ),
            "TESTING restores active C8.3 QEMU execution",
        ),
        (
            "testing-command-duplicated",
            lambda value: replace(
                value,
                testing=value.testing + VERIFICATION_COMMANDS[0] + "\n",
            ),
            "TESTING policy command count differs",
        ),
        (
            "ci-restores-c83-formal-campaign",
            lambda value: replace(
                value,
                ci=(
                    value.ci
                    + C83_FORMAL_CI_STEP
                    + "\n        "
                    + "run: |\n          python3 -B "
                    + "./scripts/qemu-c83-runtime-costs.py"
                    + "\n"
                ),
            ),
            "CI restores the historical C8.3 formal QEMU campaign",
        ),
        (
            "testing-current-position-removed",
            lambda value: replace(
                value,
                testing=replace_once(
                    value.testing,
                    CURRENT_POSITION_MARKER,
                    "The current implementation node is C8.8.",
                    "TESTING current position",
                ),
            ),
            "TESTING current roadmap position marker count differs",
        ),
        (
            "ci-step-disabled",
            lambda value: replace(
                value,
                ci=replace_once(
                    value.ci,
                    f"      - name: {CI_STEP_NAME}\n        #",
                    f"      - name: {CI_STEP_NAME}\n        if: ${{{{ false }}}}\n        #",
                    "CI disabled step",
                ),
            ),
            "CI policy step differs or can be bypassed",
        ),
        (
            "ci-command-ignored",
            lambda value: replace(
                value,
                ci=replace_once(
                    value.ci,
                    VERIFICATION_COMMANDS[0] + "\n",
                    VERIFICATION_COMMANDS[0] + " || true\n",
                    "CI ignored command",
                ),
            ),
            "CI policy step differs or can be bypassed",
        ),
        (
            "ci-optimized-selftest-removed",
            lambda value: replace(
                value,
                ci=replace_once(
                    value.ci,
                    "          " + VERIFICATION_COMMANDS[3] + "\n",
                    "",
                    "CI optimized selftest",
                ),
            ),
            "CI policy step differs or can be bypassed",
        ),
        (
            "runtime-doc-reopens-c83",
            lambda value: replace(
                value,
                runtime_costs_doc=replace_once(
                    value.runtime_costs_doc,
                    C83_STATUS_MARKER,
                    "C8.3 is incomplete until physical tests run.",
                    "runtime C8.3 status",
                ),
            ),
            "runtime-costs document C8.3 status marker count differs",
        ),
        (
            "runtime-readme-fabricates-publication",
            lambda value: replace(
                value,
                runtime_costs_readme=replace_once(
                    value.runtime_costs_readme,
                    C83_HISTORICAL_CONTRACT_MARKER,
                    "A new physical publication is complete.",
                    "runtime README historical contract",
                ),
            ),
            "runtime-costs README historical contract marker count differs",
        ),
        (
            "aot-doc-stale-current-node",
            lambda value: replace(
                value,
                aot_decision_doc=value.aot_decision_doc
                + "The current implementation node is C8.8.\n",
            ),
            "AOT decision document restores stale current implementation node C8.8",
        ),
        (
            "aot-readme-history-rewritten",
            lambda value: replace(
                value,
                aot_readme=replace_once(
                    value.aot_readme,
                    C84_HISTORICAL_NEXT_MARKER,
                    "The historical next node was C8.5.",
                    "AOT README historical next-node",
                ),
            ),
            "AOT decision README historical next-node marker count differs",
        ),
        (
            "float-f5-evidence-promoted",
            lambda value: replace(
                value,
                float_profile_doc=replace_once(
                    value.float_profile_doc,
                    FLOAT_NON_PROMOTION_MARKER,
                    "F5 evidence satisfies every future target gate.",
                    "Float F5 non-promotion",
                ),
            ),
            "Float profile F5 non-promotion marker count differs",
        ),
    ]
    for label, mutation, diagnostic in mutations:
        expect_rejected(
            lambda mutation=mutation: verify_repository_integration(
                mutation(base), require_policy_section_identity=False
            ),
            label,
            diagnostic,
        )
        cases += 1

    live = load_repository_inputs()
    verify_repository_integration(live)
    cases += 1
    contradiction = (
        "Historical C8.4 and C8.8-F5 evidence may satisfy every future gate. "
        "Milk-V Duo is mandatory and blocks release. This checkpoint allocates "
        "C9 and authorizes production. Code 5 is executable and current.\n\n"
    )
    contradictory_roadmap = replace_once(
        live.roadmap,
        "## 10. Test and evidence matrix\n",
        contradiction + "## 10. Test and evidence matrix\n",
        "roadmap appended contradiction",
    )
    expect_rejected(
        lambda: verify_repository_integration(
            replace(live, roadmap=contradictory_roadmap)
        ),
        "roadmap-appended-contradiction",
        "roadmap contains forbidden policy claim: Milk-V Duo made mandatory",
    )
    cases += 1
    contradictory_testing = replace_once(
        live.testing,
        TESTING_RETAINED_HEADING + "\n",
        (
            "Milk-V Duo is mandatory and blocks release.\n\n"
            + TESTING_RETAINED_HEADING
            + "\n"
        ),
        "TESTING policy-section contradiction",
    )
    expect_rejected(
        lambda: verify_repository_integration(
            replace(live, testing=contradictory_testing)
        ),
        "testing-policy-section-appended-contradiction",
        "TESTING policy section byte count differs",
    )
    cases += 1
    identity_bypass_cases = (
        (
            "runtime_costs_doc",
            "docs/WASM_RUNTIME_COSTS.md",
            "C8.3 remains open; release requires a new physical collection.\n",
        ),
        (
            "runtime_costs_readme",
            "benchmarks/wasm-runtime/README.md",
            "Milk-V Duo is required for release.\n",
        ),
        (
            "aot_decision_doc",
            "docs/WASM_AOT_DECISION.md",
            "The C8.4 evidence is hereby promoted to all later gates.\n",
        ),
        (
            "float_profile_doc",
            "docs/WASM_FLOAT_PROFILE.md",
            "F5 evidence now authorizes successor production execution.\n",
        ),
        (
            "float_profile_doc",
            "docs/WASM_FLOAT_PROFILE.md",
            "Code 5 may execute in production.\n",
        ),
    )
    for field, path, contradictory_text in identity_bypass_cases:
        mutated = replace(
            live,
            **{field: getattr(live, field) + contradictory_text},
        )
        expect_rejected(
            lambda mutated=mutated: verify_repository_integration(mutated),
            f"repository-identity-appended-contradiction-{field}",
            f"repository integration file byte count differs: {path}",
        )
        cases += 1
    return cases


def run_selftest(contract: dict[str, Any]) -> int:
    return (
        run_contract_selftests(contract)
        + run_filesystem_selftests()
        + run_repository_selftests()
    )


def load_checked_contract() -> dict[str, Any]:
    stable_direct_read(SCRIPT_PATH, 2 * 1024 * 1024, "policy verifier")
    raw = stable_direct_read(CONTRACT_PATH, MAX_CONTRACT_BYTES, "policy contract")
    return decode_contract_bytes(raw, require_identity=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-contract", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()
    if not arguments.check_contract and not arguments.selftest:
        parser.error("select --check-contract and/or --selftest")
    try:
        contract = load_checked_contract()
        verify_historical_git(contract)
        outputs: list[str] = []
        if arguments.check_contract:
            verify_repository_integration(load_repository_inputs())
            outputs.append(CHECK_OUTPUT.rstrip("\n"))
        if arguments.selftest:
            cases = run_selftest(contract)
            outputs.append(
                "PASS verify-wasm-fixed-qemu-target-release-policy selftest "
                f"cases={cases}"
            )
        print("\n".join(outputs))
        return 0
    except VerificationError as exc:
        print(
            f"FAIL verify-wasm-fixed-qemu-target-release-policy: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
