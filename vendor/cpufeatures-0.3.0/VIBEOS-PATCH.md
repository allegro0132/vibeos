# VibeOS EL1 detection patch

Source: crates.io cpufeatures 0.3.0, checksum
`8b2a41393f66f16b0823bb79094d54ac5fbd34ab292ddafb9a0456ac9f87d201`.
Upstream MIT/Apache-2.0 licenses are retained. Cipher implementations are unchanged.

`vibeos-el1` is an explicit opt-in for AArch64 target_os=none. It adds privileged
register detection for the `aes` feature only. ARM LLVM `aes` permits PMULL,
so ID_AA64ISAR0_EL1.AES must equal 2, FP/AdvSIMD must be implemented, and
CPACR_EL1 must allow EL1 SIMD. All other requested features fail closed.
Non-AArch64, hosted targets, and builds without the opt-in retain upstream
behavior. Do not use this opt-in in EL0 or in firmware without SIMD exception
and task-recovery protection. The board boot path enables that protection
before invoking any Rust code; feature results are cached by upstream tokens.

`vibeos-force-soft` disables this EL1 detector for controlled A/B validation.
Both compared board images keep the same full SIMD frame protection. Do not
force global compiler target features: that could bypass runtime detection.

The local feature declarations and the final bare-metal detection branch in
src/aarch64.rs are the only changes to upstream code. Cargo.toml.orig is kept
as upstream provenance; builds use Cargo.toml.
