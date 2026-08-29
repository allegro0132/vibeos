//! VibeOS — a capability-secure, single-address-space, async-first kernel.
//!
//! Three bets, all visible in this ~1800-line v0.1:
//!
//!   1. Authority is a *capability*, never a name. No paths, no uids, no root.
//!   2. Isolation is a *type system*, not a page table. Components share one
//!      address space; the compiler, not the MMU, is the enforcement boundary.
//!   3. Concurrency is a *future*, not a thread. Nothing blocks, nothing gets
//!      preempted, and an interrupt costs a queue push instead of a context
//!      switch.

#![no_std]
#![feature(alloc_error_handler)]
#![cfg_attr(not(feature = "legacy-shell"), allow(dead_code))]

#[cfg(all(
    feature = "wasm-c83-runtime-costs",
    any(
        feature = "legacy-shell",
        feature = "storage-bench",
        feature = "file-tree",
        feature = "tcp-echo",
        feature = "net-shell",
        feature = "iperf3-server",
        feature = "milkv-iperf3-server",
        feature = "ssh-security-test",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance",
        feature = "milkv-ssh",
        feature = "milkv-jitterentropy-probe",
        feature = "milkv-jitterentropy-ssh-probe",
        feature = "component-graph-principals",
        feature = "component-durable-publication",
        feature = "ssh-component-command",
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "wasm-c63-graph-principal-acceptance",
        feature = "wasm-c64-resource-route-acceptance",
        feature = "wasm-c65-async-chain-acceptance",
        feature = "wasm-c66-node-replacement-acceptance",
        feature = "wasm-c67-information-flow-acceptance",
        feature = "wasm-c73-authenticated-admission-acceptance",
        feature = "wasm-c74-crash-safe-publication-acceptance",
        feature = "wasm-c75-boot-revalidation-acceptance",
        feature = "wasm-c76-graph-version-replacement-acceptance",
        feature = "wasm-c77-ephemeral-runtime-acceptance",
        feature = "wasm-c84-profile-slot",
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "wasm-c88-f5-float-duo-compile-readiness",
        feature = "ssh-native-async-command",
        feature = "ssh-native-async-qemu-acceptance",
        feature = "ssh-native-async-revoke-qemu-acceptance"
    )
))]
compile_error!("feature `wasm-c83-runtime-costs` is an isolated benchmark image");

#[cfg(all(
    feature = "wasm-c88-f5-float-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c88-f5-float-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c88-f5-float-qemu-acceptance",
    not(feature = "qemu-default-image")
))]
compile_error!("feature `wasm-c88-f5-float-qemu-acceptance` requires the QEMU image policy");

#[cfg(all(
    feature = "wasm-c88-f5-float-qemu-acceptance",
    any(
        feature = "milkv-duo",
        feature = "milkv-duo-sd-image",
        feature = "legacy-shell",
        feature = "storage-bench",
        feature = "file-tree",
        feature = "tcp-echo",
        feature = "net-shell",
        feature = "iperf3-server",
        feature = "milkv-iperf3-server",
        feature = "ssh-security-test",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance",
        feature = "milkv-ssh",
        feature = "component-graph-principals",
        feature = "component-durable-publication",
        feature = "ssh-component-command",
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "wasm-c63-graph-principal-acceptance",
        feature = "wasm-c64-resource-route-acceptance",
        feature = "wasm-c65-async-chain-acceptance",
        feature = "wasm-c66-node-replacement-acceptance",
        feature = "wasm-c67-information-flow-acceptance",
        feature = "wasm-c73-authenticated-admission-acceptance",
        feature = "wasm-c74-crash-safe-publication-acceptance",
        feature = "wasm-c75-boot-revalidation-acceptance",
        feature = "wasm-c76-graph-version-replacement-acceptance",
        feature = "wasm-c77-ephemeral-runtime-acceptance",
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c84-profile-slot",
        feature = "ssh-native-async-command",
        feature = "ssh-native-async-qemu-acceptance",
        feature = "ssh-native-async-revoke-qemu-acceptance"
    )
))]
compile_error!(
    "feature `wasm-c88-f5-float-qemu-acceptance` is an isolated emulator qualification image"
);

#[cfg(all(
    feature = "wasm-c88-f5-float-qemu-acceptance",
    feature = "wasm-c88-f5-float-duo-compile-readiness"
))]
compile_error!("the QEMU and Milk-V Duo C8.8-F5 image contracts are mutually exclusive");

#[cfg(all(
    feature = "wasm-c88-f5-float-duo-compile-readiness",
    not(feature = "milkv-duo")
))]
compile_error!("feature `wasm-c88-f5-float-duo-compile-readiness` requires the Milk-V Duo board");

#[cfg(all(
    feature = "wasm-c88-f5-float-duo-compile-readiness",
    not(feature = "milkv-duo-sd-image")
))]
compile_error!(
    "feature `wasm-c88-f5-float-duo-compile-readiness` requires the Milk-V Duo image policy"
);

#[cfg(all(
    feature = "wasm-c88-f5-float-duo-compile-readiness",
    any(feature = "qemu-virt", feature = "qemu-default-image")
))]
compile_error!(
    "feature `wasm-c88-f5-float-duo-compile-readiness` cannot select a QEMU board or policy"
);

#[cfg(all(
    feature = "wasm-c88-f5-float-duo-compile-readiness",
    any(
        feature = "legacy-shell",
        feature = "storage-bench",
        feature = "file-tree",
        feature = "tcp-echo",
        feature = "net-shell",
        feature = "iperf3-server",
        feature = "milkv-iperf3-server",
        feature = "ssh-security-test",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance",
        feature = "milkv-ssh",
        feature = "milkv-jitterentropy-probe",
        feature = "milkv-jitterentropy-ssh-probe",
        feature = "component-graph-principals",
        feature = "component-durable-publication",
        feature = "ssh-component-command",
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "wasm-c63-graph-principal-acceptance",
        feature = "wasm-c64-resource-route-acceptance",
        feature = "wasm-c65-async-chain-acceptance",
        feature = "wasm-c66-node-replacement-acceptance",
        feature = "wasm-c67-information-flow-acceptance",
        feature = "wasm-c73-authenticated-admission-acceptance",
        feature = "wasm-c74-crash-safe-publication-acceptance",
        feature = "wasm-c75-boot-revalidation-acceptance",
        feature = "wasm-c76-graph-version-replacement-acceptance",
        feature = "wasm-c77-ephemeral-runtime-acceptance",
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c84-profile-slot",
        feature = "ssh-native-async-command",
        feature = "ssh-native-async-qemu-acceptance",
        feature = "ssh-native-async-revoke-qemu-acceptance"
    )
))]
compile_error!(
    "feature `wasm-c88-f5-float-duo-compile-readiness` is an isolated, non-production readiness image"
);

#[cfg(all(
    feature = "wasm-c84-profile-slot-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-profile-slot-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-core-poll-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-core-poll-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-profile-irq-overlay-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-profile-child-delegation-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-profile-child-delegation-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-ssh-request-parent-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-ssh-request-parent-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-ssh-managed-child-core-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!(
    "feature `wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance` is QEMU-only"
);

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-single-boot-collector",
    feature = "qemu-virt",
    not(any(
        feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance",
        feature = "wasm-c84-qemu-aot-decision"
    ))
))]
compile_error!(
    "feature `wasm-c84-ssh-managed-child-single-boot-collector` cannot expose physical formal records on QEMU"
);

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-single-boot-collector",
    not(any(
        feature = "milkv-duo",
        feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance",
        feature = "wasm-c84-qemu-aot-decision"
    ))
))]
compile_error!(
    "feature `wasm-c84-ssh-managed-child-single-boot-collector` requires Milk-V Duo, its absorbing QEMU acceptance, or the formal QEMU contract"
);

#[cfg(all(feature = "wasm-c84-qemu-aot-decision", not(feature = "qemu-virt")))]
compile_error!("feature `wasm-c84-qemu-aot-decision` is QEMU-only");

#[cfg(all(feature = "wasm-c84-qemu-aot-decision", feature = "milkv-duo"))]
compile_error!("feature `wasm-c84-qemu-aot-decision` cannot claim Milk-V Duo provenance");

#[cfg(all(
    feature = "wasm-c84-qemu-aot-decision-smoke",
    not(feature = "wasm-c84-qemu-aot-decision")
))]
compile_error!("feature `wasm-c84-qemu-aot-decision-smoke` must layer on the formal QEMU image");

#[cfg(all(
    feature = "wasm-c84-qemu-aot-decision",
    feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
))]
compile_error!("formal and absorbing C8.4 QEMU collectors are mutually exclusive");

// The decision image measures the production workload path. Diagnostic
// acceptance features add UART formatting and synthetic SSIPs inside active
// intervals, so Cargo feature unification must fail instead of silently
// contaminating a formal or dirty-smoke transcript.
#[cfg(all(
    feature = "wasm-c84-qemu-aot-decision",
    any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance",
        feature = "wasm-c84-ssh-request-parent-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance"
    )
))]
compile_error!("formal C8.4 QEMU decision images exclude diagnostic QEMU acceptance telemetry");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-single-boot-collector",
    feature = "legacy-shell"
))]
compile_error!(
    "feature `wasm-c84-ssh-managed-child-single-boot-collector` excludes the local legacy shell"
);

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance",
    not(feature = "qemu-virt")
))]
compile_error!("feature `wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance` is QEMU-only");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-trusted-sample",
    feature = "wasm-c84-ssh-managed-child-verified-stream"
))]
compile_error!(
    "features `wasm-c84-ssh-managed-child-trusted-sample` and `wasm-c84-ssh-managed-child-verified-stream` are mutually exclusive finish/verify successors"
);

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-single-boot-collector",
    feature = "wasm-c84-ssh-managed-child-verified-stream"
))]
compile_error!(
    "features `wasm-c84-ssh-managed-child-single-boot-collector` and `wasm-c84-ssh-managed-child-verified-stream` are mutually exclusive trusted-sample consumers"
);

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-trusted-sample",
    feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance",
    not(feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance"),
    not(feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"),
    not(feature = "wasm-c84-qemu-aot-decision")
))]
compile_error!(
    "feature `wasm-c84-ssh-managed-child-trusted-sample` cannot reuse the discard-only finish/verify QEMU transcript"
);

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-single-boot-collector",
    feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance",
    not(any(
        feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance",
        feature = "wasm-c84-qemu-aot-decision"
    ))
))]
compile_error!(
    "feature `wasm-c84-ssh-managed-child-single-boot-collector` cannot reuse the discard-only finish/verify QEMU transcript"
);

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance",
    any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance",
        feature = "wasm-c84-qemu-aot-decision"
    )
))]
compile_error!("C8.4 QEMU acceptances are isolated images");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
    any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
    )
))]
compile_error!("C8.4 QEMU acceptances are isolated images");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-verified-stream",
    feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance",
    not(feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance")
))]
compile_error!(
    "feature `wasm-c84-ssh-managed-child-verified-stream` cannot reuse the discard-only finish/verify QEMU transcript"
);

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance",
    any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
    )
))]
compile_error!("C8.4 QEMU acceptances are isolated images");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-finish-verify",
    feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance",
    not(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance")
))]
compile_error!(
    "feature `wasm-c84-ssh-managed-child-finish-verify` cannot reuse the cancel-only IRQ QEMU transcript"
);

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance",
    any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
    )
))]
compile_error!("C8.4 QEMU acceptances are isolated images");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance",
    any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
    )
))]
compile_error!("C8.4 QEMU acceptances are isolated images");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance",
    any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
    )
))]
compile_error!("C8.4 QEMU acceptances are isolated images");

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance",
    any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
    )
))]
compile_error!("C8.4 QEMU acceptances are isolated images");

#[cfg(all(
    feature = "wasm-c84-ssh-request-parent-qemu-acceptance",
    any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
    )
))]
compile_error!("C8.4 QEMU acceptances are isolated images");

#[cfg(any(
    all(
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance"
    ),
    all(
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance"
    ),
    all(
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
    ),
    all(
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance"
    ),
    all(
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
    ),
    all(
        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
    )
))]
compile_error!("C8.4 QEMU acceptances are isolated images");

#[cfg(all(
    feature = "wasm-c84-profile-irq-overlay",
    not(feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance"),
    any(
        feature = "wasm-c84-profile-slot-qemu-acceptance",
        feature = "wasm-c84-core-poll-qemu-acceptance",
        feature = "wasm-c84-ssh-request-parent-qemu-acceptance"
    )
))]
compile_error!("C8.4 IRQ overlay cannot modify an exact-transcript QEMU acceptance image");

#[cfg(all(feature = "tcp-echo", not(feature = "qemu-virt")))]
compile_error!("feature `tcp-echo` is the QEMU-only N1 acceptance image");
#[cfg(all(feature = "net-shell", not(feature = "milkv-duo")))]
compile_error!("feature `net-shell` is the Milk-V Duo production IPv4 image");
#[cfg(all(feature = "iperf3-server", not(feature = "qemu-virt")))]
compile_error!("feature `iperf3-server` is the QEMU iperf3 server image");
#[cfg(all(feature = "milkv-iperf3-server", not(feature = "milkv-duo")))]
compile_error!("feature `milkv-iperf3-server` is the Milk-V Duo iperf3 server image");
#[cfg(all(feature = "net-shell", feature = "tcp-echo"))]
compile_error!("features `net-shell` and `tcp-echo` are mutually exclusive IPv4 images");
#[cfg(all(
    feature = "iperf3-server",
    any(
        feature = "tcp-echo",
        feature = "ssh-test",
        feature = "ssh-security-test"
    )
))]
compile_error!("feature `iperf3-server` is an isolated QEMU network image");
#[cfg(all(
    feature = "milkv-iperf3-server",
    any(
        feature = "net-shell",
        feature = "milkv-ssh",
        feature = "milkv-ssh-acceptance",
        feature = "milkv-jitterentropy-probe",
        feature = "milkv-jitterentropy-ssh-probe"
    )
))]
compile_error!("feature `milkv-iperf3-server` is an isolated Milk-V network image");
#[cfg(all(feature = "ssh-security-test", not(feature = "qemu-virt")))]
compile_error!("feature `ssh-security-test` is the QEMU-only N3 acceptance image");
#[cfg(all(feature = "ssh-test", not(feature = "qemu-virt")))]
compile_error!("feature `ssh-test` is the QEMU-only N4 acceptance image");
#[cfg(all(
    feature = "wasm-c48-qemu-acceptance",
    not(all(feature = "qemu-virt", feature = "ssh-test"))
))]
compile_error!("feature `wasm-c48-qemu-acceptance` requires the QEMU-only `ssh-test` image");
#[cfg(all(
    feature = "wasm-c53-native-async-qemu-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!("feature `wasm-c53-native-async-qemu-acceptance` requires the QEMU default image");
#[cfg(all(
    feature = "wasm-c53-native-async-qemu-acceptance",
    any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "ssh-security-test",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance",
        feature = "milkv-ssh"
    )
))]
compile_error!(
    "feature `wasm-c53-native-async-qemu-acceptance` is isolated from every SSH/older WASM image"
);
#[cfg(all(
    feature = "wasm-c53-native-async-qemu-acceptance",
    feature = "ssh-native-async-command"
))]
compile_error!(
    "the direct native-async acceptance image and formal managed command are distinct roots"
);
#[cfg(all(
    feature = "wasm-c63-graph-principal-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!("feature `wasm-c63-graph-principal-acceptance` requires the QEMU default image");
#[cfg(all(
    feature = "wasm-c64-resource-route-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!("feature `wasm-c64-resource-route-acceptance` requires the QEMU default image");
#[cfg(all(
    feature = "wasm-c65-async-chain-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!("feature `wasm-c65-async-chain-acceptance` requires the QEMU default image");
#[cfg(all(
    feature = "wasm-c66-node-replacement-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!("feature `wasm-c66-node-replacement-acceptance` requires the QEMU default image");
#[cfg(all(
    feature = "wasm-c67-information-flow-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!("feature `wasm-c67-information-flow-acceptance` requires the QEMU default image");
#[cfg(all(
    feature = "wasm-c73-authenticated-admission-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!(
    "feature `wasm-c73-authenticated-admission-acceptance` requires the QEMU default image"
);
#[cfg(all(
    feature = "wasm-c74-crash-safe-publication-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!(
    "feature `wasm-c74-crash-safe-publication-acceptance` requires the QEMU default image"
);
#[cfg(all(
    feature = "wasm-c75-boot-revalidation-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!("feature `wasm-c75-boot-revalidation-acceptance` requires the QEMU default image");
#[cfg(all(
    feature = "wasm-c76-graph-version-replacement-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!(
    "feature `wasm-c76-graph-version-replacement-acceptance` requires the QEMU default image"
);
#[cfg(all(
    feature = "wasm-c77-ephemeral-runtime-acceptance",
    not(all(feature = "qemu-virt", feature = "qemu-default-image"))
))]
compile_error!("feature `wasm-c77-ephemeral-runtime-acceptance` requires the QEMU default image");
#[cfg(all(
    feature = "wasm-c77-ephemeral-runtime-acceptance",
    any(
        feature = "legacy-shell",
        feature = "ssh-component-command",
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "wasm-c63-graph-principal-acceptance",
        feature = "wasm-c64-resource-route-acceptance",
        feature = "wasm-c65-async-chain-acceptance",
        feature = "wasm-c66-node-replacement-acceptance",
        feature = "wasm-c67-information-flow-acceptance",
        feature = "wasm-c73-authenticated-admission-acceptance",
        feature = "wasm-c74-crash-safe-publication-acceptance",
        feature = "wasm-c75-boot-revalidation-acceptance"
    )
))]
compile_error!(
    "feature `wasm-c77-ephemeral-runtime-acceptance` is isolated from guest, command, and every earlier WASM acceptance root"
);
#[cfg(all(
    feature = "wasm-c76-graph-version-replacement-acceptance",
    any(
        feature = "legacy-shell",
        feature = "ssh-component-command",
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "wasm-c63-graph-principal-acceptance",
        feature = "wasm-c64-resource-route-acceptance",
        feature = "wasm-c65-async-chain-acceptance",
        feature = "wasm-c66-node-replacement-acceptance",
        feature = "wasm-c67-information-flow-acceptance",
        feature = "wasm-c73-authenticated-admission-acceptance",
        feature = "wasm-c74-crash-safe-publication-acceptance",
        feature = "wasm-c75-boot-revalidation-acceptance"
    )
))]
compile_error!(
    "feature `wasm-c76-graph-version-replacement-acceptance` is isolated from guest, command, and every earlier WASM acceptance root"
);
#[cfg(all(
    feature = "wasm-c75-boot-revalidation-acceptance",
    any(
        feature = "legacy-shell",
        feature = "component-graph-principals",
        feature = "ssh-component-command",
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "wasm-c63-graph-principal-acceptance",
        feature = "wasm-c64-resource-route-acceptance",
        feature = "wasm-c65-async-chain-acceptance",
        feature = "wasm-c66-node-replacement-acceptance",
        feature = "wasm-c67-information-flow-acceptance",
        feature = "wasm-c73-authenticated-admission-acceptance",
        feature = "wasm-c74-crash-safe-publication-acceptance"
    )
))]
compile_error!(
    "feature `wasm-c75-boot-revalidation-acceptance` is isolated from live guest, command, and older WASM acceptance roots"
);
#[cfg(all(
    feature = "wasm-c74-crash-safe-publication-acceptance",
    any(
        feature = "legacy-shell",
        feature = "component-graph-principals",
        feature = "ssh-component-command",
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "wasm-c63-graph-principal-acceptance",
        feature = "wasm-c64-resource-route-acceptance",
        feature = "wasm-c65-async-chain-acceptance",
        feature = "wasm-c66-node-replacement-acceptance",
        feature = "wasm-c67-information-flow-acceptance",
        feature = "wasm-c73-authenticated-admission-acceptance",
        feature = "wasm-c75-boot-revalidation-acceptance"
    )
))]
compile_error!(
    "feature `wasm-c74-crash-safe-publication-acceptance` is isolated from live guest, command, and older WASM acceptance roots"
);
#[cfg(all(
    feature = "wasm-c73-authenticated-admission-acceptance",
    any(
        feature = "legacy-shell",
        feature = "component-graph-principals",
        feature = "ssh-component-command",
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "wasm-c63-graph-principal-acceptance",
        feature = "wasm-c64-resource-route-acceptance",
        feature = "wasm-c65-async-chain-acceptance",
        feature = "wasm-c66-node-replacement-acceptance",
        feature = "wasm-c67-information-flow-acceptance"
    )
))]
compile_error!(
    "feature `wasm-c73-authenticated-admission-acceptance` is isolated from live guest and older WASM acceptance roots"
);
#[cfg(all(
    feature = "wasm-c67-information-flow-acceptance",
    any(
        feature = "legacy-shell",
        feature = "component-graph-principals",
        feature = "ssh-component-command",
        feature = "wasm-c53-native-async-qemu-acceptance"
    )
))]
compile_error!(
    "feature `wasm-c67-information-flow-acceptance` is isolated from live shell/guest diagnostics"
);
#[cfg(all(
    any(
        feature = "wasm-c63-graph-principal-acceptance",
        feature = "wasm-c64-resource-route-acceptance",
        feature = "wasm-c65-async-chain-acceptance",
        feature = "wasm-c66-node-replacement-acceptance",
        feature = "wasm-c67-information-flow-acceptance"
    ),
    any(
        all(
            feature = "wasm-c63-graph-principal-acceptance",
            feature = "wasm-c64-resource-route-acceptance"
        ),
        all(
            feature = "wasm-c63-graph-principal-acceptance",
            feature = "wasm-c65-async-chain-acceptance"
        ),
        all(
            feature = "wasm-c64-resource-route-acceptance",
            feature = "wasm-c65-async-chain-acceptance"
        ),
        all(
            feature = "wasm-c63-graph-principal-acceptance",
            feature = "wasm-c66-node-replacement-acceptance"
        ),
        all(
            feature = "wasm-c64-resource-route-acceptance",
            feature = "wasm-c66-node-replacement-acceptance"
        ),
        all(
            feature = "wasm-c65-async-chain-acceptance",
            feature = "wasm-c66-node-replacement-acceptance"
        ),
        all(
            feature = "wasm-c63-graph-principal-acceptance",
            feature = "wasm-c67-information-flow-acceptance"
        ),
        all(
            feature = "wasm-c64-resource-route-acceptance",
            feature = "wasm-c67-information-flow-acceptance"
        ),
        all(
            feature = "wasm-c65-async-chain-acceptance",
            feature = "wasm-c67-information-flow-acceptance"
        ),
        all(
            feature = "wasm-c66-node-replacement-acceptance",
            feature = "wasm-c67-information-flow-acceptance"
        )
    )
))]
compile_error!("the C6.3 through C6.7 graph acceptance images are distinct roots");
#[cfg(all(
    feature = "component-graph-principals",
    feature = "ssh-component-command"
))]
compile_error!(
    "features `component-graph-principals` and `ssh-component-command` are fail-closed lifecycle-isolation alternatives"
);
#[cfg(all(
    feature = "ssh-native-async-qemu-acceptance",
    not(all(
        feature = "qemu-virt",
        feature = "ssh-test",
        feature = "wasm-c48-qemu-acceptance"
    ))
))]
compile_error!("feature `ssh-native-async-qemu-acceptance` requires the QEMU ssh-test/C4.8 image");
#[cfg(all(
    feature = "ssh-native-async-revoke-qemu-acceptance",
    not(all(
        feature = "qemu-virt",
        feature = "ssh-test",
        feature = "wasm-c48-qemu-acceptance"
    ))
))]
compile_error!(
    "feature `ssh-native-async-revoke-qemu-acceptance` requires the QEMU ssh-test/C4.8 image"
);
#[cfg(all(
    feature = "ssh-native-async-revoke-qemu-acceptance",
    feature = "ssh-native-async-qemu-acceptance"
))]
compile_error!(
    "the C5.4c native revoke gate and standard formal-native SSH gate are isolated images"
);
#[cfg(all(feature = "milkv-ssh-acceptance", not(feature = "milkv-duo")))]
compile_error!("feature `milkv-ssh-acceptance` is the Milk-V Duo hardware acceptance image");
#[cfg(all(feature = "milkv-ssh", not(feature = "milkv-duo")))]
compile_error!("feature `milkv-ssh` is the Milk-V Duo production SSH image");
#[cfg(all(
    feature = "milkv-ssh",
    any(
        feature = "net-shell",
        feature = "milkv-ssh-acceptance",
        feature = "tcp-echo",
        feature = "ssh-test"
    )
))]
compile_error!("feature `milkv-ssh` cannot be combined with another IPv4 image policy");
#[cfg(all(feature = "milkv-jitterentropy-probe", not(feature = "milkv-duo")))]
compile_error!("feature `milkv-jitterentropy-probe` is the Milk-V Duo hardware probe image");
#[cfg(all(feature = "milkv-jitterentropy-ssh-probe", not(feature = "milkv-duo")))]
compile_error!("feature `milkv-jitterentropy-ssh-probe` is a Milk-V Duo qualification image");
#[cfg(all(feature = "ssh-test", feature = "tcp-echo"))]
compile_error!("features `ssh-test` and `tcp-echo` are mutually exclusive acceptance images");
#[cfg(all(feature = "ssh-test", feature = "ssh-security-test"))]
compile_error!(
    "features `ssh-test` and `ssh-security-test` are mutually exclusive acceptance images"
);
#[cfg(all(
    feature = "milkv-ssh-acceptance",
    any(
        feature = "net-shell",
        feature = "tcp-echo",
        feature = "ssh-test",
        feature = "ssh-security-test"
    )
))]
compile_error!(
    "feature `milkv-ssh-acceptance` cannot be combined with another IPv4 or SSH test image policy"
);
#[cfg(all(
    feature = "milkv-jitterentropy-probe",
    any(
        feature = "net-shell",
        feature = "tcp-echo",
        feature = "ssh-test",
        feature = "ssh-security-test",
        feature = "milkv-ssh-acceptance"
    )
))]
compile_error!("feature `milkv-jitterentropy-probe` is an isolated UART qualification image");

extern crate alloc;

// Portable kernel logic lives in `vibeos-core`; the bare SBI seam lives in the
// RISC-V runtime. Re-export both under the names the rest of the tree uses.
#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
pub use vibeos_core::arch as sbi;
pub use vibeos_core::net;
pub use vibeos_core::{cap, chan, exec, heap, instance, interrupt, ipi, sync};
#[cfg(feature = "qemu-virt")]
pub use vibeos_driver_virtio_core as virtio;
pub use vibeos_durable_format as durable;
pub use vibeos_program_store as program;
pub use vibeos_random as random;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use vibeos_runtime_riscv as sbi;
pub use vibeos_vsh as vsh;
pub use vibeos_vsh::terminal;

mod bench_platform;
#[cfg(feature = "milkv-duo")]
mod board_led;
mod cap_table_pool;
mod code_pool;
#[cfg(feature = "wasm-c73-authenticated-admission-acceptance")]
mod component_authenticated_admission;
#[cfg(feature = "wasm-c75-boot-revalidation-acceptance")]
mod component_boot_revalidation;
#[cfg(feature = "wasm-c74-crash-safe-publication-acceptance")]
mod component_crash_safe_publication;
#[cfg(feature = "component-durable-publication")]
mod component_durable_publication;
#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
mod component_ephemeral_runtime;
#[cfg(feature = "wasm-c67-information-flow-acceptance")]
mod component_graph_information_flow;
#[cfg(feature = "component-graph-principals")]
pub mod component_graph_principals;
#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
mod component_graph_version_replacement;
mod component_instances;
mod dev;
#[path = "authority_store_platform.rs"]
mod durable_cspace;
#[cfg(any(feature = "iperf3-server", feature = "milkv-iperf3-server"))]
mod iperf3_platform;
#[cfg(any(
    feature = "milkv-jitterentropy-probe",
    feature = "milkv-jitterentropy-ssh-probe"
))]
mod jitterentropy_probe;
#[cfg(feature = "milkv-ssh")]
mod jitterentropy_random;
#[cfg(feature = "legacy-shell")]
mod legacy_shell;
mod mmu;
#[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
mod net_echo_platform;
#[cfg(any(
    feature = "tcp-echo",
    feature = "net-shell",
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh",
    feature = "iperf3-server",
    feature = "milkv-iperf3-server"
))]
mod netstack_platform;
#[cfg(feature = "qemu-virt")]
mod pci;
mod platform;
mod plic;
mod rustc;
#[path = "program_store_platform.rs"]
mod saved_program;
#[path = "selftest_platform.rs"]
mod selftest;
#[cfg(feature = "milkv-ssh")]
mod ssh_key_format;
#[cfg(any(
    feature = "ssh-security-test",
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
mod ssh_platform;
#[cfg(feature = "milkv-ssh")]
mod ssh_provisioning;
#[cfg(feature = "wasm-c84-profile-slot")]
mod wasm_aot_profile_slot;
#[cfg(any(
    feature = "wasm-c88-f5-float-qemu-acceptance",
    feature = "wasm-c88-f5-float-duo-compile-readiness"
))]
mod wasm_float_target;
#[cfg(feature = "wasm-c83-runtime-costs")]
mod wasm_runtime_costs;
pub use vibeos_object_store as store;
#[cfg(any(
    feature = "ssh-security-test",
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
pub use vibeos_ssh_identity as ssh_security;
mod block_device;
#[cfg(feature = "milkv-duo")]
mod dwc2_host;
#[cfg(feature = "milkv-duo")]
mod dwmac_net;
mod net_device;
#[cfg(feature = "milkv-duo")]
mod sdhci_blk;
mod segment_store_platform;
mod store_platform;
mod trampoline;
mod trap;
mod tty;
mod uart;
#[cfg(feature = "milkv-duo")]
mod usb_ecm_net;
#[cfg(feature = "qemu-virt")]
mod virtio_blk;
#[cfg(feature = "qemu-virt")]
use vibeos_driver_virtio_mmio as virtio_mmio;
#[cfg(feature = "qemu-virt")]
mod virtio_net;
#[cfg(feature = "qemu-virt")]
mod virtio_rng;
mod vsh_platform;
mod world;
#[cfg(feature = "qemu-virt")]
mod xhci;

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const KERNEL_STACK_STRIDE: usize = 256 * 1024;
const STACK_ABORT_RESERVE: usize = 8192;
const BOOT_HART_BIT: usize = 1;

// Release/acquire publication makes the boot hart's heap, hooks, and mapping
// reservations visible before a secondary touches shared kernel state.
static SECONDARY_BOOT_RELEASED: AtomicBool = AtomicBool::new(false);
// A bit is published only after the hart has a private stack, logical token,
// local trap vector, and timer. This is the real HSM completion barrier.
static KERNEL_READY_HARTS: AtomicUsize = AtomicUsize::new(0);

global_asm!(
    r#"
.option norvc
.section .text.boot
.global vibeos_kernel_start
vibeos_kernel_start:
    csrw sie, zero
    csrw sip, zero
    // Zero is the fail-closed "no logical hart" encoding. `mark_online`
    // installs logical_index + 1 after validating the firmware hartid.
    csrw sscratch, zero

    // OpenSBI passes the hart id in a0. S-mode cannot read mhartid, so retain
    // it in tp for IRQ routing now and hart-local state from M5.4 onward.
    mv tp, a0

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    // OpenSBI chooses the coldboot hart dynamically. Firmware retains every
    // other hart in HSM STOPPED, so whichever physical id arrives here owns
    // logical slot 0 and performs the one global initialization pass.
    la sp, __stack_top

    // Zero .bss before any Rust runs.
    la t0, __bss_start
    la t1, __bss_end
.Lbss:
    bgeu t0, t1, .Ldone
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Lbss
.Ldone:
    // See the secondary path: `tail` avoids the +-1 MiB JAL range limit.
    tail kmain

.align 4
.global _secondary_start
_secondary_start:
    csrw sie, zero
    csrw sip, zero
    csrw sscratch, zero

    // HSM supplies the physical hartid in a0 and our logical index in a1.
    // Keep the physical id in tp and select the corresponding private stack
    // before making any Rust call.
    mv tp, a0

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    beqz a1, .Lsecondary_park
    li t0, 4
    bgeu a1, t0, .Lsecondary_park
    la t0, __stacks_bottom
    slli t1, a1, 18
    add sp, t0, t1
    li t1, 1
    slli t1, t1, 18
    add sp, sp, t1
    // A plain `j` limits the kernel to +-1 MiB between this boot stub and
    // secondary_kmain; `tail` expands to auipc+jalr and never becomes a
    // link-time range constraint on text layout.
    tail secondary_kmain

.Lsecondary_park:
    wfi
    j .Lsecondary_park
"#
);

extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
    static __stack_bottom: u8;
    fn _secondary_start();
}

/// Lowest address a compiled program's current-hart stack may reach.
///
/// `__stack_bottom` is the first byte above logical hart 0's guard. Selecting
/// the fixed slot stride keeps generated-code probes inside the same private
/// mapped stack chosen by `_secondary_start`, with 8 KiB of mapped abort room
/// still below the returned floor.
pub fn stack_floor() -> usize {
    // Leave a band so the abort path itself has room to run.
    let hart =
        ipi::current_logical_hart().expect("compiled program stack requires a mapped logical hart");
    core::ptr::addr_of!(__stack_bottom) as usize
        + hart.index() * KERNEL_STACK_STRIDE
        + STACK_ABORT_RESERVE
}

/// Harts which have completed the complete VibeOS-local startup handshake.
pub fn online_hart_mask() -> usize {
    KERNEL_READY_HARTS.load(Ordering::Acquire)
}

pub fn online_hart_count() -> usize {
    online_hart_mask().count_ones() as usize
}

#[global_allocator]
pub static HEAP: heap::Heap = heap::Heap::new();

const BANNER: &str = r#"
   __   __ __  _           ____  ____
   \ \ / /(_)| |__   ___  / __ \/ ___|
    \ V / | || '_ \ / _ \| |  | \___ \
     \_/  |_||_.__/ \___/ \____/|____/   v0.1
"#;

#[no_mangle]
pub extern "C" fn kmain() -> ! {
    uart::early_write("\r\n[VibeOS] entry\r\n");
    exec::configure_timebase(platform::TIMEBASE_HZ);
    let boot_time = sbi::time();
    #[cfg(not(feature = "legacy-shell"))]
    let _ = boot_time;
    let boot_physical_hart = sbi::current_hart_id();

    mmu::init_boot(boot_physical_hart);
    uart::early_write("[VibeOS] page tables ready\r\n");
    mmu::enable(exec::HartId::BOOT.index());
    uart::early_write("[VibeOS] Sv39 enabled\r\n");

    #[cfg(feature = "milkv-duo")]
    let blue_led = board_led::init();
    #[cfg(feature = "milkv-duo")]
    uart::early_write(if blue_led.on() {
        "[VibeOS] blue status LED on\r\n"
    } else {
        "[VibeOS] blue status LED readback failed\r\n"
    });

    uart::init();
    println!("{}", BANNER);
    println!(
        "  platform  {} ({} MHz timebase)",
        platform::NAME,
        platform::TIMEBASE_HZ / 1_000_000
    );
    #[cfg(feature = "milkv-duo")]
    println!(
        "  led       blue GPIOC24 {} (pinmux {:#x}, dir {:#010x}, data {:#010x}, input {:#010x})",
        if blue_led.on() { "on" } else { "FAILED" },
        blue_led.pinmux,
        blue_led.direction,
        blue_led.data,
        blue_led.external,
    );

    let (hs, he) = (
        core::ptr::addr_of!(__heap_start) as usize,
        core::ptr::addr_of!(__heap_end) as usize,
    );
    unsafe { HEAP.init(hs, he) };
    println!(
        "  heap      {:#x}..{:#x}  ({} KiB)",
        hs,
        he,
        (he - hs) / 1024
    );

    ipi::mark_online(exec::HartId::BOOT, boot_physical_hart)
        .expect("boot physical hart must have one logical scheduler identity");
    // Install the logical identity before any trap-local state can be used.
    trap::init_boot();
    KERNEL_READY_HARTS.store(BOOT_HART_BIT, Ordering::Release);
    exec::set_ready_notify_hook(ipi::notify_ready);
    println!(
        "  traps     stvec armed, PLIC ctx S/hart{}, IRQ {} enabled",
        boot_physical_hart,
        uart::UART_IRQ
    );

    // Install the complete fault boundary before World admits any reclaimable
    // component task. A tracked arena must never run without both hooks.
    exec::set_fault_guard(trampoline::guard_task);
    exec::set_fault_cleanup(cleanup_faulted_task);
    exec::set_fault_reclaimer(reclaim_faulted_component);
    #[cfg(any(
        feature = "wasm-c63-graph-principal-acceptance",
        feature = "wasm-c64-resource-route-acceptance",
        feature = "wasm-c65-async-chain-acceptance",
        feature = "wasm-c66-node-replacement-acceptance"
    ))]
    assert!(
        component_graph_principals::run_host_model_selftest(),
        "component graph principal host model failed"
    );

    #[cfg(feature = "wasm-c84-profile-slot")]
    wasm_aot_profile_slot::init();

    let online = start_secondary_harts();
    println!("  smp       {} hart(s) online", online);
    assert_eq!(
        mmu::enabled_hart_mask(),
        online_hart_mask(),
        "every online hart must publish Sv39 readback"
    );
    println!(
        "  mmu       Sv39 single address space, hart mask {:#x}",
        mmu::enabled_hart_mask()
    );
    #[cfg(all(
        feature = "qemu-virt",
        not(any(
            feature = "wasm-c83-runtime-costs",
            feature = "wasm-c88-f5-float-qemu-acceptance",
            feature = "wasm-c88-f5-float-duo-compile-readiness"
        ))
    ))]
    {
        let functions = pci::init().expect("QEMU PCI resource assignment must succeed");
        println!(
            "  pci       {} function(s), ECAM {:#x}, MMIO {:#x}..{:#x}",
            functions,
            platform::PCI_ECAM_START,
            platform::PCI_MMIO_START,
            platform::PCI_MMIO_END,
        );
        if let Some(info) = xhci::init().expect("QEMU XHCI initialization must succeed") {
            println!(
                "  usb       XHCI {:#06x} @ {:#x}, {} slot(s), {} port(s), {} device(s)",
                info.version,
                info.mmio_base,
                info.max_slots,
                info.max_ports,
                info.addressed_devices,
            );
        }
    }
    #[cfg(all(
        feature = "milkv-duo",
        not(any(
            feature = "wasm-c83-runtime-costs",
            feature = "wasm-c88-f5-float-qemu-acceptance",
            feature = "wasm-c88-f5-float-duo-compile-readiness"
        ))
    ))]
    match dwc2_host::init() {
        Ok(info) => println!(
            "  usb       DWC2 {:#06x} @ {:#x}, IRQ {}, {} channel(s), port {}",
            info.release,
            platform::USB_BASE,
            info.irq,
            info.host_channels,
            if dwc2_host::connected() {
                "connected"
            } else {
                "powered/waiting"
            },
        ),
        Err(error) => println!("  usb       DWC2 bring-up FAILED: {:?}", error),
    }
    #[cfg(all(
        feature = "milkv-duo",
        not(any(
            feature = "wasm-c83-runtime-costs",
            feature = "wasm-c88-f5-float-qemu-acceptance",
            feature = "wasm-c88-f5-float-duo-compile-readiness"
        ))
    ))]
    if let Some(usb) = dwc2_host::telemetry() {
        println!(
            "  usb regs  clocks {:#010x}/{:#010x}, role {:#010x}, GUSBCFG {:#010x}, HPRT {:#010x}, PHY14 {:#010x}",
            usb.clock_enable_1,
            usb.clock_enable_2,
            usb.role_override,
            usb.gusbcfg,
            usb.hprt0,
            usb.phy_utmi_control,
        );
    }
    #[cfg(all(
        feature = "milkv-duo",
        not(any(
            feature = "wasm-c83-runtime-costs",
            feature = "wasm-c88-f5-float-qemu-acceptance",
            feature = "wasm-c88-f5-float-duo-compile-readiness"
        ))
    ))]
    if dwc2_host::connected() {
        match dwc2_host::enumerate_device() {
            Ok(Some(device)) => {
                println!(
                    "  usb dev   addr {}, {:?}, {:04x}:{:04x}, USB {:#06x}, EP0 {}",
                    device.address,
                    device.speed,
                    device.vendor_id,
                    device.product_id,
                    device.usb_version,
                    device.max_packet_size_0,
                );
                match dwc2_host::configure_hid_keyboard() {
                    Ok(Some(keyboard)) => println!(
                        "  usb hid   {:?} keyboard, interface {}, IN ep {}, MPS {}, poll {} ms",
                        keyboard.protocol,
                        keyboard.interface,
                        keyboard.endpoint_in & 0x0f,
                        keyboard.max_packet_size,
                        keyboard.interval_ms,
                    ),
                    Ok(None) => println!("  usb hid   no supported keyboard interface"),
                    Err(error) => println!("  usb hid   configuration FAILED: {:?}", error),
                }
                let rtl8151_switched = match dwc2_host::switch_rtl8151_install_mode() {
                    Ok(switched) => switched,
                    Err(error) => {
                        println!("  usb net   RTL8151 mode switch FAILED: {:?}", error);
                        false
                    }
                };
                if rtl8151_switched {
                    println!(
                        "  usb net   sent RTL8151 install-mode switch; waiting for Ethernet re-enumeration"
                    );
                }
                if !rtl8151_switched {
                    match dwc2_host::configure_cdc_ecm() {
                        Ok(Some(ecm)) => println!(
                            "  usb net   CDC-ECM configured, interface {} alt {}, IN ep {}, OUT ep {}, MAC {:?}",
                            ecm.data_interface,
                            ecm.data_alternate,
                            ecm.endpoint_in & 0x0f,
                            ecm.endpoint_out & 0x0f,
                            ecm.mac_address,
                        ),
                        Ok(None) => {}
                        Err(error) => println!("  usb net   CDC-ECM configuration FAILED: {:?}", error),
                    }
                }
                match if rtl8151_switched {
                    Ok(None)
                } else {
                    dwc2_host::configure_mass_storage()
                } {
                    Ok(Some(storage)) => println!(
                        "  usb disk  SCSI/BOT interface {}, IN ep {}, OUT ep {}, {} sectors x {} bytes",
                        storage.interface,
                        storage.endpoint_in & 0x0f,
                        storage.endpoint_out & 0x0f,
                        storage.capacity_sectors.unwrap_or(0),
                        storage.block_size.unwrap_or(0),
                    ),
                    Ok(None) => {}
                    Err(error) => println!("  usb disk  configuration FAILED: {:?}", error),
                }
            }
            Ok(None) => println!("  usb dev   disconnected during enumeration"),
            Err(error) => println!("  usb dev   enumeration FAILED: {:?}", error),
        }
    }
    assert!(
        mmu::wx_remote_fence_ready(),
        "multicore W^X requires the SBI RFENCE extension"
    );
    // Safety: cap_table_pool owns one page-exclusive region for the kernel
    // lifetime; its hooks validate exact live runs, synchronously perform the
    // all-hart PTE/TLB transition, and release only retired writable runs.
    cap::set_capability_table_backend(unsafe {
        cap::CapabilityTableBackend::new(
            cap_table_pool::allocate_pages,
            cap_table_pool::set_read_only,
            cap_table_pool::release_pages,
        )
    });
    let (code_start, code_end) = mmu::code_pool_range();
    println!(
        "  W^X       {} KiB code pool {:#x}..{:#x}, MXR clear, RFENCE ready",
        (code_end - code_start) / 1024,
        code_start,
        code_end
    );
    let (rodata_start, rodata_end) = mmu::rodata_range();
    println!(
        "  read-only {} KiB .rodata {:#x}..{:#x}; {} KiB COW capability-table pool",
        (rodata_end - rodata_start) / 1024,
        rodata_start,
        rodata_end,
        cap_table_pool::CAP_TABLE_POOL_BYTES / 1024,
    );

    #[cfg(feature = "ssh-component-command")]
    component_instances::init();

    #[cfg(not(any(
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "wasm-c88-f5-float-duo-compile-readiness"
    )))]
    world::build();

    #[cfg(not(any(
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "wasm-c88-f5-float-duo-compile-readiness"
    )))]
    let world = world::world();
    #[cfg(not(any(
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "wasm-c88-f5-float-duo-compile-readiness"
    )))]
    world::start_block_supervisor();
    #[cfg(not(any(
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "wasm-c88-f5-float-duo-compile-readiness"
    )))]
    world::start_net_supervisor();
    #[cfg(all(
        feature = "milkv-duo",
        not(any(
            feature = "wasm-c83-runtime-costs",
            feature = "wasm-c88-f5-float-qemu-acceptance",
            feature = "wasm-c88-f5-float-duo-compile-readiness"
        ))
    ))]
    world::start_usb_net_supervisor();
    #[cfg(all(
        feature = "qemu-virt",
        not(any(
            feature = "wasm-c83-runtime-costs",
            feature = "wasm-c88-f5-float-qemu-acceptance",
            feature = "wasm-c88-f5-float-duo-compile-readiness"
        ))
    ))]
    world::start_rng_supervisor();
    #[cfg(all(
        feature = "qemu-virt",
        not(any(
            feature = "wasm-c83-runtime-costs",
            feature = "wasm-c88-f5-float-qemu-acceptance",
            feature = "wasm-c88-f5-float-duo-compile-readiness"
        ))
    ))]
    if xhci::info().is_some() {
        exec::spawn("usb-host", xhci::service_task());
    }
    #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
    exec::spawn("wasm-c53-native-async-acceptance", async {
        if !component_instances::run_native_async_qemu_acceptance().await {
            crate::println!("WASM_C53_NATIVE_ASYNC_FAIL");
            sbi::shutdown(true);
        }
    });
    #[cfg(feature = "wasm-c63-graph-principal-acceptance")]
    exec::spawn("wasm-c63-graph-principal-acceptance", async {
        if component_graph_principals::run_qemu_acceptance().await {
            crate::println!("WASM_C63_GRAPH_PRINCIPAL PASS nodes=2 runtime_unavailable=2 fuel_consumed=0 peak_slots=0 live_slots=0 registry_occupied=0 registry_header_mismatches=0");
        } else {
            crate::println!("WASM_C63_GRAPH_PRINCIPAL FAIL");
            sbi::shutdown(true);
        }
    });
    #[cfg(feature = "wasm-c64-resource-route-acceptance")]
    exec::spawn("wasm-c64-resource-route-acceptance", async {
        match component_graph_principals::run_c64_qemu_acceptance().await {
            Some(guest_calls) => crate::println!(
                "WASM_C64_RESOURCE_ROUTE PASS nodes=2 own=1 borrow=1 guest_calls={} fuel_consumed=0 provider_peak=1 provider_live=0 consumer_peak=1 consumer_live=0 target_revoked=1 source_revoked=0 target_first=1 runtime_unavailable=2 registry_occupied=0 registry_header_mismatches=0",
                guest_calls,
            ),
            None => {
                crate::println!("WASM_C64_RESOURCE_ROUTE FAIL");
                sbi::shutdown(true);
            }
        }
    });
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    exec::spawn("wasm-c65-async-chain-acceptance", async {
        if component_graph_principals::run_c65_qemu_acceptance().await {
            crate::println!("WASM_C65_ASYNC_CHAIN PASS nodes=3 internal_edges=2 host_deliveries=2 causes=backend-fault,cancelled cascades=2 consumer_first=2 no_active_poll=1 lost_wakes=0 guest_calls=0 runtime_ready=0 fuel_consumed=0 peak_depths=8,8,8 registry_occupied=0 registry_header_mismatches=0");
        } else {
            crate::println!("WASM_C65_ASYNC_CHAIN FAIL");
            sbi::shutdown(true);
        }
    });
    #[cfg(feature = "wasm-c66-node-replacement-acceptance")]
    exec::spawn("wasm-c66-node-replacement-acceptance", async {
        if component_graph_principals::run_c66_qemu_acceptance().await {
            crate::println!("WASM_C66_NODE_REPLACEMENT PASS nodes=3 incarnations=4 replacements=1 kind=update candidate_staged=1 old_terminal_before_new_ready=1 siblings_stable=2 sibling_restarts=0 sibling_resource_tables=2 incident_edges=2 old_routes_retired=2 fresh_routes=2 sealed_handoffs=2 stale_sibling_routes=2 stale_replacement_tokens=2 late_wake_stale=1 fresh_edge_deliveries=2 sink_deliveries=1 no_active_poll=1 lost_wakes=0 terminal_receipts=4 runtime_unavailable=4 guest_calls=0 runtime_ready=0 fuel_consumed=0 live_slots=0 waiters=0 registrations=0 registry_occupied=0 registry_header_mismatches=0");
        } else {
            crate::println!("WASM_C66_NODE_REPLACEMENT FAIL");
            sbi::shutdown(true);
        }
    });

    #[cfg(feature = "wasm-c67-information-flow-acceptance")]
    exec::spawn("wasm-c67-information-flow-acceptance", async {
        if component_graph_information_flow::run_qemu_acceptance() {
            crate::println!("WASM_C67_INFORMATION_FLOW PASS harts=4 nodes=3 edges=2 principal_policy_labels=3 typed_edges=2 async_edges=2 published=1 exact_render=1 negative_rejections=5 forbidden_classes=5 forbidden_hits=0 manifest_only=1 runtime_ready=0 guest_calls=0 registry_occupied=0 registry_header_mismatches=0");
        } else {
            crate::println!("WASM_C67_INFORMATION_FLOW FAIL");
            sbi::shutdown(true);
        }
    });
    #[cfg(feature = "wasm-c73-authenticated-admission-acceptance")]
    exec::spawn("wasm-c73-authenticated-admission-acceptance", async {
        if component_authenticated_admission::run_qemu_acceptance() {
            crate::println!("\nWASM_C73_AUTHENTICATED_ADMISSION PASS development_accepted=1 operator_p1_accepted=2 operator_p2_accepted=1 wrong_signer_rejected=1 unknown_signer_rejected=1 revoked_signer_rejected=1 old_policy_rejected=1 artifact_mutations_rejected=2 module_mutations_rejected=2 wit_mutations_rejected=2 adapter_mutations_rejected=2 limit_mutations_rejected=2 profile_mutations_rejected=2 signature_replays_rejected=2 content_hash_only_rejected=1 runtime_unavailable=4 runtime_ready=0 guest_calls=0 raw_ids=0");
        } else {
            crate::println!("WASM_C73_AUTHENTICATED_ADMISSION FAIL");
            sbi::shutdown(true);
        }
    });
    #[cfg(feature = "wasm-c74-crash-safe-publication-acceptance")]
    let c74_authority_journal = if online_hart_count() == 4 {
        world.c74_component_authority_journal()
    } else {
        None
    };
    #[cfg(feature = "wasm-c74-crash-safe-publication-acceptance")]
    exec::spawn("wasm-c74-crash-safe-publication-acceptance", async move {
        if component_crash_safe_publication::run_qemu_acceptance(c74_authority_journal).await {
            crate::println!("\nWASM_C74_CRASH_SAFE_PUBLICATION PASS evidence_committed=1 artifact_committed=1 root_committed=1 command_published=1 early_publications=0 durable_read=1 durable_grant=0 durable_invoke=0 component_tasks=0 runtime_ready=0 guest_calls=0 raw_ids=0 storage_v2_only=1 policy_v2=1 physical_readback=1");
        } else {
            crate::println!("WASM_C74_CRASH_SAFE_PUBLICATION FAIL");
            sbi::shutdown(true);
        }
    });
    #[cfg(feature = "wasm-c75-boot-revalidation-acceptance")]
    let c75_baseline_component_count = world.c75_component_count();
    #[cfg(feature = "wasm-c75-boot-revalidation-acceptance")]
    let c75_authority_journal = if online_hart_count() == 4 {
        world.c75_component_authority_journal()
    } else {
        None
    };
    #[cfg(feature = "wasm-c75-boot-revalidation-acceptance")]
    exec::spawn("wasm-c75-boot-revalidation-acceptance", async move {
        match component_boot_revalidation::run_qemu_acceptance(
            c75_authority_journal,
            c75_baseline_component_count,
        )
        .await
        {
            Some(component_boot_revalidation::C75BootOutcome::Installed) => {
                crate::println!("\nWASM_C75_BOOT_REVALIDATION PASS durable_state=installed image_candidate=1 preappend_validation=1 physical_readback=1 fresh_component=1 fresh_core=1 fresh_wit=1 fresh_adapter_absence=1 fresh_hashes=1 fresh_limits=1 fresh_signer=1 fresh_engine_identity=1 publication_after_validation=1 early_runtime_objects=0 component_cspaces=0 component_resources=0 component_tasks=0 runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0");
            }
            Some(component_boot_revalidation::C75BootOutcome::Existing) => {
                crate::println!("\nWASM_C75_BOOT_REVALIDATION PASS durable_state=existing image_candidate=0 preappend_validation=0 physical_readback=1 fresh_component=1 fresh_core=1 fresh_wit=1 fresh_adapter_absence=1 fresh_hashes=1 fresh_limits=1 fresh_signer=1 fresh_engine_identity=1 publication_after_validation=1 early_runtime_objects=0 component_cspaces=0 component_resources=0 component_tasks=0 runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0");
            }
            None => {
                crate::println!("WASM_C75_BOOT_REVALIDATION FAIL");
                sbi::shutdown(true);
            }
        }
    });
    #[cfg(all(
        feature = "wasm-c76-graph-version-replacement-acceptance",
        not(feature = "wasm-c77-ephemeral-runtime-acceptance")
    ))]
    let c76_baseline_component_count = world.c76_component_count();
    #[cfg(all(
        feature = "wasm-c76-graph-version-replacement-acceptance",
        not(feature = "wasm-c77-ephemeral-runtime-acceptance")
    ))]
    let c76_graph_authority_journal = if online_hart_count() == 4 {
        world.c76_graph_authority_journal()
    } else {
        None
    };
    #[cfg(all(
        feature = "wasm-c76-graph-version-replacement-acceptance",
        not(feature = "wasm-c77-ephemeral-runtime-acceptance")
    ))]
    exec::spawn(
        "wasm-c76-graph-version-replacement-acceptance",
        async move {
            match component_graph_version_replacement::run_qemu_acceptance(
                c76_graph_authority_journal,
                c76_baseline_component_count,
            )
            .await
            {
                Some(component_graph_version_replacement::C76BootOutcome::InstalledG0) => {
                    crate::println!("\nWASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=installed_g0 versions=1 replacements=0 image_candidate=1 physical_readback=1 fresh_graphs=1 current_visible=1 candidate_runtime_objects=0 runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0");
                }
                Some(component_graph_version_replacement::C76BootOutcome::ReplacedG1) => {
                    crate::println!("\nWASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=replaced_g1 versions=2 replacements=1 image_candidate=1 durable_before_candidate=1 physical_readback=1 fresh_graphs=2 policy_cancel=1 candidate_hidden=1 old_terminal_before_new_visible=1 siblings_stable=2 sibling_restarts=0 old_routes_retired=2 fresh_routes=2 stale_replacement_tokens=2 late_wake_stale=1 visibility_linearizations=1 mixed_versions=0 fail_stop_armed=1 runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0");
                }
                Some(component_graph_version_replacement::C76BootOutcome::ExistingG1) => {
                    crate::println!("\nWASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=existing_g1 versions=2 replacements=1 image_candidate=0 no_write=1 physical_readback=1 fresh_graphs=2 successor_visible=1 candidate_runtime_objects=0 runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0");
                }
                None => {
                    crate::println!("WASM_C76_GRAPH_VERSION_REPLACEMENT FAIL");
                    sbi::shutdown(true);
                }
            }
        },
    );
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    let c77_baseline_component_count = world.c77_component_count();
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    let c77_graph_authority_journal = if online_hart_count() == 4 {
        world.c77_graph_authority_journal()
    } else {
        None
    };
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    exec::spawn("wasm-c77-ephemeral-runtime-acceptance", async move {
        if component_ephemeral_runtime::run_qemu_acceptance(
            c77_graph_authority_journal,
            c77_baseline_component_count,
        )
        .await
        {
            crate::println!("\nWASM_C77_EPHEMERAL_RUNTIME PASS durable_state=existing_g1 graph_only=1 physical_readback=1 fresh_validation=1 same_manifest=1 cold_start_empty=1 fresh_tasks=3 fresh_arenas=3 fresh_cspaces=3 fresh_memories=3 memory_bytes=196608 fresh_resource_tables=3 live_resources=4 fresh_fuel_accounts=3 fuel_consumed=0 fresh_pending_ledgers=3 active_pending_calls=1 pending_cut=parked cold_no_write=1 runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0");
        } else {
            crate::println!("WASM_C77_EPHEMERAL_RUNTIME FAIL");
            sbi::shutdown(true);
        }
    });
    #[cfg(feature = "wasm-c83-runtime-costs")]
    exec::spawn("wasm-c83-runtime-costs", wasm_runtime_costs::run());
    #[cfg(any(
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "wasm-c88-f5-float-duo-compile-readiness"
    ))]
    exec::spawn_pinned_on(
        exec::HartId::BOOT,
        "wasm-c88-f5-float-target",
        wasm_float_target::run(),
    );
    #[cfg(feature = "wasm-c84-profile-slot-qemu-acceptance")]
    exec::spawn_pinned_on(
        exec::HartId::BOOT,
        "wasm-c84-profile-slot-acceptance",
        wasm_aot_profile_slot::run_qemu_acceptance(),
    );
    #[cfg(feature = "wasm-c84-core-poll-qemu-acceptance")]
    exec::spawn_pinned_on(
        exec::HartId::BOOT,
        "wasm-c84-core-poll-acceptance",
        wasm_aot_profile_slot::run_core_poll_qemu_acceptance(),
    );
    #[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
    exec::spawn_pinned_on(
        exec::HartId::BOOT,
        "wasm-c84-profile-irq-overlay-acceptance",
        wasm_aot_profile_slot::run_irq_qemu_acceptance(),
    );
    #[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
    exec::spawn_pinned_on(
        exec::HartId::BOOT,
        "wasm-c84-profile-child-delegation-acceptance",
        wasm_aot_profile_slot::run_child_delegation_qemu_acceptance(),
    );
    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    exec::spawn(
        "wasm-c54-native-revoke-worker",
        component_instances::run_native_async_revoke_worker(),
    );
    #[cfg(all(
        feature = "milkv-duo",
        not(any(
            feature = "wasm-c83-runtime-costs",
            feature = "wasm-c88-f5-float-qemu-acceptance",
            feature = "wasm-c88-f5-float-duo-compile-readiness"
        ))
    ))]
    if dwc2_host::info().is_some() {
        exec::spawn("usb-hid", dwc2_host::service_task());
    }
    #[cfg(any(
        feature = "tcp-echo",
        feature = "net-shell",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance",
        feature = "milkv-ssh",
        feature = "iperf3-server",
        feature = "milkv-iperf3-server"
    ))]
    world::start_ipv4_stack_supervisor();
    #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
    world::start_ssh_test_supervisor();
    #[cfg(all(
        feature = "legacy-shell",
        not(feature = "wasm-c84-ssh-managed-child-single-boot-collector")
    ))]
    world.spawn_component(
        "shell",
        world.spaces["init"].clone(),
        world::SHELL_MEMORY_BUDGET,
        legacy_shell::shell_task(boot_time),
    );
    #[cfg(not(any(
        feature = "legacy-shell",
        feature = "wasm-c67-information-flow-acceptance",
        feature = "wasm-c74-crash-safe-publication-acceptance",
        feature = "wasm-c75-boot-revalidation-acceptance",
        feature = "wasm-c76-graph-version-replacement-acceptance",
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "wasm-c88-f5-float-duo-compile-readiness",
        feature = "wasm-c84-ssh-managed-child-single-boot-collector"
    )))]
    {
        let space = world.spaces["vsh"].clone();
        let mut session = vsh::Session::with_cspace(space.0.clone());
        vsh_platform::install_standard_commands(&mut session);
        if let Some(block) = world.vsh_block {
            session
                .bind_capability("diagnostic", block)
                .expect("fixed vsh block binding name is valid");
        }
        #[cfg(feature = "tcp-echo-recovery-test")]
        session.install_host_command("tcp-fault", 0, 0, netstack_platform::vsh_inject_fault);
        #[cfg(feature = "tcp-echo-recovery-test")]
        session.install_host_command(
            "tcp-device-fault",
            0,
            0,
            netstack_platform::vsh_inject_driver_fault,
        );
        #[cfg(feature = "tcp-echo-recovery-test")]
        session.install_host_command("tcp-release", 0, 0, netstack_platform::vsh_release_stale);
        #[cfg(feature = "tcp-echo-recovery-test")]
        session.install_host_command("tcp-session", 0, 0, netstack_platform::vsh_session_info);
        world.spawn_component(
            "vsh",
            space.clone(),
            world::SHELL_MEMORY_BUDGET,
            vsh_platform::task(space, world.vsh_console, session),
        );
    }
    #[cfg(not(any(
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "wasm-c88-f5-float-duo-compile-readiness"
    )))]
    let typed_channels = if world.net_outbound.is_some() {
        "3 typed channels"
    } else {
        "1 typed channel"
    };
    #[cfg(not(any(
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "wasm-c88-f5-float-duo-compile-readiness"
    )))]
    println!(
        "  world     {} capability spaces, {}, {} components",
        world.spaces.len(),
        typed_channels,
        world.components().len()
    );
    #[cfg(feature = "wasm-c83-runtime-costs")]
    println!("  image     isolated C8.3 WebAssembly runtime-cost sampler");
    #[cfg(feature = "wasm-c88-f5-float-qemu-acceptance")]
    println!("  image     isolated C8.8-F5 fixed-QEMU float qualification");
    #[cfg(feature = "wasm-c88-f5-float-duo-compile-readiness")]
    println!("  image     isolated C8.8-F5 Milk-V Duo compile-only readiness");
    println!("  sched     async executor, no threads, no preemption");

    trap::enable_interrupts();
    uart::early_write("[VibeOS] interrupts enabled\r\n");
    let (busy, phantom_timeout) = uart::dw_irq_recoveries();
    if busy != 0 || phantom_timeout != 0 {
        println!(
            "  uart      recovered {} DW busy, {} phantom timeout IRQ(s)",
            busy, phantom_timeout
        );
    }
    exec::run()
}

/// Discover the other physical harts, assign dense logical identities, ask
/// HSM to start them, and wait for their VibeOS-local ready publication.
fn start_secondary_harts() -> usize {
    let boot_physical_hart = sbi::current_hart_id();
    let mut expected = BOOT_HART_BIT;
    let mut physical_for_logical = [usize::MAX; exec::MAX_HARTS];
    physical_for_logical[exec::HartId::BOOT.index()] = boot_physical_hart;
    let mut next_logical_index = 1;
    assert!(
        platform::HART_IDS.contains(&boot_physical_hart),
        "firmware boot hart is absent from the selected platform topology"
    );
    for &physical_hart in platform::HART_IDS {
        if physical_hart == boot_physical_hart {
            continue;
        }
        match sbi::hart_status(physical_hart) {
            Ok(sbi::HartState::Stopped) => {
                let logical = exec::HartId::new(next_logical_index)
                    .expect("secondary logical hart index is in range");
                ipi::prepare_start(logical, physical_hart)
                    .expect("secondary logical-to-physical mapping must be unique");
                physical_for_logical[logical.index()] = physical_hart;
                expected |= 1usize << logical.index();
                next_logical_index += 1;
            }
            Err(sbi::IpiError::InvalidParam) => {
                // A smaller machine is valid: deterministic benchmarks retain
                // their existing `-smp 1` boundary.
            }
            Ok(state) => panic!(
                "secondary physical hart {} is not stopped before HSM start: {:?}",
                physical_hart, state
            ),
            Err(error) => panic!(
                "could not discover secondary physical hart {} through SBI HSM: {:?}",
                physical_hart, error
            ),
        }
    }

    // The acquire side in secondary_kmain publishes every preceding boot-hart
    // initialization before a newly started CPU touches shared state.
    SECONDARY_BOOT_RELEASED.store(true, Ordering::Release);
    let entry = _secondary_start as *const () as usize;
    for (logical_index, physical_hart) in physical_for_logical.iter().copied().enumerate().skip(1) {
        if physical_hart == usize::MAX {
            break;
        }
        sbi::hart_start(physical_hart, entry, logical_index)
            .expect("SBI HSM must accept every discovered stopped hart");
    }

    let started_at = sbi::time();
    loop {
        let ready = online_hart_mask();
        if ready & expected == expected {
            break;
        }
        if sbi::time().wrapping_sub(started_at) >= exec::timebase_hz() * 5 {
            panic!(
                "secondary startup timed out: expected mask {:#x}, ready mask {:#x}",
                expected, ready
            );
        }
        core::hint::spin_loop();
    }

    for index in 0..exec::MAX_HARTS {
        if expected & (1usize << index) != 0 {
            let hart = exec::HartId::new(index).expect("ready hart index is in range");
            assert!(
                ipi::is_online(hart),
                "kernel-ready hart {} did not publish its executor identity",
                index
            );
        }
    }
    (online_hart_mask() & expected).count_ones() as usize
}

/// Rust destination for the SBI HSM secondary entry. The assembly path has
/// already installed `tp`, `gp`, and this logical hart's private stack.
#[no_mangle]
pub extern "C" fn secondary_kmain(physical_hart: usize, logical_index: usize) -> ! {
    while !SECONDARY_BOOT_RELEASED.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    let Some(logical) = exec::HartId::new(logical_index) else {
        sbi::shutdown(true);
    };
    if sbi::current_hart_id() != physical_hart || logical == exec::HartId::BOOT {
        sbi::shutdown(true);
    }

    // SBI HSM starts every secondary with satp=0. Install the boot-published
    // shared root while all addresses are still valid physical identities,
    // before trap state or ONLINE publication can expose this hart.
    mmu::enable(logical.index());

    // Install stvec and the local interrupt-enable mask before ONLINE can let
    // another hart send SSIP here. Global SIE remains clear throughout.
    trap::prepare_secondary();
    if ipi::mark_online(logical, physical_hart).is_err() {
        sbi::shutdown(true);
    }
    // Timer initialization uses hart-local allocation/recovery context and
    // therefore follows self-registration.
    trap::finish_secondary();

    KERNEL_READY_HARTS.fetch_or(1usize << logical.index(), Ordering::Release);
    trap::enable_interrupts();
    exec::run()
}

/// Executor callback after every task and external registration in a tracked
/// incarnation has been detached. Managed WASM instances first pass the
/// generational registry gate; legacy components retain the sealed-World
/// escape proof below. Raw reclamation never runs `Drop`.
unsafe fn reclaim_faulted_component(
    witness: exec::ReclaimableFaultWitness,
) -> exec::FaultReclaimOutcome {
    match unsafe { component_instances::reclaim_faulted(witness) } {
        component_instances::FaultRoute::ManagedReclaimed => {
            return exec::FaultReclaimOutcome::Reclaimed;
        }
        component_instances::FaultRoute::Quarantined => {
            return exec::FaultReclaimOutcome::Quarantined;
        }
        component_instances::FaultRoute::Legacy => {}
    }

    let domain = witness.allocation_domain();
    unsafe {
        // Repair component-stable synchronization state while the exact
        // faulting incarnation is still identifiable and before Faulted is
        // visible to safe lifecycle callers.
        block_device::recover_faulted_domain(domain);
        net_device::recover_faulted_domain(domain);
        #[cfg(feature = "milkv-duo")]
        usb_ecm_net::recover_faulted_domain(domain);
        #[cfg(feature = "qemu-virt")]
        virtio_rng::recover_faulted_domain(domain);
        world::world().recover_faulted_domain(domain);
        code_pool::recover_faulted_domain(domain);
        HEAP.reclaim_faulted_domain(domain)
            .expect("a faulted audited arena must reclaim atomically");
    }
    exec::FaultReclaimOutcome::Reclaimed
}

/// Repair exact-task stable state for both conservative untracked faults and
/// audited arena faults. The executor has detached the task permanently before
/// entering this non-allocating hook.
unsafe fn cleanup_faulted_task(task: exec::TaskId, domain: heap::AllocationDomain) {
    unsafe {
        #[cfg(feature = "ssh-component-command")]
        component_instances::recover_faulted_task(task, domain);
        cleanup_faulted_task_after_component_gate(task, domain);
    }
}

/// Shared exact-task cleanup after a managed instance has already locked and
/// validated its independent CONTROL projection. Calling CONTROL recovery a
/// second time there would mistake the detached validation guard for the
/// abandoned guard of the faulted child and poison a valid lifecycle.
unsafe fn cleanup_faulted_task_after_component_gate(
    task: exec::TaskId,
    domain: heap::AllocationDomain,
) {
    unsafe {
        store::recover_faulted_task(task, domain);
        segment_store_platform::recover_faulted_task(task, domain);
        // Durable boot recovery installs and fail-closes the saved-program
        // target. Repair all saved-program locks first so durable quarantine
        // cannot spin on a guard abandoned by this same faulted task. Both
        // hooks are idempotent and retain exact claims until isolation ends.
        saved_program::recover_faulted_task(task, domain);
        durable_cspace::recover_faulted_task(task, domain);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector")]
    if uart::raw_record_active() {
        // A physical formal record may already own TTY/TX and have emitted a
        // prefix. SBI console output bypasses both locks, so the only framing-
        // safe panic path is a silent machine stop.
        sbi::shutdown(true);
    }
    // Deliberately bypasses the UART driver: a panic may already hold its lock.
    let mut w = SbiWriter;
    let _ = core::fmt::write(&mut w, format_args!("\n[!] panic: {}\n", info));

    // An IRQ may preempt a guarded task, but its panic belongs to the kernel.
    // Longjmp from here would skip the saved trap frame and corrupt interrupt
    // state, so interrupt faults are deliberately fatal.
    if trap::in_interrupt() {
        let _ = core::fmt::write(&mut w, format_args!("[!] panic in interrupt; halting\n"));
        sbi::shutdown(true);
    }

    // If a compiled program is running, or a task is being polled behind the
    // fault guard, unwind to that landing pad instead of taking the machine
    // down. Innermost first.
    rustc::unwind_running_program();
    trampoline::unwind_faulted_task();

    let _ = core::fmt::write(&mut w, format_args!("[!] no landing pad; halting\n"));
    sbi::shutdown(true);
}

struct SbiWriter;
impl core::fmt::Write for SbiWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                sbi::legacy_putchar(b'\r');
            }
            sbi::legacy_putchar(b);
        }
        Ok(())
    }
}

#[alloc_error_handler]
fn oom(layout: core::alloc::Layout) -> ! {
    #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector")]
    if uart::raw_record_active() {
        // This check precedes both quota diagnostics and the fatal allocator
        // writer: neither may splice bytes into an in-flight formal record.
        sbi::shutdown(true);
    }
    match HEAP.take_last_failure() {
        Some(heap::AllocationFailure::QuotaExceeded {
            owner,
            requested_bytes,
            live_bytes,
            quota_bytes,
        }) if owner != heap::OwnerId::SYSTEM => {
            #[cfg(feature = "ssh-native-async-qemu-acceptance")]
            {
                let mut w = SbiWriter;
                let _ = core::fmt::write(
                    &mut w,
                    format_args!(
                        "\nWASM_C53_NATIVE_SSH_ALLOCATION_DIAG live_bytes={} requested_bytes={} quota_bytes={}\n",
                        live_bytes, requested_bytes, quota_bytes,
                    ),
                );
            }
            // Keep the production panic text deterministic; the account
            // snapshot carries exact live/peak/request evidence for
            // diagnostics and tests. Benchmark images print the numbers,
            // because oversized transient envelopes are exactly what their
            // qualification workloads probe.
            #[cfg(feature = "storage-bench")]
            panic!(
                "component allocation quota exceeded: owner={} live={} requested={} quota={}",
                owner, live_bytes, requested_bytes, quota_bytes
            );
            #[cfg(not(feature = "storage-bench"))]
            {
                let _ = (owner, requested_bytes, live_bytes, quota_bytes);
                panic!("component allocation quota exceeded")
            }
        }
        failure => {
            // A global allocator failure is kernel state, even if it happened
            // while a task guard was armed. Bypass panic/longjmp so it cannot be
            // misattributed to the interrupted component.
            let mut w = SbiWriter;
            let _ = core::fmt::write(
                &mut w,
                format_args!(
                    "\n[!] fatal allocator failure: {:?}, layout {:?}\n",
                    failure, layout
                ),
            );
            sbi::shutdown(true)
        }
    }
}
