#![no_std]

//! Compile-time logical resource and storage-layout policy selected by final
//! firmware images. Physical hardware descriptions remain in the BSP/HAL.

use vibeos_component_format::ProfileIdentity;

#[cfg(all(feature = "qemu-default", feature = "milkv-duo-sd"))]
compile_error!("image policies `qemu-default` and `milkv-duo-sd` are mutually exclusive");

#[cfg(not(any(feature = "qemu-default", feature = "milkv-duo-sd")))]
compile_error!("exactly one image policy must be selected");

#[cfg(all(
    feature = "c53-native-async-qemu-acceptance",
    not(feature = "qemu-default")
))]
compile_error!("feature `c53-native-async-qemu-acceptance` requires `qemu-default`");

/// A logical block-device view carved out of a packaged storage image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockSlice {
    pub first_sector: u64,
    pub sector_count: u64,
}

impl BlockSlice {
    pub const fn end_sector(self) -> Option<u64> {
        self.first_sector.checked_add(self.sector_count)
    }
}

/// Resource policy for stable packet frontends shared by network backends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkFrontendPolicy {
    pub queue_depth: usize,
}

/// Bounded capacity of each stable packet endpoint. This is independent of a
/// device backend's descriptor-ring size.
pub const NETWORK_FRONTEND: NetworkFrontendPolicy = NetworkFrontendPolicy { queue_depth: 8 };

/// Stream contract pinned for an image-provided Component command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStreamMode {
    Required,
    Optional,
    Closed,
}

/// Exact per-instance ceilings selected by the image independently of the
/// artifact's own declarations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentInstanceLimits {
    pub memory_bytes: usize,
    pub total_fuel: u64,
    pub poll_quantum: u64,
    pub resources: u16,
}

/// Immutable image-policy root for one admitted Component command.
///
/// Fields are private so consumers can inspect the selected policy but cannot
/// fabricate or mutate a pin. `artifact_bytes` are produced from the audited
/// in-tree WAT by a version-pinned build tool; the build independently checks
/// them against `expected_sha256` before this crate is compiled. The WIT source
/// is also pinned rather than inferred from the decoded artifact.
#[derive(Clone, Copy)]
pub struct ComponentCommandPin {
    artifact_bytes: &'static [u8],
    expected_sha256: [u8; 32],
    command_name: &'static str,
    profile: ProfileIdentity,
    wit_source: &'static str,
    world: &'static str,
    entrypoint: &'static str,
    min_args: usize,
    max_args: usize,
    stdin: ComponentStreamMode,
    stdout: ComponentStreamMode,
    stderr: ComponentStreamMode,
    limits: ComponentInstanceLimits,
}

impl ComponentCommandPin {
    pub const fn artifact_bytes(self) -> &'static [u8] {
        self.artifact_bytes
    }

    pub const fn expected_sha256(self) -> [u8; 32] {
        self.expected_sha256
    }

    pub const fn command_name(self) -> &'static str {
        self.command_name
    }

    pub const fn abi(self) -> u16 {
        self.profile.runtime_abi
    }

    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn wit_source(self) -> &'static str {
        self.wit_source
    }

    pub const fn world(self) -> &'static str {
        self.world
    }

    pub const fn entrypoint(self) -> &'static str {
        self.entrypoint
    }

    pub const fn min_args(self) -> usize {
        self.min_args
    }

    pub const fn max_args(self) -> usize {
        self.max_args
    }

    pub const fn stdin(self) -> ComponentStreamMode {
        self.stdin
    }

    pub const fn stdout(self) -> ComponentStreamMode {
        self.stdout
    }

    pub const fn stderr(self) -> ComponentStreamMode {
        self.stderr
    }

    pub const fn limits(self) -> ComponentInstanceLimits {
        self.limits
    }
}

impl core::fmt::Debug for ComponentCommandPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ComponentCommandPin")
            .field("artifact", &"<redacted>")
            .field("command_name", &self.command_name)
            .field("profile", &self.profile)
            .field("world", &self.world)
            .field("entrypoint", &self.entrypoint)
            .field("min_args", &self.min_args)
            .field("max_args", &self.max_args)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Isolated image-policy root for C5.3 native async runtime acceptance.
///
/// This type is intentionally not [`ComponentCommandPin`]. It cannot enter the
/// synchronous command runner or the existing SSH C4.8 policy gate. Enabling
/// its feature makes one immutable executable guest available only to the
/// feature-gated runtime acceptance driver. Kernel installation, SSH routing,
/// and QEMU execution remain separately reviewed boundaries.
#[cfg(feature = "c53-native-async-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct NativeAsyncAcceptancePin {
    artifact_bytes: &'static [u8],
    expected_sha256: [u8; 32],
    command_name: &'static str,
    profile: ProfileIdentity,
    wit_source: &'static str,
    world: &'static str,
    entrypoint: &'static str,
    min_args: usize,
    max_args: usize,
    stdin: ComponentStreamMode,
    stdout: ComponentStreamMode,
    stderr: ComponentStreamMode,
    limits: ComponentInstanceLimits,
}

#[cfg(feature = "c53-native-async-qemu-acceptance")]
impl NativeAsyncAcceptancePin {
    pub const fn artifact_bytes(self) -> &'static [u8] {
        self.artifact_bytes
    }

    pub const fn expected_sha256(self) -> [u8; 32] {
        self.expected_sha256
    }

    pub const fn command_name(self) -> &'static str {
        self.command_name
    }

    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn abi(self) -> u16 {
        self.profile.runtime_abi
    }

    pub const fn wit_source(self) -> &'static str {
        self.wit_source
    }

    pub const fn world(self) -> &'static str {
        self.world
    }

    pub const fn entrypoint(self) -> &'static str {
        self.entrypoint
    }

    pub const fn min_args(self) -> usize {
        self.min_args
    }

    pub const fn max_args(self) -> usize {
        self.max_args
    }

    pub const fn stdin(self) -> ComponentStreamMode {
        self.stdin
    }

    pub const fn stdout(self) -> ComponentStreamMode {
        self.stdout
    }

    pub const fn stderr(self) -> ComponentStreamMode {
        self.stderr
    }

    pub const fn limits(self) -> ComponentInstanceLimits {
        self.limits
    }
}

#[cfg(feature = "c53-native-async-qemu-acceptance")]
impl core::fmt::Debug for NativeAsyncAcceptancePin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeAsyncAcceptancePin")
            .field("artifact", &"<redacted>")
            .field("command_name", &self.command_name)
            .field("profile", &self.profile)
            .field("world", &self.world)
            .field("entrypoint", &self.entrypoint)
            .field("min_args", &self.min_args)
            .field("max_args", &self.max_args)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Image-policy authority for projecting the pinned native async artifact into
/// an inert VSH command manifest.
///
/// This is a separate policy upgrade from `NativeAsyncAcceptancePin`. There
/// is deliberately no `From`/`Into` implementation between the two roots, even
/// though both may bind the same immutable artifact and validation-only
/// profile. The command projection adapter accepts only this type.
///
/// ```compile_fail
/// # use vibeos_image_policy::{
/// #     NativeAsyncAcceptancePin, C53_NATIVE_ASYNC_COMMAND,
/// # };
/// let _: NativeAsyncAcceptancePin = C53_NATIVE_ASYNC_COMMAND.into();
/// ```
#[cfg(feature = "c53-native-async-command-projection")]
#[derive(Clone, Copy)]
pub struct NativeAsyncCommandPin {
    artifact_bytes: &'static [u8],
    expected_sha256: [u8; 32],
    command_name: &'static str,
    profile: ProfileIdentity,
    wit_source: &'static str,
    world: &'static str,
    entrypoint: &'static str,
    min_args: usize,
    max_args: usize,
    stdin: ComponentStreamMode,
    stdout: ComponentStreamMode,
    stderr: ComponentStreamMode,
    limits: ComponentInstanceLimits,
}

#[cfg(feature = "c53-native-async-command-projection")]
impl NativeAsyncCommandPin {
    pub const fn artifact_bytes(self) -> &'static [u8] {
        self.artifact_bytes
    }

    pub const fn expected_sha256(self) -> [u8; 32] {
        self.expected_sha256
    }

    pub const fn command_name(self) -> &'static str {
        self.command_name
    }

    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn abi(self) -> u16 {
        self.profile.runtime_abi
    }

    pub const fn wit_source(self) -> &'static str {
        self.wit_source
    }

    pub const fn world(self) -> &'static str {
        self.world
    }

    pub const fn entrypoint(self) -> &'static str {
        self.entrypoint
    }

    pub const fn min_args(self) -> usize {
        self.min_args
    }

    pub const fn max_args(self) -> usize {
        self.max_args
    }

    pub const fn stdin(self) -> ComponentStreamMode {
        self.stdin
    }

    pub const fn stdout(self) -> ComponentStreamMode {
        self.stdout
    }

    pub const fn stderr(self) -> ComponentStreamMode {
        self.stderr
    }

    pub const fn limits(self) -> ComponentInstanceLimits {
        self.limits
    }
}

#[cfg(feature = "c53-native-async-command-projection")]
impl core::fmt::Debug for NativeAsyncCommandPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeAsyncCommandPin")
            .field("artifact", &"<redacted>")
            .field("command_name", &self.command_name)
            .field("profile", &self.profile)
            .field("world", &self.world)
            .field("entrypoint", &self.entrypoint)
            .field("min_args", &self.min_args)
            .field("max_args", &self.max_args)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("limits", &self.limits)
            .finish()
    }
}

const C53_STREAM_FILTER_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/c53-stream-filter.component.wasm"
));

const C53_STREAM_FILTER_SHA256: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c53-stream-filter.sha256.rs"));

#[cfg(any(
    feature = "c53-native-async-qemu-acceptance",
    feature = "c53-native-async-command-projection"
))]
const C53_NATIVE_ASYNC_FILTER_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/c53-native-async-filter.component.wasm"
));

#[cfg(any(
    feature = "c53-native-async-qemu-acceptance",
    feature = "c53-native-async-command-projection"
))]
const C53_NATIVE_ASYNC_FILTER_SHA256: [u8; 32] = include!(concat!(
    env!("OUT_DIR"),
    "/c53-native-async-filter.sha256.rs"
));

const C53_STREAM_FILTER_WIT: &str = r#"
package vibe:%stream@1.0.0;

interface streams {
    resource reader;
    resource writer;

    enum close-reason {
        normal,
        failure,
        cancelled,
        denied,
        unavailable,
        exhausted,
        invalid,
        backend-fault,
    }

    read: func(input: borrow<reader>) -> list<u8>;
    write: func(output: borrow<writer>, bytes: list<u8>);
    close-reader: func(input: borrow<reader>, reason: close-reason);
    close-writer: func(output: borrow<writer>, reason: close-reason);
}

world filter {
    use streams.{reader, writer};
    import streams;
    export run: func(input: borrow<reader>, output: borrow<writer>);
}
"#;

#[cfg(any(
    feature = "c53-native-async-qemu-acceptance",
    feature = "c53-native-async-command-projection"
))]
const C53_NATIVE_ASYNC_FILTER_WIT: &str = r#"
package vibe:%stream@1.0.0;

world native-filter {
    enum close-reason {
        normal,
        failure,
        cancelled,
        denied,
        unavailable,
        exhausted,
        invalid,
        backend-fault,
    }

    type bytes = stream<u8>;
    type closed = future<close-reason>;

    record byte-stream {
        bytes: bytes,
        closed: closed,
    }

    export run: async func(input: byte-stream) -> byte-stream;
}
"#;

/// The one streaming Component made available to trusted SSH session setup by
/// the current QEMU and Duo image policies. Merely linking these bytes does not
/// install a command: exact admission and an explicit per-session policy
/// witness are still required. The two stream resources are lifecycle-owned
/// transport, never ambient authority or shell value arguments.
pub const SSH_EXEC_COMPONENT: ComponentCommandPin = ComponentCommandPin {
    artifact_bytes: C53_STREAM_FILTER_BYTES,
    expected_sha256: C53_STREAM_FILTER_SHA256,
    command_name: "case-filter",
    profile: ProfileIdentity::PROFILE_1,
    wit_source: C53_STREAM_FILTER_WIT,
    world: "vibe:stream/filter@1.0.0",
    entrypoint: "run",
    min_args: 0,
    max_args: 0,
    stdin: ComponentStreamMode::Required,
    stdout: ComponentStreamMode::Required,
    stderr: ComponentStreamMode::Optional,
    limits: ComponentInstanceLimits {
        memory_bytes: 512 * 1024,
        total_fuel: 500_000,
        poll_quantum: 100,
        resources: 4,
    },
};

/// Immutable executable guest for C5.3 native async runtime acceptance.
///
/// The checked-in artifact performs real bounded byte-stream reads and writes,
/// XORs each byte by `0x20`, and propagates all eight terminal reasons through
/// the close futures. This remains a validation-only runtime acceptance input,
/// not a production, kernel, SSH, or QEMU end-to-end activation claim.
#[cfg(feature = "c53-native-async-qemu-acceptance")]
pub const C53_NATIVE_ASYNC_QEMU_ACCEPTANCE: NativeAsyncAcceptancePin = NativeAsyncAcceptancePin {
    artifact_bytes: C53_NATIVE_ASYNC_FILTER_BYTES,
    expected_sha256: C53_NATIVE_ASYNC_FILTER_SHA256,
    command_name: "c53-native-filter",
    profile: ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    wit_source: C53_NATIVE_ASYNC_FILTER_WIT,
    world: "vibe:stream/native-filter@1.0.0",
    entrypoint: "run",
    min_args: 0,
    max_args: 0,
    stdin: ComponentStreamMode::Required,
    stdout: ComponentStreamMode::Required,
    stderr: ComponentStreamMode::Optional,
    limits: ComponentInstanceLimits {
        memory_bytes: 64 * 1024,
        total_fuel: 500_000,
        poll_quantum: 100,
        resources: 8,
    },
};

/// Explicit image-policy upgrade that lets the sealed adapter derive the
/// trusted native async projection, which carries an inert VSH manifest.
///
/// This does not activate the profile, install a VSH command, select an SSH
/// route, or authorize the native runtime. Those remain later trusted
/// lifecycle boundaries.
#[cfg(feature = "c53-native-async-command-projection")]
pub const C53_NATIVE_ASYNC_COMMAND: NativeAsyncCommandPin = NativeAsyncCommandPin {
    artifact_bytes: C53_NATIVE_ASYNC_FILTER_BYTES,
    expected_sha256: C53_NATIVE_ASYNC_FILTER_SHA256,
    command_name: "native-case-filter",
    profile: ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    wit_source: C53_NATIVE_ASYNC_FILTER_WIT,
    world: "vibe:stream/native-filter@1.0.0",
    entrypoint: "run",
    min_args: 0,
    max_args: 0,
    stdin: ComponentStreamMode::Required,
    stdout: ComponentStreamMode::Required,
    stderr: ComponentStreamMode::Optional,
    limits: ComponentInstanceLimits {
        memory_bytes: 64 * 1024,
        total_fuel: 500_000,
        poll_quantum: 100,
        resources: 8,
    },
};

/// The default QEMU image admits exactly the 1 MiB raw device created by the
/// run and acceptance harnesses. A larger attachment is not ambient authority;
/// later capacity must be admitted explicitly through Storage V2 growth.
#[cfg(feature = "qemu-default")]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 0,
    sector_count: 2_048,
});

/// The packaged Duo image places raw service data immediately after its
/// 128 MiB FAT boot partition.
#[cfg(feature = "milkv-duo-sd")]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 262_145,
    sector_count: 8_192,
});

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn frontend_queue_is_bounded() {
        assert!(NETWORK_FRONTEND.queue_depth > 0);
    }

    #[test]
    fn ssh_component_policy_pins_every_admission_field() {
        let pin = SSH_EXEC_COMPONENT;
        assert!(!pin.artifact_bytes().is_empty());
        assert_eq!(pin.expected_sha256(), C53_STREAM_FILTER_SHA256);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.artifact_bytes())),
            pin.expected_sha256()
        );
        assert_eq!(pin.command_name(), "case-filter");
        assert_eq!(pin.profile(), ProfileIdentity::PROFILE_1);
        assert_eq!(pin.abi(), ProfileIdentity::PROFILE_1.runtime_abi);
        assert_eq!(pin.world(), "vibe:stream/filter@1.0.0");
        assert_eq!(pin.entrypoint(), "run");
        assert_eq!((pin.min_args(), pin.max_args()), (0, 0));
        assert_eq!(pin.stdin(), ComponentStreamMode::Required);
        assert_eq!(pin.stdout(), ComponentStreamMode::Required);
        assert_eq!(pin.stderr(), ComponentStreamMode::Optional);
        assert_eq!(
            pin.limits(),
            ComponentInstanceLimits {
                memory_bytes: 512 * 1024,
                total_fuel: 500_000,
                poll_quantum: 100,
                resources: 4,
            }
        );
        assert!(pin.wit_source().contains("import streams;"));
        assert!(pin
            .wit_source()
            .contains("export run: func(input: borrow<reader>, output: borrow<writer>);"));
    }

    #[cfg(feature = "c53-native-async-qemu-acceptance")]
    #[test]
    fn native_async_candidate_has_an_independent_validation_only_identity() {
        let pin = C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;
        assert_ne!(pin.artifact_bytes(), SSH_EXEC_COMPONENT.artifact_bytes());
        assert_ne!(pin.expected_sha256(), SSH_EXEC_COMPONENT.expected_sha256());
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.artifact_bytes())),
            pin.expected_sha256()
        );
        assert_eq!(pin.command_name(), "c53-native-filter");
        assert_eq!(
            pin.profile(),
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
        );
        assert!(!pin.profile().execution_enabled());
        assert_eq!(pin.abi(), 3);
        assert_eq!(pin.world(), "vibe:stream/native-filter@1.0.0");
        assert_eq!(pin.entrypoint(), "run");
        assert_eq!((pin.min_args(), pin.max_args()), (0, 0));
        assert_eq!(pin.stdin(), ComponentStreamMode::Required);
        assert_eq!(pin.stdout(), ComponentStreamMode::Required);
        assert_eq!(pin.stderr(), ComponentStreamMode::Optional);
        assert_eq!(pin.limits().resources, 8);
        assert!(pin.wit_source().contains("type bytes = stream<u8>;"));
        assert!(pin
            .wit_source()
            .contains("export run: async func(input: byte-stream) -> byte-stream;"));
    }

    #[cfg(feature = "c53-native-async-command-projection")]
    #[test]
    fn native_async_command_projection_requires_its_own_exact_pin() {
        let pin = C53_NATIVE_ASYNC_COMMAND;
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.artifact_bytes())),
            pin.expected_sha256()
        );
        assert_eq!(pin.command_name(), "native-case-filter");
        assert_eq!(
            pin.profile(),
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
        );
        assert!(!pin.profile().execution_enabled());
        assert_eq!(pin.abi(), 3);
        assert_eq!(pin.world(), "vibe:stream/native-filter@1.0.0");
        assert_eq!(pin.entrypoint(), "run");
        assert_eq!((pin.min_args(), pin.max_args()), (0, 0));
        assert_eq!(pin.stdin(), ComponentStreamMode::Required);
        assert_eq!(pin.stdout(), ComponentStreamMode::Required);
        assert_eq!(pin.stderr(), ComponentStreamMode::Optional);
        assert_eq!(pin.limits().resources, 8);
    }

    #[cfg(all(
        feature = "c53-native-async-qemu-acceptance",
        feature = "c53-native-async-command-projection"
    ))]
    #[test]
    fn native_async_policy_roots_are_distinct_types_over_the_same_artifact() {
        assert_ne!(
            core::any::type_name::<NativeAsyncAcceptancePin>(),
            core::any::type_name::<NativeAsyncCommandPin>()
        );
        assert_eq!(
            C53_NATIVE_ASYNC_QEMU_ACCEPTANCE.expected_sha256(),
            C53_NATIVE_ASYNC_COMMAND.expected_sha256()
        );
        assert_eq!(
            C53_NATIVE_ASYNC_QEMU_ACCEPTANCE.artifact_bytes(),
            C53_NATIVE_ASYNC_COMMAND.artifact_bytes()
        );
    }

    #[cfg(feature = "qemu-default")]
    #[test]
    fn qemu_data_slice_is_exact_and_checked() {
        assert_eq!(BLOCK_DATA_SLICE.unwrap().end_sector(), Some(2_048));
    }

    #[cfg(feature = "milkv-duo-sd")]
    #[test]
    fn duo_data_slice_does_not_overflow() {
        assert_eq!(BLOCK_DATA_SLICE.unwrap().end_sector(), Some(270_337));
    }
}
