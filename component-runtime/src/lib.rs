//! Bounded Component Model validation and Canonical ABI runtime primitives.

#![cfg_attr(
    not(feature = "native-async-acceptance"),
    doc = r#"
The native async acceptance façade is structurally absent by default:

```compile_fail
use vibeos_component_runtime::native_async_acceptance;
```
"#
)]
#![no_std]

extern crate alloc;

pub mod abi_value;
pub mod async_abi;
pub mod async_state;
pub(crate) mod buffer_registry;
pub mod canonical;
pub mod decode;
mod execution;
pub mod graph;
pub mod host;
pub mod memory;
mod native_async;
mod predecode;
pub mod resource;
pub mod sync;
pub mod types;
pub mod value;
pub mod world;

pub use execution::{HostCoreExportInfo, HostImportInfo};

/// Acceptance-only façade for the sealed native async validation candidate.
///
/// Enabling this feature does not change either the advertised profile or its
/// `runtime_ready` bit. Production execution remains inert; an acceptance
/// harness must opt into both the Cargo feature and the explicitly named
/// validation-candidate constructor.
#[cfg(feature = "native-async-acceptance")]
pub mod native_async_acceptance {
    pub use crate::native_async::{
        NativeAsyncCancelOutcome as CancelOutcome, NativeAsyncComponent as Component,
        NativeAsyncControlError as ControlError, NativeAsyncError as Error,
        NativeAsyncFinalizeError as FinalizeError, NativeAsyncHostError as HostError,
        NativeAsyncHostRequest as HostRequest, NativeAsyncHostToken as HostToken,
        NativeAsyncInvocation as Invocation, NativeAsyncMetrics as Metrics,
        NativeAsyncPoll as Poll, NativeAsyncStorageMetrics as StorageMetrics,
        NativeAsyncWaitRegistration as WaitRegistration, NativeAsyncWaitToken as WaitToken,
        NativeAsyncWorkCosts as WorkCosts,
    };
}
