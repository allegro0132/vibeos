//! C8.8-F2 acceptance-only deterministic scalar-float engine candidate.
//!
//! This package is deliberately inert unless `c88-f2-acceptance` is selected.
//! It does not implement a production resolver, does not bind artifact profile
//! code 5 to an engine, and exports no activation trait. A future production
//! float profile must receive a new artifact/ABI identity.

#![no_std]

extern crate alloc;

/// Audited source identity for the isolated C8.8-F2 candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateIdentity {
    pub package: &'static str,
    pub version: &'static str,
    pub upstream_revision: &'static str,
    pub patched_manifest_sha256: &'static str,
    pub patch_delta_sha256: &'static str,
    pub backend_package: &'static str,
    pub backend_version: &'static str,
    pub backend_archive_sha256: &'static str,
    pub backend_revision: &'static str,
    pub backend_llvm_revision: &'static str,
    pub feature_set: &'static str,
    pub acceptance_feature: &'static str,
    pub production_ready: bool,
}

pub const CANDIDATE_IDENTITY: CandidateIdentity = CandidateIdentity {
    package: "vibeos-wasmi-softfloat",
    version: "1.1.0-vibeos-f2.1",
    upstream_revision: "8273dfb09d493971b7bb12fe614d740cdc857175",
    patched_manifest_sha256: "2d94218e4fa5eea30b8e516e055fae8f72465dbc1ef75f8b1df3495cbcd0432f",
    patch_delta_sha256: "3d2aec1d7e510fc3b3edb87dcacb2d4ed34eb448356704a027841b047938ec64",
    backend_package: "rustc_apfloat",
    backend_version: "0.2.3+llvm-462a31f5a5ab",
    backend_archive_sha256: "486c2179b4796f65bfe2ee33679acf0927ac83ecf583ad6c91c3b4570911b9ad",
    backend_revision: "eeaacad81247af65d4043cb3e32d023a652d7951",
    backend_llvm_revision: "462a31f5a5abb905869ea93cc49b096079b11aa4",
    feature_set: "default-features=false,extra-checks,prefer-btree-collections;simd=false",
    acceptance_feature: "c88-f2-acceptance",
    production_ready: false,
};

/// The same audited source payload under the independently frozen C8.9
/// executable binding. This is not an activation bit for code 5.
pub const EXECUTABLE_IDENTITY: CandidateIdentity = CandidateIdentity {
    acceptance_feature: "c89-executable",
    production_ready: true,
    ..CANDIDATE_IDENTITY
};

#[cfg(any(feature = "c88-f2-acceptance", feature = "c89-executable"))]
mod acceptance {
    use alloc::vec::Vec;
    use core::cmp::min;
    #[cfg(feature = "c89-executable")]
    use vibeos_component_format::{
        current_validation_engine_identity, ProfileIdentity, C89_SOFTFLOAT_ENGINE_PACKAGE,
        C89_SOFTFLOAT_ENGINE_VERSION,
    };
    use vibeos_component_format::{
        profile_2_sync_float_validation_contract, TrapCode, WasmiCompilationMode,
        WasmiEnforcedLimits, WasmiFuelCosts, WasmiRuntimeConfiguration, PROFILE_1_LIMITS,
    };
    #[cfg(feature = "c89-executable")]
    use vibeos_wasm_runtime::{current_core_validation_engine, inspect_core_with_current_engine};
    use vibeos_wasm_runtime::{
        inspect_profile_2_candidate_compile_reservation, AdmissionDetail, AdmissionError,
        CoreSummary, OwnerAllocationReservation,
    };
    use wasmi_softfloat::{
        errors::{ErrorKind, InstantiationError, MemoryError, TableError},
        CompilationMode, Config, EnforcedLimits, Engine, Error, Func, Instance, Linker, Module,
        ResumableCall, ResumableCallOutOfFuel, Store, StoreLimits, StoreLimitsBuilder, Val,
        ValType, F32, F64,
    };

    /// Bit-preserving Core value boundary. Primitive host floats are excluded.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CandidateValue {
        I32(i32),
        I64(i64),
        F32Bits(u32),
        F64Bits(u64),
    }

    impl CandidateValue {
        const fn value_type(self) -> ValType {
            match self {
                Self::I32(_) => ValType::I32,
                Self::I64(_) => ValType::I64,
                Self::F32Bits(_) => ValType::F32,
                Self::F64Bits(_) => ValType::F64,
            }
        }

        fn into_wasmi(self) -> Val {
            match self {
                Self::I32(value) => Val::I32(value),
                Self::I64(value) => Val::I64(value),
                Self::F32Bits(bits) => Val::F32(F32::from_bits(bits)),
                Self::F64Bits(bits) => Val::F64(F64::from_bits(bits)),
            }
        }

        fn from_wasmi(value: &Val) -> Option<Self> {
            match value {
                Val::I32(value) => Some(Self::I32(*value)),
                Val::I64(value) => Some(Self::I64(*value)),
                Val::F32(value) => Some(Self::F32Bits(value.to_bits())),
                Val::F64(value) => Some(Self::F64Bits(value.to_bits())),
                _ => None,
            }
        }
    }

    fn default_value(value_type: ValType) -> Option<Val> {
        match value_type {
            ValType::I32 => Some(Val::I32(0)),
            ValType::I64 => Some(Val::I64(0)),
            ValType::F32 => Some(Val::F32(F32::from_bits(0))),
            ValType::F64 => Some(Val::F64(F64::from_bits(0))),
            _ => None,
        }
    }

    fn build_candidate_engine() -> Result<Engine, AdmissionError> {
        let runtime = profile_2_sync_float_validation_contract().target_wasmi_configuration();
        build_engine(runtime)
    }

    #[cfg(feature = "c89-executable")]
    fn build_executable_engine() -> Result<Engine, AdmissionError> {
        let identity =
            current_validation_engine_identity(ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE)
                .ok_or_else(|| admission(AdmissionDetail::UnsupportedFeature))?;
        let package = identity.wasmi();
        if package.name() != C89_SOFTFLOAT_ENGINE_PACKAGE
            || package.version() != C89_SOFTFLOAT_ENGINE_VERSION
            || identity.profile() != ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE
        {
            return Err(admission(AdmissionDetail::UnsupportedFeature));
        }
        build_engine(identity.runtime())
    }

    fn build_engine(runtime: WasmiRuntimeConfiguration) -> Result<Engine, AdmissionError> {
        if !runtime.floats() || runtime.simd_compiled() || runtime.relaxed_simd_compiled() {
            return Err(AdmissionError {
                trap: TrapCode::UnsupportedFeature,
                detail: AdmissionDetail::UnsupportedFeature,
            });
        }
        let mut config = Config::default();
        config
            .floats(runtime.floats())
            .wasm_mutable_global(runtime.mutable_global())
            .wasm_sign_extension(runtime.sign_extension())
            .wasm_saturating_float_to_int(runtime.saturating_float_to_int())
            .wasm_multi_value(runtime.multi_value())
            .wasm_multi_memory(runtime.multi_memory())
            .wasm_bulk_memory(runtime.bulk_memory())
            .wasm_reference_types(runtime.reference_types())
            .wasm_tail_call(runtime.tail_call())
            .wasm_extended_const(runtime.extended_const())
            .wasm_custom_page_sizes(runtime.custom_page_sizes())
            .wasm_memory64(runtime.memory64())
            .wasm_wide_arithmetic(runtime.wide_arithmetic())
            .consume_fuel(runtime.consume_fuel())
            .ignore_custom_sections(runtime.ignore_custom_sections())
            .compilation_mode(match runtime.compilation_mode() {
                WasmiCompilationMode::Eager => CompilationMode::Eager,
            })
            .set_max_recursion_depth(runtime.max_recursion_depth())
            .set_min_stack_height(runtime.min_stack_height())
            .set_max_stack_height(runtime.max_stack_height())
            .set_max_cached_stacks(runtime.max_cached_stacks())
            .enforced_limits(match runtime.enforced_limits() {
                WasmiEnforcedLimits::Strict => EnforcedLimits::strict(),
            });
        match runtime.fuel_costs() {
            WasmiFuelCosts::Wasmi110Default => {}
        }
        Ok(Engine::new(&config))
    }

    fn admission(detail: AdmissionDetail) -> AdmissionError {
        AdmissionError {
            trap: TrapCode::Validation,
            detail,
        }
    }

    /// A bounded, import-free module compiled only by the reviewed candidate.
    #[derive(Debug)]
    pub struct CandidateModule {
        engine: Engine,
        module: Module,
        summary: CoreSummary,
        reserved_compile_bytes: usize,
    }

    impl CandidateModule {
        pub fn compile(
            bytes: &[u8],
            reservation: OwnerAllocationReservation,
        ) -> Result<Self, AdmissionError> {
            let (summary, reserved_compile_bytes) =
                inspect_profile_2_candidate_compile_reservation(bytes, reservation)?;
            if summary.imports != 0 {
                return Err(admission(AdmissionDetail::ImportRequiresLinker));
            }
            let engine = build_candidate_engine()?;
            let module =
                Module::new(&engine, bytes).map_err(|_| admission(AdmissionDetail::Malformed))?;
            Ok(Self {
                engine,
                module,
                summary,
                reserved_compile_bytes,
            })
        }

        /// Compile code 6 only after resolving its opaque current-engine
        /// proof. Code 5 continues to use the acceptance-only constructor.
        #[cfg(feature = "c89-executable")]
        pub fn compile_executable(
            bytes: &[u8],
            reservation: OwnerAllocationReservation,
        ) -> Result<Self, AdmissionError> {
            let proof =
                current_core_validation_engine(ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE)
                    .ok_or_else(|| admission(AdmissionDetail::UnsupportedFeature))?;
            let summary = inspect_core_with_current_engine(bytes, &proof)?;
            let (_, reserved_compile_bytes) =
                super_compile_reservation(bytes, summary, reservation)?;
            if summary.imports != 0 {
                return Err(admission(AdmissionDetail::ImportRequiresLinker));
            }
            let engine = build_executable_engine()?;
            let module =
                Module::new(&engine, bytes).map_err(|_| admission(AdmissionDetail::Malformed))?;
            Ok(Self {
                engine,
                module,
                summary,
                reserved_compile_bytes,
            })
        }

        pub const fn summary(&self) -> CoreSummary {
            self.summary
        }

        pub const fn reserved_compile_bytes(&self) -> usize {
            self.reserved_compile_bytes
        }

        pub fn instantiate(&self) -> Result<CandidateInstance, TrapCode> {
            self.instantiate_with_memory_limit(PROFILE_1_LIMITS.max_memory_pages as usize * 65_536)
        }

        /// Instantiates the acceptance candidate beneath one exact owner
        /// memory ceiling.
        ///
        /// The ceiling is installed in Wasmi's store limiter before the
        /// module is instantiated, so both the declared minimum and every
        /// later `memory.grow` are charged to the same candidate lifecycle.
        /// It is not a production profile selector and does not make artifact
        /// profile code 5 current or runtime-ready.
        pub fn instantiate_with_memory_limit(
            &self,
            memory_bytes: usize,
        ) -> Result<CandidateInstance, TrapCode> {
            let maximum = PROFILE_1_LIMITS.max_memory_pages as usize * 65_536;
            if memory_bytes == 0 || memory_bytes > maximum {
                return Err(TrapCode::LimitExceeded);
            }
            let limits = StoreLimitsBuilder::new()
                .memory_size(memory_bytes)
                .table_elements(PROFILE_1_LIMITS.max_table_elements as usize)
                .instances(1)
                .tables(PROFILE_1_LIMITS.max_tables as usize)
                .memories(PROFILE_1_LIMITS.max_memories as usize)
                .trap_on_grow_failure(true)
                .build();
            let mut store = Store::new(&self.engine, CandidateHostState { limits });
            store.limiter(|state| &mut state.limits);
            let linker = Linker::new(&self.engine);
            let instance = linker
                .instantiate_and_start(&mut store, &self.module)
                .map_err(|error| map_error(&error))?;
            Ok(CandidateInstance {
                store,
                instance,
                active: None,
                last_metrics: None,
            })
        }
    }

    #[cfg(feature = "c89-executable")]
    fn super_compile_reservation(
        bytes: &[u8],
        summary: CoreSummary,
        reservation: OwnerAllocationReservation,
    ) -> Result<(CoreSummary, usize), AdmissionError> {
        // The policy charge is frozen by the predecessor and intentionally
        // shared by the semantically identical code-6 numeric surface.
        let required = vibeos_wasm_runtime::profile_2_candidate_required_compile_bytes(bytes)?;
        if reservation.bytes() < required {
            return Err(AdmissionError {
                trap: TrapCode::LimitExceeded,
                detail: AdmissionDetail::AllocationReservation,
            });
        }
        Ok((summary, required))
    }

    #[derive(Debug)]
    struct CandidateHostState {
        limits: StoreLimits,
    }

    /// Fuel accounting observed at an acceptance-call boundary.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CandidateCallMetrics {
        pub consumed_fuel: u64,
        pub remaining_fuel: u64,
    }

    /// One deterministic scheduler observation.
    #[derive(Debug, PartialEq, Eq)]
    pub enum CandidatePoll {
        Pending(CandidateCallMetrics),
        Ready(Vec<CandidateValue>),
        Trapped(TrapCode),
    }

    pub struct CandidateInstance {
        store: Store<CandidateHostState>,
        instance: Instance,
        active: Option<ActiveCall>,
        last_metrics: Option<CandidateCallMetrics>,
    }

    impl CandidateInstance {
        pub fn start_call(
            &mut self,
            export: &str,
            inputs: &[CandidateValue],
            total_fuel: u64,
            poll_quantum: u64,
        ) -> Result<(), TrapCode> {
            if self.active.is_some() {
                return Err(TrapCode::Validation);
            }
            if total_fuel == 0
                || total_fuel > PROFILE_1_LIMITS.total_fuel
                || poll_quantum == 0
                || poll_quantum > PROFILE_1_LIMITS.poll_quantum
                || poll_quantum > total_fuel
            {
                return Err(TrapCode::LimitExceeded);
            }
            let function = self
                .instance
                .get_func(&self.store, export)
                .ok_or(TrapCode::Validation)?;
            let ty = function.ty(&self.store);
            if inputs.len() != ty.params().len()
                || !inputs
                    .iter()
                    .zip(ty.params())
                    .all(|(value, expected)| value.value_type() == *expected)
            {
                return Err(TrapCode::Validation);
            }
            let mut wasm_inputs = Vec::new();
            wasm_inputs
                .try_reserve_exact(inputs.len())
                .map_err(|_| TrapCode::LimitExceeded)?;
            wasm_inputs.extend(inputs.iter().copied().map(CandidateValue::into_wasmi));
            let mut outputs = Vec::new();
            outputs
                .try_reserve_exact(ty.results().len())
                .map_err(|_| TrapCode::LimitExceeded)?;
            for ty in ty.results() {
                outputs.push(default_value(*ty).ok_or(TrapCode::Validation)?);
            }
            let mut result_values = Vec::new();
            result_values
                .try_reserve_exact(ty.results().len())
                .map_err(|_| TrapCode::LimitExceeded)?;
            self.last_metrics = None;
            self.active = Some(ActiveCall {
                function,
                inputs: wasm_inputs,
                outputs,
                result_values,
                continuation: None,
                remaining_fuel: total_fuel,
                poll_quantum,
                consumed_fuel: 0,
                started: false,
            });
            Ok(())
        }

        pub fn poll_call(&mut self) -> CandidatePoll {
            let Some(active) = self.active.as_mut() else {
                return CandidatePoll::Trapped(TrapCode::Validation);
            };
            match active.poll(&mut self.store) {
                ActivePoll::Pending(metrics) => CandidatePoll::Pending(metrics),
                ActivePoll::Ready(values) => {
                    self.last_metrics = Some(active.metrics());
                    self.active = None;
                    CandidatePoll::Ready(values)
                }
                ActivePoll::Trapped(trap) => {
                    self.last_metrics = Some(active.metrics());
                    self.active = None;
                    CandidatePoll::Trapped(trap)
                }
            }
        }

        pub fn call_metrics(&self) -> Option<CandidateCallMetrics> {
            self.active
                .as_ref()
                .map(ActiveCall::metrics)
                .or(self.last_metrics)
        }
    }

    struct ActiveCall {
        function: Func,
        inputs: Vec<Val>,
        outputs: Vec<Val>,
        result_values: Vec<CandidateValue>,
        continuation: Option<ResumableCallOutOfFuel>,
        remaining_fuel: u64,
        poll_quantum: u64,
        consumed_fuel: u64,
        started: bool,
    }

    enum ActivePoll {
        Pending(CandidateCallMetrics),
        Ready(Vec<CandidateValue>),
        Trapped(TrapCode),
    }

    impl ActiveCall {
        const fn metrics(&self) -> CandidateCallMetrics {
            CandidateCallMetrics {
                consumed_fuel: self.consumed_fuel,
                remaining_fuel: self.remaining_fuel,
            }
        }

        fn poll(&mut self, store: &mut Store<CandidateHostState>) -> ActivePoll {
            if self.remaining_fuel == 0 {
                self.continuation = None;
                return ActivePoll::Trapped(TrapCode::FuelExhausted);
            }
            let grant = min(self.remaining_fuel, self.poll_quantum);
            if store.set_fuel(grant).is_err() {
                return ActivePoll::Trapped(TrapCode::FuelExhausted);
            }
            let result = if let Some(continuation) = self.continuation.take() {
                if let Some(trap) = out_of_fuel_terminal(
                    continuation.required_fuel(),
                    self.remaining_fuel,
                    self.poll_quantum,
                ) {
                    return ActivePoll::Trapped(trap);
                }
                continuation.resume(&mut *store, &mut self.outputs)
            } else if !self.started {
                self.started = true;
                self.function
                    .call_resumable(&mut *store, &self.inputs, &mut self.outputs)
            } else {
                return ActivePoll::Trapped(TrapCode::Validation);
            };
            let left = store.get_fuel().unwrap_or(0).min(grant);
            let used = grant - left;
            self.consumed_fuel = self.consumed_fuel.saturating_add(used);
            self.remaining_fuel = self.remaining_fuel.saturating_sub(used);
            match result {
                Ok(ResumableCall::Finished) => {
                    self.result_values.clear();
                    for value in &self.outputs {
                        let Some(value) = CandidateValue::from_wasmi(value) else {
                            return ActivePoll::Trapped(TrapCode::Validation);
                        };
                        self.result_values.push(value);
                    }
                    ActivePoll::Ready(core::mem::take(&mut self.result_values))
                }
                Ok(ResumableCall::OutOfFuel(continuation)) => {
                    if let Some(trap) = out_of_fuel_terminal(
                        continuation.required_fuel(),
                        self.remaining_fuel,
                        self.poll_quantum,
                    ) {
                        return ActivePoll::Trapped(trap);
                    }
                    self.continuation = Some(continuation);
                    ActivePoll::Pending(self.metrics())
                }
                Ok(ResumableCall::HostTrap(_)) => ActivePoll::Trapped(TrapCode::Validation),
                Err(error) => ActivePoll::Trapped(map_error(&error)),
            }
        }
    }

    fn out_of_fuel_terminal(
        required_fuel: u64,
        remaining_fuel: u64,
        poll_quantum: u64,
    ) -> Option<TrapCode> {
        if required_fuel > remaining_fuel {
            Some(TrapCode::FuelExhausted)
        } else if required_fuel > poll_quantum {
            Some(TrapCode::LimitExceeded)
        } else {
            None
        }
    }

    fn map_error(error: &Error) -> TrapCode {
        use wasmi_softfloat::TrapCode as WasmiTrap;
        match error.kind() {
            ErrorKind::Instantiation(error) => return map_instantiation_error(error),
            ErrorKind::Memory(error) => return map_memory_error(*error),
            ErrorKind::Table(error) => return map_table_error(*error),
            _ => {}
        }
        match error.kind().as_trap_code() {
            Some(WasmiTrap::UnreachableCodeReached) => TrapCode::Unreachable,
            Some(WasmiTrap::IntegerDivisionByZero) => TrapCode::IntegerDivisionByZero,
            Some(WasmiTrap::IntegerOverflow) => TrapCode::IntegerOverflow,
            Some(WasmiTrap::BadConversionToInteger) => TrapCode::InvalidConversionToInteger,
            Some(WasmiTrap::MemoryOutOfBounds) => TrapCode::MemoryOutOfBounds,
            Some(WasmiTrap::TableOutOfBounds | WasmiTrap::IndirectCallToNull) => {
                TrapCode::TableOutOfBounds
            }
            Some(WasmiTrap::BadSignature) => TrapCode::IndirectCallTypeMismatch,
            Some(WasmiTrap::StackOverflow) => TrapCode::CallDepthExceeded,
            Some(WasmiTrap::OutOfFuel) => TrapCode::FuelExhausted,
            Some(WasmiTrap::GrowthOperationLimited) => TrapCode::LimitExceeded,
            None => TrapCode::Validation,
        }
    }

    fn map_memory_error(error: MemoryError) -> TrapCode {
        match error {
            MemoryError::OutOfBoundsGrowth | MemoryError::OutOfBoundsAccess => {
                TrapCode::MemoryOutOfBounds
            }
            MemoryError::OutOfFuel { .. } => TrapCode::FuelExhausted,
            MemoryError::OutOfSystemMemory
            | MemoryError::ResourceLimiterDeniedAllocation
            | MemoryError::MinimumSizeOverflow
            | MemoryError::MaximumSizeOverflow => TrapCode::LimitExceeded,
            MemoryError::InvalidMemoryType | MemoryError::InvalidStaticBufferSize => {
                TrapCode::Validation
            }
        }
    }

    fn map_table_error(error: TableError) -> TrapCode {
        match error {
            TableError::SetOutOfBounds
            | TableError::FillOutOfBounds
            | TableError::GrowOutOfBounds
            | TableError::InitOutOfBounds
            | TableError::CopyOutOfBounds => TrapCode::TableOutOfBounds,
            TableError::ElementTypeMismatch => TrapCode::IndirectCallTypeMismatch,
            TableError::OutOfFuel { .. } => TrapCode::FuelExhausted,
            TableError::OutOfSystemMemory
            | TableError::ResourceLimiterDeniedAllocation
            | TableError::MinimumSizeOverflow
            | TableError::MaximumSizeOverflow => TrapCode::LimitExceeded,
            _ => TrapCode::Validation,
        }
    }

    fn map_instantiation_error(error: &InstantiationError) -> TrapCode {
        match error {
            InstantiationError::ElementSegmentDoesNotFit { .. } => TrapCode::TableOutOfBounds,
            InstantiationError::TooManyInstances
            | InstantiationError::TooManyTables
            | InstantiationError::TooManyMemories => TrapCode::LimitExceeded,
            InstantiationError::FailedToInstantiateMemory(error) => map_memory_error(*error),
            InstantiationError::FailedToInstantiateTable(error) => map_table_error(*error),
            _ => TrapCode::Validation,
        }
    }
}

#[cfg(any(feature = "c88-f2-acceptance", feature = "c89-executable"))]
pub use acceptance::{
    CandidateCallMetrics, CandidateInstance, CandidateModule, CandidatePoll, CandidateValue,
};
