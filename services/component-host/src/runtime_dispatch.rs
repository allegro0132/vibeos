use alloc::alloc::alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ptr::NonNull;

use crate::{
    BlobError, ClockError, ComponentAuthority, ComponentCallError, ComponentHostServices, LogField,
    LogLevel, RandomError, SharedCSpace, StructuredLogError, StructuredLogEvent,
    MAX_BLOB_READ_BYTES, MAX_RANDOM_FILL_BYTES,
};
use vibeos_component_runtime::decode::{ComponentPlan, HostImportInfo};
use vibeos_component_runtime::host::{
    HostDispatcher, HostError, HostPayloadAllocation, HostRequest, HostResponse,
    OneResponseReservation,
};
use vibeos_component_runtime::resource::ResourceTypeId;
use vibeos_component_runtime::types::{FunctionType, NamedParameterType};
use vibeos_component_runtime::value::{CanonicalValue, ResourceOwnership, ValueType};
use vibeos_component_runtime::world::{
    EntityShape, FunctionEffect, FunctionShape, NamedEntityShape, NamedValueShape, TypeShape,
    ValueShape,
};

pub const CLOCK_INTERFACE: &str = "vibe:clock/monotonic@1.0.0";
pub const CLOCK_NOW_FUNCTION: &str = "now";
pub const RANDOM_INTERFACE: &str = "vibe:random/random@1.0.0";
pub const RANDOM_FILL_FUNCTION: &str = "fill";
pub const BLOB_INTERFACE: &str = "vibe:blob/blob@1.0.0";
pub const BLOB_LEN_FUNCTION: &str = "len";
pub const BLOB_READ_FUNCTION: &str = "read";
pub const LOG_INTERFACE: &str = "vibe:log/structured@1.0.0";
pub const LOG_WRITE_FUNCTION: &str = "write";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostManifestError {
    Empty,
    Zero,
    DuplicateFunction,
    DuplicateResourceType,
    ConflictingResourceType,
    UnexpectedImport,
    InvalidShape,
}

/// Nominal resource IDs obtained from the already world-validated component
/// plan. Interface spelling alone is not trusted to establish resource type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VibeHostManifest {
    clock: Option<ResourceTypeId>,
    random: Option<ResourceTypeId>,
    blob: Option<ResourceTypeId>,
    log: Option<ResourceTypeId>,
}

/// One capability requirement derived from an exact, validator-produced host
/// import. This is inert policy metadata: it contains neither a capability
/// handle, a guest resource token, nor a CSpace identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VibeHostRequirement {
    interface: &'static str,
    resource: &'static str,
    kind: crate::HostResourceKind,
    rights: vibeos_core::cap::Rights,
}

impl VibeHostRequirement {
    pub const fn interface(self) -> &'static str {
        self.interface
    }

    pub const fn resource(self) -> &'static str {
        self.resource
    }

    pub const fn kind(self) -> crate::HostResourceKind {
        self.kind
    }

    pub const fn rights(self) -> vibeos_core::cap::Rights {
        self.rights
    }
}

impl VibeHostManifest {
    /// Derive nominal resource bindings from the validator-produced plan.
    /// Every callable host import must match the exact versioned allowlist,
    /// member name, parameter names, ownership, and result shape.
    pub fn from_plan(plan: &ComponentPlan<'_>) -> Result<Self, HostManifestError> {
        validate_normalized_imports(plan.imports())?;
        let mut manifest = Self {
            clock: None,
            random: None,
            blob: None,
            log: None,
        };
        let mut clock_seen = false;
        let mut random_seen = false;
        let mut blob_len_seen = false;
        let mut blob_read_seen = false;
        let mut log_seen = false;
        let mut count = 0_usize;

        for import in plan.host_imports() {
            count = count
                .checked_add(1)
                .ok_or(HostManifestError::InvalidShape)?;
            let resource_type = borrowed_resource_type(&import.function_type)
                .ok_or(HostManifestError::InvalidShape)?;
            if resource_type.0 == 0 {
                return Err(HostManifestError::Zero);
            }
            match (import.interface.as_str(), import.function.as_str()) {
                (CLOCK_INTERFACE, CLOCK_NOW_FUNCTION) => {
                    mark_once(&mut clock_seen)?;
                    if !clock_shape(&import.function_type, resource_type) {
                        return Err(HostManifestError::InvalidShape);
                    }
                    set_resource_type(&mut manifest.clock, resource_type)?;
                }
                (RANDOM_INTERFACE, RANDOM_FILL_FUNCTION) => {
                    mark_once(&mut random_seen)?;
                    if !random_shape(&import.function_type, resource_type) {
                        return Err(HostManifestError::InvalidShape);
                    }
                    set_resource_type(&mut manifest.random, resource_type)?;
                }
                (BLOB_INTERFACE, BLOB_LEN_FUNCTION) => {
                    mark_once(&mut blob_len_seen)?;
                    if !blob_len_shape(&import.function_type, resource_type) {
                        return Err(HostManifestError::InvalidShape);
                    }
                    set_resource_type(&mut manifest.blob, resource_type)?;
                }
                (BLOB_INTERFACE, BLOB_READ_FUNCTION) => {
                    mark_once(&mut blob_read_seen)?;
                    if !blob_read_shape(&import.function_type, resource_type) {
                        return Err(HostManifestError::InvalidShape);
                    }
                    set_resource_type(&mut manifest.blob, resource_type)?;
                }
                (LOG_INTERFACE, LOG_WRITE_FUNCTION) => {
                    mark_once(&mut log_seen)?;
                    if !log_shape(&import.function_type, resource_type) {
                        return Err(HostManifestError::InvalidShape);
                    }
                    set_resource_type(&mut manifest.log, resource_type)?;
                }
                _ => return Err(HostManifestError::UnexpectedImport),
            }
        }
        if count == 0 {
            return Err(HostManifestError::Empty);
        }

        let ids = [manifest.clock, manifest.random, manifest.blob, manifest.log];
        for (index, id) in ids.iter().enumerate() {
            if id.is_some() && ids[..index].contains(id) {
                return Err(HostManifestError::DuplicateResourceType);
            }
        }
        Ok(manifest)
    }

    /// Iterate the exact resource requirements represented by this manifest.
    ///
    /// Resource type IDs deliberately remain private because they are nominal
    /// to one decode. Admission persists only the versioned interface,
    /// semantic kind, and operation rights; a later re-decode derives fresh
    /// nominal IDs before instantiation.
    pub fn requirements(self) -> impl Iterator<Item = VibeHostRequirement> {
        [
            self.clock.map(|_| VibeHostRequirement {
                interface: CLOCK_INTERFACE,
                resource: "clock",
                kind: crate::HostResourceKind::Clock,
                rights: vibeos_core::cap::Rights::READ,
            }),
            self.random.map(|_| VibeHostRequirement {
                interface: RANDOM_INTERFACE,
                resource: "random-source",
                kind: crate::HostResourceKind::Random,
                rights: vibeos_core::cap::Rights::READ,
            }),
            self.blob.map(|_| VibeHostRequirement {
                interface: BLOB_INTERFACE,
                resource: "blob",
                kind: crate::HostResourceKind::Blob,
                rights: vibeos_core::cap::Rights::READ,
            }),
            self.log.map(|_| VibeHostRequirement {
                interface: LOG_INTERFACE,
                resource: "structured-log",
                kind: crate::HostResourceKind::StructuredLog,
                rights: vibeos_core::cap::Rights::WRITE,
            }),
        ]
        .into_iter()
        .flatten()
    }
}

fn validate_normalized_imports(imports: &[NamedEntityShape]) -> Result<(), HostManifestError> {
    if imports.is_empty() {
        return Err(HostManifestError::Empty);
    }
    let mut clock = false;
    let mut random = false;
    let mut blob = false;
    let mut log = false;
    for import in imports {
        let valid = match import.name.as_str() {
            CLOCK_INTERFACE => {
                mark_once(&mut clock)?;
                clock_interface(import)
            }
            RANDOM_INTERFACE => {
                mark_once(&mut random)?;
                random_interface(import)
            }
            BLOB_INTERFACE => {
                mark_once(&mut blob)?;
                blob_interface(import)
            }
            LOG_INTERFACE => {
                mark_once(&mut log)?;
                log_interface(import)
            }
            _ => return Err(HostManifestError::UnexpectedImport),
        };
        if !valid {
            return Err(HostManifestError::InvalidShape);
        }
    }
    Ok(())
}

fn interface_members(entity: &NamedEntityShape) -> Option<&[NamedEntityShape]> {
    match &entity.entity {
        EntityShape::Interface(members) => Some(members),
        _ => None,
    }
}

fn resource(entity: &NamedEntityShape, name: &str) -> bool {
    entity.name == name && entity.entity == EntityShape::Type(TypeShape::Resource)
}

fn enum_type(entity: &NamedEntityShape, name: &str, cases: &[&str]) -> bool {
    entity.name == name
        && matches!(&entity.entity, EntityShape::Type(TypeShape::Value(ValueShape::Enum(actual)))
            if strings_are(actual, cases))
}

fn record_type(entity: &NamedEntityShape, name: &str, fields: &[(&str, Shape<'_>)]) -> bool {
    entity.name == name
        && matches!(&entity.entity, EntityShape::Type(TypeShape::Value(ValueShape::Record(actual)))
            if named_values_are(actual, fields))
}

fn function(
    entity: &NamedEntityShape,
    name: &str,
    parameters: &[(&str, Shape<'_>)],
    result: Option<Shape<'_>>,
) -> bool {
    entity.name == name
        && matches!(&entity.entity, EntityShape::Function(FunctionShape {
            effect: FunctionEffect::Sync,
            parameters: actual,
            result: actual_result,
        })
            if named_values_are(actual, parameters) && optional_shape_is(actual_result.as_ref(), result))
}

#[derive(Clone, Copy)]
enum Shape<'a> {
    U8,
    U32,
    U64,
    String,
    Borrow(&'a str),
    Enum(&'a [&'a str]),
    List(&'a Shape<'a>),
    Record(&'a [(&'a str, Shape<'a>)]),
    Result {
        ok: Option<&'a Shape<'a>>,
        error: Option<&'a Shape<'a>>,
    },
}

fn optional_shape_is(actual: Option<&ValueShape>, expected: Option<Shape<'_>>) -> bool {
    match (actual, expected) {
        (None, None) => true,
        (Some(actual), Some(expected)) => shape_is(actual, expected),
        _ => false,
    }
}

fn shape_is(actual: &ValueShape, expected: Shape<'_>) -> bool {
    match (actual, expected) {
        (ValueShape::U8, Shape::U8)
        | (ValueShape::U32, Shape::U32)
        | (ValueShape::U64, Shape::U64)
        | (ValueShape::String, Shape::String) => true,
        (ValueShape::Borrow(actual), Shape::Borrow(expected)) => actual == expected,
        (ValueShape::Enum(actual), Shape::Enum(expected)) => strings_are(actual, expected),
        (ValueShape::List(actual), Shape::List(expected)) => shape_is(actual, *expected),
        (ValueShape::Record(actual), Shape::Record(expected)) => named_values_are(actual, expected),
        (
            ValueShape::Result { ok, error },
            Shape::Result {
                ok: expected_ok,
                error: expected_error,
            },
        ) => {
            optional_shape_is(ok.as_deref(), expected_ok.copied())
                && optional_shape_is(error.as_deref(), expected_error.copied())
        }
        _ => false,
    }
}

fn strings_are(actual: &[alloc::string::String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
}

fn named_values_are(actual: &[NamedValueShape], expected: &[(&str, Shape<'_>)]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, (name, shape))| actual.name == *name && shape_is(&actual.value, *shape))
}

fn clock_interface(import: &NamedEntityShape) -> bool {
    matches!(interface_members(import), Some([clock, now])
        if resource(clock, "clock")
            && function(now, "now", &[("clock", Shape::Borrow("clock"))], Some(Shape::U64)))
}

fn random_interface(import: &NamedEntityShape) -> bool {
    const ERROR_CASES: &[&str] = &["denied", "exhausted"];
    const BYTE: Shape<'_> = Shape::U8;
    const BYTES: Shape<'_> = Shape::List(&BYTE);
    const ERROR: Shape<'_> = Shape::Enum(ERROR_CASES);
    const RESULT: Shape<'_> = Shape::Result {
        ok: Some(&BYTES),
        error: Some(&ERROR),
    };
    matches!(interface_members(import), Some([source, error, fill])
    if resource(source, "random-source")
        && enum_type(error, "random-error", ERROR_CASES)
        && function(
            fill,
            "fill",
            &[("source", Shape::Borrow("random-source")), ("len", Shape::U32)],
            Some(RESULT),
        ))
}

fn blob_interface(import: &NamedEntityShape) -> bool {
    const ERROR_CASES: &[&str] = &["denied", "invalid", "failed"];
    const BYTE: Shape<'_> = Shape::U8;
    const BYTES: Shape<'_> = Shape::List(&BYTE);
    const ERROR: Shape<'_> = Shape::Enum(ERROR_CASES);
    const RESULT: Shape<'_> = Shape::Result {
        ok: Some(&BYTES),
        error: Some(&ERROR),
    };
    matches!(interface_members(import), Some([blob, error, len, read])
    if resource(blob, "blob")
        && enum_type(error, "blob-error", ERROR_CASES)
        && function(len, "len", &[("blob", Shape::Borrow("blob"))], Some(Shape::U64))
        && function(
            read,
            "read",
            &[
                ("blob", Shape::Borrow("blob")),
                ("offset", Shape::U64),
                ("len", Shape::U32),
            ],
            Some(RESULT),
        ))
}

fn log_interface(import: &NamedEntityShape) -> bool {
    const LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];
    const ERROR_CASES: &[&str] = &["denied", "invalid", "failed"];
    const FIELD_PARTS: &[(&str, Shape<'_>)] = &[("key", Shape::String), ("value", Shape::String)];
    const FIELD: Shape<'_> = Shape::Record(FIELD_PARTS);
    const FIELDS: Shape<'_> = Shape::List(&FIELD);
    const EVENT_PARTS: &[(&str, Shape<'_>)] = &[
        ("level", Shape::Enum(LEVELS)),
        ("target", Shape::String),
        ("message", Shape::String),
        ("fields", FIELDS),
    ];
    const EVENT: Shape<'_> = Shape::Record(EVENT_PARTS);
    const ERROR: Shape<'_> = Shape::Enum(ERROR_CASES);
    const RESULT: Shape<'_> = Shape::Result {
        ok: None,
        error: Some(&ERROR),
    };
    matches!(interface_members(import), Some([log, level, field, event, error, write])
    if resource(log, "structured-log")
        && enum_type(level, "level", LEVELS)
        && record_type(field, "field", FIELD_PARTS)
        && record_type(event, "event", EVENT_PARTS)
        && enum_type(error, "log-error", ERROR_CASES)
        && function(
            write,
            "write",
            &[("log", Shape::Borrow("structured-log")), ("event", EVENT)],
            Some(RESULT),
        ))
}

fn mark_once(seen: &mut bool) -> Result<(), HostManifestError> {
    if *seen {
        return Err(HostManifestError::DuplicateFunction);
    }
    *seen = true;
    Ok(())
}

fn set_resource_type(
    destination: &mut Option<ResourceTypeId>,
    value: ResourceTypeId,
) -> Result<(), HostManifestError> {
    match destination {
        Some(existing) if *existing != value => Err(HostManifestError::ConflictingResourceType),
        Some(_) => Ok(()),
        empty @ None => {
            *empty = Some(value);
            Ok(())
        }
    }
}

fn borrowed_resource_type(function: &FunctionType) -> Option<ResourceTypeId> {
    let first = function.parameters.first()?;
    match &first.value {
        ValueType::Resource {
            resource_type,
            ownership: ResourceOwnership::Borrow,
        } => Some(*resource_type),
        _ => None,
    }
}

const CLOCK_WORK: u64 = 1;
const RANDOM_BASE_WORK: u64 = 4;
const BLOB_LEN_WORK: u64 = 1;
const BLOB_READ_BASE_WORK: u64 = 4;
const LOG_BASE_WORK: u64 = 4;

const DENIED_CASE: u32 = 0;
const EXHAUSTED_CASE: u32 = 1;
const INVALID_CASE: u32 = 1;
const FAILED_CASE: u32 = 2;

/// Exact synchronous Profile-1 dispatcher for one component CSpace.
pub struct ComponentHostDispatcher {
    cspace: SharedCSpace,
    manifest: VibeHostManifest,
}

impl ComponentHostDispatcher {
    pub fn new(cspace: SharedCSpace, manifest: VibeHostManifest) -> Self {
        Self { cspace, manifest }
    }

    fn dispatch_clock(
        &self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostResponse, HostError> {
        if !self
            .manifest
            .clock
            .is_some_and(|resource| clock_shape(&request.import().function_type, resource))
            || !matches!(request.arguments(), [CanonicalValue::Resource(_)])
        {
            return Err(HostError::Denied);
        }
        let response = HostResponse::reserve_one(CLOCK_WORK)?;
        let value = request
            .with_borrow_argument(0, |authority| {
                ComponentHostServices::clock_now_ns(authority, &self.cspace)
            })
            .map_err(|_| HostError::Denied)?
            .map_err(map_clock_error)?;
        response.commit(CanonicalValue::U64(value))
    }

    fn dispatch_random(
        &self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostResponse, HostError> {
        if !self
            .manifest
            .random
            .is_some_and(|resource| random_shape(&request.import().function_type, resource))
        {
            return Err(HostError::Denied);
        }
        let [CanonicalValue::Resource(_), CanonicalValue::U32(length)] = request.arguments() else {
            return Err(HostError::Denied);
        };
        let length = usize::try_from(*length).map_err(|_| HostError::Exhausted)?;
        let work = byte_work(RANDOM_BASE_WORK, length)?;
        if length > MAX_RANDOM_FILL_BYTES {
            return result_response(Err(EXHAUSTED_CASE), work);
        }

        request
            .with_borrow_argument(0, |authority| {
                let prepared = PreparedResult::bytes(length, work)?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(length)
                    .map_err(|_| HostError::Exhausted)?;
                bytes.resize(length, 0);
                match ComponentHostServices::random_fill_exact(authority, &self.cspace, &mut bytes)
                {
                    Ok(()) => prepared.success_external_bytes(bytes),
                    Err(error) => prepared.error(map_random_error(error)),
                }
            })
            .map_err(|_| HostError::Denied)?
    }

    fn dispatch_blob_len(
        &self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostResponse, HostError> {
        if !self
            .manifest
            .blob
            .is_some_and(|resource| blob_len_shape(&request.import().function_type, resource))
            || !matches!(request.arguments(), [CanonicalValue::Resource(_)])
        {
            return Err(HostError::Denied);
        }
        let response = HostResponse::reserve_one(BLOB_LEN_WORK)?;
        request
            .with_borrow_argument(0, |authority| {
                match ComponentHostServices::blob_len(authority, &self.cspace) {
                    Ok(length) => response.commit(CanonicalValue::U64(length)),
                    Err(ComponentCallError::Authority(_)) => Err(HostError::Denied),
                    Err(ComponentCallError::Resource(BlobError::BackendFault)) => {
                        Err(HostError::BackendFault)
                    }
                    Err(ComponentCallError::Resource(_)) => Err(HostError::InvalidArgument),
                }
            })
            .map_err(|_| HostError::Denied)?
    }

    fn dispatch_blob_read(
        &self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostResponse, HostError> {
        if !self
            .manifest
            .blob
            .is_some_and(|resource| blob_read_shape(&request.import().function_type, resource))
        {
            return Err(HostError::Denied);
        }
        let [CanonicalValue::Resource(_), CanonicalValue::U64(offset), CanonicalValue::U32(length)] =
            request.arguments()
        else {
            return Err(HostError::Denied);
        };
        let length = usize::try_from(*length).map_err(|_| HostError::Exhausted)?;
        let work = byte_work(BLOB_READ_BASE_WORK, length)?;
        if length > MAX_BLOB_READ_BYTES {
            return result_response(Err(INVALID_CASE), work);
        }

        request
            .with_borrow_argument(0, |authority| {
                let prepared = PreparedResult::bytes(length, work)?;
                match ComponentHostServices::blob_read(authority, &self.cspace, *offset, length) {
                    Ok(bytes) => prepared.success_external_bytes(bytes),
                    Err(error) => prepared.error(map_blob_error(error)),
                }
            })
            .map_err(|_| HostError::Denied)?
    }

    fn dispatch_log(
        &self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostResponse, HostError> {
        if !self
            .manifest
            .log
            .is_some_and(|resource| log_shape(&request.import().function_type, resource))
        {
            return Err(HostError::Denied);
        }
        let [CanonicalValue::Resource(_), CanonicalValue::Record(record)] = request.arguments()
        else {
            return Err(HostError::Denied);
        };
        let [CanonicalValue::Enum(level), CanonicalValue::String(target), CanonicalValue::String(message), CanonicalValue::List(raw_fields)] =
            record.as_slice()
        else {
            return Err(HostError::Denied);
        };
        let level = match level {
            0 => LogLevel::Trace,
            1 => LogLevel::Debug,
            2 => LogLevel::Info,
            3 => LogLevel::Warn,
            4 => LogLevel::Error,
            _ => return Err(HostError::Denied),
        };
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(raw_fields.len())
            .map_err(|_| HostError::Exhausted)?;
        let mut byte_count = target
            .len()
            .checked_add(message.len())
            .ok_or(HostError::Exhausted)?;
        for field in raw_fields {
            let CanonicalValue::Record(parts) = field else {
                return Err(HostError::Denied);
            };
            let [CanonicalValue::String(key), CanonicalValue::String(value)] = parts.as_slice()
            else {
                return Err(HostError::Denied);
            };
            byte_count = byte_count
                .checked_add(key.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or(HostError::Exhausted)?;
            fields.push(LogField {
                key: key.as_bytes(),
                value: value.as_bytes(),
            });
        }
        let work = byte_work(LOG_BASE_WORK, byte_count)?;
        let event = StructuredLogEvent {
            level,
            target: target.as_bytes(),
            message: message.as_bytes(),
            fields: &fields,
        };
        let prepared = PreparedResult::unit(work)?;
        request
            .with_borrow_argument(
                0,
                |authority| match ComponentHostServices::structured_log_write(
                    authority,
                    &self.cspace,
                    &event,
                ) {
                    Ok(()) => prepared.success_unit(),
                    Err(error) => prepared.error(map_log_error(error)),
                },
            )
            .map_err(|_| HostError::Denied)?
    }
}

impl HostDispatcher<ComponentAuthority> for ComponentHostDispatcher {
    fn required_work(
        &self,
        import: &HostImportInfo,
        arguments: &[CanonicalValue],
    ) -> Result<u64, HostError> {
        match (import.interface.as_str(), import.function.as_str()) {
            (CLOCK_INTERFACE, CLOCK_NOW_FUNCTION)
                if self
                    .manifest
                    .clock
                    .is_some_and(|resource| clock_shape(&import.function_type, resource))
                    && matches!(arguments, [CanonicalValue::Resource(_)]) =>
            {
                Ok(CLOCK_WORK)
            }
            (RANDOM_INTERFACE, RANDOM_FILL_FUNCTION)
                if self
                    .manifest
                    .random
                    .is_some_and(|resource| random_shape(&import.function_type, resource)) =>
            {
                let [CanonicalValue::Resource(_), CanonicalValue::U32(length)] = arguments else {
                    return Err(HostError::Denied);
                };
                byte_work(
                    RANDOM_BASE_WORK,
                    usize::try_from(*length).map_err(|_| HostError::Exhausted)?,
                )
            }
            (BLOB_INTERFACE, BLOB_LEN_FUNCTION)
                if self
                    .manifest
                    .blob
                    .is_some_and(|resource| blob_len_shape(&import.function_type, resource))
                    && matches!(arguments, [CanonicalValue::Resource(_)]) =>
            {
                Ok(BLOB_LEN_WORK)
            }
            (BLOB_INTERFACE, BLOB_READ_FUNCTION)
                if self
                    .manifest
                    .blob
                    .is_some_and(|resource| blob_read_shape(&import.function_type, resource)) =>
            {
                let [CanonicalValue::Resource(_), CanonicalValue::U64(_), CanonicalValue::U32(length)] =
                    arguments
                else {
                    return Err(HostError::Denied);
                };
                byte_work(
                    BLOB_READ_BASE_WORK,
                    usize::try_from(*length).map_err(|_| HostError::Exhausted)?,
                )
            }
            (LOG_INTERFACE, LOG_WRITE_FUNCTION)
                if self
                    .manifest
                    .log
                    .is_some_and(|resource| log_shape(&import.function_type, resource)) =>
            {
                let [CanonicalValue::Resource(_), CanonicalValue::Record(record)] = arguments
                else {
                    return Err(HostError::Denied);
                };
                quote_log_record(record)
            }
            _ => Err(HostError::Denied),
        }
    }

    fn result_allocations(
        &self,
        import: &HostImportInfo,
        arguments: &[CanonicalValue],
    ) -> Result<Vec<HostPayloadAllocation>, HostError> {
        let length = match (
            import.interface.as_str(),
            import.function.as_str(),
            arguments,
        ) {
            (
                RANDOM_INTERFACE,
                RANDOM_FILL_FUNCTION,
                [CanonicalValue::Resource(_), CanonicalValue::U32(length)],
            ) if self
                .manifest
                .random
                .is_some_and(|resource| random_shape(&import.function_type, resource)) =>
            {
                usize::try_from(*length).map_err(|_| HostError::Exhausted)?
            }
            (
                BLOB_INTERFACE,
                BLOB_READ_FUNCTION,
                [CanonicalValue::Resource(_), CanonicalValue::U64(_), CanonicalValue::U32(length)],
            ) if self
                .manifest
                .blob
                .is_some_and(|resource| blob_read_shape(&import.function_type, resource)) =>
            {
                usize::try_from(*length).map_err(|_| HostError::Exhausted)?
            }
            _ => return Ok(Vec::new()),
        };
        let maximum = if import.interface == RANDOM_INTERFACE {
            MAX_RANDOM_FILL_BYTES
        } else {
            MAX_BLOB_READ_BYTES
        };
        if length == 0 || length > maximum {
            return Ok(Vec::new());
        }
        let mut allocations = Vec::new();
        allocations
            .try_reserve_exact(1)
            .map_err(|_| HostError::Exhausted)?;
        allocations.push(HostPayloadAllocation {
            size: u32::try_from(length).map_err(|_| HostError::Exhausted)?,
            alignment: 1,
        });
        Ok(allocations)
    }

    fn dispatch(
        &mut self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostResponse, HostError> {
        match (
            request.import().interface.as_str(),
            request.import().function.as_str(),
        ) {
            (CLOCK_INTERFACE, CLOCK_NOW_FUNCTION) => self.dispatch_clock(request),
            (RANDOM_INTERFACE, RANDOM_FILL_FUNCTION) => self.dispatch_random(request),
            (BLOB_INTERFACE, BLOB_LEN_FUNCTION) => self.dispatch_blob_len(request),
            (BLOB_INTERFACE, BLOB_READ_FUNCTION) => self.dispatch_blob_read(request),
            (LOG_INTERFACE, LOG_WRITE_FUNCTION) => self.dispatch_log(request),
            _ => Err(HostError::Denied),
        }
    }
}

fn parameter_is(parameter: &NamedParameterType, name: &str, value: &ValueType) -> bool {
    parameter.name == name && &parameter.value == value
}

fn borrowed(parameter: &NamedParameterType, name: &str, expected: ResourceTypeId) -> bool {
    parameter.name == name
        && parameter.value
            == ValueType::Resource {
                resource_type: expected,
                ownership: ResourceOwnership::Borrow,
            }
}

fn byte_list_type(value: &ValueType) -> bool {
    matches!(value, ValueType::List(item) if **item == ValueType::U8)
}

fn result_type(value: &ValueType, ok_list: bool, error_cases: u32) -> bool {
    let ValueType::Result { ok, error } = value else {
        return false;
    };
    let ok_matches = if ok_list {
        ok.as_deref().is_some_and(byte_list_type)
    } else {
        ok.is_none()
    };
    ok_matches && matches!(error.as_deref(), Some(ValueType::Enum(cases)) if *cases == error_cases)
}

fn clock_shape(function: &FunctionType, expected: ResourceTypeId) -> bool {
    matches!(function.parameters.as_slice(), [clock] if borrowed(clock, "clock", expected))
        && function.result == Some(ValueType::U64)
}

fn random_shape(function: &FunctionType, expected: ResourceTypeId) -> bool {
    matches!(function.parameters.as_slice(), [source, length]
        if borrowed(source, "source", expected) && parameter_is(length, "len", &ValueType::U32))
        && function
            .result
            .as_ref()
            .is_some_and(|result| result_type(result, true, 2))
}

fn blob_len_shape(function: &FunctionType, expected: ResourceTypeId) -> bool {
    matches!(function.parameters.as_slice(), [blob] if borrowed(blob, "blob", expected))
        && function.result == Some(ValueType::U64)
}

fn blob_read_shape(function: &FunctionType, expected: ResourceTypeId) -> bool {
    matches!(function.parameters.as_slice(), [blob, offset, length]
        if borrowed(blob, "blob", expected)
            && parameter_is(offset, "offset", &ValueType::U64)
            && parameter_is(length, "len", &ValueType::U32))
        && function
            .result
            .as_ref()
            .is_some_and(|result| result_type(result, true, 3))
}

fn log_shape(function: &FunctionType, expected: ResourceTypeId) -> bool {
    let [log, event] = function.parameters.as_slice() else {
        return false;
    };
    if !borrowed(log, "log", expected) || event.name != "event" {
        return false;
    }
    let ValueType::Record(event_fields) = &event.value else {
        return false;
    };
    let [ValueType::Enum(5), ValueType::String, ValueType::String, ValueType::List(fields)] =
        event_fields.as_slice()
    else {
        return false;
    };
    matches!(fields.as_ref(), ValueType::Record(parts)
        if matches!(parts.as_slice(), [ValueType::String, ValueType::String]))
        && function
            .result
            .as_ref()
            .is_some_and(|result| result_type(result, false, 3))
}

fn byte_work(base: u64, bytes: usize) -> Result<u64, HostError> {
    base.checked_add(u64::try_from(bytes).map_err(|_| HostError::Exhausted)?)
        .ok_or(HostError::Exhausted)
}

fn quote_log_record(record: &[CanonicalValue]) -> Result<u64, HostError> {
    let [CanonicalValue::Enum(level), CanonicalValue::String(target), CanonicalValue::String(message), CanonicalValue::List(fields)] =
        record
    else {
        return Err(HostError::Denied);
    };
    if *level >= 5 {
        return Err(HostError::Denied);
    }
    let mut bytes = target
        .len()
        .checked_add(message.len())
        .ok_or(HostError::Exhausted)?;
    for field in fields {
        let CanonicalValue::Record(parts) = field else {
            return Err(HostError::Denied);
        };
        let [CanonicalValue::String(key), CanonicalValue::String(value)] = parts.as_slice() else {
            return Err(HostError::Denied);
        };
        bytes = bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(HostError::Exhausted)?;
    }
    byte_work(LOG_BASE_WORK, bytes)
}

struct PreparedResult {
    response: OneResponseReservation,
    payload: Option<Box<CanonicalValue>>,
    error: Box<CanonicalValue>,
}

impl PreparedResult {
    fn unit(work: u64) -> Result<Self, HostError> {
        Ok(Self {
            response: HostResponse::reserve_one(work)?,
            payload: None,
            error: try_box(CanonicalValue::Enum(0))?,
        })
    }

    fn bytes(length: usize, work: u64) -> Result<Self, HostError> {
        let mut items = Vec::new();
        items
            .try_reserve_exact(length)
            .map_err(|_| HostError::Exhausted)?;
        items.resize_with(length, || CanonicalValue::U8(0));
        Ok(Self {
            response: HostResponse::reserve_one(work)?,
            payload: Some(try_box(CanonicalValue::List(items))?),
            error: try_box(CanonicalValue::Enum(0))?,
        })
    }

    fn success_external_bytes(mut self, bytes: Vec<u8>) -> Result<HostResponse, HostError> {
        let Some(payload) = self.payload.as_deref_mut() else {
            return Err(HostError::InvalidArgument);
        };
        let CanonicalValue::List(items) = payload else {
            return Err(HostError::InvalidArgument);
        };
        if items.len() != bytes.len() {
            return Err(HostError::BackendFault);
        }
        for (destination, byte) in items.iter_mut().zip(bytes) {
            *destination = CanonicalValue::U8(byte);
        }
        self.success_bytes()
    }

    fn success_bytes(self) -> Result<HostResponse, HostError> {
        self.response
            .commit(CanonicalValue::Result(Ok(self.payload)))
    }

    fn success_unit(self) -> Result<HostResponse, HostError> {
        self.response.commit(CanonicalValue::Result(Ok(None)))
    }

    fn error(mut self, case: u32) -> Result<HostResponse, HostError> {
        *self.error = CanonicalValue::Enum(case);
        self.response
            .commit(CanonicalValue::Result(Err(Some(self.error))))
    }
}

fn result_response(
    result: Result<Option<CanonicalValue>, u32>,
    work: u64,
) -> Result<HostResponse, HostError> {
    let prepared = PreparedResult::unit(work)?;
    match result {
        Ok(None) => prepared.success_unit(),
        Ok(Some(value)) => {
            let mut prepared = prepared;
            prepared.payload = Some(try_box(value)?);
            prepared.success_bytes()
        }
        Err(case) => prepared.error(case),
    }
}

fn try_box<T>(value: T) -> Result<Box<T>, HostError> {
    let layout = Layout::new::<T>();
    // SAFETY: the global allocator receives the exact layout for one T. A
    // non-null result is initialized once and transferred immediately to Box.
    let pointer = unsafe { alloc(layout) };
    let pointer = NonNull::<T>::new(pointer.cast()).ok_or(HostError::Exhausted)?;
    // SAFETY: pointer denotes fresh, properly aligned storage for one T.
    unsafe {
        pointer.as_ptr().write(value);
        Ok(Box::from_raw(pointer.as_ptr()))
    }
}

fn map_clock_error(error: ComponentCallError<ClockError>) -> HostError {
    match error {
        ComponentCallError::Authority(_) => HostError::Denied,
        ComponentCallError::Resource(_) => HostError::BackendFault,
    }
}

fn map_random_error(error: ComponentCallError<RandomError>) -> u32 {
    match error {
        ComponentCallError::Authority(_) => DENIED_CASE,
        ComponentCallError::Resource(RandomError::TooLarge { .. })
        | ComponentCallError::Resource(RandomError::Allocation)
        | ComponentCallError::Resource(RandomError::BackendFault) => EXHAUSTED_CASE,
    }
}

fn map_blob_error(error: ComponentCallError<BlobError>) -> u32 {
    match error {
        ComponentCallError::Authority(_) => DENIED_CASE,
        ComponentCallError::Resource(BlobError::TooLarge { .. })
        | ComponentCallError::Resource(BlobError::RangeOverflow)
        | ComponentCallError::Resource(BlobError::OutOfBounds { .. }) => INVALID_CASE,
        ComponentCallError::Resource(BlobError::Allocation)
        | ComponentCallError::Resource(BlobError::BackendFault) => FAILED_CASE,
    }
}

fn map_log_error(error: ComponentCallError<StructuredLogError>) -> u32 {
    match error {
        ComponentCallError::Authority(_) => DENIED_CASE,
        ComponentCallError::Resource(StructuredLogError::Allocation)
        | ComponentCallError::Resource(StructuredLogError::BackendFault) => FAILED_CASE,
        ComponentCallError::Resource(_) => INVALID_CASE,
    }
}
