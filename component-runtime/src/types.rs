//! Fallible normalization of validated Component Model function types.

use crate::{
    resource::ResourceTypeId,
    value::{AsyncValueTypeId, ResourceOwnership, ValueType},
    world::FunctionEffect,
};
use alloc::{alloc::alloc, boxed::Box, string::String, vec::Vec};
use core::{alloc::Layout, ptr::NonNull};
use vibeos_component_format::PROFILE_1_LIMITS;
use wasmparser::{
    component_types::{
        AliasableResourceId, ComponentDefinedType, ComponentDefinedTypeId, ComponentEntityType,
        ComponentFuncTypeId, ComponentValType,
    },
    types::Types,
    PrimitiveValType,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TypeError {
    Unsupported = 1,
    NestingLimit = 2,
    DefinitionLimit = 3,
    Allocation = 4,
    InvalidFunction = 5,
}

impl TypeError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct NamedParameterType {
    pub name: String,
    pub value: ValueType,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FunctionType {
    pub effect: FunctionEffect,
    pub parameters: Vec<NamedParameterType>,
    pub result: Option<ValueType>,
}

pub(crate) fn try_clone_function_type(value: &FunctionType) -> Result<FunctionType, TypeError> {
    let mut parameters = Vec::new();
    parameters
        .try_reserve_exact(value.parameters.len())
        .map_err(|_| TypeError::Allocation)?;
    for parameter in &value.parameters {
        parameters.push(NamedParameterType {
            name: copied(&parameter.name)?,
            value: try_clone_value_type(&parameter.value)?,
        });
    }
    Ok(FunctionType {
        effect: value.effect,
        parameters,
        result: value
            .result
            .as_ref()
            .map(try_clone_value_type)
            .transpose()?,
    })
}

fn try_clone_value_type(value: &ValueType) -> Result<ValueType, TypeError> {
    Ok(match value {
        ValueType::Bool => ValueType::Bool,
        ValueType::U8 => ValueType::U8,
        ValueType::U16 => ValueType::U16,
        ValueType::U32 => ValueType::U32,
        ValueType::U64 => ValueType::U64,
        ValueType::S8 => ValueType::S8,
        ValueType::S16 => ValueType::S16,
        ValueType::S32 => ValueType::S32,
        ValueType::S64 => ValueType::S64,
        ValueType::Char => ValueType::Char,
        ValueType::String => ValueType::String,
        ValueType::List(item) => ValueType::List(try_box(try_clone_value_type(item)?)?),
        ValueType::Tuple(items) => ValueType::Tuple(try_clone_types(items)?),
        ValueType::Record(items) => ValueType::Record(try_clone_types(items)?),
        ValueType::Flags(count) => ValueType::Flags(*count),
        ValueType::Enum(cases) => ValueType::Enum(*cases),
        ValueType::Option(item) => ValueType::Option(try_box(try_clone_value_type(item)?)?),
        ValueType::Result { ok, error } => ValueType::Result {
            ok: ok
                .as_deref()
                .map(|value| try_clone_value_type(value).and_then(try_box))
                .transpose()?,
            error: error
                .as_deref()
                .map(|value| try_clone_value_type(value).and_then(try_box))
                .transpose()?,
        },
        ValueType::Variant(cases) => {
            let mut result = Vec::new();
            result
                .try_reserve_exact(cases.len())
                .map_err(|_| TypeError::Allocation)?;
            for case in cases {
                result.push(case.as_ref().map(try_clone_value_type).transpose()?);
            }
            ValueType::Variant(result)
        }
        ValueType::Resource {
            resource_type,
            ownership,
        } => ValueType::Resource {
            resource_type: *resource_type,
            ownership: *ownership,
        },
        ValueType::Stream { type_id, element } => ValueType::Stream {
            type_id: *type_id,
            element: element
                .as_deref()
                .map(|value| try_clone_value_type(value).and_then(try_box))
                .transpose()?,
        },
        ValueType::Future { type_id, payload } => ValueType::Future {
            type_id: *type_id,
            payload: payload
                .as_deref()
                .map(|value| try_clone_value_type(value).and_then(try_box))
                .transpose()?,
        },
    })
}

fn try_clone_types(values: &[ValueType]) -> Result<Vec<ValueType>, TypeError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(values.len())
        .map_err(|_| TypeError::Allocation)?;
    for value in values {
        result.push(try_clone_value_type(value)?);
    }
    Ok(result)
}

#[derive(Default)]
pub(crate) struct TypeBuilder {
    resources: Vec<AliasableResourceId>,
    async_values: Vec<AsyncValueRepresentative>,
    future_values: u32,
    stream_values: u32,
    /// Distinct validated nodes already charged to the type-graph budget.
    accounted_values: Vec<ComponentValueKey>,
    nodes: u32,
    /// Total nodes materialized into owned `ValueType` trees.
    materialized_nodes: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ComponentValueKey {
    Primitive(PrimitiveValType),
    Defined(ComponentDefinedTypeId),
}

impl From<ComponentValType> for ComponentValueKey {
    fn from(value: ComponentValType) -> Self {
        match value {
            ComponentValType::Primitive(primitive) => Self::Primitive(primitive),
            ComponentValType::Type(defined) => Self::Defined(defined),
        }
    }
}

impl TypeBuilder {
    pub(crate) fn component_value(
        &mut self,
        types: &Types,
        value: ComponentValType,
    ) -> Result<ValueType, TypeError> {
        self.value(types, value, 1)
    }

    pub(crate) fn defined_value(
        &mut self,
        types: &Types,
        value: ComponentDefinedTypeId,
    ) -> Result<ValueType, TypeError> {
        self.component_value(types, ComponentValType::Type(value))
    }

    pub(crate) fn function(
        &mut self,
        types: &Types,
        function: ComponentFuncTypeId,
    ) -> Result<FunctionType, TypeError> {
        let function = &types[function];
        if function.params.len() > PROFILE_1_LIMITS.max_params_per_function as usize {
            return Err(TypeError::Unsupported);
        }
        let mut parameters = Vec::new();
        parameters
            .try_reserve_exact(function.params.len())
            .map_err(|_| TypeError::Allocation)?;
        for (name, ty) in function.params.iter() {
            parameters.push(NamedParameterType {
                name: copied(name.as_str())?,
                value: self.value(types, *ty, 1)?,
            });
        }
        let result = function
            .result
            .map(|ty| self.value(types, ty, 1))
            .transpose()?;
        Ok(FunctionType {
            effect: if function.async_ {
                FunctionEffect::Async
            } else {
                FunctionEffect::Sync
            },
            parameters,
            result,
        })
    }

    fn value(
        &mut self,
        types: &Types,
        value: ComponentValType,
        depth: u32,
    ) -> Result<ValueType, TypeError> {
        self.materialize()?;
        self.enter(value, depth)?;
        match value {
            ComponentValType::Primitive(primitive) => primitive_type(primitive),
            ComponentValType::Type(id) => match &types[id] {
                ComponentDefinedType::Primitive(primitive) => primitive_type(*primitive),
                ComponentDefinedType::Record(record) => {
                    let mut fields = Vec::new();
                    fields
                        .try_reserve_exact(record.fields.len())
                        .map_err(|_| TypeError::Allocation)?;
                    for field in record.fields.values() {
                        fields.push(self.value(types, *field, depth + 1)?);
                    }
                    Ok(ValueType::Record(fields))
                }
                ComponentDefinedType::Variant(variant) => {
                    let mut cases = Vec::new();
                    cases
                        .try_reserve_exact(variant.cases.len())
                        .map_err(|_| TypeError::Allocation)?;
                    for case in variant.cases.values() {
                        cases.push(
                            case.ty
                                .map(|ty| self.value(types, ty, depth + 1))
                                .transpose()?,
                        );
                    }
                    Ok(ValueType::Variant(cases))
                }
                ComponentDefinedType::List { element, .. } => Ok(ValueType::List(try_box(
                    self.value(types, *element, depth + 1)?,
                )?)),
                ComponentDefinedType::Tuple(tuple) => {
                    let mut fields = Vec::new();
                    fields
                        .try_reserve_exact(tuple.types.len())
                        .map_err(|_| TypeError::Allocation)?;
                    for field in tuple.types.iter() {
                        fields.push(self.value(types, *field, depth + 1)?);
                    }
                    Ok(ValueType::Tuple(fields))
                }
                ComponentDefinedType::Flags(names) => Ok(ValueType::Flags(
                    u32::try_from(names.len()).map_err(|_| TypeError::DefinitionLimit)?,
                )),
                ComponentDefinedType::Enum(names) => Ok(ValueType::Enum(
                    u32::try_from(names.len()).map_err(|_| TypeError::DefinitionLimit)?,
                )),
                ComponentDefinedType::Option { ty, .. } => Ok(ValueType::Option(try_box(
                    self.value(types, *ty, depth + 1)?,
                )?)),
                ComponentDefinedType::Result { ok, err, .. } => Ok(ValueType::Result {
                    ok: ok
                        .map(|ty| self.value(types, ty, depth + 1).and_then(try_box))
                        .transpose()?,
                    error: err
                        .map(|ty| self.value(types, ty, depth + 1).and_then(try_box))
                        .transpose()?,
                }),
                ComponentDefinedType::Own(resource) => Ok(ValueType::Resource {
                    resource_type: self.resource(*resource)?,
                    ownership: ResourceOwnership::Own,
                }),
                ComponentDefinedType::Borrow(resource) => Ok(ValueType::Resource {
                    resource_type: self.resource(*resource)?,
                    ownership: ResourceOwnership::Borrow,
                }),
                ComponentDefinedType::Future { ty, .. } => {
                    let payload = ty
                        .map(|ty| self.value(types, ty, depth + 1).and_then(try_box))
                        .transpose()?;
                    if payload.as_deref().is_some_and(contains_borrow) {
                        return Err(TypeError::Unsupported);
                    }
                    Ok(ValueType::Future {
                        type_id: self.async_value(types, id, AsyncValueKind::Future)?,
                        payload,
                    })
                }
                ComponentDefinedType::Stream { ty, .. } => {
                    let element = ty
                        .map(|ty| self.value(types, ty, depth + 1).and_then(try_box))
                        .transpose()?;
                    if element.as_deref().is_some_and(contains_borrow) {
                        return Err(TypeError::Unsupported);
                    }
                    Ok(ValueType::Stream {
                        type_id: self.async_value(types, id, AsyncValueKind::Stream)?,
                        element,
                    })
                }
                ComponentDefinedType::Map { .. } | ComponentDefinedType::FixedLengthList { .. } => {
                    Err(TypeError::Unsupported)
                }
            },
        }
    }

    fn async_value(
        &mut self,
        types: &Types,
        value: ComponentDefinedTypeId,
        kind: AsyncValueKind,
    ) -> Result<AsyncValueTypeId, TypeError> {
        // `value()` calls this only after the candidate and all of its payload
        // nodes have been materialized under `materialized_nodes`. Every saved
        // representative passed through the same path, so the validator's
        // structural traversal cannot bypass the owned-tree budget.
        if let Some(index) = self.async_values.iter().position(|candidate| {
            candidate.kind == kind && component_values_are_equivalent(types, candidate.value, value)
        }) {
            return AsyncValueTypeId::new(index as u32 + 1).ok_or(TypeError::DefinitionLimit);
        }
        let total_limit = PROFILE_1_LIMITS
            .max_future_types
            .checked_add(PROFILE_1_LIMITS.max_stream_types)
            .ok_or(TypeError::DefinitionLimit)?;
        if self.async_values.len() >= total_limit as usize {
            return Err(TypeError::DefinitionLimit);
        }
        let (kind_count, kind_limit) = match kind {
            AsyncValueKind::Future => (self.future_values, PROFILE_1_LIMITS.max_future_types),
            AsyncValueKind::Stream => (self.stream_values, PROFILE_1_LIMITS.max_stream_types),
        };
        let kind_count = kind_count
            .checked_add(1)
            .ok_or(TypeError::DefinitionLimit)?;
        if kind_count > kind_limit {
            return Err(TypeError::DefinitionLimit);
        }
        self.async_values
            .try_reserve(1)
            .map_err(|_| TypeError::Allocation)?;
        self.async_values
            .push(AsyncValueRepresentative { kind, value });
        match kind {
            AsyncValueKind::Future => self.future_values = kind_count,
            AsyncValueKind::Stream => self.stream_values = kind_count,
        }
        AsyncValueTypeId::new(self.async_values.len() as u32).ok_or(TypeError::DefinitionLimit)
    }

    fn resource(&mut self, resource: AliasableResourceId) -> Result<ResourceTypeId, TypeError> {
        if let Some(index) = self
            .resources
            .iter()
            .position(|candidate| *candidate == resource)
        {
            return Ok(ResourceTypeId(index as u32 + 1));
        }
        if self.resources.len() >= PROFILE_1_LIMITS.max_resources as usize {
            return Err(TypeError::DefinitionLimit);
        }
        self.resources
            .try_reserve(1)
            .map_err(|_| TypeError::Allocation)?;
        self.resources.push(resource);
        Ok(ResourceTypeId(self.resources.len() as u32))
    }

    fn enter(&mut self, value: ComponentValType, depth: u32) -> Result<(), TypeError> {
        if depth > PROFILE_1_LIMITS.max_canonical_nesting {
            return Err(TypeError::NestingLimit);
        }
        let value = ComponentValueKey::from(value);
        if self.accounted_values.contains(&value) {
            return Ok(());
        }
        let nodes = self
            .nodes
            .checked_add(1)
            .ok_or(TypeError::DefinitionLimit)?;
        if nodes > PROFILE_1_LIMITS.max_component_definitions {
            return Err(TypeError::DefinitionLimit);
        }
        self.accounted_values
            .try_reserve(1)
            .map_err(|_| TypeError::Allocation)?;
        self.accounted_values.push(value);
        self.nodes = nodes;
        Ok(())
    }

    fn materialize(&mut self) -> Result<(), TypeError> {
        let nodes = self
            .materialized_nodes
            .checked_add(1)
            .ok_or(TypeError::DefinitionLimit)?;
        if nodes > PROFILE_1_LIMITS.max_canonical_values {
            return Err(TypeError::DefinitionLimit);
        }
        self.materialized_nodes = nodes;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AsyncValueKind {
    Future,
    Stream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AsyncValueRepresentative {
    kind: AsyncValueKind,
    value: ComponentDefinedTypeId,
}

fn component_values_are_equivalent(
    types: &Types,
    left: ComponentDefinedTypeId,
    right: ComponentDefinedTypeId,
) -> bool {
    let left = ComponentEntityType::Value(ComponentValType::Type(left));
    let right = ComponentEntityType::Value(ComponentValType::Type(right));
    let types = types.as_ref();
    ComponentEntityType::is_subtype_of(&left, types, &right, types)
        && ComponentEntityType::is_subtype_of(&right, types, &left, types)
}

fn primitive_type(primitive: PrimitiveValType) -> Result<ValueType, TypeError> {
    Ok(match primitive {
        PrimitiveValType::Bool => ValueType::Bool,
        PrimitiveValType::S8 => ValueType::S8,
        PrimitiveValType::U8 => ValueType::U8,
        PrimitiveValType::S16 => ValueType::S16,
        PrimitiveValType::U16 => ValueType::U16,
        PrimitiveValType::S32 => ValueType::S32,
        PrimitiveValType::U32 => ValueType::U32,
        PrimitiveValType::S64 => ValueType::S64,
        PrimitiveValType::U64 => ValueType::U64,
        PrimitiveValType::Char => ValueType::Char,
        PrimitiveValType::String => ValueType::String,
        PrimitiveValType::F32 | PrimitiveValType::F64 | PrimitiveValType::ErrorContext => {
            return Err(TypeError::Unsupported);
        }
    })
}

fn contains_borrow(value: &ValueType) -> bool {
    match value {
        ValueType::Resource {
            ownership: ResourceOwnership::Borrow,
            ..
        } => true,
        ValueType::List(value) | ValueType::Option(value) => contains_borrow(value),
        ValueType::Tuple(values) | ValueType::Record(values) => values.iter().any(contains_borrow),
        ValueType::Result { ok, error } => {
            ok.as_deref().is_some_and(contains_borrow)
                || error.as_deref().is_some_and(contains_borrow)
        }
        ValueType::Variant(cases) => cases.iter().flatten().any(contains_borrow),
        ValueType::Stream { element, .. } => element.as_deref().is_some_and(contains_borrow),
        ValueType::Future { payload, .. } => payload.as_deref().is_some_and(contains_borrow),
        _ => false,
    }
}

fn try_box(value: ValueType) -> Result<Box<ValueType>, TypeError> {
    let layout = Layout::new::<ValueType>();
    // SAFETY: `alloc` receives the non-zero layout for one `ValueType`; a non-null
    // result is aligned and initialized exactly once before becoming a Box.
    let pointer = unsafe { alloc(layout) };
    let pointer = NonNull::<ValueType>::new(pointer.cast()).ok_or(TypeError::Allocation)?;
    // SAFETY: `pointer` is fresh storage for one `ValueType` and ownership is
    // transferred immediately to `Box::from_raw` after initialization.
    unsafe {
        pointer.as_ptr().write(value);
        Ok(Box::from_raw(pointer.as_ptr()))
    }
}

fn copied(value: &str) -> Result<String, TypeError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| TypeError::Allocation)?;
    result.push_str(value);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    use core::fmt::Write as _;
    use wasm_encoder::{CanonicalFunctionSection, Component, ComponentTypeSection};
    use wasmparser::{
        component_types::{ComponentAnyTypeId, ComponentEntityType},
        Validator, WasmFeatures,
    };

    #[test]
    fn async_function_effect_and_endpoint_type_identity_survive_normalization() {
        let bytes = wat::parse_str(
            r#"(component
                  (type $bytes (stream u8))
                  (type $done (future string))
                  (type $run
                    (func async
                      (param "first" $bytes)
                      (param "again" $bytes)
                      (param "done" $done)))
                  (import "run" (func $run-import (type $run))))"#,
        )
        .unwrap();
        let types = Validator::new_with_features(WasmFeatures::all())
            .validate_all(&bytes)
            .unwrap();
        let item = types.component_item_for_import("run").unwrap();
        let ComponentEntityType::Func(function) = item.ty else {
            panic!("run import is a function")
        };

        let normalized = TypeBuilder::default().function(&types, function).unwrap();
        assert_eq!(normalized.effect, FunctionEffect::Async);
        assert_eq!(normalized.parameters.len(), 3);

        let ValueType::Stream {
            type_id: first_id,
            element: Some(first_element),
        } = &normalized.parameters[0].value
        else {
            panic!("first parameter is a typed stream")
        };
        assert_eq!(first_element.as_ref(), &ValueType::U8);
        let ValueType::Stream {
            type_id: again_id,
            element: Some(again_element),
        } = &normalized.parameters[1].value
        else {
            panic!("second parameter is the same typed stream")
        };
        assert_eq!(first_id, again_id);
        assert_eq!(again_element.as_ref(), &ValueType::U8);

        let ValueType::Future {
            type_id: future_id,
            payload: Some(payload),
        } = &normalized.parameters[2].value
        else {
            panic!("third parameter is a typed future")
        };
        assert_eq!(payload.as_ref(), &ValueType::String);
        assert_ne!(first_id, future_id);

        let cloned = try_clone_function_type(&normalized).unwrap();
        assert_eq!(cloned, normalized);
    }

    #[test]
    fn async_payload_borrow_guard_is_recursive() {
        let value = ValueType::Record(vec![ValueType::Option(
            try_box(ValueType::Resource {
                resource_type: ResourceTypeId(1),
                ownership: ResourceOwnership::Borrow,
            })
            .unwrap(),
        )]);
        assert!(contains_borrow(&value));
        assert!(!contains_borrow(&ValueType::Resource {
            resource_type: ResourceTypeId(1),
            ownership: ResourceOwnership::Own,
        }));
    }

    #[test]
    fn repeated_component_value_reuses_graph_budget_and_async_identity() {
        let mut component_types = ComponentTypeSection::new();
        component_types
            .defined_type()
            .stream(Some(wasm_encoder::PrimitiveValType::U8.into()));
        let mut component = Component::new();
        component.section(&component_types);
        let types = Validator::new_with_features(WasmFeatures::all())
            .validate_all(&component.finish())
            .unwrap();
        let stream = types.component_defined_type_at(0);
        let mut builder = TypeBuilder::default();
        let mut identity = None;

        for _ in 0..PROFILE_1_LIMITS.max_component_definitions {
            let ValueType::Stream {
                type_id,
                element: Some(element),
            } = builder.defined_value(&types, stream).unwrap()
            else {
                panic!("defined type is stream<u8>")
            };
            assert_eq!(element.as_ref(), &ValueType::U8);
            assert_eq!(*identity.get_or_insert(type_id), type_id);
        }

        assert_eq!(builder.nodes, 2);
        assert_eq!(
            builder.materialized_nodes,
            PROFILE_1_LIMITS.max_component_definitions * 2
        );
        assert_eq!(builder.accounted_values.len(), 2);
        assert_eq!(builder.async_values.len(), 1);
        assert_eq!(builder.async_values[0].value, stream);
        assert_eq!(builder.async_values[0].kind, AsyncValueKind::Stream);
    }

    #[test]
    fn repeated_dag_materialization_has_an_independent_total_budget() {
        let mut levels = 1u32;
        let mut expanded_nodes = 2u32;
        while expanded_nodes <= PROFILE_1_LIMITS.max_canonical_values {
            expanded_nodes = expanded_nodes
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .unwrap();
            levels += 1;
        }
        assert!(levels + 1 <= PROFILE_1_LIMITS.max_canonical_nesting);

        let mut component_types = ComponentTypeSection::new();
        component_types
            .defined_type()
            .list(wasm_encoder::PrimitiveValType::U8);
        for index in 1..levels {
            let child = wasm_encoder::ComponentValType::Type(index - 1);
            component_types.defined_type().tuple([child, child]);
        }
        let mut component = Component::new();
        component.section(&component_types);
        let types = Validator::new_with_features(WasmFeatures::all())
            .validate_all(&component.finish())
            .unwrap();
        let mut builder = TypeBuilder::default();

        assert!(matches!(
            builder.defined_value(&types, types.component_defined_type_at(levels - 1)),
            Err(TypeError::DefinitionLimit)
        ));
        assert_eq!(
            builder.materialized_nodes,
            PROFILE_1_LIMITS.max_canonical_values
        );
        assert_eq!(builder.nodes, levels + 1);
        assert_eq!(builder.accounted_values.len(), builder.nodes as usize);
    }

    #[test]
    fn eq_aliases_reuse_one_structural_async_identity() {
        fn assert_aliases_reuse(kind: &str, limit: u32) {
            let mut source = format!("(component (type $private ({kind} u8))");
            for index in 0..=limit {
                write!(source, "(import \"{kind}-{index}\" (type (eq $private)))").unwrap();
            }
            source.push(')');
            let bytes = wat::parse_str(&source).unwrap();
            let types = Validator::new_with_features(WasmFeatures::all())
                .validate_all(&bytes)
                .unwrap();
            let mut builder = TypeBuilder::default();
            let mut identity = None;

            for index in 0..=limit {
                let name = format!("{kind}-{index}");
                let item = types.component_item_for_import(&name).unwrap();
                let ComponentEntityType::Type {
                    created: ComponentAnyTypeId::Defined(created),
                    ..
                } = item.ty
                else {
                    panic!("eq import creates a defined value type")
                };
                let type_id = match (kind, builder.defined_value(&types, created).unwrap()) {
                    ("future", ValueType::Future { type_id, .. })
                    | ("stream", ValueType::Stream { type_id, .. }) => type_id,
                    _ => panic!("eq alias retains its async kind"),
                };
                assert_eq!(*identity.get_or_insert(type_id), type_id);
            }

            assert_eq!(builder.async_values.len(), 1);
            match kind {
                "future" => {
                    assert_eq!(builder.future_values, 1);
                    assert_eq!(builder.stream_values, 0);
                }
                "stream" => {
                    assert_eq!(builder.future_values, 0);
                    assert_eq!(builder.stream_values, 1);
                }
                _ => unreachable!(),
            }
        }

        assert_aliases_reuse("future", PROFILE_1_LIMITS.max_future_types);
        assert_aliases_reuse("stream", PROFILE_1_LIMITS.max_stream_types);
    }

    #[test]
    fn async_identity_is_structural_and_preserves_names_payloads_and_kind() {
        let bytes = wat::parse_str(
            r#"(component
                  (type $stream-a (stream u8))
                  (type $stream-b (stream u8))
                  (type $stream-u16 (stream u16))
                  (type $future-u8 (future u8))
                  (type $left (record (field "left" u8)))
                  (type $right (record (field "right" u8)))
                  (type $stream-left (stream $left))
                  (type $stream-right (stream $right)))"#,
        )
        .unwrap();
        let types = Validator::new_with_features(WasmFeatures::all())
            .validate_all(&bytes)
            .unwrap();
        let mut builder = TypeBuilder::default();
        let mut normalize = |index| match builder
            .defined_value(&types, types.component_defined_type_at(index))
            .unwrap()
        {
            ValueType::Stream { type_id, .. } | ValueType::Future { type_id, .. } => type_id,
            _ => panic!("type is an async endpoint"),
        };

        let stream_a = normalize(0);
        assert_eq!(normalize(1), stream_a);
        let stream_u16 = normalize(2);
        let future_u8 = normalize(3);
        let stream_left = normalize(6);
        let stream_right = normalize(7);
        assert_ne!(stream_u16, stream_a);
        assert_ne!(future_u8, stream_a);
        assert_ne!(stream_left, stream_right);
        assert_eq!(builder.stream_values, 4);
        assert_eq!(builder.future_values, 1);
    }

    #[test]
    fn structurally_unique_async_shapes_obey_the_per_kind_limit() {
        let limit = PROFILE_1_LIMITS.max_stream_types;
        let mut source = String::from("(component");
        for index in 0..=limit {
            write!(
                source,
                "(type $payload-{index} (record (field \"field-{index}\" u8)))"
            )
            .unwrap();
        }
        for index in 0..=limit {
            write!(source, "(type $stream-{index} (stream $payload-{index}))").unwrap();
        }
        source.push(')');
        let bytes = wat::parse_str(&source).unwrap();
        let types = Validator::new_with_features(WasmFeatures::all())
            .validate_all(&bytes)
            .unwrap();
        let mut builder = TypeBuilder::default();
        let first_stream = limit + 1;

        for index in 0..limit {
            builder
                .async_value(
                    &types,
                    types.component_defined_type_at(first_stream + index),
                    AsyncValueKind::Stream,
                )
                .unwrap();
        }
        assert_eq!(builder.stream_values, limit);
        assert_eq!(
            builder.async_value(
                &types,
                types.component_defined_type_at(first_stream + limit),
                AsyncValueKind::Stream,
            ),
            Err(TypeError::DefinitionLimit)
        );
        assert_eq!(builder.async_values.len(), limit as usize);
    }

    #[test]
    fn repeated_stream_canonicals_share_the_normalized_graph_budget() {
        let repeated = PROFILE_1_LIMITS.max_component_definitions / 2 + 1;
        let mut component_types = ComponentTypeSection::new();
        component_types
            .defined_type()
            .stream(Some(wasm_encoder::PrimitiveValType::U8.into()));
        let mut canonicals = CanonicalFunctionSection::new();
        for _ in 0..repeated {
            canonicals.stream_new(0);
        }
        let mut component = Component::new();
        component.section(&component_types);
        component.section(&canonicals);
        let bytes = component.finish();

        let plan = crate::decode::inspect_component_for_profile(
            &bytes,
            vibeos_component_format::ProfileIdentity::PROFILE_1_ASYNC,
        )
        .unwrap();
        assert_eq!(plan.summary().async_abi.stream_builtins, repeated);
        assert_eq!(plan.async_canonical_plans().len(), repeated as usize);
    }

    #[test]
    fn genuinely_distinct_component_values_still_hit_the_graph_limit() {
        let mut component_types = ComponentTypeSection::new();
        for _ in 1..PROFILE_1_LIMITS.max_component_definitions {
            component_types.defined_type().enum_type(["case"]);
        }
        component_types
            .defined_type()
            .list(wasm_encoder::PrimitiveValType::U8);
        let mut component = Component::new();
        component.section(&component_types);
        let types = Validator::new_with_features(WasmFeatures::all())
            .validate_all(&component.finish())
            .unwrap();
        let mut builder = TypeBuilder::default();

        for index in 0..PROFILE_1_LIMITS.max_component_definitions - 1 {
            assert_eq!(
                builder
                    .defined_value(&types, types.component_defined_type_at(index))
                    .unwrap(),
                ValueType::Enum(1)
            );
        }
        assert_eq!(
            builder.nodes,
            PROFILE_1_LIMITS.max_component_definitions - 1
        );
        assert_eq!(builder.accounted_values.len(), builder.nodes as usize);
        assert_eq!(
            builder.defined_value(
                &types,
                types.component_defined_type_at(PROFILE_1_LIMITS.max_component_definitions - 1),
            ),
            Err(TypeError::DefinitionLimit)
        );
        assert_eq!(builder.nodes, PROFILE_1_LIMITS.max_component_definitions);
        assert_eq!(builder.accounted_values.len(), builder.nodes as usize);
    }
}
