//! Fallible normalization of validated Component Model function types.

use crate::{
    resource::ResourceTypeId,
    value::{ResourceOwnership, ValueType},
};
use alloc::{string::String, vec::Vec};
use vibeos_component_format::PROFILE_1_LIMITS;
use wasmparser::{
    component_types::{
        AliasableResourceId, ComponentDefinedType, ComponentFuncTypeId, ComponentValType,
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
        ValueType::List(item) => {
            ValueType::List(alloc::boxed::Box::new(try_clone_value_type(item)?))
        }
        ValueType::Tuple(items) => ValueType::Tuple(try_clone_types(items)?),
        ValueType::Record(items) => ValueType::Record(try_clone_types(items)?),
        ValueType::Flags(count) => ValueType::Flags(*count),
        ValueType::Enum(cases) => ValueType::Enum(*cases),
        ValueType::Option(item) => {
            ValueType::Option(alloc::boxed::Box::new(try_clone_value_type(item)?))
        }
        ValueType::Result { ok, error } => ValueType::Result {
            ok: ok
                .as_deref()
                .map(try_clone_value_type)
                .transpose()?
                .map(alloc::boxed::Box::new),
            error: error
                .as_deref()
                .map(try_clone_value_type)
                .transpose()?
                .map(alloc::boxed::Box::new),
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
    nodes: u32,
}

impl TypeBuilder {
    pub(crate) fn function(
        &mut self,
        types: &Types,
        function: ComponentFuncTypeId,
    ) -> Result<FunctionType, TypeError> {
        let function = &types[function];
        if function.async_
            || function.params.len() > PROFILE_1_LIMITS.max_params_per_function as usize
        {
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
        Ok(FunctionType { parameters, result })
    }

    fn value(
        &mut self,
        types: &Types,
        value: ComponentValType,
        depth: u32,
    ) -> Result<ValueType, TypeError> {
        self.enter(depth)?;
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
                ComponentDefinedType::List { element, .. } => Ok(ValueType::List(
                    alloc::boxed::Box::new(self.value(types, *element, depth + 1)?),
                )),
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
                ComponentDefinedType::Option { ty, .. } => Ok(ValueType::Option(
                    alloc::boxed::Box::new(self.value(types, *ty, depth + 1)?),
                )),
                ComponentDefinedType::Result { ok, err, .. } => Ok(ValueType::Result {
                    ok: ok
                        .map(|ty| self.value(types, ty, depth + 1).map(alloc::boxed::Box::new))
                        .transpose()?,
                    error: err
                        .map(|ty| self.value(types, ty, depth + 1).map(alloc::boxed::Box::new))
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
                ComponentDefinedType::Map { .. }
                | ComponentDefinedType::FixedLengthList { .. }
                | ComponentDefinedType::Future { .. }
                | ComponentDefinedType::Stream { .. } => Err(TypeError::Unsupported),
            },
        }
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

    fn enter(&mut self, depth: u32) -> Result<(), TypeError> {
        if depth > PROFILE_1_LIMITS.max_canonical_nesting {
            return Err(TypeError::NestingLimit);
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(TypeError::DefinitionLimit)?;
        if self.nodes > PROFILE_1_LIMITS.max_component_definitions {
            return Err(TypeError::DefinitionLimit);
        }
        Ok(())
    }
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

fn copied(value: &str) -> Result<String, TypeError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| TypeError::Allocation)?;
    result.push_str(value);
    Ok(result)
}
