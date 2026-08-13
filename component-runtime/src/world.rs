//! Exact WIT-world resolution and normalized component type matching.

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use vibeos_component_format::PROFILE_1_LIMITS;
use wasmparser::component_types::{
    ComponentAnyTypeId, ComponentDefinedType, ComponentDefinedTypeId, ComponentEntityType,
    ComponentValType, ResourceId,
};
use wasmparser::types::Types;
use wasmparser::PrimitiveValType;
use wit_parser::{Handle, Resolve, Type, TypeDefKind, TypeId, WorldItem};

#[derive(Debug, PartialEq, Eq)]
pub struct NamedValueShape {
    pub name: String,
    pub value: ValueShape,
}

#[derive(Debug, PartialEq, Eq)]
pub struct NamedCaseShape {
    pub name: String,
    pub value: Option<ValueShape>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValueShape {
    Bool,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    Char,
    String,
    List(Box<ValueShape>),
    Tuple(Vec<ValueShape>),
    Record(Vec<NamedValueShape>),
    Flags(Vec<String>),
    Enum(Vec<String>),
    Option(Box<ValueShape>),
    Result {
        ok: Option<Box<ValueShape>>,
        error: Option<Box<ValueShape>>,
    },
    Variant(Vec<NamedCaseShape>),
    Own(String),
    Borrow(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct FunctionShape {
    pub parameters: Vec<NamedValueShape>,
    pub result: Option<ValueShape>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TypeShape {
    Resource,
    Value(ValueShape),
}

#[derive(Debug, PartialEq, Eq)]
pub enum EntityShape {
    Function(FunctionShape),
    Interface(Vec<NamedEntityShape>),
    Type(TypeShape),
}

#[derive(Debug, PartialEq, Eq)]
pub struct NamedEntityShape {
    pub name: String,
    pub entity: EntityShape,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum WorldError {
    SourceTooLarge = 1,
    InvalidWit = 2,
    MissingWorld = 3,
    VersionMismatch = 4,
    UnsupportedType = 5,
    TypeGraphLimit = 6,
    Allocation = 7,
    MissingImport = 8,
    UnexpectedImport = 9,
    MissingExport = 10,
    UnexpectedExport = 11,
    TypeMismatch = 12,
}

impl WorldError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct WorldContract {
    pub identity: String,
    pub imports: Vec<NamedEntityShape>,
    pub exports: Vec<NamedEntityShape>,
}

impl WorldContract {
    /// Resolves one fully-qualified world such as
    /// `vibe:fixture/typed-filter@1.0.0`.
    pub fn parse(source: &str, exact_world: &str) -> Result<Self, WorldError> {
        if source.len() > PROFILE_1_LIMITS.max_component_bytes || exact_world.len() > 256 {
            return Err(WorldError::SourceTooLarge);
        }
        if !exact_world.contains('/') || !exact_world.contains('@') {
            return Err(WorldError::VersionMismatch);
        }
        let mut resolve = Resolve::default();
        let package = resolve
            .push_source("profile.wit", source)
            .map_err(|_| WorldError::InvalidWit)?;
        let (package_name, world_name) = exact_world
            .rsplit_once('/')
            .ok_or(WorldError::VersionMismatch)?;
        let (_, version) = world_name
            .rsplit_once('@')
            .ok_or(WorldError::VersionMismatch)?;
        let mut expected_package = copied(package_name)?;
        expected_package
            .try_reserve(version.len() + 1)
            .map_err(|_| WorldError::Allocation)?;
        expected_package.push('@');
        expected_package.push_str(version);
        if resolve.packages[package].name.to_string() != expected_package {
            return Err(WorldError::VersionMismatch);
        }
        let world_id = resolve
            .select_world(&[package], Some(exact_world))
            .map_err(|_| WorldError::MissingWorld)?;
        let world = &resolve.worlds[world_id];
        let owner = world.package.ok_or(WorldError::VersionMismatch)?;
        let identity = resolve.id_of_name(owner, &world.name);
        if identity != exact_world {
            return Err(WorldError::VersionMismatch);
        }
        if world.imports.len() > PROFILE_1_LIMITS.max_imports as usize
            || world.exports.len() > PROFILE_1_LIMITS.max_exports as usize
        {
            return Err(WorldError::TypeGraphLimit);
        }
        let mut budget = ShapeBudget::default();
        let imports = normalize_wit_entities(&resolve, world.imports.iter(), &mut budget)?;
        let exports = normalize_wit_entities(&resolve, world.exports.iter(), &mut budget)?;
        Ok(Self {
            identity,
            imports,
            exports,
        })
    }

    pub fn check_component(
        &self,
        imports: &[NamedEntityShape],
        exports: &[NamedEntityShape],
    ) -> Result<(), WorldError> {
        check_side(&self.imports, imports, true)?;
        check_side(&self.exports, exports, false)
    }
}

fn check_side(
    expected: &[NamedEntityShape],
    actual: &[NamedEntityShape],
    imports: bool,
) -> Result<(), WorldError> {
    for expected_item in expected {
        let actual_item = actual
            .iter()
            .find(|item| item.name == expected_item.name)
            .ok_or(if imports {
                WorldError::MissingImport
            } else {
                WorldError::MissingExport
            })?;
        if actual_item.entity != expected_item.entity {
            return Err(WorldError::TypeMismatch);
        }
    }
    if actual.len() != expected.len() {
        return Err(if imports {
            WorldError::UnexpectedImport
        } else {
            WorldError::UnexpectedExport
        });
    }
    Ok(())
}

#[derive(Default)]
struct ShapeBudget {
    nodes: u32,
}

impl ShapeBudget {
    fn enter(&mut self, depth: u32) -> Result<(), WorldError> {
        if depth > PROFILE_1_LIMITS.max_canonical_nesting {
            return Err(WorldError::TypeGraphLimit);
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(WorldError::TypeGraphLimit)?;
        if self.nodes > PROFILE_1_LIMITS.max_component_definitions {
            return Err(WorldError::TypeGraphLimit);
        }
        Ok(())
    }
}

fn copied(value: &str) -> Result<String, WorldError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| WorldError::Allocation)?;
    result.push_str(value);
    Ok(result)
}

fn push_named_value(
    target: &mut Vec<NamedValueShape>,
    name: &str,
    value: ValueShape,
) -> Result<(), WorldError> {
    target.try_reserve(1).map_err(|_| WorldError::Allocation)?;
    target.push(NamedValueShape {
        name: copied(name)?,
        value,
    });
    Ok(())
}

fn push_named_entity(
    target: &mut Vec<NamedEntityShape>,
    name: &str,
    entity: EntityShape,
) -> Result<(), WorldError> {
    target.try_reserve(1).map_err(|_| WorldError::Allocation)?;
    target.push(NamedEntityShape {
        name: copied(name)?,
        entity,
    });
    Ok(())
}

fn normalize_wit_entities<'a>(
    resolve: &Resolve,
    items: impl Iterator<Item = (&'a wit_parser::WorldKey, &'a WorldItem)>,
    budget: &mut ShapeBudget,
) -> Result<Vec<NamedEntityShape>, WorldError> {
    let mut result = Vec::new();
    for (key, item) in items {
        let name = resolve.name_world_key(key);
        let entity = match item {
            WorldItem::Interface { id, .. } => {
                EntityShape::Interface(normalize_wit_interface(resolve, *id, budget, 1)?)
            }
            WorldItem::Function(function) => {
                EntityShape::Function(normalize_wit_function(resolve, function, &[], budget, 1)?)
            }
            WorldItem::Type { id, .. } => {
                EntityShape::Type(normalize_wit_type_entity(resolve, *id, &[], budget, 1)?)
            }
        };
        push_named_entity(&mut result, &name, entity)?;
    }
    Ok(result)
}

fn normalize_wit_interface(
    resolve: &Resolve,
    interface_id: wit_parser::InterfaceId,
    budget: &mut ShapeBudget,
    depth: u32,
) -> Result<Vec<NamedEntityShape>, WorldError> {
    budget.enter(depth)?;
    let interface = &resolve.interfaces[interface_id];
    let mut resources = Vec::new();
    for (name, id) in &interface.types {
        if let Some(resource) = resolve_wit_resource_alias(resolve, *id)? {
            resources
                .try_reserve(1)
                .map_err(|_| WorldError::Allocation)?;
            resources.push((resource, copied(name)?));
        }
    }
    let total = interface
        .types
        .len()
        .checked_add(interface.functions.len())
        .ok_or(WorldError::TypeGraphLimit)?;
    if total > PROFILE_1_LIMITS.max_component_definitions as usize {
        return Err(WorldError::TypeGraphLimit);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(total)
        .map_err(|_| WorldError::Allocation)?;
    for (name, id) in &interface.types {
        let entity = normalize_wit_type_entity(resolve, *id, &resources, budget, depth + 1)?;
        push_named_entity(&mut result, name, EntityShape::Type(entity))?;
    }
    for (name, function) in &interface.functions {
        let shape = normalize_wit_function(resolve, function, &resources, budget, depth + 1)?;
        push_named_entity(&mut result, name, EntityShape::Function(shape))?;
    }
    Ok(result)
}

fn normalize_wit_function(
    resolve: &Resolve,
    function: &wit_parser::Function,
    resources: &[(TypeId, String)],
    budget: &mut ShapeBudget,
    depth: u32,
) -> Result<FunctionShape, WorldError> {
    budget.enter(depth)?;
    if function.kind.is_async()
        || function.params.len() > PROFILE_1_LIMITS.max_params_per_function as usize
    {
        return Err(WorldError::UnsupportedType);
    }
    let mut parameters = Vec::new();
    parameters
        .try_reserve_exact(function.params.len())
        .map_err(|_| WorldError::Allocation)?;
    for parameter in &function.params {
        let value = normalize_wit_value(resolve, parameter.ty, resources, budget, depth + 1)?;
        push_named_value(&mut parameters, &parameter.name, value)?;
    }
    let result = function
        .result
        .map(|ty| normalize_wit_value(resolve, ty, resources, budget, depth + 1))
        .transpose()?;
    Ok(FunctionShape { parameters, result })
}

fn normalize_wit_type_entity(
    resolve: &Resolve,
    id: TypeId,
    resources: &[(TypeId, String)],
    budget: &mut ShapeBudget,
    depth: u32,
) -> Result<TypeShape, WorldError> {
    if resolve_wit_resource_alias(resolve, id)?.is_some() {
        budget.enter(depth)?;
        Ok(TypeShape::Resource)
    } else {
        Ok(TypeShape::Value(normalize_wit_type_id(
            resolve, id, resources, budget, depth,
        )?))
    }
}

fn resolve_wit_resource_alias(
    resolve: &Resolve,
    mut id: TypeId,
) -> Result<Option<TypeId>, WorldError> {
    for _ in 0..PROFILE_1_LIMITS.max_canonical_nesting {
        match resolve.types[id].kind {
            TypeDefKind::Resource => return Ok(Some(id)),
            TypeDefKind::Type(Type::Id(next)) => id = next,
            _ => return Ok(None),
        }
    }
    Err(WorldError::TypeGraphLimit)
}

fn normalize_wit_value(
    resolve: &Resolve,
    ty: Type,
    resources: &[(TypeId, String)],
    budget: &mut ShapeBudget,
    depth: u32,
) -> Result<ValueShape, WorldError> {
    budget.enter(depth)?;
    match ty {
        Type::Bool => Ok(ValueShape::Bool),
        Type::U8 => Ok(ValueShape::U8),
        Type::U16 => Ok(ValueShape::U16),
        Type::U32 => Ok(ValueShape::U32),
        Type::U64 => Ok(ValueShape::U64),
        Type::S8 => Ok(ValueShape::S8),
        Type::S16 => Ok(ValueShape::S16),
        Type::S32 => Ok(ValueShape::S32),
        Type::S64 => Ok(ValueShape::S64),
        Type::Char => Ok(ValueShape::Char),
        Type::String => Ok(ValueShape::String),
        Type::F32 | Type::F64 | Type::ErrorContext => Err(WorldError::UnsupportedType),
        Type::Id(id) => normalize_wit_type_id(resolve, id, resources, budget, depth + 1),
    }
}

fn normalize_wit_type_id(
    resolve: &Resolve,
    id: TypeId,
    resources: &[(TypeId, String)],
    budget: &mut ShapeBudget,
    depth: u32,
) -> Result<ValueShape, WorldError> {
    budget.enter(depth)?;
    match &resolve.types[id].kind {
        TypeDefKind::Record(record) => {
            let mut fields = Vec::new();
            fields
                .try_reserve_exact(record.fields.len())
                .map_err(|_| WorldError::Allocation)?;
            for field in &record.fields {
                let value = normalize_wit_value(resolve, field.ty, resources, budget, depth + 1)?;
                push_named_value(&mut fields, &field.name, value)?;
            }
            Ok(ValueShape::Record(fields))
        }
        TypeDefKind::Handle(handle) => {
            let (owned, resource) = match handle {
                Handle::Own(id) => (true, *id),
                Handle::Borrow(id) => (false, *id),
            };
            // `use interface.{resource}` introduces a type alias. Handles may
            // retain that alias id while the interface resource table stores
            // the underlying resource identity, so compare canonical roots.
            let resource =
                resolve_wit_resource_alias(resolve, resource)?.ok_or(WorldError::TypeMismatch)?;
            let name = resources
                .iter()
                .find_map(|(id, name)| (*id == resource).then_some(name))
                .ok_or(WorldError::TypeMismatch)?;
            Ok(if owned {
                ValueShape::Own(copied(name)?)
            } else {
                ValueShape::Borrow(copied(name)?)
            })
        }
        TypeDefKind::Flags(flags) => {
            let mut names = Vec::new();
            names
                .try_reserve_exact(flags.flags.len())
                .map_err(|_| WorldError::Allocation)?;
            for flag in &flags.flags {
                names.push(copied(&flag.name)?);
            }
            Ok(ValueShape::Flags(names))
        }
        TypeDefKind::Tuple(tuple) => {
            let mut types = Vec::new();
            types
                .try_reserve_exact(tuple.types.len())
                .map_err(|_| WorldError::Allocation)?;
            for ty in &tuple.types {
                types.push(normalize_wit_value(
                    resolve,
                    *ty,
                    resources,
                    budget,
                    depth + 1,
                )?);
            }
            Ok(ValueShape::Tuple(types))
        }
        TypeDefKind::Variant(variant) => {
            let mut cases = Vec::new();
            cases
                .try_reserve_exact(variant.cases.len())
                .map_err(|_| WorldError::Allocation)?;
            for case in &variant.cases {
                cases.push(NamedCaseShape {
                    name: copied(&case.name)?,
                    value: case
                        .ty
                        .map(|ty| normalize_wit_value(resolve, ty, resources, budget, depth + 1))
                        .transpose()?,
                });
            }
            Ok(ValueShape::Variant(cases))
        }
        TypeDefKind::Enum(enumeration) => {
            let mut names = Vec::new();
            names
                .try_reserve_exact(enumeration.cases.len())
                .map_err(|_| WorldError::Allocation)?;
            for case in &enumeration.cases {
                names.push(copied(&case.name)?);
            }
            Ok(ValueShape::Enum(names))
        }
        TypeDefKind::Option(ty) => Ok(ValueShape::Option(Box::new(normalize_wit_value(
            resolve,
            *ty,
            resources,
            budget,
            depth + 1,
        )?))),
        TypeDefKind::Result(result) => Ok(ValueShape::Result {
            ok: result
                .ok
                .map(|ty| normalize_wit_value(resolve, ty, resources, budget, depth + 1))
                .transpose()?
                .map(Box::new),
            error: result
                .err
                .map(|ty| normalize_wit_value(resolve, ty, resources, budget, depth + 1))
                .transpose()?
                .map(Box::new),
        }),
        TypeDefKind::List(ty) => Ok(ValueShape::List(Box::new(normalize_wit_value(
            resolve,
            *ty,
            resources,
            budget,
            depth + 1,
        )?))),
        TypeDefKind::Type(ty) => normalize_wit_value(resolve, *ty, resources, budget, depth + 1),
        TypeDefKind::Resource
        | TypeDefKind::Map(_, _)
        | TypeDefKind::FixedLengthList(_, _)
        | TypeDefKind::Future(_)
        | TypeDefKind::Stream(_)
        | TypeDefKind::Unknown => Err(WorldError::UnsupportedType),
    }
}

pub(crate) fn normalize_component_entities(
    types: &Types,
    names: &[String],
    imports: bool,
) -> Result<Vec<NamedEntityShape>, WorldError> {
    let mut budget = ShapeBudget::default();
    let mut resource_names = Vec::new();
    for name in names {
        let item = if imports {
            types.component_item_for_import(name)
        } else {
            types.component_item_for_export(name)
        }
        .ok_or(WorldError::TypeMismatch)?;
        if let ComponentEntityType::Type {
            referenced: ComponentAnyTypeId::Resource(resource),
            ..
        } = item.ty
        {
            resource_names
                .try_reserve(1)
                .map_err(|_| WorldError::Allocation)?;
            resource_names.push((resource.resource(), copied(name)?));
        }
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(names.len())
        .map_err(|_| WorldError::Allocation)?;
    for name in names {
        let item = if imports {
            types.component_item_for_import(name)
        } else {
            types.component_item_for_export(name)
        }
        .ok_or(WorldError::TypeMismatch)?;
        let entity = normalize_component_entity(types, item.ty, &resource_names, &mut budget, 1)?;
        push_named_entity(&mut result, name, entity)?;
    }
    Ok(result)
}

fn normalize_component_entity(
    types: &Types,
    entity: ComponentEntityType,
    outer_resources: &[(ResourceId, String)],
    budget: &mut ShapeBudget,
    depth: u32,
) -> Result<EntityShape, WorldError> {
    budget.enter(depth)?;
    match entity {
        ComponentEntityType::Func(id) => {
            let function = &types[id];
            if function.async_
                || function.params.len() > PROFILE_1_LIMITS.max_params_per_function as usize
            {
                return Err(WorldError::UnsupportedType);
            }
            let mut parameters = Vec::new();
            parameters
                .try_reserve_exact(function.params.len())
                .map_err(|_| WorldError::Allocation)?;
            for (name, ty) in function.params.iter() {
                let value =
                    normalize_component_value(types, *ty, outer_resources, budget, depth + 1)?;
                push_named_value(&mut parameters, name.as_str(), value)?;
            }
            let result = function
                .result
                .map(|ty| normalize_component_value(types, ty, outer_resources, budget, depth + 1))
                .transpose()?;
            Ok(EntityShape::Function(FunctionShape { parameters, result }))
        }
        ComponentEntityType::Instance(id) => {
            let instance = &types[id];
            let mut resources = Vec::new();
            resources
                .try_reserve_exact(
                    outer_resources
                        .len()
                        .checked_add(instance.exports.len())
                        .ok_or(WorldError::TypeGraphLimit)?,
                )
                .map_err(|_| WorldError::Allocation)?;
            for (resource, name) in outer_resources {
                resources.push((*resource, copied(name)?));
            }
            for (name, item) in &instance.exports {
                if let ComponentEntityType::Type {
                    referenced: ComponentAnyTypeId::Resource(resource),
                    ..
                } = item.ty
                {
                    resources.push((resource.resource(), copied(name)?));
                }
            }
            let mut exports = Vec::new();
            exports
                .try_reserve_exact(instance.exports.len())
                .map_err(|_| WorldError::Allocation)?;
            for (name, item) in &instance.exports {
                let entity =
                    normalize_component_entity(types, item.ty, &resources, budget, depth + 1)?;
                push_named_entity(&mut exports, name, entity)?;
            }
            Ok(EntityShape::Interface(exports))
        }
        ComponentEntityType::Type { referenced, .. } => match referenced {
            ComponentAnyTypeId::Resource(_) => Ok(EntityShape::Type(TypeShape::Resource)),
            ComponentAnyTypeId::Defined(id) => Ok(EntityShape::Type(TypeShape::Value(
                normalize_component_defined(types, id, outer_resources, budget, depth + 1)?,
            ))),
            _ => Err(WorldError::UnsupportedType),
        },
        ComponentEntityType::Module(_)
        | ComponentEntityType::Value(_)
        | ComponentEntityType::Component(_) => Err(WorldError::UnsupportedType),
    }
}

fn normalize_component_value(
    types: &Types,
    ty: ComponentValType,
    resources: &[(ResourceId, String)],
    budget: &mut ShapeBudget,
    depth: u32,
) -> Result<ValueShape, WorldError> {
    budget.enter(depth)?;
    match ty {
        ComponentValType::Primitive(primitive) => primitive_shape(primitive),
        ComponentValType::Type(id) => {
            normalize_component_defined(types, id, resources, budget, depth + 1)
        }
    }
}

fn primitive_shape(primitive: PrimitiveValType) -> Result<ValueShape, WorldError> {
    match primitive {
        PrimitiveValType::Bool => Ok(ValueShape::Bool),
        PrimitiveValType::U8 => Ok(ValueShape::U8),
        PrimitiveValType::U16 => Ok(ValueShape::U16),
        PrimitiveValType::U32 => Ok(ValueShape::U32),
        PrimitiveValType::U64 => Ok(ValueShape::U64),
        PrimitiveValType::S8 => Ok(ValueShape::S8),
        PrimitiveValType::S16 => Ok(ValueShape::S16),
        PrimitiveValType::S32 => Ok(ValueShape::S32),
        PrimitiveValType::S64 => Ok(ValueShape::S64),
        PrimitiveValType::Char => Ok(ValueShape::Char),
        PrimitiveValType::String => Ok(ValueShape::String),
        PrimitiveValType::F32 | PrimitiveValType::F64 | PrimitiveValType::ErrorContext => {
            Err(WorldError::UnsupportedType)
        }
    }
}

fn normalize_component_defined(
    types: &Types,
    id: ComponentDefinedTypeId,
    resources: &[(ResourceId, String)],
    budget: &mut ShapeBudget,
    depth: u32,
) -> Result<ValueShape, WorldError> {
    budget.enter(depth)?;
    match &types[id] {
        ComponentDefinedType::Primitive(primitive) => primitive_shape(*primitive),
        ComponentDefinedType::Record(record) => {
            let mut fields = Vec::new();
            fields
                .try_reserve_exact(record.fields.len())
                .map_err(|_| WorldError::Allocation)?;
            for (name, ty) in &record.fields {
                let value = normalize_component_value(types, *ty, resources, budget, depth + 1)?;
                push_named_value(&mut fields, name.as_str(), value)?;
            }
            Ok(ValueShape::Record(fields))
        }
        ComponentDefinedType::Variant(variant) => {
            let mut cases = Vec::new();
            cases
                .try_reserve_exact(variant.cases.len())
                .map_err(|_| WorldError::Allocation)?;
            for (name, case) in &variant.cases {
                cases.push(NamedCaseShape {
                    name: copied(name.as_str())?,
                    value: case
                        .ty
                        .map(|ty| {
                            normalize_component_value(types, ty, resources, budget, depth + 1)
                        })
                        .transpose()?,
                });
            }
            Ok(ValueShape::Variant(cases))
        }
        ComponentDefinedType::List { element, .. } => Ok(ValueShape::List(Box::new(
            normalize_component_value(types, *element, resources, budget, depth + 1)?,
        ))),
        ComponentDefinedType::Tuple(tuple) => {
            let mut result = Vec::new();
            result
                .try_reserve_exact(tuple.types.len())
                .map_err(|_| WorldError::Allocation)?;
            for ty in tuple.types.iter() {
                result.push(normalize_component_value(
                    types,
                    *ty,
                    resources,
                    budget,
                    depth + 1,
                )?);
            }
            Ok(ValueShape::Tuple(result))
        }
        ComponentDefinedType::Flags(flags) => {
            let mut names = Vec::new();
            names
                .try_reserve_exact(flags.len())
                .map_err(|_| WorldError::Allocation)?;
            for name in flags {
                names.push(copied(name.as_str())?);
            }
            Ok(ValueShape::Flags(names))
        }
        ComponentDefinedType::Enum(enumeration) => {
            let mut names = Vec::new();
            names
                .try_reserve_exact(enumeration.len())
                .map_err(|_| WorldError::Allocation)?;
            for name in enumeration {
                names.push(copied(name.as_str())?);
            }
            Ok(ValueShape::Enum(names))
        }
        ComponentDefinedType::Option { ty, .. } => Ok(ValueShape::Option(Box::new(
            normalize_component_value(types, *ty, resources, budget, depth + 1)?,
        ))),
        ComponentDefinedType::Result { ok, err, .. } => Ok(ValueShape::Result {
            ok: ok
                .map(|ty| normalize_component_value(types, ty, resources, budget, depth + 1))
                .transpose()?
                .map(Box::new),
            error: err
                .map(|ty| normalize_component_value(types, ty, resources, budget, depth + 1))
                .transpose()?
                .map(Box::new),
        }),
        ComponentDefinedType::Own(resource) | ComponentDefinedType::Borrow(resource) => {
            let name = resources
                .iter()
                .find_map(|(id, name)| (*id == resource.resource()).then_some(name))
                .ok_or(WorldError::TypeMismatch)?;
            Ok(if matches!(&types[id], ComponentDefinedType::Own(_)) {
                ValueShape::Own(copied(name)?)
            } else {
                ValueShape::Borrow(copied(name)?)
            })
        }
        ComponentDefinedType::Map { .. }
        | ComponentDefinedType::FixedLengthList { .. }
        | ComponentDefinedType::Future { .. }
        | ComponentDefinedType::Stream { .. } => Err(WorldError::UnsupportedType),
    }
}
