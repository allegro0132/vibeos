use std::{
    cell::Cell,
    collections::BTreeSet,
    panic::{catch_unwind, AssertUnwindSafe},
    rc::Rc,
};
use vibeos_component_format::PROFILE_1_LIMITS;
use vibeos_component_runtime::{
    resource::{ResourceError, ResourceTable, ResourceToken, ResourceTypeId},
    value::{
        try_list_value, try_string_value, validate_type, validate_value,
        validate_value_with_resources, CanonicalLayout, CanonicalValue, ResourceOwnership,
        ValueError, ValuePosition, ValueType,
    },
};

const RANDOM: ResourceTypeId = ResourceTypeId(7);
const BLOB: ResourceTypeId = ResourceTypeId(8);

#[test]
fn resource_tokens_are_table_type_and_incarnation_bound() {
    let mut first = ResourceTable::new(11, 2).unwrap();
    let mut second = ResourceTable::<u32>::new(12, 2).unwrap();
    let token = first.insert_owned(RANDOM, 41_u32).unwrap();

    assert_eq!(
        second.contains(token, RANDOM),
        Err(ResourceError::WrongInstance)
    );
    let rebound = second.token_from_guest_index(token.guest_index());
    assert_eq!(second.contains(rebound, RANDOM), Err(ResourceError::Stale));
    assert_eq!(first.contains(token, BLOB), Err(ResourceError::WrongType));

    let second_token = second.insert_owned(RANDOM, 90).unwrap();
    assert_eq!(
        first.contains(second_token, RANDOM),
        Err(ResourceError::WrongInstance)
    );
    assert_eq!(first.drop_owned(token, RANDOM), Ok(41));
    assert_eq!(first.drop_owned(token, RANDOM), Err(ResourceError::Stale));
    let reused = first.insert_owned(RANDOM, 42).unwrap();
    assert_ne!(token.guest_index(), reused.guest_index());
    assert_eq!(first.contains(token, RANDOM), Err(ResourceError::Stale));
}

#[test]
fn observed_handle_does_not_reveal_another_slot() {
    let mut table = ResourceTable::new(0xfeed_cafe_1020_3040, 2).unwrap();
    let first = table.insert_owned(RANDOM, 10_u32).unwrap();
    let second = table.insert_owned(BLOB, 20_u32).unwrap();

    // This exactly recovered every other slot under the former XOR encoding.
    let former_slot = first.guest_index() & 0xff;
    let former_generation = first.guest_index() >> 8;
    let forged_generation = former_generation ^ (former_slot + 1) ^ 2;
    let legacy_forgery = (forged_generation << 8) | 1;
    assert_ne!(legacy_forgery, second.guest_index());

    for guess in [0, 1, first.guest_index().wrapping_add(1), legacy_forgery] {
        if guess != first.guest_index() && guess != second.guest_index() {
            assert_eq!(
                table.contains(table.token_from_guest_index(guess), BLOB),
                Err(ResourceError::Stale)
            );
        }
    }
    assert_eq!(table.drop_owned(second, BLOB), Ok(20));
}

#[test]
fn reservations_and_ownership_moves_are_transactional() {
    let mut source = ResourceTable::new(21, 2).unwrap();
    let mut target = ResourceTable::new(22, 2).unwrap();
    let source_token = source
        .insert_owned(RANDOM, String::from("authority"))
        .unwrap();

    {
        let transfer = source.begin_take_owned(source_token, RANDOM).unwrap();
        assert_eq!(transfer.authority().unwrap(), "authority");
        // Dropping the uncommitted transaction restores the source.
    }
    assert_eq!(source.contains(source_token, RANDOM), Ok(true));

    let wrong_target = target.reserve().unwrap();
    let transfer = source.begin_take_owned(source_token, RANDOM).unwrap();
    let failure = transfer.commit_into(wrong_target, BLOB).unwrap_err();
    assert_eq!(failure.error(), ResourceError::WrongType);
    let (_, wrong_target) = failure.into_parts();
    wrong_target.rollback();
    assert_eq!(source.contains(source_token, RANDOM), Ok(true));
    assert!(target.is_empty());

    let reservation = target.reserve().unwrap();
    let transfer = source.begin_take_owned(source_token, RANDOM).unwrap();
    let target_token = transfer.commit_into(reservation, RANDOM).unwrap();
    assert_eq!(
        source.contains(source_token, RANDOM),
        Err(ResourceError::Stale)
    );
    assert_eq!(target.contains(target_token, RANDOM), Ok(true));
    assert_eq!(
        target.drop_owned(target_token, RANDOM).unwrap(),
        "authority"
    );
}

#[test]
fn failed_commits_return_every_linear_input() {
    let mut original = ResourceTable::new(61, 1).unwrap();
    let reservation = original.reserve().unwrap();
    reservation.rollback();
    assert!(original.insert_owned(RANDOM, String::from("kept")).is_ok());

    let failure = original
        .insert_owned(RANDOM, String::from("returned"))
        .unwrap_err();
    assert_eq!(failure.error(), ResourceError::TableFull);
    let (error, authority) = failure.into_parts();
    assert_eq!(error, ResourceError::TableFull);
    assert_eq!(authority, "returned");

    let mut source = ResourceTable::new(62, 1).unwrap();
    let mut intended_target = ResourceTable::new(63, 1).unwrap();
    let source_token = source.insert_owned(RANDOM, 77_u32).unwrap();
    let reservation = intended_target.reserve().unwrap();
    let transfer = source.begin_take_owned(source_token, RANDOM).unwrap();
    let failure = transfer.commit_into(reservation, BLOB).unwrap_err();
    assert_eq!(failure.error(), ResourceError::WrongType);
    let (_, reservation) = failure.into_parts();
    reservation.rollback();
    assert_eq!(source.drop_owned(source_token, RANDOM), Ok(77));
    assert!(intended_target.insert_owned(RANDOM, 78).is_ok());
}

#[test]
fn borrow_scope_is_unforgeable_non_escaping_and_unwind_safe() {
    let mut table = ResourceTable::new(31, 1).unwrap();
    let token = table.insert_owned(RANDOM, 99_u32).unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = table.with_borrow(token, RANDOM, |borrowed| {
            assert_eq!(borrowed.with(|authority| *authority), 99);
            assert_eq!(
                format!("{borrowed:?}"),
                "BorrowedResource { resource_type: ResourceTypeId(7), scope: \"<active>\", .. }"
            );
            panic!("host fixture unwind");
        });
    }));
    assert!(result.is_err());

    table
        .with_borrow_scope(|scope| {
            assert_eq!(format!("{scope:?}"), "BorrowScope(<active>)");
            assert_eq!(
                scope
                    .with_borrow(token, RANDOM, |borrowed| borrowed.with(|value| *value))
                    .unwrap(),
                99
            );
            assert_eq!(
                scope.with_borrow(token, BLOB, |_| ()),
                Err(ResourceError::WrongType)
            );
        })
        .unwrap();
    assert_eq!(table.drop_owned(token, RANDOM), Ok(99));
}

#[test]
fn cross_table_borrow_is_invocation_scoped_and_non_owning() {
    let mut source = ResourceTable::new(32, 1).unwrap();
    let target = ResourceTable::<()>::new(33, 1).unwrap();
    let token = source.insert_owned(RANDOM, 101_u32).unwrap();
    let source_len = source.len();

    source
        .with_cross_table_borrow(token, RANDOM, &target, BLOB, |scope| {
            assert_eq!(format!("{scope:?}"), "CrossTableBorrowScope(<active>)");
            let alias = scope.alias();
            assert_eq!(format!("{alias:?}"), "CrossTableBorrowAlias(<active>)");
            assert_eq!(
                scope.with_alias(&alias, |borrowed| {
                    assert_eq!(borrowed.resource_type(), RANDOM);
                    borrowed.with(|authority| *authority)
                }),
                Ok(101)
            );
        })
        .unwrap();

    assert_eq!(source.len(), source_len);
    assert_eq!(source.contains(token, RANDOM), Ok(true));
    assert!(target.is_empty());
    assert_eq!(source.drop_owned(token, RANDOM), Ok(101));
}

#[test]
fn cross_table_borrow_rejects_same_table_and_wrong_source_type() {
    let mut source = ResourceTable::new(34, 1).unwrap();
    let target = ResourceTable::<()>::new(35, 1).unwrap();
    let token = source.insert_owned(RANDOM, 102_u32).unwrap();

    assert_eq!(
        source.with_cross_table_borrow(token, RANDOM, &source, BLOB, |_| ()),
        Err(ResourceError::WrongInstance)
    );
    assert_eq!(
        source.with_cross_table_borrow(token, BLOB, &target, RANDOM, |_| ()),
        Err(ResourceError::WrongType)
    );
    assert_eq!(source.contains(token, RANDOM), Ok(true));
    assert!(target.is_empty());
}

#[test]
fn nested_cross_table_borrow_scopes_reject_each_others_aliases() {
    let mut source = ResourceTable::new(36, 1).unwrap();
    let target = ResourceTable::<()>::new(37, 1).unwrap();
    let token = source.insert_owned(RANDOM, 103_u32).unwrap();

    source
        .with_cross_table_borrow(token, RANDOM, &target, BLOB, |outer| {
            let outer_alias = outer.alias();
            source
                .with_cross_table_borrow(token, RANDOM, &target, BLOB, |inner| {
                    let inner_alias = inner.alias();
                    assert_eq!(
                        inner.with_alias(&outer_alias, |_| ()),
                        Err(ResourceError::WrongScope)
                    );
                    assert_eq!(
                        outer.with_alias(&inner_alias, |_| ()),
                        Err(ResourceError::WrongScope)
                    );
                    assert_eq!(
                        inner.with_alias(&inner_alias, |borrowed| {
                            borrowed.with(|authority| *authority)
                        }),
                        Ok(103)
                    );
                })
                .unwrap();
            assert_eq!(
                outer.with_alias(&outer_alias, |borrowed| {
                    borrowed.with(|authority| *authority)
                }),
                Ok(103)
            );
        })
        .unwrap();

    assert_eq!(source.contains(token, RANDOM), Ok(true));
    assert!(target.is_empty());
}

#[test]
fn table_exhaustion_and_handle_retirement_do_not_lose_authority() {
    let mut table = ResourceTable::new(41, 1).unwrap();
    let mut seen = BTreeSet::new();
    for authority in 0..4_096_u32 {
        let token = table.insert_owned(RANDOM, authority).unwrap();
        assert!(seen.insert(token.guest_index()));
        let failure = table.insert_owned(RANDOM, u32::MAX).unwrap_err();
        assert_eq!(failure.error(), ResourceError::TableFull);
        assert_eq!(failure.into_parts().1, u32::MAX);
        assert_eq!(table.drop_owned(token, RANDOM), Ok(authority));
        assert_eq!(table.contains(token, RANDOM), Err(ResourceError::Stale));
    }
}

#[test]
fn abandoned_and_unwound_reservations_restore_capacity() {
    let mut table = ResourceTable::new(42, 1).unwrap();
    drop(table.reserve().unwrap());
    let token = table.insert_owned(RANDOM, 1_u32).unwrap();
    assert_eq!(table.drop_owned(token, RANDOM), Ok(1));

    let unwind = catch_unwind(AssertUnwindSafe(|| {
        let _reservation = table.reserve().unwrap();
        panic!("reservation scope unwinds");
    }));
    assert!(unwind.is_err());
    let token = table.insert_owned(RANDOM, 2_u32).unwrap();
    assert_eq!(table.drop_owned(token, RANDOM), Ok(2));
}

#[test]
fn table_full_returns_authority_without_running_drop() {
    #[derive(Debug)]
    struct Authority(Rc<Cell<u32>>);

    impl Drop for Authority {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    let drops = Rc::new(Cell::new(0));
    let mut table = ResourceTable::new(43, 1).unwrap();
    let live = table
        .insert_owned(RANDOM, Authority(drops.clone()))
        .unwrap();
    let failure = table
        .insert_owned(RANDOM, Authority(drops.clone()))
        .unwrap_err();
    assert_eq!(failure.error(), ResourceError::TableFull);
    assert_eq!(drops.get(), 0);
    let (_, returned) = failure.into_parts();
    assert_eq!(drops.get(), 0);
    drop(returned);
    assert_eq!(drops.get(), 1);
    drop(table.drop_owned(live, RANDOM).unwrap());
    assert_eq!(drops.get(), 2);
}

#[test]
fn rich_value_profile_validates_every_synchronous_shape() {
    let ty = ValueType::Record(vec![
        ValueType::String,
        ValueType::List(Box::new(ValueType::U8)),
        ValueType::Tuple(vec![ValueType::Bool, ValueType::Char, ValueType::U64]),
        ValueType::Flags(3),
        ValueType::Enum(3),
        ValueType::Option(Box::new(ValueType::S32)),
        ValueType::Result {
            ok: Some(Box::new(ValueType::String)),
            error: Some(Box::new(ValueType::U16)),
        },
        ValueType::Variant(vec![
            None,
            Some(ValueType::Tuple(vec![
                ValueType::String,
                ValueType::List(Box::new(ValueType::U8)),
            ])),
        ]),
        ValueType::Resource {
            resource_type: RANDOM,
            ownership: ResourceOwnership::Borrow,
        },
    ]);
    let mut resources = ResourceTable::new(51, 1).unwrap();
    let token = resources.insert_owned(RANDOM, ()).unwrap();
    let value = CanonicalValue::Record(vec![
        CanonicalValue::String(String::from("label")),
        CanonicalValue::List(vec![CanonicalValue::U8(1), CanonicalValue::U8(2)]),
        CanonicalValue::Tuple(vec![
            CanonicalValue::Bool(true),
            CanonicalValue::Char('λ'),
            CanonicalValue::U64(9),
        ]),
        CanonicalValue::Flags(vec![0b101]),
        CanonicalValue::Enum(2),
        CanonicalValue::Option(Some(Box::new(CanonicalValue::S32(-4)))),
        CanonicalValue::Result(Ok(Some(Box::new(CanonicalValue::String(String::from(
            "ok",
        )))))),
        CanonicalValue::Variant {
            case: 1,
            payload: Some(Box::new(CanonicalValue::Tuple(vec![
                CanonicalValue::String(String::from("accepted")),
                CanonicalValue::List(vec![CanonicalValue::U8(3)]),
            ]))),
        },
        CanonicalValue::Resource(token),
    ]);
    let type_account = validate_type(&ty).unwrap();
    let account = validate_value(&ty, &value).unwrap();
    assert!(type_account.nodes >= 20);
    assert!(account.nodes >= 20);
    assert!(account.bytes >= type_account.layout.size);
    assert_eq!(account.list_elements, 3);
    assert!(account.max_depth >= 4);
}

#[test]
fn resource_values_require_exact_live_type_and_borrows_cannot_escape() {
    let mut table = ResourceTable::new(52, 1).unwrap();
    let token = table.insert_owned(RANDOM, ()).unwrap();
    let borrow_type = ValueType::Resource {
        resource_type: RANDOM,
        ownership: ResourceOwnership::Borrow,
    };
    let value = CanonicalValue::Resource(token);
    assert!(
        validate_value_with_resources(&borrow_type, &value, &table, ValuePosition::Parameter)
            .is_ok()
    );
    assert_eq!(
        validate_value_with_resources(&borrow_type, &value, &table, ValuePosition::Result),
        Err(ValueError::BorrowEscape)
    );
    let hidden_borrow = ValueType::Option(Box::new(ValueType::Resource {
        resource_type: RANDOM,
        ownership: ResourceOwnership::Borrow,
    }));
    assert_eq!(
        validate_value_with_resources(
            &hidden_borrow,
            &CanonicalValue::Option(None),
            &table,
            ValuePosition::Result
        ),
        Err(ValueError::BorrowEscape)
    );

    let wrong_type = ValueType::Resource {
        resource_type: BLOB,
        ownership: ResourceOwnership::Own,
    };
    assert_eq!(
        validate_value_with_resources(&wrong_type, &value, &table, ValuePosition::Parameter),
        Err(ValueError::Resource)
    );
    let guessed = CanonicalValue::Resource(table.token_from_guest_index(0xdead_beef));
    assert_eq!(
        validate_value_with_resources(&borrow_type, &guessed, &table, ValuePosition::Parameter),
        Err(ValueError::Resource)
    );
}

fn deep_type() -> ValueType {
    let mut ty = ValueType::U8;
    for _ in 0..PROFILE_1_LIMITS.max_canonical_nesting {
        ty = ValueType::Option(Box::new(ty));
    }
    ty
}

#[test]
fn every_unselected_schema_branch_is_still_bounded() {
    let cases = [
        (
            ValueType::List(Box::new(deep_type())),
            CanonicalValue::List(vec![]),
        ),
        (
            ValueType::Option(Box::new(deep_type())),
            CanonicalValue::Option(None),
        ),
        (
            ValueType::Result {
                ok: Some(Box::new(deep_type())),
                error: None,
            },
            CanonicalValue::Result(Err(None)),
        ),
        (
            ValueType::Variant(vec![None, Some(deep_type())]),
            CanonicalValue::Variant {
                case: 0,
                payload: None,
            },
        ),
    ];
    for (ty, value) in cases {
        assert_eq!(validate_type(&ty), Err(ValueError::NestingLimit));
        assert_eq!(validate_value(&ty, &value), Err(ValueError::NestingLimit));
    }
}

#[test]
fn canonical_layout_includes_aggregate_and_variant_padding() {
    let tuple = ValueType::Tuple(vec![ValueType::U8, ValueType::U64]);
    assert_eq!(
        validate_type(&tuple).unwrap().layout,
        CanonicalLayout {
            size: 16,
            alignment: 8
        }
    );
    assert_eq!(
        validate_value(
            &tuple,
            &CanonicalValue::Tuple(vec![CanonicalValue::U8(1), CanonicalValue::U64(2)])
        )
        .unwrap()
        .bytes,
        16
    );

    let variant = ValueType::Variant(vec![Some(ValueType::U8), Some(ValueType::U64)]);
    assert_eq!(
        validate_type(&variant).unwrap().layout,
        CanonicalLayout {
            size: 16,
            alignment: 8
        }
    );
    assert_eq!(
        validate_value(
            &variant,
            &CanonicalValue::Variant {
                case: 0,
                payload: Some(Box::new(CanonicalValue::U8(1)))
            }
        )
        .unwrap()
        .bytes,
        16
    );

    let list = ValueType::List(Box::new(ValueType::U64));
    assert_eq!(
        validate_value(
            &list,
            &CanonicalValue::List(vec![CanonicalValue::U64(1), CanonicalValue::U64(2)])
        )
        .unwrap()
        .bytes,
        24
    );
}

#[test]
fn hostile_values_hit_exact_limits_without_panicking() {
    assert_eq!(
        validate_value(&ValueType::Flags(u32::MAX), &CanonicalValue::Flags(vec![])),
        Err(ValueError::InvalidFlags)
    );
    assert_eq!(
        validate_value(&ValueType::Flags(0), &CanonicalValue::Flags(vec![])),
        Err(ValueError::InvalidFlags)
    );
    assert_eq!(
        validate_value(&ValueType::Enum(2), &CanonicalValue::Enum(2)),
        Err(ValueError::InvalidDiscriminant)
    );
    let too_many = CanonicalValue::List(
        (0..=PROFILE_1_LIMITS.max_list_elements)
            .map(|_| CanonicalValue::U8(0))
            .collect(),
    );
    assert_eq!(
        validate_value(&ValueType::List(Box::new(ValueType::U8)), &too_many),
        Err(ValueError::ListLimit)
    );
    assert_eq!(validate_type(&deep_type()), Err(ValueError::NestingLimit));
}

#[test]
fn fallible_value_builders_enforce_limits_before_growth() {
    let value = try_string_value("bounded").unwrap();
    assert_eq!(
        validate_value(&ValueType::String, &value).unwrap().bytes,
        15
    );
    let accepted_elements = PROFILE_1_LIMITS
        .max_list_elements
        .min(PROFILE_1_LIMITS.max_canonical_values - 1);
    let list = try_list_value(
        &ValueType::U16,
        (0..accepted_elements).map(|value| CanonicalValue::U16(value as u16)),
    )
    .unwrap();
    assert!(matches!(list, CanonicalValue::List(_)));
    assert_eq!(
        try_list_value(
            &ValueType::U8,
            (0..=accepted_elements).map(|_| CanonicalValue::U8(0))
        ),
        Err(ValueError::ValueLimit)
    );
}

#[derive(Clone, Copy)]
struct Live {
    token: ResourceToken,
    resource_type: ResourceTypeId,
    authority: u32,
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn randomized_resource_state_matches_reference_model() {
    let mut state = 0x243f_6a88_85a3_08d3_u64;
    let mut table = ResourceTable::new(0x1319_8a2e_0370_7344, 16).unwrap();
    let mut live: Vec<Live> = Vec::new();
    let mut stale: Vec<ResourceToken> = Vec::new();
    let mut all_handles = BTreeSet::new();
    let mut next_authority = 1_u32;

    for _ in 0..20_000 {
        match next_random(&mut state) % 7 {
            0 => {
                let resource_type = if next_random(&mut state) & 1 == 0 {
                    RANDOM
                } else {
                    BLOB
                };
                if live.len() == 16 {
                    let failure = table
                        .insert_owned(resource_type, next_authority)
                        .unwrap_err();
                    assert_eq!(failure.error(), ResourceError::TableFull);
                    assert_eq!(failure.into_parts().1, next_authority);
                } else {
                    let token = table.insert_owned(resource_type, next_authority).unwrap();
                    assert!(all_handles.insert(token.guest_index()));
                    live.push(Live {
                        token,
                        resource_type,
                        authority: next_authority,
                    });
                    next_authority = next_authority.wrapping_add(1);
                }
            }
            1 if !live.is_empty() => {
                let index = next_random(&mut state) as usize % live.len();
                let item = live.swap_remove(index);
                let wrong = if item.resource_type == RANDOM {
                    BLOB
                } else {
                    RANDOM
                };
                assert_eq!(
                    table.drop_owned(item.token, wrong),
                    Err(ResourceError::WrongType)
                );
                assert_eq!(
                    table.drop_owned(item.token, item.resource_type),
                    Ok(item.authority)
                );
                stale.push(item.token);
            }
            2 if !live.is_empty() => {
                let item = live[next_random(&mut state) as usize % live.len()];
                assert_eq!(
                    table
                        .with_borrow(item.token, item.resource_type, |borrowed| {
                            borrowed.with(|authority| *authority)
                        })
                        .unwrap(),
                    item.authority
                );
            }
            3 if !live.is_empty() => {
                let item = live[next_random(&mut state) as usize % live.len()];
                let transfer = table
                    .begin_take_owned(item.token, item.resource_type)
                    .unwrap();
                assert_eq!(*transfer.authority().unwrap(), item.authority);
                drop(transfer);
            }
            4 => {
                if let Ok(reservation) = table.reserve() {
                    reservation.rollback();
                }
            }
            5 => {
                let guess = next_random(&mut state) as u32;
                if let Some(item) = live.iter().find(|item| item.token.guest_index() == guess) {
                    assert_eq!(
                        table.contains(table.token_from_guest_index(guess), item.resource_type),
                        Ok(true)
                    );
                } else {
                    assert_eq!(
                        table.contains(table.token_from_guest_index(guess), RANDOM),
                        Err(ResourceError::Stale)
                    );
                }
            }
            _ if !stale.is_empty() => {
                let token = stale[next_random(&mut state) as usize % stale.len()];
                assert_eq!(table.contains(token, RANDOM), Err(ResourceError::Stale));
                assert_eq!(table.contains(token, BLOB), Err(ResourceError::Stale));
            }
            _ => {}
        }
        assert_eq!(table.len(), live.len());
        for item in &live {
            assert_eq!(table.contains(item.token, item.resource_type), Ok(true));
        }
    }

    for item in live {
        assert_eq!(
            table.drop_owned(item.token, item.resource_type),
            Ok(item.authority)
        );
    }
    assert!(table.is_empty());
}
