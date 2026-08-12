use vibeos_storage_device::{
    admit_non_overlapping, successful_write_durability, validate_flush, validate_grant_layout,
    validate_request, BlockRange, BlockRangeProvisioner, ContractError, DeviceGeometry, DeviceId,
    DeviceInfo, DeviceSession, DiscardGeometry, FailureReason, Legacy512Adapter, MutationCertainty,
    MutationFailure, Operation, RangeInfo, RangeSession, WriteCache, WriteDurability,
};

fn id(value: u128) -> DeviceId {
    DeviceId::new(value).unwrap()
}

fn geometry() -> DeviceGeometry {
    DeviceGeometry::new(
        512,
        Some(4096),
        8,
        0,
        8,
        None,
        WriteCache::Volatile,
        true,
        false,
        Some(DiscardGeometry::new(8, 0, 1024).unwrap()),
    )
    .unwrap()
}

fn info(device: DeviceId, incarnation: u64) -> DeviceInfo {
    DeviceInfo::new(
        DeviceSession::new(device, incarnation).unwrap(),
        10_000,
        false,
        geometry(),
    )
    .unwrap()
}

#[test]
fn attenuation_can_only_shrink_the_parent() {
    let root = unsafe { BlockRange::root(id(1), 1_000, 500) }.unwrap();
    let child = root.attenuate(100, 200).unwrap();
    let leaf = child.attenuate(50, 25).unwrap();
    assert_eq!(child.first_block(), 1_100);
    assert_eq!(leaf.first_block(), 1_150);
    assert!(root.contains(child));
    assert!(child.contains(leaf));
    assert_eq!(root.attenuate(499, 2), Err(ContractError::OutsideRange));
    assert_eq!(
        child.attenuate(u64::MAX, 2),
        Err(ContractError::ArithmeticOverflow)
    );
    assert_eq!(child.attenuate(0, 0), Err(ContractError::EmptyRange));
}

#[test]
fn overflow_out_of_range_and_independent_overlap_fail_closed() {
    assert_eq!(
        unsafe { BlockRange::root(id(1), u64::MAX, 2) },
        Err(ContractError::ArithmeticOverflow)
    );
    let first = unsafe { BlockRange::root(id(1), 64, 512) }.unwrap();
    let adjacent = unsafe { BlockRange::root(id(1), 576, 10) }.unwrap();
    let overlap = unsafe { BlockRange::root(id(1), 575, 10) }.unwrap();
    let other_device = unsafe { BlockRange::root(id(2), 64, 512) }.unwrap();
    assert_eq!(admit_non_overlapping(&[first], adjacent), Ok(()));
    assert_eq!(
        admit_non_overlapping(&[first], overlap),
        Err(ContractError::OverlappingRange)
    );
    assert_eq!(admit_non_overlapping(&[first], other_device), Ok(()));
    assert_eq!(first.translate(511, 1), Ok(575));
    assert_eq!(first.translate(512, 1), Err(ContractError::OutsideRange));
}

#[test]
fn a_complete_grant_layout_is_contained_and_pairwise_disjoint() {
    let parent = unsafe { BlockRange::root(id(1), 0, 2_048) }.unwrap();
    let diagnostics = parent.attenuate(0, 64).unwrap();
    let m4 = parent.attenuate(64, 512).unwrap();
    let v2_tail = parent.attenuate(576, 1_472).unwrap();
    assert_eq!(
        validate_grant_layout(parent, &[diagnostics, m4, v2_tail]),
        Ok(())
    );
    assert_eq!(
        validate_grant_layout(
            parent,
            &[
                diagnostics,
                unsafe { BlockRange::root(id(1), 63, 2) }.unwrap()
            ]
        ),
        Err(ContractError::OverlappingRange)
    );
    assert_eq!(
        validate_grant_layout(
            parent,
            &[unsafe { BlockRange::root(id(1), 2_047, 2) }.unwrap()]
        ),
        Err(ContractError::OutsideRange)
    );
    assert_eq!(
        validate_grant_layout(parent, &[unsafe { BlockRange::root(id(2), 0, 1) }.unwrap()]),
        Err(ContractError::WrongDevice)
    );
}

#[test]
fn stale_and_changed_devices_are_rejected_before_address_disclosure() {
    let device = id(7);
    let range = unsafe { BlockRange::root(device, 64, 512) }.unwrap();
    let binding = RangeSession::bind(range, info(device, 3)).unwrap();
    assert_eq!(
        binding.validate_current(info(device, 4)),
        Err(ContractError::StaleIncarnation)
    );
    assert_eq!(
        binding.validate_current(info(id(8), 3)),
        Err(ContractError::WrongDevice)
    );
}

#[test]
fn online_range_capabilities_join_only_adjacent_current_session_siblings() {
    let session = DeviceSession::new(id(8), 3).unwrap();
    // SAFETY: the test fixture is the sole root provisioning policy for this
    // device/session and derives every tested child from this issuer.
    let provisioner = unsafe { BlockRangeProvisioner::new(session, 64, 512) }.unwrap();
    let left = provisioner.derive(0, 128).unwrap();
    let right = provisioner.derive(128, 384).unwrap();
    let joined = left.join_adjacent(right).unwrap();
    assert_eq!(joined.range().first_block(), 64);
    assert_eq!(joined.range().block_count(), 512);
    assert_eq!(joined.session(), session);
    assert_eq!(right.join_adjacent(left), Err(ContractError::OutsideRange));

    // SAFETY: a distinct test-only incarnation deliberately models stale
    // trusted discovery output, which must not join the current session.
    let stale =
        unsafe { BlockRangeProvisioner::new(DeviceSession::new(id(8), 4).unwrap(), 64, 512) }
            .unwrap()
            .derive(128, 384)
            .unwrap();
    assert_eq!(
        left.join_adjacent(stale),
        Err(ContractError::StaleIncarnation)
    );
    // SAFETY: this deliberately independent test root models a foreign
    // authority tree; same coordinates/session do not grant join authority.
    let foreign = unsafe { BlockRangeProvisioner::new(session, 0, 1_024) }
        .unwrap()
        .derive(192, 384)
        .unwrap();
    assert_eq!(
        left.join_adjacent(foreign),
        Err(ContractError::OutsideRange)
    );
    assert_eq!(format!("{left:?}"), "BlockRangeCapability(<opaque>)");
}

#[test]
fn request_validation_binds_range_geometry_buffer_and_features() {
    let device = id(9);
    let current = info(device, 1);
    let binding = RangeSession::bind(
        unsafe { BlockRange::root(device, 64, 512) }.unwrap(),
        current,
    )
    .unwrap();
    let request = validate_request(binding, current, Operation::Read, 10, 2, 1024).unwrap();
    assert_eq!(request.physical_first_block(), 74);
    assert_eq!(request.byte_len(), 1024);
    assert_eq!(
        validate_request(binding, current, Operation::Read, 10, 2, 512),
        Err(ContractError::WrongBufferLength)
    );
    assert_eq!(
        validate_request(binding, current, Operation::Read, 10, 9, 4608),
        Err(ContractError::TransferTooLarge)
    );
    assert_eq!(
        validate_request(binding, current, Operation::Write { fua: true }, 0, 1, 512),
        Err(ContractError::FuaUnsupported)
    );
    let flush = validate_flush(binding, current).unwrap();
    assert_eq!(flush.session(), current.session());
    assert_eq!(flush.range(), binding.range());
    let scoped = RangeInfo::new(binding.range(), current).unwrap();
    assert_eq!(scoped.capacity_blocks(), 512);
    assert_eq!(scoped.range(), binding.range());
}

#[test]
fn discard_geometry_and_read_only_state_are_enforced() {
    let device = id(11);
    let current = info(device, 1);
    let binding = RangeSession::bind(
        unsafe { BlockRange::root(device, 0, 512) }.unwrap(),
        current,
    )
    .unwrap();
    assert!(validate_request(binding, current, Operation::Discard, 8, 8, 0).is_ok());
    assert_eq!(
        validate_request(binding, current, Operation::Discard, 1, 8, 0),
        Err(ContractError::DiscardMisaligned)
    );
    let read_only = DeviceInfo::new(current.session(), 10_000, true, geometry()).unwrap();
    let read_only_binding = RangeSession::bind(binding.range(), read_only).unwrap();
    assert_eq!(
        validate_request(
            read_only_binding,
            read_only,
            Operation::Write { fua: false },
            0,
            1,
            512,
        ),
        Err(ContractError::ReadOnly)
    );
}

#[test]
fn discard_alignment_uses_the_translated_device_lba() {
    let device = id(12);
    let current = info(device, 1);
    let aligned =
        RangeSession::bind(unsafe { BlockRange::root(device, 8, 64) }.unwrap(), current).unwrap();
    assert!(validate_request(aligned, current, Operation::Discard, 0, 8, 0).is_ok());
    let shifted =
        RangeSession::bind(unsafe { BlockRange::root(device, 1, 64) }.unwrap(), current).unwrap();
    assert_eq!(
        validate_request(shifted, current, Operation::Discard, 0, 8, 0),
        Err(ContractError::DiscardMisaligned)
    );
}

#[test]
fn legacy_adapter_preserves_numbers_without_widening_the_range() {
    let range = unsafe { BlockRange::root(id(13), 1_064, 512) }.unwrap();
    let adapter = Legacy512Adapter::new(range, 64).unwrap();
    assert_eq!(adapter.legacy_end_sector(), 576);
    assert_eq!(adapter.relative_sector(64), Ok(0));
    assert_eq!(adapter.relative_sector(575), Ok(511));
    assert_eq!(adapter.device_block_for_legacy_sector(64), Ok(1_064));
    assert_eq!(adapter.device_block_for_legacy_sector(575), Ok(1_575));
    assert_eq!(
        adapter.device_block_for_legacy_sector(63),
        Err(ContractError::OutsideRange)
    );
    assert_eq!(
        adapter.device_block_for_legacy_sector(576),
        Err(ContractError::OutsideRange)
    );
}

#[test]
fn durability_and_failure_ambiguity_are_explicit() {
    assert_eq!(
        successful_write_durability(geometry(), false),
        Ok(WriteDurability::RequiresFlush)
    );
    assert_eq!(
        successful_write_durability(geometry(), true),
        Err(ContractError::FuaUnsupported)
    );
    assert_eq!(
        MutationFailure::cancelled(false).certainty(),
        MutationCertainty::NotSubmitted
    );
    assert_eq!(
        MutationFailure::cancelled(true).certainty(),
        MutationCertainty::Ambiguous
    );
    assert_eq!(
        MutationFailure::after_submission(FailureReason::DriverRestarted).reason(),
        FailureReason::DriverRestarted
    );
    let mapped = MutationFailure::not_submitted(7u8).map(u16::from);
    assert_eq!(mapped.into_parts(), (7u16, MutationCertainty::NotSubmitted));
    let promoted = MutationFailure::not_submitted(FailureReason::DriverRestarted).force_ambiguous();
    assert_eq!(promoted.certainty(), MutationCertainty::Ambiguous);
    assert_eq!(promoted.reason(), FailureReason::DriverRestarted);
}

#[test]
fn invalid_geometry_is_rejected() {
    assert_eq!(
        DeviceGeometry::new(
            0,
            Some(4096),
            8,
            0,
            1,
            None,
            WriteCache::Unknown,
            true,
            false,
            None,
        ),
        Err(ContractError::InvalidGeometry)
    );
    assert_eq!(
        DeviceGeometry::new(
            8192,
            Some(8192),
            1,
            0,
            1,
            None,
            WriteCache::Unknown,
            true,
            false,
            None,
        ),
        Err(ContractError::InvalidGeometry)
    );
    for logical in [512, 1024, 2048, 4096] {
        assert!(DeviceGeometry::new(
            logical,
            Some(logical),
            1,
            0,
            1,
            None,
            WriteCache::Unknown,
            true,
            false,
            None,
        )
        .is_ok());
    }
    assert_eq!(
        DeviceGeometry::new(
            512,
            Some(4096),
            8,
            8,
            1,
            None,
            WriteCache::Unknown,
            true,
            false,
            None,
        ),
        Err(ContractError::InvalidGeometry)
    );
    assert_eq!(
        DeviceSession::new(id(1), 0),
        Err(ContractError::ZeroIncarnation)
    );
}

#[test]
fn fua_alone_does_not_order_prior_plain_writes() {
    let fua_only = DeviceGeometry::new(
        512,
        None,
        1,
        0,
        1,
        None,
        WriteCache::Volatile,
        false,
        true,
        None,
    )
    .unwrap();
    assert!(!fua_only.has_ordered_durability());
    assert_eq!(
        successful_write_durability(fua_only, true),
        Ok(WriteDurability::Durable)
    );
}
