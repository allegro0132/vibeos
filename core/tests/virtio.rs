use core::mem::{align_of, size_of};

use vibeos_core::virtio::*;

fn read_write_features() -> NegotiatedFeatures {
    negotiate_block_features(VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH).unwrap()
}

fn read_only_features() -> NegotiatedFeatures {
    negotiate_block_features(VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_RO | VIRTIO_BLK_F_FLUSH).unwrap()
}

fn addresses() -> BlockDmaAddresses {
    BlockDmaAddresses {
        header: 0x1000,
        data: 0x2000,
        status: 0x3000,
    }
}

fn complete_ok(queue: &mut SplitQueueModel, submission: Submission, status: u8) -> Completion {
    queue
        .complete(
            submission,
            queue.used_index().wrapping_add(1),
            UsedElement::new(
                submission.head as u32,
                maximum_used_length(submission.operation),
            ),
            status,
        )
        .unwrap()
}

#[test]
fn modern_mmio_constants_match_virtio_1_2() {
    assert_eq!(MMIO_MAGIC_VALUE, 0x7472_6976);
    assert_eq!(MMIO_VERSION_MODERN, 2);
    assert_eq!(DEVICE_ID_BLOCK, 2);
    assert_eq!(DEVICE_ID_ENTROPY, 4);
    assert_eq!(MMIO_MAGIC_VALUE_OFFSET, 0x000);
    assert_eq!(MMIO_DEVICE_FEATURES_OFFSET, 0x010);
    assert_eq!(MMIO_DRIVER_FEATURES_OFFSET, 0x020);
    assert_eq!(MMIO_QUEUE_SEL_OFFSET, 0x030);
    assert_eq!(MMIO_QUEUE_READY_OFFSET, 0x044);
    assert_eq!(MMIO_QUEUE_NOTIFY_OFFSET, 0x050);
    assert_eq!(MMIO_INTERRUPT_STATUS_OFFSET, 0x060);
    assert_eq!(MMIO_INTERRUPT_ACK_OFFSET, 0x064);
    assert_eq!(MMIO_STATUS_OFFSET, 0x070);
    assert_eq!(MMIO_QUEUE_DESC_LOW_OFFSET, 0x080);
    assert_eq!(MMIO_QUEUE_DRIVER_LOW_OFFSET, 0x090);
    assert_eq!(MMIO_QUEUE_DEVICE_LOW_OFFSET, 0x0a0);
    assert_eq!(MMIO_CONFIG_GENERATION_OFFSET, 0x0fc);
    assert_eq!(MMIO_CONFIG_OFFSET, 0x100);
    assert_eq!(SPLIT_QUEUE_SIZE, 8);
}

#[test]
fn probe_accepts_only_a_modern_block_device() {
    let valid = MmioIdentity {
        magic: MMIO_MAGIC_VALUE,
        version: MMIO_VERSION_MODERN,
        device_id: DEVICE_ID_BLOCK,
        vendor_id: 0x554d_4551,
    };
    assert_eq!(probe_modern_block(valid), Ok(()));

    assert_eq!(
        probe_modern_block(MmioIdentity { magic: 0, ..valid }),
        Err(ProbeError::BadMagic { observed: 0 })
    );
    assert_eq!(
        probe_modern_block(MmioIdentity {
            version: 1,
            ..valid
        }),
        Err(ProbeError::LegacyTransport { observed: 1 })
    );
    assert_eq!(
        probe_modern_block(MmioIdentity {
            version: 3,
            ..valid
        }),
        Err(ProbeError::UnsupportedVersion { observed: 3 })
    );
    assert_eq!(
        probe_modern_block(MmioIdentity {
            device_id: 0,
            ..valid
        }),
        Err(ProbeError::NotBlockDevice { observed: 0 })
    );
    assert_eq!(
        probe_modern_block(MmioIdentity {
            device_id: 1,
            ..valid
        }),
        Err(ProbeError::NotBlockDevice { observed: 1 })
    );
}

#[test]
fn interrupt_helper_masks_reserved_bits_and_preserves_both_causes() {
    let causes = InterruptCauses::from_status(0xffff_fffb);
    assert!(causes.used_buffer());
    assert!(causes.configuration_change());
    assert_eq!(causes.ack_bits(), 3);

    let none = InterruptCauses::from_status(1 << 31);
    assert!(none.is_empty());
    assert_eq!(none.ack_bits(), 0);

    let config = InterruptCauses::from_status(INTERRUPT_CONFIGURATION_CHANGE);
    assert!(!config.used_buffer());
    assert!(config.configuration_change());
}

#[test]
fn feature_words_round_trip_and_out_of_range_selector_reads_zero() {
    let features = 0xfedc_ba98_7654_3210;
    assert_eq!(feature_word(features, 0), 0x7654_3210);
    assert_eq!(feature_word(features, 1), 0xfedc_ba98);
    assert_eq!(feature_word(features, 2), 0);
    assert_eq!(features_from_words(0x7654_3210, 0xfedc_ba98), features);
}

#[test]
fn config_generation_reader_accepts_a_stable_sample() {
    let mut calls = 0;
    let value = consistent_config_u64(4, || {
        calls += 1;
        ConfigU64Sample {
            generation_before: 7,
            low: 0x7654_3210,
            high: 0xfedc_ba98,
            generation_after: 7,
        }
    });
    assert_eq!(value, Some(0xfedc_ba98_7654_3210));
    assert_eq!(calls, 1);
}

#[test]
fn config_generation_reader_retries_then_accepts() {
    let mut calls = 0;
    let value = consistent_config_u64(4, || {
        calls += 1;
        ConfigU64Sample {
            generation_before: calls,
            low: 17,
            high: 0,
            generation_after: if calls < 3 { calls + 1 } else { calls },
        }
    });
    assert_eq!(value, Some(17));
    assert_eq!(calls, 3);
}

#[test]
fn config_generation_reader_exhausts_its_exact_budget() {
    let mut calls = 0;
    let value = consistent_config_u64(3, || {
        calls += 1;
        ConfigU64Sample {
            generation_before: calls,
            low: 17,
            high: 0,
            generation_after: calls + 1,
        }
    });
    assert_eq!(value, None);
    assert_eq!(calls, 3);
    assert_eq!(consistent_config_u64(0, || unreachable!()), None);
}

#[test]
fn negotiation_requires_version_one_and_selects_only_supported_features() {
    assert_eq!(
        negotiate_block_features(VIRTIO_BLK_F_FLUSH),
        Err(FeatureError::MissingVersion1)
    );

    let unknown = 1u64 << 48;
    let offered = VIRTIO_F_VERSION_1
        | VIRTIO_BLK_F_RO
        | VIRTIO_BLK_F_FLUSH
        | VIRTIO_RING_F_INDIRECT_DESC
        | VIRTIO_RING_F_EVENT_IDX
        | VIRTIO_F_ACCESS_PLATFORM
        | VIRTIO_F_RING_PACKED
        | unknown;
    let negotiated = negotiate_block_features(offered).unwrap();
    assert_eq!(negotiated.offered(), offered);
    assert_eq!(
        negotiated.accepted(),
        VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_RO | VIRTIO_BLK_F_FLUSH
    );
    assert_eq!(
        negotiated.rejected(),
        VIRTIO_RING_F_INDIRECT_DESC
            | VIRTIO_RING_F_EVENT_IDX
            | VIRTIO_F_ACCESS_PLATFORM
            | VIRTIO_F_RING_PACKED
    );
    assert_eq!(negotiated.accepted() & BLOCK_DRIVER_REJECTED_FEATURES, 0);
    assert_eq!(negotiated.accepted() & unknown, 0);
    assert!(negotiated.read_only());
    assert!(negotiated.supports_flush());
}

#[test]
fn entropy_identity_and_feature_profile_are_exact() {
    assert_eq!(ENTROPY_QUEUE, 0);
    assert_eq!(ENTROPY_MAX_REQUEST, 256);
    let valid = MmioIdentity {
        magic: MMIO_MAGIC_VALUE,
        version: MMIO_VERSION_MODERN,
        device_id: DEVICE_ID_ENTROPY,
        vendor_id: 0x554d_4551,
    };
    assert_eq!(probe_modern_entropy(valid), Ok(()));
    assert_eq!(
        probe_modern_entropy(MmioIdentity {
            device_id: DEVICE_ID_NETWORK,
            ..valid
        }),
        Err(ProbeError::NotEntropyDevice {
            observed: DEVICE_ID_NETWORK
        })
    );
    assert_eq!(
        negotiate_entropy_features(0),
        Err(FeatureError::MissingVersion1)
    );

    let unknown = 1u64 << 48;
    let offered = VIRTIO_F_VERSION_1
        | VIRTIO_RING_F_INDIRECT_DESC
        | VIRTIO_RING_F_EVENT_IDX
        | VIRTIO_F_ACCESS_PLATFORM
        | VIRTIO_F_RING_PACKED
        | unknown;
    let selected = negotiate_entropy_features(offered).unwrap();
    assert_eq!(selected.accepted(), VIRTIO_F_VERSION_1);
    assert_eq!(
        selected.rejected(),
        VIRTIO_RING_F_INDIRECT_DESC
            | VIRTIO_RING_F_EVENT_IDX
            | VIRTIO_F_ACCESS_PLATFORM
            | VIRTIO_F_RING_PACKED
    );
    assert_eq!(selected.accepted() & unknown, 0);

    let mut init = ModernInit::new();
    init.acknowledge().unwrap();
    init.declare_driver().unwrap();
    assert_eq!(
        init.select_entropy_features(offered).unwrap().accepted(),
        VIRTIO_F_VERSION_1
    );
}

#[test]
fn modern_status_machine_performs_the_cumulative_happy_path() {
    let mut init = ModernInit::new();
    assert_eq!(init.phase(), InitPhase::Reset);
    assert_eq!(init.status_to_write(), 0);
    assert_eq!(init.acknowledge(), Ok(STATUS_ACKNOWLEDGE));
    assert_eq!(
        init.declare_driver(),
        Ok(STATUS_ACKNOWLEDGE | STATUS_DRIVER)
    );
    let selected = init
        .select_features(VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH)
        .unwrap();
    assert_eq!(selected.accepted(), VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH);
    assert_eq!(init.features(), Some(selected));
    assert_eq!(
        init.set_features_ok(),
        Ok(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK)
    );
    assert_eq!(init.confirm_features(init.status_to_write()), Ok(()));
    assert_eq!(init.phase(), InitPhase::FeaturesAccepted);
    assert_eq!(
        init.set_driver_ok(),
        Ok(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK)
    );
    assert_eq!(init.phase(), InitPhase::Ready);
    assert_eq!(init.observe(init.status_to_write()), Ok(()));
}

#[test]
fn status_machine_rejects_skips_missing_version_and_feature_rejection() {
    let mut skipped = ModernInit::new();
    assert_eq!(
        skipped.declare_driver(),
        Err(InitError::InvalidTransition {
            phase: InitPhase::Reset
        })
    );
    assert_eq!(skipped.phase(), InitPhase::Reset);

    let mut missing = ModernInit::new();
    missing.acknowledge().unwrap();
    missing.declare_driver().unwrap();
    assert_eq!(
        missing.select_features(VIRTIO_BLK_F_FLUSH),
        Err(InitError::MissingVersion1)
    );
    assert_eq!(missing.phase(), InitPhase::Failed);
    assert_ne!(missing.status_to_write() & STATUS_FAILED, 0);

    let mut rejected = ModernInit::new();
    rejected.acknowledge().unwrap();
    rejected.declare_driver().unwrap();
    rejected.select_features(VIRTIO_F_VERSION_1).unwrap();
    rejected.set_features_ok().unwrap();
    let without_features_ok = STATUS_ACKNOWLEDGE | STATUS_DRIVER;
    assert_eq!(
        rejected.confirm_features(without_features_ok),
        Err(InitError::FeaturesRejected)
    );
    assert_eq!(rejected.phase(), InitPhase::Failed);
    assert_ne!(rejected.status_to_write() & STATUS_FAILED, 0);
}

fn features_ok_init() -> ModernInit {
    let mut init = ModernInit::new();
    init.acknowledge().unwrap();
    init.declare_driver().unwrap();
    init.select_features(VIRTIO_F_VERSION_1).unwrap();
    init.set_features_ok().unwrap();
    init
}

#[test]
fn status_machine_observes_device_failure_and_reset_request() {
    let mut failed = features_ok_init();
    let observed = failed.status_to_write() | STATUS_FAILED;
    assert_eq!(
        failed.confirm_features(observed),
        Err(InitError::DeviceFailed)
    );
    assert_eq!(failed.phase(), InitPhase::Failed);

    let mut reset = features_ok_init();
    let observed = reset.status_to_write() | STATUS_DEVICE_NEEDS_RESET;
    assert_eq!(
        reset.confirm_features(observed),
        Err(InitError::DeviceNeedsReset)
    );
    assert_eq!(reset.phase(), InitPhase::ResetRequired);

    let mut ready = features_ok_init();
    ready.confirm_features(ready.status_to_write()).unwrap();
    ready.set_driver_ok().unwrap();
    assert_eq!(
        ready.observe(STATUS_ACKNOWLEDGE),
        Err(InitError::StatusRegressed {
            expected: STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
            observed: STATUS_ACKNOWLEDGE
        })
    );

    let mut needs_reset = features_ok_init();
    needs_reset
        .confirm_features(needs_reset.status_to_write())
        .unwrap();
    needs_reset.set_driver_ok().unwrap();
    assert_eq!(
        needs_reset.observe(needs_reset.status_to_write() | STATUS_DEVICE_NEEDS_RESET),
        Err(InitError::DeviceNeedsReset)
    );
    assert_eq!(needs_reset.phase(), InitPhase::ResetRequired);
}

#[test]
fn status_machine_requires_zero_readback_before_reinitialization() {
    let mut init = features_ok_init();
    assert_eq!(init.begin_reset(), 0);
    assert_eq!(init.phase(), InitPhase::ResetPending);
    assert_eq!(init.features(), None);
    assert_eq!(
        init.confirm_reset(STATUS_ACKNOWLEDGE),
        Err(InitError::ResetNotConfirmed {
            observed: STATUS_ACKNOWLEDGE
        })
    );
    assert_eq!(init.phase(), InitPhase::ResetPending);
    assert_eq!(init.confirm_reset(0), Ok(()));
    assert_eq!(init, ModernInit::new());
}

#[test]
fn split_ring_wire_types_have_the_required_layout() {
    assert_eq!(size_of::<Descriptor>(), 16);
    assert_eq!(align_of::<Descriptor>(), 16);
    assert_eq!(size_of::<UsedElement>(), 8);
    assert_eq!(size_of::<AvailableRing>(), 20);
    assert_eq!(align_of::<AvailableRing>(), 2);
    assert_eq!(size_of::<UsedRing>(), 68);
    assert_eq!(align_of::<UsedRing>(), 4);
    assert_eq!(size_of::<BlockRequestHeader>(), 16);
}

#[test]
fn descriptor_and_request_header_accessors_decode_wire_values() {
    let descriptor = Descriptor::new(0x1122_3344_5566_7788, 0xaabb_ccdd, 3, 7);
    assert_eq!(descriptor.address(), 0x1122_3344_5566_7788);
    assert_eq!(descriptor.length(), 0xaabb_ccdd);
    assert_eq!(descriptor.flags(), DESC_F_NEXT | DESC_F_WRITE);
    assert_eq!(descriptor.next(), 7);
    assert!(descriptor.device_writable());

    for operation in [
        BlockOperation::Read { sector: 17 },
        BlockOperation::Write { sector: 29 },
        BlockOperation::Flush,
    ] {
        let header = BlockRequestHeader::new(operation);
        assert_eq!(header.request_type(), operation.request_type());
        assert_eq!(header.sector(), operation.sector());
        assert_eq!(header.reserved, 0);
    }
}

#[test]
fn read_chain_has_three_descriptors_with_device_write_direction() {
    let chain = build_block_chain(BlockOperation::Read { sector: 7 }, addresses()).unwrap();
    assert_eq!(chain.descriptor_count(), 3);
    let [header, data, status] = chain.descriptors;
    assert_eq!(header.address(), 0x1000);
    assert_eq!(header.length(), 16);
    assert_eq!(header.flags(), DESC_F_NEXT);
    assert_eq!(header.next(), BLOCK_DATA_DESCRIPTOR);
    assert!(!header.device_writable());
    assert_eq!(data.address(), 0x2000);
    assert_eq!(data.length(), BLOCK_SECTOR_SIZE);
    assert_eq!(data.flags(), DESC_F_NEXT | DESC_F_WRITE);
    assert_eq!(data.next(), BLOCK_STATUS_DESCRIPTOR);
    assert!(data.device_writable());
    assert_eq!(status.address(), 0x3000);
    assert_eq!(status.length(), 1);
    assert_eq!(status.flags(), DESC_F_WRITE);
    assert_eq!(status.next(), 0);
    assert!(status.device_writable());
}

#[test]
fn write_chain_keeps_payload_device_readable() {
    let chain = build_block_chain(BlockOperation::Write { sector: 8 }, addresses()).unwrap();
    assert_eq!(chain.descriptor_count(), 3);
    let data = chain.descriptors[BLOCK_DATA_DESCRIPTOR as usize];
    assert_eq!(data.flags(), DESC_F_NEXT);
    assert!(!data.device_writable());
    assert_eq!(data.next(), BLOCK_STATUS_DESCRIPTOR);
    assert!(chain.descriptors[BLOCK_STATUS_DESCRIPTOR as usize].device_writable());
}

#[test]
fn flush_chain_skips_the_data_descriptor() {
    let mut dma = addresses();
    dma.data = 0;
    let chain = build_block_chain(BlockOperation::Flush, dma).unwrap();
    assert_eq!(chain.descriptor_count(), 2);
    let header = chain.descriptors[BLOCK_HEADER_DESCRIPTOR as usize];
    assert_eq!(header.flags(), DESC_F_NEXT);
    assert_eq!(header.next(), BLOCK_STATUS_DESCRIPTOR);
    assert_eq!(
        chain.descriptors[BLOCK_DATA_DESCRIPTOR as usize],
        Descriptor::default()
    );
    assert_eq!(
        chain.descriptors[BLOCK_STATUS_DESCRIPTOR as usize].flags(),
        DESC_F_WRITE
    );
}

#[test]
fn chain_builder_rejects_zero_overflow_and_overlapping_dma() {
    for bad in [
        BlockDmaAddresses {
            header: 0,
            ..addresses()
        },
        BlockDmaAddresses {
            status: 0,
            ..addresses()
        },
        BlockDmaAddresses {
            data: 0,
            ..addresses()
        },
    ] {
        assert_eq!(
            build_block_chain(BlockOperation::Read { sector: 0 }, bad),
            Err(ChainError::ZeroAddress)
        );
    }

    assert_eq!(
        build_block_chain(
            BlockOperation::Read { sector: 0 },
            BlockDmaAddresses {
                header: u64::MAX - 8,
                ..addresses()
            }
        ),
        Err(ChainError::AddressOverflow)
    );
    assert_eq!(
        build_block_chain(
            BlockOperation::Read { sector: 0 },
            BlockDmaAddresses {
                data: u64::MAX - 255,
                ..addresses()
            }
        ),
        Err(ChainError::AddressOverflow)
    );
    assert_eq!(
        build_block_chain(
            BlockOperation::Flush,
            BlockDmaAddresses {
                status: u64::MAX,
                ..addresses()
            }
        ),
        Err(ChainError::AddressOverflow)
    );

    for bad in [
        BlockDmaAddresses {
            data: 0x1008,
            ..addresses()
        },
        BlockDmaAddresses {
            status: 0x100f,
            ..addresses()
        },
        BlockDmaAddresses {
            status: 0x21ff,
            ..addresses()
        },
    ] {
        assert_eq!(
            build_block_chain(BlockOperation::Read { sector: 0 }, bad),
            Err(ChainError::OverlappingBuffers)
        );
    }

    // Touching half-open ranges are not overlaps.
    assert!(build_block_chain(
        BlockOperation::Read { sector: 0 },
        BlockDmaAddresses {
            header: 0x1000,
            data: 0x1010,
            status: 0x1210,
        }
    )
    .is_ok());
}

#[test]
fn used_length_bounds_and_block_status_values_match_block_protocol() {
    assert_eq!(maximum_used_length(BlockOperation::Read { sector: 0 }), 513);
    assert_eq!(maximum_used_length(BlockOperation::Write { sector: 0 }), 1);
    assert_eq!(maximum_used_length(BlockOperation::Flush), 1);
    assert_eq!(BlockStatus::from_wire(0), Some(BlockStatus::Ok));
    assert_eq!(BlockStatus::from_wire(1), Some(BlockStatus::IoError));
    assert_eq!(BlockStatus::from_wire(2), Some(BlockStatus::Unsupported));
    assert_eq!(BlockStatus::from_wire(3), None);
}

#[test]
fn ring_index_helpers_use_u16_wrapping_and_queue_modulo() {
    assert_eq!(ring_slot(0), 0);
    assert_eq!(ring_slot(7), 7);
    assert_eq!(ring_slot(8), 0);
    assert_eq!(ring_slot(u16::MAX), 7);
    assert_eq!(advance_ring_index(u16::MAX), 0);
    assert!(used_advanced_once(u16::MAX, 0));
    assert!(!used_advanced_once(u16::MAX, 1));
}

#[test]
fn queue_enforces_permissions_and_single_in_flight() {
    let mut read_only = SplitQueueModel::new(read_only_features());
    assert_eq!(
        read_only.submit(BlockOperation::Write { sector: 1 }),
        Err(QueueError::ReadOnly)
    );
    let read = read_only
        .submit(BlockOperation::Read { sector: 1 })
        .unwrap();
    assert_eq!(read.available_index, 1);
    assert_eq!(read.available_slot, 0);
    assert_eq!(read.head, BLOCK_HEADER_DESCRIPTOR);
    assert!(!read_only.dma_reusable());
    assert_eq!(
        read_only.submit(BlockOperation::Read { sector: 2 }),
        Err(QueueError::Busy)
    );
    complete_ok(&mut read_only, read, BLOCK_STATUS_OK);
    assert!(read_only.dma_reusable());

    let no_flush = negotiate_block_features(VIRTIO_F_VERSION_1).unwrap();
    assert_eq!(
        SplitQueueModel::new(no_flush).submit(BlockOperation::Flush),
        Err(QueueError::FlushUnsupported)
    );
}

#[test]
fn queue_accepts_all_defined_block_completion_statuses() {
    for (raw, expected) in [
        (BLOCK_STATUS_OK, BlockStatus::Ok),
        (BLOCK_STATUS_IOERR, BlockStatus::IoError),
        (BLOCK_STATUS_UNSUPP, BlockStatus::Unsupported),
    ] {
        let mut queue = SplitQueueModel::new(read_write_features());
        let submission = queue.submit(BlockOperation::Write { sector: 8 }).unwrap();
        let completion = complete_ok(&mut queue, submission, raw);
        assert_eq!(completion.submission, submission);
        assert_eq!(completion.block_status, expected);
        assert_eq!(queue.state(), QueueState::Idle);
        assert_eq!(queue.used_index(), 1);
    }
}

#[test]
fn queue_rejects_underreported_used_lengths_before_reading_status() {
    // A modern driver may consume only the first used.len bytes. The status
    // byte follows all read data, so any under-report leaves status outside
    // the initialized prefix even if the device actually wrote it.
    for status in [BLOCK_STATUS_OK, BLOCK_STATUS_IOERR, BLOCK_STATUS_UNSUPP] {
        let mut queue = SplitQueueModel::new(read_write_features());
        let submission = queue.submit(BlockOperation::Read { sector: 7 }).unwrap();
        let error = queue
            .complete(submission, 1, UsedElement::new(0, 512), status)
            .unwrap_err();
        assert_eq!(
            error,
            QueueError::UsedLengthTooShort {
                minimum: 513,
                observed: 512,
            }
        );
    }

    let mut queue = SplitQueueModel::new(read_write_features());
    let submission = queue.submit(BlockOperation::Write { sector: 8 }).unwrap();
    assert_eq!(
        queue
            .complete(submission, 1, UsedElement::new(0, 0), BLOCK_STATUS_OK)
            .unwrap_err(),
        QueueError::UsedLengthTooShort {
            minimum: 1,
            observed: 0,
        }
    );
}

fn assert_malformed_completion(
    mutate: impl FnOnce(&mut SplitQueueModel, Submission) -> QueueError,
    expected: QueueError,
) {
    let mut queue = SplitQueueModel::new(read_write_features());
    let submission = queue.submit(BlockOperation::Read { sector: 7 }).unwrap();
    assert_eq!(mutate(&mut queue, submission), expected);
    assert!(matches!(
        queue.state(),
        QueueState::ResetRequired {
            reason: ResetReason::MalformedCompletion,
            abandoned: Some(active),
        } if active == submission
    ));
    assert!(!queue.dma_reusable());
    assert_eq!(
        queue.submit(BlockOperation::Read { sector: 9 }),
        Err(QueueError::ResetRequired)
    );
}

#[test]
fn every_malformed_used_field_quarantines_dma_until_reset() {
    assert_malformed_completion(
        |queue, submission| {
            queue
                .complete(
                    submission,
                    0,
                    UsedElement::new(0, maximum_used_length(submission.operation)),
                    BLOCK_STATUS_OK,
                )
                .unwrap_err()
        },
        QueueError::UsedIndexDidNotAdvance {
            expected: 1,
            observed: 0,
        },
    );
    assert_malformed_completion(
        |queue, submission| {
            queue
                .complete(
                    submission,
                    1,
                    UsedElement::new(SPLIT_QUEUE_SIZE as u32, 513),
                    BLOCK_STATUS_OK,
                )
                .unwrap_err()
        },
        QueueError::UsedIdOutOfRange { observed: 8 },
    );
    assert_malformed_completion(
        |queue, submission| {
            queue
                .complete(submission, 1, UsedElement::new(1, 513), BLOCK_STATUS_OK)
                .unwrap_err()
        },
        QueueError::WrongUsedId {
            expected: 0,
            observed: 1,
        },
    );
    assert_malformed_completion(
        |queue, submission| {
            queue
                .complete(submission, 1, UsedElement::new(0, 514), BLOCK_STATUS_OK)
                .unwrap_err()
        },
        QueueError::UsedLengthOutOfRange {
            maximum: 513,
            observed: 514,
        },
    );
    assert_malformed_completion(
        |queue, submission| {
            queue
                .complete(submission, 1, UsedElement::new(0, 512), BLOCK_STATUS_OK)
                .unwrap_err()
        },
        QueueError::UsedLengthTooShort {
            minimum: 513,
            observed: 512,
        },
    );
    assert_malformed_completion(
        |queue, submission| {
            queue
                .complete(submission, 1, UsedElement::new(0, 513), 0xff)
                .unwrap_err()
        },
        QueueError::UnknownBlockStatus { observed: 0xff },
    );
}

#[test]
fn timeout_requires_confirmed_reset_before_descriptor_reuse() {
    let mut queue = SplitQueueModel::new(read_write_features());
    let first = queue.submit(BlockOperation::Read { sector: 7 }).unwrap();
    assert_eq!(queue.timeout(first), Ok(()));
    assert!(matches!(
        queue.state(),
        QueueState::ResetRequired {
            reason: ResetReason::Timeout,
            abandoned: Some(active),
        } if active == first
    ));
    assert_eq!(
        queue.complete(first, 1, UsedElement::new(0, 513), BLOCK_STATUS_OK),
        Err(QueueError::ResetRequired)
    );
    assert_eq!(
        queue.confirm_reset(STATUS_ACKNOWLEDGE),
        Err(QueueError::ResetNotConfirmed {
            observed_status: STATUS_ACKNOWLEDGE
        })
    );
    assert!(!queue.dma_reusable());
    assert_eq!(queue.confirm_reset(0), Ok(()));
    assert_eq!(queue.epoch(), first.epoch + 1);
    assert_eq!(queue.available_index(), 0);
    assert_eq!(queue.used_index(), 0);
    assert!(queue.dma_reusable());

    let second = queue.submit(BlockOperation::Read { sector: 8 }).unwrap();
    assert_eq!(second.available_slot, 0);
    assert_eq!(
        queue.complete(first, 1, UsedElement::new(0, 513), BLOCK_STATUS_OK),
        Err(QueueError::StaleSession {
            expected: second.epoch,
            observed: first.epoch,
        })
    );
    assert_eq!(queue.state(), QueueState::InFlight(second));
    complete_ok(&mut queue, second, BLOCK_STATUS_OK);
}

#[test]
fn cancellation_and_fault_paths_also_require_reset() {
    let mut cancelled = SplitQueueModel::new(read_write_features());
    let request = cancelled
        .submit(BlockOperation::Write { sector: 8 })
        .unwrap();
    assert_eq!(cancelled.cancel(request), Ok(()));
    assert!(matches!(
        cancelled.state(),
        QueueState::ResetRequired {
            reason: ResetReason::Cancelled,
            ..
        }
    ));

    let mut faulted = SplitQueueModel::new(read_write_features());
    let request = faulted.submit(BlockOperation::Read { sector: 7 }).unwrap();
    faulted.require_reset(ResetReason::DriverFault);
    assert!(matches!(
        faulted.state(),
        QueueState::ResetRequired {
            reason: ResetReason::DriverFault,
            abandoned: Some(active),
        } if active == request
    ));
    faulted.require_reset(ResetReason::DeviceNeedsReset);
    assert!(matches!(
        faulted.state(),
        QueueState::ResetRequired {
            reason: ResetReason::DeviceNeedsReset,
            abandoned: Some(active),
        } if active == request
    ));

    let mut idle = SplitQueueModel::new(read_write_features());
    idle.require_reset(ResetReason::DriverFault);
    assert!(matches!(
        idle.state(),
        QueueState::ResetRequired {
            abandoned: None,
            ..
        }
    ));
}

#[test]
fn wrong_and_stale_tokens_do_not_steal_an_active_request() {
    let mut queue = SplitQueueModel::new(read_write_features());
    let active = queue.submit(BlockOperation::Read { sector: 7 }).unwrap();
    let wrong = Submission {
        operation: BlockOperation::Read { sector: 8 },
        ..active
    };
    assert_eq!(queue.timeout(wrong), Err(QueueError::WrongSubmission));
    assert_eq!(queue.state(), QueueState::InFlight(active));

    let stale = Submission {
        epoch: active.epoch - 1,
        ..active
    };
    assert_eq!(
        queue.cancel(stale),
        Err(QueueError::StaleSession {
            expected: active.epoch,
            observed: stale.epoch,
        })
    );
    assert_eq!(queue.state(), QueueState::InFlight(active));
}

#[test]
fn reset_requires_a_quarantine_and_session_epoch_never_wraps() {
    let mut idle = SplitQueueModel::new(read_write_features());
    assert_eq!(idle.confirm_reset(0), Err(QueueError::ResetNotRequired));
    assert!(SplitQueueModel::at_epoch(read_write_features(), 0).is_none());

    let mut exhausted = SplitQueueModel::at_epoch(read_write_features(), u64::MAX).unwrap();
    exhausted.require_reset(ResetReason::DriverFault);
    assert_eq!(exhausted.confirm_reset(0), Err(QueueError::EpochExhausted));
    assert!(!exhausted.dma_reusable());
    assert_eq!(exhausted.epoch(), u64::MAX);
}

#[test]
fn queue_ring_indices_really_cross_the_u16_boundary() {
    let mut queue = SplitQueueModel::new(read_write_features());
    let mut last = None;
    for sector in 0..=u16::MAX as u64 {
        let submission = queue.submit(BlockOperation::Read { sector }).unwrap();
        complete_ok(&mut queue, submission, BLOCK_STATUS_OK);
        last = Some(submission);
    }
    let last = last.unwrap();
    assert_eq!(last.available_index, 0);
    assert_eq!(last.available_slot, 7);
    assert_eq!(queue.available_index(), 0);
    assert_eq!(queue.used_index(), 0);
    assert_eq!(queue.state(), QueueState::Idle);
}

// --- ROADMAP M4.4: minimal modern virtio-net -----------------------------

fn complete_net_rx(
    device: &mut NetDeviceModel,
    submission: NetSubmission,
    used_length: u32,
) -> NetReceiveCompletion {
    device
        .complete_receive(
            device.used_index(NetQueue::Receive).wrapping_add(1),
            UsedElement::new(submission.token.head as u32, used_length),
            VirtioNetHeader::received_without_offload(),
        )
        .unwrap()
}

fn complete_net_tx(
    device: &mut NetDeviceModel,
    submission: NetSubmission,
    used_length: u32,
) -> NetTransmitCompletion {
    device
        .complete_transmit(
            device.used_index(NetQueue::Transmit).wrapping_add(1),
            UsedElement::new(submission.token.head as u32, used_length),
        )
        .unwrap()
}

#[test]
fn modern_network_identity_queues_and_minimal_features_are_exact() {
    assert_eq!(DEVICE_ID_NETWORK, 1);
    assert_eq!(NET_RECEIVE_QUEUE, 0);
    assert_eq!(NET_TRANSMIT_QUEUE, 1);
    assert_eq!(NET_QUEUE_SIZE, 8);
    assert_eq!(NET_HEADER_SIZE, 12);
    assert_eq!(NET_MAX_FRAME_SIZE, 1_514);
    assert_eq!(NET_RECEIVE_BUFFER_SIZE, 1_526);
    assert_eq!(NetQueue::Receive.index(), NET_RECEIVE_QUEUE);
    assert_eq!(NetQueue::Transmit.index(), NET_TRANSMIT_QUEUE);

    let valid = MmioIdentity {
        magic: MMIO_MAGIC_VALUE,
        version: MMIO_VERSION_MODERN,
        device_id: DEVICE_ID_NETWORK,
        vendor_id: 0x554d_4551,
    };
    assert_eq!(probe_modern_net(valid), Ok(()));
    assert_eq!(
        probe_modern_net(MmioIdentity { magic: 0, ..valid }),
        Err(ProbeError::BadMagic { observed: 0 })
    );
    assert_eq!(
        probe_modern_net(MmioIdentity {
            version: 1,
            ..valid
        }),
        Err(ProbeError::LegacyTransport { observed: 1 })
    );
    assert_eq!(
        probe_modern_net(MmioIdentity {
            version: 3,
            ..valid
        }),
        Err(ProbeError::UnsupportedVersion { observed: 3 })
    );
    assert_eq!(
        probe_modern_net(MmioIdentity {
            device_id: DEVICE_ID_BLOCK,
            ..valid
        }),
        Err(ProbeError::NotNetworkDevice {
            observed: DEVICE_ID_BLOCK
        })
    );

    assert_eq!(
        negotiate_net_features(VIRTIO_NET_F_MAC),
        Err(FeatureError::MissingVersion1)
    );
    let optional = VIRTIO_NET_F_CSUM
        | VIRTIO_NET_F_GUEST_CSUM
        | VIRTIO_NET_F_MAC
        | VIRTIO_NET_F_GUEST_TSO4
        | VIRTIO_NET_F_HOST_TSO6
        | VIRTIO_NET_F_MRG_RXBUF
        | VIRTIO_NET_F_CTRL_VQ
        | VIRTIO_NET_F_MQ
        | VIRTIO_RING_F_INDIRECT_DESC
        | VIRTIO_RING_F_EVENT_IDX
        | VIRTIO_F_ACCESS_PLATFORM
        | VIRTIO_F_RING_PACKED;
    let features = negotiate_net_features(VIRTIO_F_VERSION_1 | optional).unwrap();
    assert_eq!(features.accepted(), VIRTIO_F_VERSION_1);
    assert_eq!(features.rejected(), optional);

    let mut init = ModernInit::new();
    init.acknowledge().unwrap();
    init.declare_driver().unwrap();
    assert_eq!(
        init.select_net_features(VIRTIO_F_VERSION_1 | optional)
            .unwrap()
            .accepted(),
        VIRTIO_F_VERSION_1
    );
}

#[test]
fn modern_net_header_is_12_byte_little_endian_and_ignores_unused_rx_fields() {
    assert_eq!(size_of::<VirtioNetHeader>(), 12);
    assert_eq!(align_of::<VirtioNetHeader>(), 2);
    assert_eq!(VirtioNetHeader::transmit().to_bytes(), [0; 12]);
    assert!(VirtioNetHeader::transmit().is_plain_transmit());

    let bytes = [0, 0, 0x22, 0x11, 0x44, 0x33, 0x66, 0x55, 0x88, 0x77, 1, 0];
    let header = VirtioNetHeader::from_bytes(bytes);
    assert_eq!(header.to_bytes(), bytes);
    assert_eq!(header.header_length(), 0x1122);
    assert_eq!(header.gso_size(), 0x3344);
    assert_eq!(header.checksum_start(), 0x5566);
    assert_eq!(header.checksum_offset(), 0x7788);
    assert_eq!(header.num_buffers(), 1);
    assert!(
        header.is_plain_receive(),
        "unnegotiated u16 offload fields are ignored, never consumed"
    );

    for malformed in [
        VirtioNetHeader {
            flags: 1,
            ..VirtioNetHeader::received_without_offload()
        },
        VirtioNetHeader {
            gso_type: 1,
            ..VirtioNetHeader::received_without_offload()
        },
        VirtioNetHeader {
            num_buffers: 0,
            ..VirtioNetHeader::received_without_offload()
        },
        VirtioNetHeader {
            num_buffers: 2u16.to_le(),
            ..VirtioNetHeader::received_without_offload()
        },
    ] {
        assert!(!malformed.is_plain_receive());
    }
}

#[test]
fn net_descriptors_are_one_contiguous_buffer_with_exact_direction_and_bounds() {
    let receive = build_net_descriptor(NetOperation::Receive, 0x1000).unwrap();
    assert_eq!(receive.address(), 0x1000);
    assert_eq!(receive.length(), 1_526);
    assert_eq!(receive.flags(), DESC_F_WRITE);
    assert_eq!(receive.next(), 0);

    for length in [1, 60, 1_500, 1_514] {
        let operation = NetOperation::Transmit {
            frame_length: length,
        };
        let transmit = build_net_descriptor(operation, 0x2000).unwrap();
        assert_eq!(transmit.length(), NET_HEADER_SIZE + length as u32);
        assert_eq!(transmit.flags(), 0);
        assert!(!transmit.device_writable());
        assert_eq!(net_descriptor_length(operation), Some(12 + length as u32));
    }

    assert_eq!(
        build_net_descriptor(NetOperation::Receive, 0),
        Err(ChainError::ZeroAddress)
    );
    assert_eq!(
        build_net_descriptor(NetOperation::Receive, u64::MAX - 1_000),
        Err(ChainError::AddressOverflow)
    );
    for length in [0, 1_515, u16::MAX] {
        let operation = NetOperation::Transmit {
            frame_length: length,
        };
        assert_eq!(net_descriptor_length(operation), None);
        assert_eq!(
            build_net_descriptor(operation, 0x2000),
            Err(ChainError::InvalidPacketLength { observed: length })
        );
    }
}

#[test]
fn both_network_queues_are_independently_bounded_at_eight() {
    let mut device = NetDeviceModel::new();
    let mut receive = Vec::new();
    let mut transmit = Vec::new();
    for index in 0..NET_QUEUE_SIZE {
        let rx = device.post_receive().unwrap();
        let tx = device.submit_transmit(index as usize + 1).unwrap();
        assert_eq!(rx.token.queue, NetQueue::Receive);
        assert_eq!(tx.token.queue, NetQueue::Transmit);
        assert_eq!(rx.token.head, index);
        assert_eq!(tx.token.head, index);
        assert_eq!(rx.available_slot, index);
        assert_eq!(tx.available_slot, index);
        receive.push(rx);
        transmit.push(tx);
    }
    assert_eq!(device.inflight(NetQueue::Receive), 8);
    assert_eq!(device.inflight(NetQueue::Transmit), 8);
    assert_eq!(
        device.post_receive(),
        Err(NetQueueError::QueueFull {
            queue: NetQueue::Receive
        })
    );
    assert_eq!(
        device.submit_transmit(64),
        Err(NetQueueError::QueueFull {
            queue: NetQueue::Transmit
        })
    );
    assert_eq!(device.available_index(NetQueue::Receive), 8);
    assert_eq!(device.available_index(NetQueue::Transmit), 8);

    // Descriptor head allocation is independent from the wrapping available
    // ring slot: an out-of-order completion frees head 3 while avail slot 0 is
    // published next.
    complete_net_rx(&mut device, receive[3], NET_HEADER_SIZE + 60);
    let replacement = device.post_receive().unwrap();
    assert_eq!(replacement.token.head, 3);
    assert_eq!(replacement.available_slot, 0);
    assert!(replacement.token.serial > transmit[7].token.serial);
}

#[test]
fn receive_completion_checks_bounds_before_header_and_ignores_unused_fields() {
    assert_eq!(
        validate_net_receive_length(11),
        Err(NetReceiveLengthError::HeaderIncomplete {
            minimum: 12,
            observed: 11,
        })
    );
    assert_eq!(validate_net_receive_length(12), Ok(0));
    assert_eq!(validate_net_receive_length(13), Ok(1));
    assert_eq!(validate_net_receive_length(1_526), Ok(1_514));
    assert_eq!(
        validate_net_receive_length(1_527),
        Err(NetReceiveLengthError::BufferOverrun {
            maximum: 1_526,
            observed: 1_527,
        })
    );

    for (used_length, frame_length) in [(12, 0), (13, 1), (1_526, 1_514)] {
        let mut device = NetDeviceModel::new();
        let submission = device.post_receive().unwrap();
        let completion = device
            .complete_receive(
                1,
                UsedElement::new(submission.token.head as u32, used_length),
                VirtioNetHeader::from_bytes([0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0]),
            )
            .unwrap();
        assert_eq!(completion.frame_length, frame_length);
        assert_eq!(device.inflight(NetQueue::Receive), 0);
    }

    for (used_length, expected) in [
        (
            11,
            NetQueueError::UsedLengthTooShort {
                minimum: 12,
                observed: 11,
            },
        ),
        (
            1_527,
            NetQueueError::UsedLengthOutOfRange {
                maximum: 1_526,
                observed: 1_527,
            },
        ),
    ] {
        let mut device = NetDeviceModel::new();
        let submission = device.post_receive().unwrap();
        // Deliberately malformed too: a short used length must be rejected
        // before this header can be interpreted.
        let malformed_header = VirtioNetHeader {
            flags: 0xff,
            ..VirtioNetHeader::default()
        };
        assert_eq!(
            device.complete_receive(
                1,
                UsedElement::new(submission.token.head as u32, used_length),
                malformed_header,
            ),
            Err(expected)
        );
        assert_eq!(
            device.state(),
            NetDeviceState::ResetRequired {
                reason: NetResetReason::MalformedCompletion
            }
        );
    }
}

#[test]
fn unsupported_receive_metadata_quarantines_both_queues_until_reset() {
    for header in [
        VirtioNetHeader {
            flags: 1,
            ..VirtioNetHeader::received_without_offload()
        },
        VirtioNetHeader {
            gso_type: 1,
            ..VirtioNetHeader::received_without_offload()
        },
        VirtioNetHeader {
            num_buffers: 2u16.to_le(),
            ..VirtioNetHeader::received_without_offload()
        },
    ] {
        let mut device = NetDeviceModel::new();
        let receive = device.post_receive().unwrap();
        let transmit = device.submit_transmit(60).unwrap();
        assert_eq!(
            device.complete_receive(1, UsedElement::new(receive.token.head as u32, 72), header,),
            Err(NetQueueError::UnsupportedReceiveHeader { observed: header })
        );
        assert_eq!(device.inflight(NetQueue::Receive), 1);
        assert_eq!(device.inflight(NetQueue::Transmit), 1);
        assert!(!device.slot_reusable(NetQueue::Receive, receive.token.head));
        assert!(!device.slot_reusable(NetQueue::Transmit, transmit.token.head));
        assert_eq!(
            device.complete_transmit(1, UsedElement::new(transmit.token.head as u32, 0)),
            Err(NetQueueError::ResetRequired)
        );
    }
}

#[test]
fn transmit_completion_ignores_the_reserved_used_length() {
    for reported in [0, 1, NET_HEADER_SIZE + 60, u32::MAX] {
        let mut device = NetDeviceModel::new();
        let submission = device.submit_transmit(60).unwrap();
        let completion = complete_net_tx(&mut device, submission, reported);
        assert_eq!(completion.submission, submission);
        assert!(device.slot_reusable(NetQueue::Transmit, submission.token.head));
    }
}

#[test]
fn batched_and_out_of_order_used_entries_advance_one_cursor_at_a_time() {
    let mut device = NetDeviceModel::new();
    let submissions = [
        device.post_receive().unwrap(),
        device.post_receive().unwrap(),
        device.post_receive().unwrap(),
    ];

    for submission in [submissions[2], submissions[0], submissions[1]] {
        let completion = device
            .complete_receive(
                3,
                UsedElement::new(submission.token.head as u32, 72),
                VirtioNetHeader::received_without_offload(),
            )
            .unwrap();
        assert_eq!(completion.submission, submission);
    }
    assert_eq!(device.used_index(NetQueue::Receive), 3);
    assert_eq!(device.inflight(NetQueue::Receive), 0);
}

#[test]
fn no_used_entry_is_benign_but_every_malformed_used_field_requires_device_reset() {
    let mut no_completion = NetDeviceModel::new();
    let active = no_completion.post_receive().unwrap();
    assert_eq!(
        no_completion.complete_receive(
            0,
            UsedElement::new(active.token.head as u32, 72),
            VirtioNetHeader::received_without_offload(),
        ),
        Err(NetQueueError::NoUsedCompletion {
            queue: NetQueue::Receive
        })
    );
    assert_eq!(no_completion.state(), NetDeviceState::Active);
    assert_eq!(
        no_completion.active_submission(NetQueue::Receive, 0),
        Some(active)
    );

    let cases = [
        (
            2,
            UsedElement::new(0, 72),
            NetQueueError::UsedIndexAdvancedTooFar {
                queue: NetQueue::Receive,
                pending: 2,
                active: 1,
            },
        ),
        (
            1,
            UsedElement::new(8, 72),
            NetQueueError::UsedIdOutOfRange {
                queue: NetQueue::Receive,
                observed: 8,
            },
        ),
        (
            1,
            UsedElement::new(1, 72),
            NetQueueError::UsedIdNotActive {
                queue: NetQueue::Receive,
                observed: 1,
            },
        ),
    ];
    for (observed_index, used, expected) in cases {
        let mut device = NetDeviceModel::new();
        device.post_receive().unwrap();
        assert_eq!(
            device.complete_receive(
                observed_index,
                used,
                VirtioNetHeader::received_without_offload(),
            ),
            Err(expected)
        );
        assert_eq!(
            device.state(),
            NetDeviceState::ResetRequired {
                reason: NetResetReason::MalformedCompletion
            }
        );
    }

    let mut duplicate = NetDeviceModel::new();
    let first = duplicate.post_receive().unwrap();
    let second = duplicate.post_receive().unwrap();
    complete_net_rx(&mut duplicate, first, 72);
    assert_eq!(
        duplicate.complete_receive(
            2,
            UsedElement::new(first.token.head as u32, 72),
            VirtioNetHeader::received_without_offload(),
        ),
        Err(NetQueueError::UsedIdNotActive {
            queue: NetQueue::Receive,
            observed: first.token.head
        })
    );
    assert_eq!(
        duplicate.active_submission(NetQueue::Receive, second.token.head),
        Some(second)
    );
}

#[test]
fn wrong_stale_and_cross_queue_tokens_never_steal_live_dma() {
    let mut device = NetDeviceModel::new();
    let receive = device.post_receive().unwrap();
    let transmit = device.submit_transmit(60).unwrap();

    for wrong in [
        NetToken {
            serial: receive.token.serial + 1,
            ..receive.token
        },
        NetToken {
            queue: NetQueue::Transmit,
            ..receive.token
        },
        NetToken {
            head: 7,
            ..receive.token
        },
    ] {
        assert_eq!(device.cancel(wrong), Err(NetQueueError::WrongToken));
        assert_eq!(device.state(), NetDeviceState::Active);
    }
    let stale = NetToken {
        epoch: receive.token.epoch - 1,
        ..receive.token
    };
    assert_eq!(
        device.timeout(stale),
        Err(NetQueueError::StaleSession {
            expected: receive.token.epoch,
            observed: stale.epoch,
        })
    );
    assert_eq!(
        device.active_submission(NetQueue::Receive, receive.token.head),
        Some(receive)
    );
    assert_eq!(
        device.active_submission(NetQueue::Transmit, transmit.token.head),
        Some(transmit)
    );
}

#[test]
fn reset_is_device_wide_and_requires_zero_then_reinitialization() {
    let mut device = NetDeviceModel::new();
    let receive = device.post_receive().unwrap();
    let transmit = device.submit_transmit(60).unwrap();
    assert_eq!(device.timeout(receive.token), Ok(()));
    assert_eq!(
        device.state(),
        NetDeviceState::ResetRequired {
            reason: NetResetReason::Timeout
        }
    );
    assert_eq!(device.post_receive(), Err(NetQueueError::ResetRequired));
    assert_eq!(
        device.complete_transmit(1, UsedElement::new(transmit.token.head as u32, 0)),
        Err(NetQueueError::ResetRequired)
    );
    assert!(!device.all_dma_reusable());
    assert_eq!(
        device.confirm_reset(STATUS_ACKNOWLEDGE),
        Err(NetQueueError::ResetNotConfirmed {
            observed_status: STATUS_ACKNOWLEDGE
        })
    );
    assert_eq!(device.inflight(NetQueue::Receive), 1);
    assert_eq!(device.inflight(NetQueue::Transmit), 1);

    assert_eq!(device.confirm_reset(0), Ok(()));
    assert_eq!(device.state(), NetDeviceState::ResetConfirmed);
    assert_eq!(device.epoch(), receive.token.epoch + 1);
    assert_eq!(device.inflight(NetQueue::Receive), 0);
    assert_eq!(device.inflight(NetQueue::Transmit), 0);
    assert_eq!(device.available_index(NetQueue::Receive), 0);
    assert_eq!(device.used_index(NetQueue::Transmit), 0);
    assert!(device.all_dma_reusable());
    assert_eq!(
        device.submit_transmit(60),
        Err(NetQueueError::ReinitializeRequired)
    );
    assert_eq!(device.reinitialize(), Ok(()));
    assert_eq!(device.state(), NetDeviceState::Active);
    let fresh = device.submit_transmit(60).unwrap();
    assert_eq!(fresh.token.epoch, receive.token.epoch + 1);
    assert_eq!(
        device.cancel(transmit.token),
        Err(NetQueueError::StaleSession {
            expected: fresh.token.epoch,
            observed: transmit.token.epoch,
        })
    );
    assert_eq!(
        device.active_submission(NetQueue::Transmit, fresh.token.head),
        Some(fresh)
    );
}

#[test]
fn terminal_network_quarantine_and_identity_exhaustion_fail_closed() {
    let mut device = NetDeviceModel::new();
    let receive = device.post_receive().unwrap();
    device.quarantine(NetResetReason::ResetFailed);
    assert_eq!(
        device.state(),
        NetDeviceState::Quarantined {
            reason: NetResetReason::ResetFailed
        }
    );
    assert_eq!(device.post_receive(), Err(NetQueueError::Quarantined));
    assert_eq!(device.submit_transmit(0), Err(NetQueueError::Quarantined));
    assert_eq!(
        device.cancel(receive.token),
        Err(NetQueueError::Quarantined)
    );
    assert_eq!(device.confirm_reset(0), Err(NetQueueError::Quarantined));
    assert_eq!(device.reinitialize(), Err(NetQueueError::Quarantined));
    assert!(!device.slot_reusable(NetQueue::Receive, receive.token.head));
    device.require_reset(NetResetReason::DriverFault);
    assert!(matches!(device.state(), NetDeviceState::Quarantined { .. }));

    assert!(NetDeviceModel::at_epoch(0).is_none());
    assert!(NetDeviceModel::at_epoch_and_serial(1, 0).is_none());
    let mut serial = NetDeviceModel::at_epoch_and_serial(1, u64::MAX).unwrap();
    assert_eq!(serial.post_receive(), Err(NetQueueError::SerialExhausted));
    assert_eq!(
        serial.state(),
        NetDeviceState::Quarantined {
            reason: NetResetReason::IdentityExhausted
        }
    );

    let mut epoch = NetDeviceModel::at_epoch(u64::MAX).unwrap();
    let active = epoch.post_receive().unwrap();
    epoch.require_reset(NetResetReason::DriverFault);
    assert_eq!(epoch.confirm_reset(0), Err(NetQueueError::EpochExhausted));
    assert_eq!(epoch.epoch(), u64::MAX);
    assert_eq!(
        epoch.active_submission(NetQueue::Receive, active.token.head),
        Some(active)
    );
    assert!(!epoch.slot_reusable(NetQueue::Receive, active.token.head));
}

#[test]
fn network_ring_wrap_does_not_create_token_aba() {
    let mut device = NetDeviceModel::new();
    let first = device.post_receive().unwrap();
    complete_net_rx(&mut device, first, 72);

    for _ in 1..=u16::MAX {
        let submission = device.post_receive().unwrap();
        complete_net_rx(&mut device, submission, 72);
    }
    assert_eq!(device.available_index(NetQueue::Receive), 0);
    assert_eq!(device.used_index(NetQueue::Receive), 0);

    let current = device.post_receive().unwrap();
    assert_eq!(current.token.head, first.token.head);
    assert_eq!(current.available_slot, first.available_slot);
    assert_ne!(current.token.serial, first.token.serial);
    assert_eq!(device.cancel(first.token), Err(NetQueueError::WrongToken));
    assert_eq!(
        device.active_submission(NetQueue::Receive, current.token.head),
        Some(current)
    );
}
