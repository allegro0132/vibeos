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
