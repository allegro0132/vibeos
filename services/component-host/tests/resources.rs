use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vibeos_component_host::{
    AuthorityError, BlobBackend, BlobBackendFault, BlobError, BlobResource, ClockBackend,
    ClockBackendFault, ClockError, ClockResource, ComponentAuthority, ComponentAuthoritySpace,
    ComponentCallError, ComponentHostServices, LogField, LogLevel, RandomBackend,
    RandomBackendFault, RandomError, RandomResource, SharedCSpace, StructuredLogError,
    StructuredLogEvent, StructuredLogResource, StructuredLogSink, StructuredLogSinkFault,
    ValidatedLogEvent, MAX_BLOB_READ_BYTES, MAX_LOG_EVENT_BYTES, MAX_LOG_FIELDS,
    MAX_LOG_FIELD_KEY_BYTES, MAX_LOG_FIELD_VALUE_BYTES, MAX_LOG_MESSAGE_BYTES,
    MAX_LOG_TARGET_BYTES, MAX_RANDOM_FILL_BYTES,
};
use vibeos_core::cap::{CSpace, Resource, Rights};
use vibeos_core::sync::SpinLock;

fn bind<T: Resource>(
    name: &str,
    resource: Arc<T>,
    rights: Rights,
    bind: impl FnOnce(&ComponentAuthoritySpace, vibeos_core::cap::Cap) -> ComponentAuthority,
) -> (SharedCSpace, ComponentAuthority) {
    let cspace = Arc::new(SpinLock::new(CSpace::new(name)));
    let binding = ComponentAuthoritySpace::new(cspace.clone(), 1).unwrap();
    let cap = cspace.lock().mint(resource, rights);
    let authority = bind(&binding, cap);
    (cspace, authority)
}

struct ScriptClock {
    values: &'static [u64],
    next: AtomicUsize,
    fail_at: Option<usize>,
}

impl ClockBackend for ScriptClock {
    fn now_ns(&self) -> Result<u64, ClockBackendFault> {
        let index = self.next.fetch_add(1, Ordering::SeqCst);
        if self.fail_at == Some(index) {
            return Err(ClockBackendFault);
        }
        self.values.get(index).copied().ok_or(ClockBackendFault)
    }
}

#[test]
fn clock_is_monotonic_bounded_by_read_authority_and_reports_backend_faults() {
    let backend = Arc::new(ScriptClock {
        values: &[10, 12, 11],
        next: AtomicUsize::new(0),
        fail_at: None,
    });
    let (cspace, authority) = bind(
        "clock",
        Arc::new(ClockResource::new(backend)),
        Rights::READ,
        |binding, cap| {
            binding
                .bind_ephemeral::<ClockResource>(cap, Rights::READ)
                .unwrap()
        },
    );
    assert_eq!(
        ComponentHostServices::clock_now_ns(&authority, &cspace),
        Ok(10)
    );
    assert_eq!(
        ComponentHostServices::clock_now_ns(&authority, &cspace),
        Ok(12)
    );
    assert_eq!(
        ComponentHostServices::clock_now_ns(&authority, &cspace),
        Err(ComponentCallError::Resource(ClockError::NonMonotonic)),
    );
    assert_eq!(cspace.lock().list().len(), 1);
    assert_eq!(cspace.lock().list()[0].2, Rights::READ);

    let faulty = Arc::new(ScriptClock {
        values: &[],
        next: AtomicUsize::new(0),
        fail_at: Some(0),
    });
    let (fault_space, fault_authority) = bind(
        "faulty-clock",
        Arc::new(ClockResource::new(faulty)),
        Rights::READ,
        |binding, cap| {
            binding
                .bind_ephemeral::<ClockResource>(cap, Rights::READ)
                .unwrap()
        },
    );
    assert_eq!(
        ComponentHostServices::clock_now_ns(&fault_authority, &fault_space),
        Err(ComponentCallError::Resource(ClockError::BackendFault)),
    );
}

#[test]
fn clock_wrong_rights_and_revocation_are_denied_before_backend_use() {
    let backend = Arc::new(ScriptClock {
        values: &[1],
        next: AtomicUsize::new(0),
        fail_at: None,
    });
    let wrong_space = Arc::new(SpinLock::new(CSpace::new("wrong-clock-rights")));
    let wrong_binding = ComponentAuthoritySpace::new(wrong_space.clone(), 1).unwrap();
    let wrong_cap = wrong_space
        .lock()
        .mint(Arc::new(ClockResource::new(backend.clone())), Rights::WRITE);
    assert_eq!(
        wrong_binding
            .bind_ephemeral::<ClockResource>(wrong_cap, Rights::WRITE)
            .unwrap_err(),
        AuthorityError::RightsExceedCeiling,
    );
    assert_eq!(backend.next.load(Ordering::SeqCst), 0);

    let live_backend = Arc::new(ScriptClock {
        values: &[2],
        next: AtomicUsize::new(0),
        fail_at: None,
    });
    let cspace = Arc::new(SpinLock::new(CSpace::new("revoked-clock")));
    let binding = ComponentAuthoritySpace::new(cspace.clone(), 1).unwrap();
    let cap = cspace.lock().mint(
        Arc::new(ClockResource::new(live_backend.clone())),
        Rights::READ,
    );
    let authority = binding
        .bind_ephemeral::<ClockResource>(cap, Rights::READ)
        .unwrap();
    assert_eq!(cspace.lock().revoke_slot(cap.slot()), 1);
    assert_eq!(
        ComponentHostServices::clock_now_ns(&authority, &cspace),
        Err(ComponentCallError::Authority(
            AuthorityError::InvalidOrRevoked,
        )),
    );
    assert_eq!(live_backend.next.load(Ordering::SeqCst), 0);
}

#[test]
fn service_resolution_rejects_wrong_space_collision_and_restart() {
    let first_backend = Arc::new(ScriptClock {
        values: &[1],
        next: AtomicUsize::new(0),
        fail_at: None,
    });
    let second_backend = Arc::new(ScriptClock {
        values: &[2],
        next: AtomicUsize::new(0),
        fail_at: None,
    });
    let (first, authority) = bind(
        "service-first",
        Arc::new(ClockResource::new(first_backend.clone())),
        Rights::READ,
        |binding, cap| {
            binding
                .bind_ephemeral::<ClockResource>(cap, Rights::READ)
                .unwrap()
        },
    );
    let (second, _) = bind(
        "service-second",
        Arc::new(ClockResource::new(second_backend.clone())),
        Rights::READ,
        |binding, cap| {
            binding
                .bind_ephemeral::<ClockResource>(cap, Rights::READ)
                .unwrap()
        },
    );
    assert_eq!(first.lock().list()[0].0, second.lock().list()[0].0);
    assert_eq!(
        ComponentHostServices::clock_now_ns(&authority, &second),
        Err(ComponentCallError::Authority(AuthorityError::WrongSpace)),
    );
    assert_eq!(first_backend.next.load(Ordering::SeqCst), 0);
    assert_eq!(second_backend.next.load(Ordering::SeqCst), 0);

    assert_eq!(first.lock().reset(), 1);
    assert_eq!(
        ComponentHostServices::clock_now_ns(&authority, &first),
        Err(ComponentCallError::Authority(
            AuthorityError::IncarnationMismatch,
        )),
    );
    assert_eq!(first_backend.next.load(Ordering::SeqCst), 0);
}

struct FillBackend {
    calls: AtomicUsize,
    fail: bool,
}

impl RandomBackend for FillBackend {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomBackendFault> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        destination.fill(0xa5);
        if self.fail {
            Err(RandomBackendFault)
        } else {
            Ok(())
        }
    }
}

#[test]
fn random_fill_is_bounded_atomic_on_fault_and_accepts_empty_output() {
    let backend = Arc::new(FillBackend {
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let (cspace, authority) = bind(
        "random",
        Arc::new(RandomResource::new(backend.clone())),
        Rights::READ,
        |binding, cap| {
            binding
                .bind_ephemeral::<RandomResource>(cap, Rights::READ)
                .unwrap()
        },
    );
    let mut empty = [];
    assert_eq!(
        ComponentHostServices::random_fill_exact(&authority, &cspace, &mut empty),
        Ok(()),
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);

    let mut output = [0_u8; 8];
    assert_eq!(
        ComponentHostServices::random_fill_exact(&authority, &cspace, &mut output),
        Ok(()),
    );
    assert_eq!(output, [0xa5; 8]);

    let mut oversized = vec![0_u8; MAX_RANDOM_FILL_BYTES + 1];
    assert_eq!(
        ComponentHostServices::random_fill_exact(&authority, &cspace, &mut oversized),
        Err(ComponentCallError::Resource(RandomError::TooLarge {
            requested: MAX_RANDOM_FILL_BYTES + 1,
            maximum: MAX_RANDOM_FILL_BYTES,
        })),
    );

    let faulty = Arc::new(FillBackend {
        calls: AtomicUsize::new(0),
        fail: true,
    });
    let (fault_space, fault_authority) = bind(
        "faulty-random",
        Arc::new(RandomResource::new(faulty)),
        Rights::READ,
        |binding, cap| {
            binding
                .bind_ephemeral::<RandomResource>(cap, Rights::READ)
                .unwrap()
        },
    );
    let mut unchanged = [0x5a; 4];
    assert_eq!(
        ComponentHostServices::random_fill_exact(&fault_authority, &fault_space, &mut unchanged,),
        Err(ComponentCallError::Resource(RandomError::BackendFault)),
    );
    assert_eq!(unchanged, [0x5a; 4]);
}

struct MemoryBlob {
    bytes: &'static [u8],
    fail_len: bool,
    fail_read: bool,
    reads: AtomicUsize,
}

impl BlobBackend for MemoryBlob {
    fn len(&self) -> Result<u64, BlobBackendFault> {
        if self.fail_len {
            Err(BlobBackendFault)
        } else {
            Ok(self.bytes.len() as u64)
        }
    }

    fn read_exact(&self, offset: u64, destination: &mut [u8]) -> Result<(), BlobBackendFault> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.fail_read {
            return Err(BlobBackendFault);
        }
        let start = usize::try_from(offset).map_err(|_| BlobBackendFault)?;
        let end = start
            .checked_add(destination.len())
            .ok_or(BlobBackendFault)?;
        destination.copy_from_slice(self.bytes.get(start..end).ok_or(BlobBackendFault)?);
        Ok(())
    }
}

fn blob_authority(name: &str, backend: Arc<MemoryBlob>) -> (SharedCSpace, ComponentAuthority) {
    bind(
        name,
        Arc::new(BlobResource::new(backend)),
        Rights::READ,
        |binding, cap| {
            binding
                .bind_ephemeral::<BlobResource>(cap, Rights::READ)
                .unwrap()
        },
    )
}

#[test]
fn blob_reads_are_checked_bounded_and_empty_safe() {
    let backend = Arc::new(MemoryBlob {
        bytes: b"abcdef",
        fail_len: false,
        fail_read: false,
        reads: AtomicUsize::new(0),
    });
    let (cspace, authority) = blob_authority("blob", backend.clone());
    assert_eq!(ComponentHostServices::blob_len(&authority, &cspace), Ok(6));
    assert_eq!(
        ComponentHostServices::blob_read(&authority, &cspace, 2, 3),
        Ok(b"cde".to_vec()),
    );
    assert_eq!(
        ComponentHostServices::blob_read(&authority, &cspace, 6, 0),
        Ok(Vec::new()),
    );
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        ComponentHostServices::blob_read(&authority, &cspace, 7, 0),
        Err(ComponentCallError::Resource(BlobError::OutOfBounds {
            offset: 7,
            length: 0,
            blob_length: 6,
        })),
    );
    assert_eq!(
        ComponentHostServices::blob_read(&authority, &cspace, u64::MAX, 1),
        Err(ComponentCallError::Resource(BlobError::RangeOverflow)),
    );
    assert_eq!(
        ComponentHostServices::blob_read(&authority, &cspace, 0, MAX_BLOB_READ_BYTES + 1,),
        Err(ComponentCallError::Resource(BlobError::TooLarge {
            requested: MAX_BLOB_READ_BYTES + 1,
            maximum: MAX_BLOB_READ_BYTES,
        })),
    );
}

#[test]
fn blob_backend_faults_are_distinct() {
    let len_fault = Arc::new(MemoryBlob {
        bytes: b"x",
        fail_len: true,
        fail_read: false,
        reads: AtomicUsize::new(0),
    });
    let (len_space, len_authority) = blob_authority("blob-len-fault", len_fault);
    assert_eq!(
        ComponentHostServices::blob_len(&len_authority, &len_space),
        Err(ComponentCallError::Resource(BlobError::BackendFault)),
    );

    let read_fault = Arc::new(MemoryBlob {
        bytes: b"x",
        fail_len: false,
        fail_read: true,
        reads: AtomicUsize::new(0),
    });
    let (read_space, read_authority) = blob_authority("blob-read-fault", read_fault);
    assert_eq!(
        ComponentHostServices::blob_read(&read_authority, &read_space, 0, 1),
        Err(ComponentCallError::Resource(BlobError::BackendFault)),
    );
}

#[test]
fn random_blob_and_log_each_enforce_exact_service_rights_and_revocation() {
    let random_backend = Arc::new(FillBackend {
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let wrong_random_space = Arc::new(SpinLock::new(CSpace::new("wrong-random-rights")));
    let wrong_random_binding = ComponentAuthoritySpace::new(wrong_random_space.clone(), 1).unwrap();
    let wrong_random_cap = wrong_random_space.lock().mint(
        Arc::new(RandomResource::new(random_backend.clone())),
        Rights::WRITE,
    );
    assert_eq!(
        wrong_random_binding
            .bind_ephemeral::<RandomResource>(wrong_random_cap, Rights::WRITE)
            .unwrap_err(),
        AuthorityError::RightsExceedCeiling,
    );
    assert_eq!(random_backend.calls.load(Ordering::SeqCst), 0);

    let mut random_output = [0_u8; 1];

    let live_random_backend = Arc::new(FillBackend {
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let (random_space, random_authority) = bind(
        "revoked-random",
        Arc::new(RandomResource::new(live_random_backend.clone())),
        Rights::READ,
        |binding, cap| {
            binding
                .bind_ephemeral::<RandomResource>(cap, Rights::READ)
                .unwrap()
        },
    );
    let random_cap = random_space.lock().list()[0].0;
    assert_eq!(random_space.lock().revoke_slot(random_cap.slot()), 1);
    assert!(matches!(
        ComponentHostServices::random_fill_exact(
            &random_authority,
            &random_space,
            &mut random_output,
        ),
        Err(ComponentCallError::Authority(
            AuthorityError::InvalidOrRevoked,
        )),
    ));
    assert_eq!(live_random_backend.calls.load(Ordering::SeqCst), 0);

    let blob_backend = Arc::new(MemoryBlob {
        bytes: b"blob",
        fail_len: false,
        fail_read: false,
        reads: AtomicUsize::new(0),
    });
    let wrong_blob_space = Arc::new(SpinLock::new(CSpace::new("wrong-blob-rights")));
    let wrong_blob_binding = ComponentAuthoritySpace::new(wrong_blob_space.clone(), 1).unwrap();
    let wrong_blob_cap = wrong_blob_space.lock().mint(
        Arc::new(BlobResource::new(blob_backend.clone())),
        Rights::WRITE,
    );
    assert_eq!(
        wrong_blob_binding
            .bind_ephemeral::<BlobResource>(wrong_blob_cap, Rights::WRITE)
            .unwrap_err(),
        AuthorityError::RightsExceedCeiling,
    );
    assert_eq!(blob_backend.reads.load(Ordering::SeqCst), 0);

    let (blob_space, blob_authority) = blob_authority("revoked-blob", blob_backend.clone());
    let blob_cap = blob_space.lock().list()[0].0;
    assert_eq!(blob_space.lock().revoke_slot(blob_cap.slot()), 1);
    assert!(matches!(
        ComponentHostServices::blob_read(&blob_authority, &blob_space, 0, 1),
        Err(ComponentCallError::Authority(
            AuthorityError::InvalidOrRevoked,
        )),
    ));
    assert_eq!(blob_backend.reads.load(Ordering::SeqCst), 0);

    let log_sink = Arc::new(RecordingSink {
        events: Mutex::new(Vec::new()),
        fail: false,
    });
    let (log_space, log_authority) = log_authority("revoked-log", log_sink.clone(), Rights::WRITE);
    let log_cap = log_space.lock().list()[0].0;
    assert_eq!(log_space.lock().revoke_slot(log_cap.slot()), 1);
    let event = StructuredLogEvent {
        level: LogLevel::Info,
        target: b"component",
        message: b"message",
        fields: &[],
    };
    assert!(matches!(
        ComponentHostServices::structured_log_write(&log_authority, &log_space, &event),
        Err(ComponentCallError::Authority(
            AuthorityError::InvalidOrRevoked,
        )),
    ));
    assert!(log_sink.events.lock().unwrap().is_empty());
}

#[derive(Debug, PartialEq, Eq)]
struct RecordedEvent {
    level: LogLevel,
    target: String,
    message: String,
    fields: Vec<(String, String)>,
}

struct RecordingSink {
    events: Mutex<Vec<RecordedEvent>>,
    fail: bool,
}

impl StructuredLogSink for RecordingSink {
    fn write(&self, event: &ValidatedLogEvent<'_>) -> Result<(), StructuredLogSinkFault> {
        if self.fail {
            return Err(StructuredLogSinkFault);
        }
        self.events.lock().unwrap().push(RecordedEvent {
            level: event.level,
            target: event.target.to_owned(),
            message: event.message.to_owned(),
            fields: event
                .fields
                .iter()
                .map(|field| (field.key.to_owned(), field.value.to_owned()))
                .collect(),
        });
        Ok(())
    }
}

fn log_authority(
    name: &str,
    sink: Arc<RecordingSink>,
    rights: Rights,
) -> (SharedCSpace, ComponentAuthority) {
    bind(
        name,
        Arc::new(StructuredLogResource::new(sink)),
        rights,
        |binding, cap| {
            binding
                .bind_ephemeral::<StructuredLogResource>(cap, rights)
                .unwrap()
        },
    )
}

#[test]
fn structured_log_validates_utf8_empty_and_individual_bounds_before_sink() {
    let sink = Arc::new(RecordingSink {
        events: Mutex::new(Vec::new()),
        fail: false,
    });
    let (cspace, authority) = log_authority("log", sink.clone(), Rights::WRITE);
    let fields = [LogField {
        key: b"request_id",
        value: b"42",
    }];
    let event = StructuredLogEvent {
        level: LogLevel::Info,
        target: b"component",
        message: b"",
        fields: &fields,
    };
    assert_eq!(
        ComponentHostServices::structured_log_write(&authority, &cspace, &event),
        Ok(()),
    );
    assert_eq!(sink.events.lock().unwrap().len(), 1);

    let empty_target = StructuredLogEvent {
        target: b"",
        ..event
    };
    assert_eq!(
        ComponentHostServices::structured_log_write(&authority, &cspace, &empty_target),
        Err(ComponentCallError::Resource(
            StructuredLogError::EmptyTarget,
        )),
    );
    let invalid_message = StructuredLogEvent {
        message: &[0xff],
        ..event
    };
    assert_eq!(
        ComponentHostServices::structured_log_write(&authority, &cspace, &invalid_message),
        Err(ComponentCallError::Resource(
            StructuredLogError::InvalidMessageUtf8,
        )),
    );

    let long_target = vec![b't'; MAX_LOG_TARGET_BYTES + 1];
    let too_long_target = StructuredLogEvent {
        target: &long_target,
        ..event
    };
    assert!(matches!(
        ComponentHostServices::structured_log_write(&authority, &cspace, &too_long_target),
        Err(ComponentCallError::Resource(
            StructuredLogError::TargetTooLong { .. }
        )),
    ));
    let long_message = vec![b'm'; MAX_LOG_MESSAGE_BYTES + 1];
    let too_long_message = StructuredLogEvent {
        message: &long_message,
        ..event
    };
    assert!(matches!(
        ComponentHostServices::structured_log_write(&authority, &cspace, &too_long_message),
        Err(ComponentCallError::Resource(
            StructuredLogError::MessageTooLong { .. }
        )),
    ));

    let field = LogField {
        key: b"k",
        value: b"v",
    };
    let too_many_fields = vec![field; MAX_LOG_FIELDS + 1];
    let event_with_too_many = StructuredLogEvent {
        fields: &too_many_fields,
        ..event
    };
    assert!(matches!(
        ComponentHostServices::structured_log_write(&authority, &cspace, &event_with_too_many),
        Err(ComponentCallError::Resource(
            StructuredLogError::TooManyFields { .. }
        )),
    ));

    let long_key = vec![b'k'; MAX_LOG_FIELD_KEY_BYTES + 1];
    let long_key_fields = [LogField {
        key: &long_key,
        value: b"v",
    }];
    let long_key_event = StructuredLogEvent {
        fields: &long_key_fields,
        ..event
    };
    assert!(matches!(
        ComponentHostServices::structured_log_write(&authority, &cspace, &long_key_event),
        Err(ComponentCallError::Resource(
            StructuredLogError::FieldKeyTooLong { .. }
        )),
    ));
    let long_value = vec![b'v'; MAX_LOG_FIELD_VALUE_BYTES + 1];
    let long_value_fields = [LogField {
        key: b"k",
        value: &long_value,
    }];
    let long_value_event = StructuredLogEvent {
        fields: &long_value_fields,
        ..event
    };
    assert!(matches!(
        ComponentHostServices::structured_log_write(&authority, &cspace, &long_value_event),
        Err(ComponentCallError::Resource(
            StructuredLogError::FieldValueTooLong { .. }
        )),
    ));
    assert_eq!(sink.events.lock().unwrap().len(), 1);
}

#[test]
fn structured_log_enforces_aggregate_bound_rights_and_sink_faults() {
    let sink = Arc::new(RecordingSink {
        events: Mutex::new(Vec::new()),
        fail: false,
    });
    let (cspace, authority) = log_authority("bounded-log", sink.clone(), Rights::WRITE);
    let target = vec![b't'; MAX_LOG_TARGET_BYTES];
    let message = vec![b'm'; MAX_LOG_MESSAGE_BYTES];
    let key = vec![b'k'; MAX_LOG_FIELD_KEY_BYTES];
    let value = vec![b'v'; MAX_LOG_FIELD_VALUE_BYTES];
    let field = LogField {
        key: &key,
        value: &value,
    };
    let fields = vec![field; MAX_LOG_FIELDS];
    let oversized = StructuredLogEvent {
        level: LogLevel::Warn,
        target: &target,
        message: &message,
        fields: &fields,
    };
    assert!(MAX_LOG_EVENT_BYTES < target.len() + message.len() + fields.len() * 320);
    assert!(matches!(
        ComponentHostServices::structured_log_write(&authority, &cspace, &oversized),
        Err(ComponentCallError::Resource(
            StructuredLogError::EventTooLarge { .. }
        )),
    ));
    assert!(sink.events.lock().unwrap().is_empty());

    let wrong_sink = Arc::new(RecordingSink {
        events: Mutex::new(Vec::new()),
        fail: false,
    });
    let wrong_space = Arc::new(SpinLock::new(CSpace::new("read-only-log")));
    let wrong_binding = ComponentAuthoritySpace::new(wrong_space.clone(), 1).unwrap();
    let wrong_cap = wrong_space.lock().mint(
        Arc::new(StructuredLogResource::new(wrong_sink.clone())),
        Rights::READ,
    );
    assert_eq!(
        wrong_binding
            .bind_ephemeral::<StructuredLogResource>(wrong_cap, Rights::READ)
            .unwrap_err(),
        AuthorityError::RightsExceedCeiling,
    );
    let minimal = StructuredLogEvent {
        level: LogLevel::Error,
        target: b"component",
        message: b"failure",
        fields: &[],
    };
    assert!(wrong_sink.events.lock().unwrap().is_empty());

    let failing_sink = Arc::new(RecordingSink {
        events: Mutex::new(Vec::new()),
        fail: true,
    });
    let (fault_space, fault_authority) = log_authority("faulty-log", failing_sink, Rights::WRITE);
    assert_eq!(
        ComponentHostServices::structured_log_write(&fault_authority, &fault_space, &minimal,),
        Err(ComponentCallError::Resource(
            StructuredLogError::BackendFault,
        )),
    );

    assert_eq!(std::mem::size_of::<ComponentHostServices>(), 0);
    assert_eq!(cspace.lock().list().len(), 1);
    assert_eq!(cspace.lock().list()[0].2, Rights::WRITE);
}
