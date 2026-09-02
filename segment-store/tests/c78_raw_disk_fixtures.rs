//! C7.8 raw fault-media corpus exporter.
//!
//! This integration test deliberately produces bytes and reconstruction
//! recipes, not a recovery verdict.  The independent C7.8 host verifier owns
//! every semantic classification.  The exporter reuses the real SegmentStore
//! publication path and the C7.6 policy-v3 graph fixture machinery exercised
//! by `c74_crash_safe_publication`.

mod fixture {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File, OpenOptions};
    use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use vibeos_durable_format::{
        encode_object_transaction, preflight_recovery, preview_grant_transaction,
        preview_revoke_transaction, DerivationId, DurableRights, GrantFlags, GrantRecord, ObjectId,
        ObjectKind, RecordBody, RecordChain, ResourceKind, RootPolicy, SlotIdentity, SpaceId,
        StoreId, TransactionId, RECORD_SIZE,
    };
    use vibeos_segment_format::{admitted_pages, Page, StoreUuid};
    use vibeos_segment_store::{
        root_policy_commitment, FormatOptions, PageDevice, PageDeviceInfo,
        PersistentAuthorityImport, SegmentStore, StoreLimits, StoreRuntimeContext,
        LEGACY_SYSTEM_PRINCIPAL,
    };
    use vibeos_storage_device::MutationFailure;

    const SEGMENTS: u64 = 32;
    const STORE_ID_RAW: u128 = 0x5649_4245_4f53_2d53_544f_5245_2d4d_3401;
    const ARTIFACT_KIND_RAW: u32 = 0x434d_5031;
    const EVIDENCE_KIND_RAW: u32 = 0x434d_4531;
    const STORED_OBJECT_KIND_RAW: u32 = 0x5354_4f52;
    const C76_GRAPH_SPACE_RAW: u128 = 0x5649_4245_4f53_2d47_5241_5048_2d56_3100;
    const C76_GRAPH_VERSION_KIND_RAW: u32 = 0x4347_5631;
    const C76_GRAPH_EVIDENCE_KIND_RAW: u32 = 0x4347_4531;
    const POLICY_V3: &[u8] = b"vibeos.storage-v2.external-policy.v3\0persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0graph-space=0x564942454f532d47524150482d563100,slot=0,generations=0..1,rights=r,kind=0x43475631\0graph-attachments=exact-root-relative,per-generation=3*0x434d5031+3*0x434d4531+1*0x43474531,inline=1,ungranted=1,max-replacement=1";

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        loop {
            match future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Injected,
        DriverRestarted,
        OutsideRange,
    }

    impl core::fmt::Display for TestError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(formatter, "{self:?}")
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    enum MutationKind {
        Write,
        Flush,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum FaultTraceEntry {
        Write {
            first_page: u64,
            page_count: usize,
            input: Vec<Page>,
        },
        Flush,
    }

    impl FaultTraceEntry {
        fn kind(&self) -> MutationKind {
            match self {
                Self::Write { .. } => MutationKind::Write,
                Self::Flush => MutationKind::Flush,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Effect {
        Visible,
        Durable,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FaultAction {
        Normal,
        FailNotSubmitted,
        FailAmbiguous(Effect),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DeviceMode {
        PageFallback,
        CachedBatch,
    }

    #[derive(Clone, Copy)]
    struct FaultPlan {
        mutation_index: usize,
        action: FaultAction,
    }

    #[derive(Clone)]
    struct FaultMedia {
        page_count: u64,
        durable: BTreeMap<u64, Page>,
        visible: BTreeMap<u64, Page>,
        cache: BTreeMap<u64, Page>,
        mode: DeviceMode,
        mutation_count: usize,
        batch_write_count: usize,
        trace: Vec<FaultTraceEntry>,
        fault: Option<FaultPlan>,
    }

    #[derive(Clone)]
    struct FaultDevice {
        media: Arc<Mutex<FaultMedia>>,
    }

    impl FaultDevice {
        fn from_durable(image: BTreeMap<u64, Page>) -> Self {
            Self::from_durable_with_mode(image, DeviceMode::PageFallback)
        }

        fn from_durable_with_mode(image: BTreeMap<u64, Page>, mode: DeviceMode) -> Self {
            Self {
                media: Arc::new(Mutex::new(FaultMedia {
                    page_count: admitted_pages(SEGMENTS).unwrap(),
                    visible: image.clone(),
                    durable: image,
                    cache: BTreeMap::new(),
                    mode,
                    mutation_count: 0,
                    batch_write_count: 0,
                    trace: Vec::new(),
                    fault: None,
                })),
            }
        }

        fn arm(&self, mutation_index: usize, action: FaultAction) {
            let mut media = self.media.lock().unwrap();
            media.mutation_count = 0;
            media.trace.clear();
            media.fault = Some(FaultPlan {
                mutation_index,
                action,
            });
        }

        fn mutation_count(&self) -> usize {
            self.media.lock().unwrap().mutation_count
        }

        fn trace(&self) -> Vec<FaultTraceEntry> {
            self.media.lock().unwrap().trace.clone()
        }

        fn durable_image(&self) -> BTreeMap<u64, Page> {
            self.media.lock().unwrap().durable.clone()
        }

        fn next_action(&self, entry: FaultTraceEntry) -> FaultAction {
            let mut media = self.media.lock().unwrap();
            let index = media.mutation_count;
            media.mutation_count += 1;
            media.trace.push(entry);
            media
                .fault
                .filter(|plan| plan.mutation_index == index)
                .map_or(FaultAction::Normal, |plan| plan.action)
        }

        fn write_pages_effect(&self, first_page: u64, input: &[Page], effect: Effect) {
            let mut media = self.media.lock().unwrap();
            for (offset, bytes) in input.iter().enumerate() {
                let page = first_page + offset as u64;
                media.visible.insert(page, *bytes);
                if matches!(effect, Effect::Durable) {
                    media.durable.insert(page, *bytes);
                }
            }
        }

        fn invalidate_cache(&self, first_page: u64, page_count: usize) {
            let mut media = self.media.lock().unwrap();
            for page in first_page..first_page.saturating_add(page_count as u64) {
                media.cache.remove(&page);
            }
        }

        fn cache_pages(&self, first_page: u64, input: &[Page]) {
            let mut media = self.media.lock().unwrap();
            if media.mode == DeviceMode::CachedBatch {
                for (offset, page) in input.iter().enumerate() {
                    media.cache.insert(first_page + offset as u64, *page);
                }
            }
        }

        fn flush_effect(&self, effect: Effect) {
            if matches!(effect, Effect::Durable) {
                let mut media = self.media.lock().unwrap();
                media.durable = media.visible.clone();
            }
        }
    }

    impl PageDevice for FaultDevice {
        type Error = TestError;

        fn info(&self) -> PageDeviceInfo {
            let page_count = self.media.lock().unwrap().page_count;
            PageDeviceInfo {
                device_id: [0xc7; 16],
                range_first_logical_block: 2048,
                logical_block_count: page_count * 8,
                logical_block_size: 512,
                page_count,
            }
        }

        async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
            let mut media = self.media.lock().unwrap();
            if page >= media.page_count {
                return Err(TestError::OutsideRange);
            }
            if media.mode == DeviceMode::CachedBatch {
                if let Some(stored) = media.cache.get(&page) {
                    output.copy_from_slice(stored);
                    return Ok(());
                }
            }
            output.fill(0);
            if let Some(stored) = media.visible.get(&page) {
                output.copy_from_slice(stored);
            }
            if media.mode == DeviceMode::CachedBatch {
                media.cache.insert(page, *output);
            }
            Ok(())
        }

        async fn write_page(
            &self,
            page: u64,
            input: &Page,
        ) -> Result<(), MutationFailure<Self::Error>> {
            if self.media.lock().unwrap().mode == DeviceMode::CachedBatch {
                self.invalidate_cache(page, 1);
            }
            if page >= self.media.lock().unwrap().page_count {
                return Err(MutationFailure::not_submitted(TestError::OutsideRange));
            }
            match self.next_action(FaultTraceEntry::Write {
                first_page: page,
                page_count: 1,
                input: vec![*input],
            }) {
                FaultAction::Normal => {
                    self.write_pages_effect(page, core::slice::from_ref(input), Effect::Visible);
                    self.cache_pages(page, core::slice::from_ref(input));
                    Ok(())
                }
                FaultAction::FailNotSubmitted => {
                    Err(MutationFailure::not_submitted(TestError::Injected))
                }
                FaultAction::FailAmbiguous(effect) => {
                    self.write_pages_effect(page, core::slice::from_ref(input), effect);
                    Err(MutationFailure::ambiguous(TestError::DriverRestarted))
                }
            }
        }

        async fn read_pages(
            &self,
            first_page: u64,
            output: &mut [Page],
        ) -> Result<(), Self::Error> {
            if output.is_empty() {
                return Ok(());
            }
            if self.media.lock().unwrap().mode == DeviceMode::PageFallback {
                for (offset, page) in output.iter_mut().enumerate() {
                    let page_number = first_page + offset as u64;
                    let media = self.media.lock().unwrap();
                    if page_number >= media.page_count {
                        return Err(TestError::OutsideRange);
                    }
                    page.fill(0);
                    if let Some(stored) = media.visible.get(&page_number) {
                        page.copy_from_slice(stored);
                    }
                }
                return Ok(());
            }
            let mut media = self.media.lock().unwrap();
            let end = first_page
                .checked_add(output.len() as u64)
                .ok_or(TestError::OutsideRange)?;
            if end > media.page_count {
                return Err(TestError::OutsideRange);
            }
            let all_cached = output.iter_mut().enumerate().all(|(offset, page)| {
                media
                    .cache
                    .get(&(first_page + offset as u64))
                    .is_some_and(|stored| {
                        page.copy_from_slice(stored);
                        true
                    })
            });
            if all_cached {
                return Ok(());
            }
            for (offset, page) in output.iter_mut().enumerate() {
                let page_number = first_page + offset as u64;
                page.fill(0);
                if let Some(stored) = media.visible.get(&page_number) {
                    page.copy_from_slice(stored);
                }
            }
            for (offset, page) in output.iter().enumerate() {
                media.cache.insert(first_page + offset as u64, *page);
            }
            Ok(())
        }

        async fn write_pages(
            &self,
            first_page: u64,
            input: &[Page],
        ) -> Result<(), MutationFailure<Self::Error>> {
            if input.is_empty() {
                return Ok(());
            }
            let mode = self.media.lock().unwrap().mode;
            self.invalidate_cache(first_page, input.len());
            let end = first_page
                .checked_add(input.len() as u64)
                .ok_or_else(|| MutationFailure::not_submitted(TestError::OutsideRange))?;
            if end > self.media.lock().unwrap().page_count {
                return Err(MutationFailure::not_submitted(TestError::OutsideRange));
            }
            if mode == DeviceMode::PageFallback && input.len() > 1 {
                for (offset, page) in input.iter().enumerate() {
                    self.write_page(first_page + offset as u64, page).await?;
                }
                return Ok(());
            }
            if mode == DeviceMode::CachedBatch {
                self.media.lock().unwrap().batch_write_count += 1;
            }
            match self.next_action(FaultTraceEntry::Write {
                first_page,
                page_count: input.len(),
                input: input.to_vec(),
            }) {
                FaultAction::Normal => {
                    self.write_pages_effect(first_page, input, Effect::Visible);
                    self.cache_pages(first_page, input);
                    Ok(())
                }
                FaultAction::FailNotSubmitted => {
                    Err(MutationFailure::not_submitted(TestError::Injected))
                }
                FaultAction::FailAmbiguous(effect) => {
                    self.write_pages_effect(first_page, input, effect);
                    Err(MutationFailure::ambiguous(TestError::DriverRestarted))
                }
            }
        }

        async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
            match self.next_action(FaultTraceEntry::Flush) {
                FaultAction::Normal => {
                    self.flush_effect(Effect::Durable);
                    Ok(())
                }
                FaultAction::FailNotSubmitted => {
                    Err(MutationFailure::not_submitted(TestError::Injected))
                }
                FaultAction::FailAmbiguous(effect) => {
                    self.flush_effect(effect);
                    Err(MutationFailure::ambiguous(TestError::DriverRestarted))
                }
            }
        }
    }

    fn limits() -> StoreLimits {
        StoreLimits {
            recovery_memory_bytes: 128 * 1024 * 1024,
            ..StoreLimits::default()
        }
    }

    fn store_id() -> StoreId {
        StoreId::new(STORE_ID_RAW).unwrap()
    }

    fn format_records() -> Vec<[u8; RECORD_SIZE]> {
        vec![RecordChain::new(store_id())
            .append(None, RecordBody::Format)
            .unwrap()]
    }

    fn c76_graph_space() -> SpaceId {
        SpaceId::new(C76_GRAPH_SPACE_RAW).unwrap()
    }

    fn c76_kind(index: usize) -> ObjectKind {
        ObjectKind::new(match index {
            0..=2 => ARTIFACT_KIND_RAW,
            3..=5 => EVIDENCE_KIND_RAW,
            6 => C76_GRAPH_EVIDENCE_KIND_RAW,
            7 => C76_GRAPH_VERSION_KIND_RAW,
            _ => unreachable!(),
        })
        .unwrap()
    }

    #[derive(Clone)]
    struct C76GraphFixture {
        g0: Vec<[u8; RECORD_SIZE]>,
        g1: Vec<[u8; RECORD_SIZE]>,
        g0_root: GrantRecord,
        g1_root: GrantRecord,
        g0_attachments: Vec<vibeos_durable_format::RecoveredObject>,
        g1_attachments: Vec<vibeos_durable_format::RecoveredObject>,
    }

    impl C76GraphFixture {
        fn bytes(records: &[[u8; RECORD_SIZE]]) -> Vec<u8> {
            records.iter().flatten().copied().collect()
        }

        fn g0_bytes(&self) -> Vec<u8> {
            Self::bytes(&self.g0)
        }

        fn g1_bytes(&self) -> Vec<u8> {
            Self::bytes(&self.g1)
        }

        fn import(
            &self,
            records: &[[u8; RECORD_SIZE]],
            root: &GrantRecord,
            attachments: &[vibeos_durable_format::RecoveredObject],
        ) -> PersistentAuthorityImport {
            let preflight = preflight_recovery(records, store_id()).unwrap();
            PersistentAuthorityImport::from_m4_with_exact_inline_attachments_preflighted(
                records,
                store_id(),
                &[RootPolicy {
                    grant: root.clone(),
                }],
                &[],
                attachments,
                POLICY_V3,
                Vec::new(),
                preflight,
            )
            .unwrap()
            .with_system_principal(LEGACY_SYSTEM_PRINCIPAL, u64::MAX, u64::MAX, false)
            .unwrap()
        }

        fn g0_import(&self) -> PersistentAuthorityImport {
            self.import(&self.g0, &self.g0_root, &self.g0_attachments)
        }

        fn g1_import(&self) -> PersistentAuthorityImport {
            let mut attachments = self.g0_attachments.clone();
            attachments.extend_from_slice(&self.g1_attachments);
            attachments.sort_unstable_by_key(|object| object.object_id);
            self.import(&self.g1, &self.g1_root, &attachments)
        }
    }

    fn c76_formatted_image() -> BTreeMap<u64, Page> {
        let device = FaultDevice::from_durable(BTreeMap::new());
        let (runtime, _quota, _provisioner) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &[],
            )
            .unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"C78-GRAPH-G0!!!!").unwrap(),
            cleaner_reserve_segments: 4,
            limits: limits(),
        }))
        .unwrap();
        drop(store);
        device.durable_image()
    }

    fn c76_prepared_image(
        formatted: &BTreeMap<u64, Page>,
        fixture: &C76GraphFixture,
    ) -> BTreeMap<u64, Page> {
        let device = FaultDevice::from_durable(formatted.clone());
        let (runtime, _quota, provisioner) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &[],
            )
            .unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
        block_on(store.mount()).unwrap();
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let view =
            block_on(store.import_persistent_authority(&maintenance, fixture.g0_import())).unwrap();
        assert_eq!(view.record_stream(), fixture.g0_bytes());
        assert_eq!(view.objects().len(), 1);
        drop(store);
        device.durable_image()
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum InstallOutcome {
        Completed,
        AlreadyComplete,
        Failed,
        Pending,
    }

    fn c76_drive_install(device: &FaultDevice, fixture: &C76GraphFixture) -> InstallOutcome {
        let (runtime, _quota, provisioner) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &[],
            )
            .unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
        if block_on(store.mount()).is_err() {
            return InstallOutcome::Failed;
        }
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let mut install =
            Box::pin(store.import_persistent_authority(&maintenance, fixture.g0_import()));
        match poll_once(install.as_mut()) {
            Poll::Ready(Ok(view)) => {
                assert_eq!(view.record_stream(), fixture.g0_bytes());
                assert_eq!(view.objects().len(), 1);
                InstallOutcome::Completed
            }
            Poll::Ready(Err(_)) => InstallOutcome::Failed,
            Poll::Pending => InstallOutcome::Pending,
        }
    }

    fn c76_drive_replace(device: &FaultDevice, fixture: &C76GraphFixture) -> InstallOutcome {
        let (runtime, _quota, provisioner) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &[],
            )
            .unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
        if block_on(store.mount()).is_err() {
            return InstallOutcome::Failed;
        }
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let writer = store
            .derive_persistent_authority_writer(&maintenance)
            .unwrap();
        let view =
            match block_on(store.recover_persistent_authority(root_policy_commitment(POLICY_V3))) {
                Ok(view) => view,
                Err(_) => return InstallOutcome::Failed,
            };
        if view.record_stream() == fixture.g1_bytes() {
            return InstallOutcome::AlreadyComplete;
        }
        if view.record_stream() != fixture.g0_bytes() {
            return InstallOutcome::Failed;
        }
        let principal = view.principals()[0].clone();
        let mut append = Box::pin(store.append_persistent_authority(
            &writer,
            view.checkpoint_generation(),
            fixture.g1_import(),
            &principal,
        ));
        match poll_once(append.as_mut()) {
            Poll::Ready(Ok(result)) => {
                assert_eq!(result.view().record_stream(), fixture.g1_bytes());
                InstallOutcome::Completed
            }
            Poll::Ready(Err(_)) => InstallOutcome::Failed,
            Poll::Pending => InstallOutcome::Pending,
        }
    }

    const EXPORT_ENV: &str = "C78_RAW_DISK_FIXTURE_DIR";
    const MANIFEST: &str = "manifest.jsonl";
    const SCHEMA: &str = "vibeos.c78.raw-disk-corpus";
    const SCOPE: &str = "frozen-c7-v1-policy-v3-component-graph";
    const ACTIVE_PUBLIC_KEY: [u8; 32] = [
        0x1d, 0xfa, 0xeb, 0x2e, 0x9d, 0x9f, 0xf3, 0xd5, 0xc4, 0xeb, 0x7f, 0x81, 0xa1, 0x19, 0x7d,
        0xd0, 0x9f, 0x8a, 0x30, 0x1a, 0x5a, 0x31, 0xb6, 0xed, 0x15, 0x92, 0x1e, 0x93, 0x95, 0x74,
        0x15, 0x4f,
    ];
    const VECTOR_TEXT: &str =
        include_str!("../../policy/image/artifacts/c76-graph-version-replacement.vectors");

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(DIGITS[usize::from(byte >> 4)] as char);
            out.push(DIGITS[usize::from(byte & 0x0f)] as char);
        }
        out
    }

    fn digest(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }

    fn json_string(value: &str) -> String {
        let mut out = String::from("\"");
        for character in value.chars() {
            match character {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                value if value <= '\u{1f}' => {
                    use core::fmt::Write as _;
                    write!(&mut out, "\\u{:04x}", value as u32).unwrap();
                }
                value => out.push(value),
            }
        }
        out.push('"');
        out
    }

    #[derive(Clone)]
    struct StoredBytes {
        path: String,
        sha256: String,
        byte_len: usize,
    }

    impl StoredBytes {
        fn json(&self) -> String {
            format!(
                "{{\"path\":{},\"sha256\":{},\"byte_len\":{}}}",
                json_string(&self.path),
                json_string(&self.sha256),
                self.byte_len,
            )
        }
    }

    struct Corpus {
        root: PathBuf,
        manifest: BufWriter<File>,
        recipe_shards: BTreeMap<String, BufWriter<File>>,
        event_keys: BTreeSet<String>,
        recipe_digests: BTreeSet<String>,
        logical_events: usize,
        physical_events: usize,
    }

    impl Corpus {
        fn new(root: PathBuf) -> Self {
            if let Ok(metadata) = fs::symlink_metadata(&root) {
                assert!(
                    !metadata.file_type().is_symlink(),
                    "export root cannot be a symlink"
                );
                assert!(metadata.is_dir(), "export root must be a directory");
                assert!(
                    fs::read_dir(&root).unwrap().next().is_none(),
                    "export root must be empty"
                );
            } else {
                fs::create_dir_all(&root).unwrap();
            }
            for child in ["bases", "blobs", "recipes"] {
                fs::create_dir(root.join(child)).unwrap();
            }
            let manifest = BufWriter::new(
                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(root.join(MANIFEST))
                    .unwrap(),
            );
            Self {
                root,
                manifest,
                recipe_shards: BTreeMap::new(),
                event_keys: BTreeSet::new(),
                recipe_digests: BTreeSet::new(),
                logical_events: 0,
                physical_events: 0,
            }
        }

        fn line(&mut self, value: &str) {
            self.manifest.write_all(value.as_bytes()).unwrap();
            self.manifest.write_all(b"\n").unwrap();
        }

        fn header(&mut self) {
            let policy_sha256 = hex(&root_policy_commitment(POLICY_V3));
            let trust_anchor_sha256 = digest(&ACTIVE_PUBLIC_KEY);
            self.line(&format!(
                "{{\"record\":\"header\",\"schema\":{},\"version\":1,\"scope\":{},\"policy_sha256\":{},\"trust_anchor_sha256\":{},\"manifest_format\":\"json-lines-v1\",\"recipe_format\":\"recursive-base-plus-ordered-overlay-prefix-patches-v1\",\"event_key_fields\":[\"scenario\",\"transition\",\"mode\",\"phase\",\"operation\",\"ordinal\",\"cut\"],\"cuts\":{{\"logical\":[0,512],\"physical\":[0,4096]}},\"trace_digest_semantics\":{{\"geometry_sha256\":\"frozen-content-independent-coverage-identity\",\"trace_sha256\":\"data-driven-content-evidence\"}},\"expected_class_semantics\":\"coverage-hint-only\",\"expected_class_verifier_authority\":false,\"verdicts_emitted\":false}}",
                json_string(SCHEMA),
                json_string(SCOPE),
                json_string(&policy_sha256),
                json_string(&trust_anchor_sha256),
            ));
        }

        fn store_blob(&mut self, bytes: &[u8]) -> StoredBytes {
            let sha256 = digest(bytes);
            let relative = format!("blobs/{sha256}.bin");
            let absolute = self.root.join(&relative);
            if absolute.exists() {
                assert_eq!(fs::read(&absolute).unwrap(), bytes, "blob digest collision");
            } else {
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&absolute)
                    .unwrap();
                file.write_all(bytes).unwrap();
                file.sync_all().unwrap();
            }
            StoredBytes {
                path: relative,
                sha256,
                byte_len: bytes.len(),
            }
        }

        fn store_raw(&mut self, bytes: &[u8]) -> StoredBytes {
            let sha256 = digest(bytes);
            let relative = format!("bases/{sha256}.raw");
            let absolute = self.root.join(&relative);
            if absolute.exists() {
                assert_eq!(fs::read(&absolute).unwrap(), bytes, "raw digest collision");
            } else {
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&absolute)
                    .unwrap();
                file.write_all(bytes).unwrap();
                file.sync_all().unwrap();
            }
            StoredBytes {
                path: relative,
                sha256,
                byte_len: bytes.len(),
            }
        }

        fn store_sparse_raw(
            &mut self,
            pages: &BTreeMap<u64, Page>,
            page_count: u64,
        ) -> StoredBytes {
            let zero = [0_u8; 4096];
            let mut hasher = Sha256::new();
            for page in 0..page_count {
                hasher.update(pages.get(&page).unwrap_or(&zero));
            }
            let sha256 = hex(&hasher.finalize());
            let byte_len = usize::try_from(page_count).unwrap() * 4096;
            let relative = format!("bases/{sha256}.raw");
            let absolute = self.root.join(&relative);
            if absolute.exists() {
                let metadata = fs::symlink_metadata(&absolute).unwrap();
                assert!(metadata.file_type().is_file(), "raw base must be a file");
                assert_eq!(metadata.len(), byte_len as u64, "raw base length mismatch");
                let mut file = File::open(&absolute).unwrap();
                let mut existing_hasher = Sha256::new();
                let mut buffer = [0_u8; 64 * 1024];
                loop {
                    let read = file.read(&mut buffer).unwrap();
                    if read == 0 {
                        break;
                    }
                    existing_hasher.update(&buffer[..read]);
                }
                assert_eq!(
                    hex(&existing_hasher.finalize()),
                    sha256,
                    "raw base content mismatch"
                );
            } else {
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(&absolute)
                    .unwrap();
                file.set_len(byte_len as u64).unwrap();
                for (page, bytes) in pages {
                    if bytes.iter().any(|byte| *byte != 0) {
                        file.seek(SeekFrom::Start(page * 4096)).unwrap();
                        file.write_all(bytes).unwrap();
                    }
                }
                file.sync_all().unwrap();
            }
            StoredBytes {
                path: relative,
                sha256,
                byte_len,
            }
        }

        fn recipe(
            &mut self,
            base: &StoredBytes,
            patches: &[(usize, StoredBytes, usize)],
        ) -> StoredBytes {
            let mut previous_offset = None;
            let mut previous_end = 0_usize;
            let mut encoded = format!("{{\"base\":{},\"patches\":[", base.json());
            for (index, (offset, blob, prefix_len)) in patches.iter().enumerate() {
                assert!(*prefix_len <= blob.byte_len, "patch prefix exceeds blob");
                let patch_end = offset.checked_add(*prefix_len).unwrap();
                assert!(patch_end <= base.byte_len, "patch exceeds raw image");
                assert!(
                    previous_offset.map_or(true, |previous| *offset > previous),
                    "patch offsets within one recipe layer must be strictly increasing"
                );
                assert!(
                    index == 0 || *offset >= previous_end,
                    "patches within one recipe layer must not overlap"
                );
                previous_offset = Some(*offset);
                previous_end = patch_end;
                if index != 0 {
                    encoded.push(',');
                }
                encoded.push_str(&format!(
                    "{{\"offset\":{},\"blob\":{},\"prefix_len\":{}}}",
                    offset,
                    blob.json(),
                    prefix_len,
                ));
            }
            encoded.push_str("]}");
            let sha256 = digest(encoded.as_bytes());
            let shard = sha256[..1].to_owned();
            let path = format!("recipes/{shard}.jsonl#{sha256}");
            if self.recipe_digests.insert(sha256.clone()) {
                let writer = self.recipe_shards.entry(shard.clone()).or_insert_with(|| {
                    BufWriter::new(
                        OpenOptions::new()
                            .create_new(true)
                            .write(true)
                            .open(self.root.join(format!("recipes/{shard}.jsonl")))
                            .unwrap(),
                    )
                });
                writer.write_all(sha256.as_bytes()).unwrap();
                writer.write_all(b"\t").unwrap();
                writer.write_all(encoded.as_bytes()).unwrap();
                writer.write_all(b"\n").unwrap();
            }
            StoredBytes {
                path,
                sha256,
                // A recipe reference denotes its reconstructed raw image, not
                // the JSON recipe's encoded length. A recipe may therefore be
                // the base of another content-addressed recipe without
                // materializing another large sparse raw file.
                byte_len: base.byte_len,
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn event(
            &mut self,
            scenario: &str,
            transition: &str,
            mode: &str,
            phase: &str,
            operation: &str,
            ordinal: usize,
            cut: usize,
            expected_class: &str,
            image_sha256: Option<&str>,
            image_byte_len: usize,
            recipe: &StoredBytes,
            detail: &str,
        ) {
            let key = format!("{scenario}|{transition}|{mode}|{phase}|{operation}|{ordinal}|{cut}");
            assert!(
                self.event_keys.insert(key.clone()),
                "duplicate event key {key}"
            );
            self.line(&format!(
                "{{\"record\":\"event\",\"key\":{},\"scenario\":{},\"transition\":{},\"mode\":{},\"media_kind\":{},\"phase\":{},\"operation\":{},\"ordinal\":{},\"cut\":{},\"expected_class\":{},\"image\":{{\"path\":{},\"sha256\":{},\"byte_len\":{},\"recipe_sha256\":{}}},\"detail\":{}}}",
                json_string(&key),
                json_string(scenario),
                json_string(transition),
                json_string(mode),
                json_string(if scenario.starts_with("logical-") {
                    "authority-record-stream"
                } else {
                    "storage-v2-page-device"
                }),
                json_string(phase),
                json_string(operation),
                ordinal,
                cut,
                json_string(expected_class),
                json_string(&recipe.path),
                image_sha256.map_or_else(|| "null".to_owned(), json_string),
                image_byte_len,
                json_string(&recipe.sha256),
                detail,
            ));
        }

        fn finish(mut self) {
            self.line(&format!(
                "{{\"record\":\"coverage\",\"logical_events\":{},\"physical_events\":{},\"event_keys_unique\":true,\"recipes_content_addressed\":true,\"raw_images_reconstructable\":true}}",
                self.logical_events, self.physical_events,
            ));
            self.manifest.flush().unwrap();
            for writer in self.recipe_shards.values_mut() {
                writer.flush().unwrap();
            }
        }
    }

    fn vector(name: &str) -> Vec<u8> {
        let prefix = format!("{name}=");
        let encoded = VECTOR_TEXT
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("missing C7.6 vector {name}"));
        assert_eq!(encoded.len() % 2, 0);
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("non-canonical C7.6 vector hex"),
                };
                digit(pair[0]) << 4 | digit(pair[1])
            })
            .collect()
    }

    fn actual_version_values(generation: usize) -> [Vec<u8>; 8] {
        let prefix = format!("g{generation}");
        [
            vector(&format!("{prefix}_artifact_0")),
            vector(&format!("{prefix}_artifact_1")),
            vector(&format!("{prefix}_artifact_2")),
            vector(&format!("{prefix}_evidence_0")),
            vector(&format!("{prefix}_evidence_1")),
            vector(&format!("{prefix}_evidence_2")),
            vector(&format!("{prefix}_graph_evidence")),
            vector(&format!("{prefix}_descriptor")),
        ]
    }

    fn append_actual_c76_objects(
        chain: &mut RecordChain,
        records: &mut Vec<[u8; RECORD_SIZE]>,
        base: u128,
        generation: usize,
    ) -> Vec<ObjectId> {
        let mut ids = Vec::new();
        for (index, bytes) in actual_version_values(generation).into_iter().enumerate() {
            let object = ObjectId::new(base + (index * 2) as u128 + 1).unwrap();
            records.extend(
                encode_object_transaction(
                    chain,
                    TransactionId::new(base + (index * 2) as u128).unwrap(),
                    object,
                    c76_kind(index),
                    &bytes,
                )
                .unwrap()
                .records,
            );
            ids.push(object);
        }
        ids
    }

    impl C76GraphFixture {
        fn new_actual() -> Self {
            let mut g0 = format_records();
            let empty = preflight_recovery(&g0, store_id()).unwrap();
            let mut chain =
                RecordChain::from_checkpoint(store_id(), empty.chain_checkpoint().unwrap())
                    .unwrap();
            let base0 = empty.id_high_water().max(1);
            g0.push(
                chain
                    .append(
                        None,
                        RecordBody::IdHighWater {
                            exclusive_end: (base0 + 18).max(C76_GRAPH_SPACE_RAW + 1),
                        },
                    )
                    .unwrap(),
            );
            let g0_ids = append_actual_c76_objects(&mut chain, &mut g0, base0, 0);
            let g0_root = GrantRecord {
                derivation_id: DerivationId::new(base0 + 17).unwrap(),
                parent_id: None,
                object_id: g0_ids[7],
                target: SlotIdentity {
                    space: c76_graph_space(),
                    slot: 0,
                    generation: 0,
                },
                rights: DurableRights::READ,
                resource_kind: ResourceKind::new(STORED_OBJECT_KIND_RAW).unwrap(),
                flags: GrantFlags::ROOT,
            };
            let (root, _) = preview_grant_transaction(
                &chain,
                TransactionId::new(base0 + 16).unwrap(),
                g0_root.clone(),
            )
            .unwrap();
            g0.extend(root.records);

            let recovered0 = preflight_recovery(&g0, store_id()).unwrap();
            let base1 = recovered0.id_high_water();
            let mut chain =
                RecordChain::from_checkpoint(store_id(), recovered0.chain_checkpoint().unwrap())
                    .unwrap();
            let mut g1 = g0.clone();
            g1.push(
                chain
                    .append(
                        None,
                        RecordBody::IdHighWater {
                            exclusive_end: base1 + 19,
                        },
                    )
                    .unwrap(),
            );
            let g1_ids = append_actual_c76_objects(&mut chain, &mut g1, base1, 1);
            let (revoke, next) = preview_revoke_transaction(
                &chain,
                TransactionId::new(base1 + 16).unwrap(),
                g0_root.derivation_id,
            )
            .unwrap();
            g1.extend(revoke.records);
            chain = next;
            let g1_root = GrantRecord {
                derivation_id: DerivationId::new(base1 + 18).unwrap(),
                parent_id: None,
                object_id: g1_ids[7],
                target: SlotIdentity {
                    space: c76_graph_space(),
                    slot: 0,
                    generation: 1,
                },
                rights: DurableRights::READ,
                resource_kind: ResourceKind::new(STORED_OBJECT_KIND_RAW).unwrap(),
                flags: GrantFlags::ROOT,
            };
            let (root, _) = preview_grant_transaction(
                &chain,
                TransactionId::new(base1 + 17).unwrap(),
                g1_root.clone(),
            )
            .unwrap();
            g1.extend(root.records);

            let recovered0 = preflight_recovery(&g0, store_id()).unwrap();
            let recovered1 = preflight_recovery(&g1, store_id()).unwrap();
            let objects_for = |recovered: &vibeos_durable_format::RecoveryPreflight,
                               ids: &[ObjectId]| {
                ids.iter()
                    .map(|id| {
                        recovered
                            .committed_objects()
                            .iter()
                            .find(|object| object.object_id == *id)
                            .unwrap()
                            .clone()
                    })
                    .collect::<Vec<_>>()
            };
            let mut objects0 = objects_for(&recovered0, &g0_ids);
            let _g0_descriptor = objects0.pop().unwrap();
            let mut objects1 = objects_for(&recovered1, &g1_ids);
            let _g1_descriptor = objects1.pop().unwrap();
            assert_eq!(g0.len(), 61, "actual C7.6 G0 record count drifted");
            assert_eq!(g1.len() - g0.len(), 61, "actual C7.6 G1 delta drifted");
            Self {
                g0,
                g1,
                g0_root,
                g1_root,
                g0_attachments: objects0,
                g1_attachments: objects1,
            }
        }
    }

    fn raw_digest(bytes: &[u8]) -> String {
        digest(bytes)
    }

    fn export_logical_transition(
        corpus: &mut Corpus,
        scenario: &str,
        transition: &str,
        base_records: &[[u8; RECORD_SIZE]],
        delta: &[[u8; RECORD_SIZE]],
        final_records: usize,
        strict_prefix_class: &str,
        after_class: &str,
    ) {
        assert_eq!(
            delta.len(),
            61,
            "C7.8 logical transition must have 61 records"
        );
        let final_len = final_records * RECORD_SIZE;
        let mut base_bytes = vec![0_u8; final_len];
        let base_len = base_records.len() * RECORD_SIZE;
        base_bytes[..base_len].copy_from_slice(&C76GraphFixture::bytes(base_records));
        let base = corpus.store_raw(&base_bytes);
        let record_blobs: Vec<_> = delta
            .iter()
            .map(|record| corpus.store_blob(record))
            .collect();
        let mut complete_prefixes = Vec::with_capacity(delta.len() - 1);
        let mut joined = Vec::new();
        for (ordinal, record) in delta.iter().enumerate() {
            joined.extend_from_slice(record);
            if ordinal + 1 < delta.len() {
                complete_prefixes.push(corpus.store_blob(&joined));
            }
        }
        corpus.line(&format!(
            "{{\"record\":\"logical-domain\",\"scenario\":{},\"transition\":{},\"base\":{},\"record_count\":{},\"record_size\":{},\"cuts\":[0,{}],\"record_blobs\":[{}]}}",
            json_string(scenario),
            json_string(transition),
            base.json(),
            delta.len(),
            RECORD_SIZE,
            RECORD_SIZE,
            record_blobs.iter().map(StoredBytes::json).collect::<Vec<_>>().join(","),
        ));

        for ordinal in 0..delta.len() {
            for cut in 0..=RECORD_SIZE {
                let mut image = base_bytes.clone();
                let complete = ordinal * RECORD_SIZE;
                if complete != 0 {
                    image[base_len..base_len + complete].copy_from_slice(&joined[..complete]);
                }
                let offset = base_len + complete;
                image[offset..offset + cut].copy_from_slice(&delta[ordinal][..cut]);
                let mut patches = Vec::with_capacity(2);
                if complete != 0 {
                    patches.push((base_len, complete_prefixes[ordinal - 1].clone(), complete));
                }
                if cut != 0 {
                    patches.push((offset, record_blobs[ordinal].clone(), cut));
                }
                let recipe = corpus.recipe(&base, &patches);
                let is_final = ordinal + 1 == delta.len() && cut == RECORD_SIZE;
                corpus.event(
                    scenario,
                    transition,
                    "durable-record-stream",
                    "record",
                    if cut == RECORD_SIZE {
                        "complete"
                    } else {
                        "prefix"
                    },
                    ordinal,
                    cut,
                    if is_final {
                        after_class
                    } else {
                        strict_prefix_class
                    },
                    Some(&raw_digest(&image)),
                    image.len(),
                    &recipe,
                    &format!(
                        "{{\"record_ordinal\":{},\"record_count\":{}}}",
                        ordinal,
                        delta.len()
                    ),
                );
                corpus.logical_events += 1;
            }
        }
    }

    fn mode_name(mode: DeviceMode) -> &'static str {
        match mode {
            DeviceMode::PageFallback => "page-fallback",
            DeviceMode::CachedBatch => "cached-batch",
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PhysicalTransition {
        Install,
        Upgrade,
    }

    impl PhysicalTransition {
        fn scenario(self) -> &'static str {
            match self {
                Self::Install => "physical-install",
                Self::Upgrade => "physical-upgrade",
            }
        }

        fn name(self) -> &'static str {
            match self {
                Self::Install => "vacant-to-g0",
                Self::Upgrade => "g0-to-g1",
            }
        }

        fn before_class(self) -> &'static str {
            match self {
                Self::Install => "vacant",
                Self::Upgrade => "g0",
            }
        }

        fn after_class(self) -> &'static str {
            match self {
                Self::Install => "g0",
                Self::Upgrade => "g1",
            }
        }

        fn intermediate_class(self) -> &'static str {
            match self {
                Self::Install => "vacant-or-g0-or-reject",
                Self::Upgrade => "g0-or-g1-or-reject",
            }
        }

        fn mutation_class(self) -> &'static str {
            match self {
                Self::Install => "vacant-or-g0",
                Self::Upgrade => "g0-or-g1",
            }
        }

        fn drive(self, device: &FaultDevice, fixture: &C76GraphFixture) -> InstallOutcome {
            match self {
                Self::Install => c76_drive_install(device, fixture),
                Self::Upgrade => c76_drive_replace(device, fixture),
            }
        }
    }

    fn fault_snapshot(
        initial: &BTreeMap<u64, Page>,
        fixture: &C76GraphFixture,
        transition: PhysicalTransition,
        mode: DeviceMode,
        boundary: usize,
        action: FaultAction,
        baseline_trace: &[FaultTraceEntry],
    ) -> BTreeMap<u64, Page> {
        let device = FaultDevice::from_durable_with_mode(initial.clone(), mode);
        device.arm(boundary, action);
        let _ = transition.drive(&device, fixture);
        assert_eq!(device.mutation_count(), boundary + 1);
        let actual_trace = device.trace();
        assert_eq!(actual_trace.len(), boundary + 1);
        assert!(
            actual_trace.as_slice() == &baseline_trace[..=boundary],
            "fault rerun trace differs from exact baseline prefix for {} {} at {boundary}",
            transition.name(),
            mode_name(mode),
        );
        device.durable_image()
    }

    fn sparse_page_patches(
        corpus: &mut Corpus,
        base: &BTreeMap<u64, Page>,
        state: &BTreeMap<u64, Page>,
        page_count: u64,
    ) -> Vec<(usize, StoredBytes, usize)> {
        let zero = [0_u8; 4096];
        let mut patches = Vec::new();
        for page in 0..page_count {
            let before = base.get(&page).unwrap_or(&zero);
            let after = state.get(&page).unwrap_or(&zero);
            if before != after {
                patches.push((page as usize * 4096, corpus.store_blob(after), 4096));
            }
        }
        patches
    }

    struct PhysicalOperation {
        trace: FaultTraceEntry,
        before: BTreeMap<u64, Page>,
        after: BTreeMap<u64, Page>,
        changed: Vec<u64>,
    }

    fn canonical_physical_trace(
        transition: PhysicalTransition,
        mode: DeviceMode,
        operations: &[PhysicalOperation],
    ) -> (String, String, String) {
        let zero = [0_u8; 4096];
        let mut transcript = format!(
            "scenario={};transition={};mode={}\n",
            transition.scenario(),
            transition.name(),
            mode_name(mode),
        );
        let mut geometry = transcript.clone();
        for (ordinal, operation) in operations.iter().enumerate() {
            match &operation.trace {
                FaultTraceEntry::Write {
                    first_page,
                    page_count,
                    input,
                } => {
                    assert_eq!(*page_count, input.len());
                    geometry.push_str(&format!(
                        "ordinal={ordinal};kind=write;first_page={first_page};page_count={page_count}\n"
                    ));
                    transcript.push_str(&format!(
                        "ordinal={ordinal};kind=write;first_page={first_page};page_count={};requested_pages=",
                        page_count,
                    ));
                    for (page_ordinal, bytes) in input.iter().enumerate() {
                        if page_ordinal != 0 {
                            transcript.push(',');
                        }
                        let page = first_page + page_ordinal as u64;
                        transcript.push_str(&format!(
                            "{}:{}:{}:{}",
                            page,
                            digest(operation.before.get(&page).unwrap_or(&zero)),
                            digest(bytes),
                            digest(operation.after.get(&page).unwrap_or(&zero)),
                        ));
                    }
                }
                FaultTraceEntry::Flush => {
                    geometry.push_str(&format!("ordinal={ordinal};kind=flush\n"));
                    transcript.push_str(&format!("ordinal={ordinal};kind=flush;changed_pages="));
                    for (index, page) in operation.changed.iter().enumerate() {
                        if index != 0 {
                            transcript.push(',');
                        }
                        transcript.push_str(&format!(
                            "{}:{}:{}",
                            page,
                            digest(operation.before.get(page).unwrap_or(&zero)),
                            digest(operation.after.get(page).unwrap_or(&zero)),
                        ));
                    }
                }
            }
            transcript.push('\n');
        }
        let trace_sha256 = digest(transcript.as_bytes());
        let geometry_sha256 = digest(geometry.as_bytes());
        (transcript, trace_sha256, geometry_sha256)
    }

    fn export_physical_mode(
        corpus: &mut Corpus,
        initial: &BTreeMap<u64, Page>,
        fixture: &C76GraphFixture,
        linked_g0: &BTreeMap<u64, Page>,
        transition: PhysicalTransition,
        mode: DeviceMode,
    ) {
        let page_count = admitted_pages(SEGMENTS).unwrap();
        let baseline = FaultDevice::from_durable_with_mode(initial.clone(), mode);
        assert_eq!(
            transition.drive(&baseline, fixture),
            InstallOutcome::Completed
        );
        let trace = baseline.trace();
        assert!(!trace.is_empty());
        if mode == DeviceMode::CachedBatch {
            assert!(trace.iter().any(|entry| matches!(
                entry,
                FaultTraceEntry::Write { page_count, .. } if *page_count > 1
            )));
        }
        let zero = [0_u8; 4096];
        let operations: Vec<_> = trace
            .iter()
            .cloned()
            .enumerate()
            .map(|(mutation, trace_entry)| {
                let before = fault_snapshot(
                    initial,
                    fixture,
                    transition,
                    mode,
                    mutation,
                    FaultAction::FailNotSubmitted,
                    &trace,
                );
                let after = fault_snapshot(
                    initial,
                    fixture,
                    transition,
                    mode,
                    mutation,
                    FaultAction::FailAmbiguous(Effect::Durable),
                    &trace,
                );
                let changed = (0..page_count)
                    .filter(|page| {
                        before.get(page).unwrap_or(&zero) != after.get(page).unwrap_or(&zero)
                    })
                    .collect();
                if let FaultTraceEntry::Write {
                    first_page,
                    page_count,
                    input,
                } = &trace_entry
                {
                    assert_eq!(*page_count, input.len());
                    for (offset, bytes) in input.iter().enumerate() {
                        let page = first_page + offset as u64;
                        assert_eq!(
                            after.get(&page).unwrap_or(&zero),
                            bytes,
                            "durable ambiguous write must apply each exact requested input page"
                        );
                    }
                }
                PhysicalOperation {
                    trace: trace_entry,
                    before,
                    after,
                    changed,
                }
            })
            .collect();
        let (trace_transcript, trace_sha256, geometry_sha256) =
            canonical_physical_trace(transition, mode, &operations);
        let trace_blob = corpus.store_blob(trace_transcript.as_bytes());
        let mode = mode_name(mode);
        let initial_base = corpus.store_sparse_raw(initial, page_count);
        let final_pages = baseline.durable_image();
        if transition == PhysicalTransition::Install {
            assert_eq!(
                &final_pages, linked_g0,
                "physical install must end at the exact G0 image used by the upgrade domain"
            );
        }
        let final_base = corpus.store_sparse_raw(&final_pages, page_count);
        let write_count = operations
            .iter()
            .filter(|operation| operation.trace.kind() == MutationKind::Write)
            .count();
        let flush_count = operations.len() - write_count;
        let requested_page_count: usize = operations
            .iter()
            .map(|operation| match &operation.trace {
                FaultTraceEntry::Write { page_count, .. } => *page_count,
                FaultTraceEntry::Flush => 0,
            })
            .sum();
        corpus.line(&format!(
            "{{\"record\":\"physical-domain\",\"scenario\":{},\"transition\":{},\"mode\":{},\"geometry_sha256\":{},\"trace_sha256\":{},\"trace\":{},\"operation_count\":{},\"write_count\":{},\"flush_count\":{},\"requested_page_count\":{},\"page_size\":4096,\"write_cuts\":[0,4096],\"flush_effects\":[\"none\",\"durable\"],\"before\":{},\"after\":{}}}",
            json_string(transition.scenario()),
            json_string(transition.name()),
            json_string(mode),
            json_string(&geometry_sha256),
            json_string(&trace_sha256),
            trace_blob.json(),
            trace.len(),
            write_count,
            flush_count,
            requested_page_count,
            initial_base.json(),
            final_base.json(),
        ));

        for (ordinal, (base, expected)) in [
            (&initial_base, transition.before_class()),
            (&final_base, transition.after_class()),
        ]
        .into_iter()
        .enumerate()
        {
            let recipe = corpus.recipe(base, &[]);
            corpus.event(
                transition.scenario(),
                transition.name(),
                mode,
                "baseline",
                "snapshot",
                ordinal,
                4096,
                expected,
                Some(&base.sha256),
                base.byte_len,
                &recipe,
                &format!("{{\"trace_sha256\":{}}}", json_string(&trace_sha256)),
            );
            corpus.physical_events += 1;
        }

        let mut page_ordinal = 0_usize;
        for (mutation, operation) in operations.iter().enumerate() {
            let before_patches =
                sparse_page_patches(corpus, initial, &operation.before, page_count);
            let after_patches = sparse_page_patches(corpus, initial, &operation.after, page_count);
            let before_recipe = corpus.recipe(&initial_base, &before_patches);
            let after_recipe = corpus.recipe(&initial_base, &after_patches);
            let changed_detail = operation
                .changed
                .iter()
                .map(|page| {
                    format!(
                        "{{\"page\":{},\"before_sha256\":{},\"after_sha256\":{}}}",
                        page,
                        json_string(&digest(operation.before.get(page).unwrap_or(&zero))),
                        json_string(&digest(operation.after.get(page).unwrap_or(&zero))),
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            if operation.trace.kind() == MutationKind::Flush {
                corpus.line(&format!(
                    "{{\"record\":\"physical-operation\",\"scenario\":{},\"transition\":{},\"mode\":{},\"mutation_ordinal\":{},\"kind\":\"flush\",\"first_page\":null,\"page_count\":0,\"requested_pages\":[],\"changed_pages\":[{}],\"trace_sha256\":{}}}",
                    json_string(transition.scenario()),
                    json_string(transition.name()),
                    json_string(mode),
                    mutation,
                    changed_detail,
                    json_string(&trace_sha256),
                ));
                for (effect_ordinal, (effect, patches)) in
                    [("none", &before_recipe), ("durable", &after_recipe)]
                        .into_iter()
                        .enumerate()
                {
                    corpus.event(
                        transition.scenario(),
                        transition.name(),
                        mode,
                        "flush",
                        effect,
                        mutation,
                        effect_ordinal,
                        transition.mutation_class(),
                        None,
                        initial_base.byte_len,
                        patches,
                        &format!(
                            "{{\"mutation_ordinal\":{},\"trace_sha256\":{}}}",
                            mutation,
                            json_string(&trace_sha256)
                        ),
                    );
                    corpus.physical_events += 1;
                }
                continue;
            }

            let FaultTraceEntry::Write {
                first_page,
                page_count,
                input,
            } = &operation.trace
            else {
                unreachable!();
            };
            assert_eq!(*page_count, input.len());
            let requested_detail = input
                .iter()
                .enumerate()
                .map(|(offset, bytes)| {
                    let page = first_page + offset as u64;
                    let input_blob = corpus.store_blob(bytes);
                    format!(
                        "{{\"page\":{},\"before_sha256\":{},\"input\":{},\"after_sha256\":{}}}",
                        page,
                        json_string(&digest(operation.before.get(&page).unwrap_or(&zero))),
                        input_blob.json(),
                        json_string(&digest(operation.after.get(&page).unwrap_or(&zero))),
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            corpus.line(&format!(
                "{{\"record\":\"physical-operation\",\"scenario\":{},\"transition\":{},\"mode\":{},\"mutation_ordinal\":{},\"kind\":\"write\",\"first_page\":{},\"page_count\":{},\"requested_pages\":[{}],\"changed_pages\":[{}],\"trace_sha256\":{}}}",
                json_string(transition.scenario()),
                json_string(transition.name()),
                json_string(mode),
                mutation,
                first_page,
                page_count,
                requested_detail,
                changed_detail,
                json_string(&trace_sha256),
            ));

            let mut prior_after = before_recipe.clone();
            for (batch_page_ordinal, input_page) in input.iter().enumerate() {
                let page = first_page + batch_page_ordinal as u64;
                let input_blob = corpus.store_blob(input_page);
                for cut in 0..=4096 {
                    let one_patch = (page as usize * 4096, input_blob.clone(), cut);
                    let recipe = if cut == 0 {
                        prior_after.clone()
                    } else {
                        corpus.recipe(&prior_after, core::slice::from_ref(&one_patch))
                    };
                    corpus.event(
                        transition.scenario(),
                        transition.name(),
                        mode,
                        "write",
                        if cut == 4096 { "complete" } else { "prefix" },
                        page_ordinal,
                        cut,
                        transition.intermediate_class(),
                        None,
                        initial_base.byte_len,
                        &recipe,
                        &format!("{{\"mutation_ordinal\":{},\"batch_page_ordinal\":{},\"page\":{},\"trace_sha256\":{}}}", mutation, batch_page_ordinal, page, json_string(&trace_sha256)),
                    );
                    corpus.physical_events += 1;
                }
                prior_after = corpus.recipe(
                    &prior_after,
                    core::slice::from_ref(&(page as usize * 4096, input_blob, 4096)),
                );
                page_ordinal += 1;
            }
            corpus.event(
                transition.scenario(),
                transition.name(),
                mode,
                "mutation",
                "complete",
                mutation,
                4096,
                transition.mutation_class(),
                None,
                initial_base.byte_len,
                &after_recipe,
                &format!(
                    "{{\"mutation_ordinal\":{},\"requested_page_count\":{},\"changed_page_count\":{},\"trace_sha256\":{}}}",
                    mutation,
                    input.len(),
                    operation.changed.len(),
                    json_string(&trace_sha256)
                ),
            );
            corpus.physical_events += 1;
        }
    }

    pub(super) fn run_export(root: PathBuf) {
        let fixture = C76GraphFixture::new_actual();
        assert_eq!(fixture.g0.len(), 61);
        assert_eq!(fixture.g1.len(), 122);
        let mut corpus = Corpus::new(root);
        corpus.header();
        export_logical_transition(
            &mut corpus,
            "logical-install",
            "vacant-to-g0",
            &[],
            &fixture.g0,
            fixture.g0.len(),
            "no-g0-publication",
            "g0",
        );
        export_logical_transition(
            &mut corpus,
            "logical-upgrade",
            "g0-to-g1",
            &fixture.g0,
            &fixture.g1[fixture.g0.len()..],
            fixture.g1.len(),
            "no-g1-publication",
            "g1",
        );
        assert_eq!(corpus.logical_events, 2 * 61 * 513);

        let formatted = c76_formatted_image();
        let g0 = c76_prepared_image(&formatted, &fixture);
        for mode in [DeviceMode::PageFallback, DeviceMode::CachedBatch] {
            export_physical_mode(
                &mut corpus,
                &formatted,
                &fixture,
                &g0,
                PhysicalTransition::Install,
                mode,
            );
            export_physical_mode(
                &mut corpus,
                &g0,
                &fixture,
                &g0,
                PhysicalTransition::Upgrade,
                mode,
            );
        }
        assert!(corpus.physical_events > 4);
        corpus.finish();
    }

    pub(super) fn requested_directory() -> Option<PathBuf> {
        std::env::var_os(EXPORT_ENV).map(PathBuf::from)
    }

    pub(super) fn smoke_without_export() {
        let fixture = C76GraphFixture::new_actual();
        assert_eq!(fixture.g0.len(), 61);
        assert_eq!(fixture.g1.len(), 122);
        let expected: [u8; 32] = Sha256::digest(POLICY_V3).into();
        assert_eq!(root_policy_commitment(POLICY_V3), expected);
        assert_eq!(vector("active_public_key"), ACTIVE_PUBLIC_KEY);
    }
}

#[test]
fn c78_exports_complete_raw_fault_disk_corpus_when_requested() {
    if let Some(directory) = fixture::requested_directory() {
        fixture::run_export(directory);
    } else {
        fixture::smoke_without_export();
    }
}
