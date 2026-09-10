//! Raw WASI command lifecycle. SYSTEM owns inputs, streams and the control
//! record; the audited child owns only its interpreter allocations. No guest
//! allocation or pointer is published outside the child's arena.
#[cfg(feature = "wasmtime-command")]
#[path = "wasi_wasmtime.rs"]
pub(crate) mod wasmtime_backend;
extern crate alloc;
use crate::HEAP;
use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    any::Any,
    future::{poll_fn, Future},
    pin::{pin, Pin},
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use vibeos_core::{
    cap::{CSpace, Cap, Resource, Rights},
    exec,
    heap::{self, AllocationDomain},
    sync::SpinLock,
};
use vibeos_vsh::{
    CapabilityCommandContext, CapabilityCommandFuture, ExpandedArgument, PathRequirement,
    PlannerError, ResolvedArgument, Span, Status,
};
use vibeos_wasi_command::{CommandIo, GuestIo};
use vibeos_wasi_runtime::{
    WasiClockError, WasiInvocation, WasiIo, WasiIoError, WasiLimits, WasiTerminal,
};
static BUSY: AtomicBool = AtomicBool::new(false);
#[cfg(all(feature = "python-command", any(feature = "wasmtime-command", feature = "wasi-rv64-cache")))]
compile_error!("python-wasi currently requires the bounded Wasmi interpreter backend");
struct KernelIo<'a>(GuestIo<'a>);
impl WasiIo for KernelIo<'_> {
    fn read(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<Result<usize, WasiIoError>> {
        self.0.read(cx, bytes)
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        fd: u32,
        bytes: &[u8],
    ) -> Poll<Result<usize, WasiIoError>> {
        self.0.write(cx, fd, bytes)
    }
    fn clock_time(&mut self, id: u32, precision: u64) -> Result<u64, WasiClockError> {
        crate::wasi_clock::time(id, precision).map_err(clock_error)
    }
    fn clock_resolution(&mut self, id: u32) -> Result<u64, WasiClockError> {
        crate::wasi_clock::resolution(id).map_err(clock_error)
    }
}
fn clock_error(errno: i32) -> WasiClockError {
    if errno == 52 { WasiClockError::Unsupported } else { WasiClockError::Failed }
}

fn invocation_limits() -> WasiLimits {
    WasiLimits {
        #[cfg(feature = "wasi-long-fuel")]
        total_fuel: 100_000_000_000,
        ..WasiLimits::default()
    }
}
struct Endpoint;
impl Resource for Endpoint {
    fn kind(&self) -> &'static str {
        "wasi-stdio"
    }
    fn describe(&self) -> String {
        "WASI standard stream".into()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
struct Job {
    bytes: Vec<u8>,
    argv: Vec<String>,
    io: Arc<CommandIo>,
    space: CSpace,
    caps: [Cap; 3],
    result: SpinLock<Option<WasiTerminal>>,
    #[cfg(feature = "wasmtime-command")]
    native_signal: wasmtime_backend::PollSignal,
    #[cfg(feature = "wasmtime-command-fuel-batch")]
    native_fuel: wasmtime_backend::FuelBatch,
    #[cfg(feature = "wasmtime-threads")]
    threads: wasmtime_backend::Threads,
    authority: Option<Box<dyn Fn() -> bool + Send + Sync>>,
}
struct Guest {
    job: usize,
    instance: Option<WasiInvocation>,
    #[cfg(feature = "wasi-benchmark")]
    profile: (u64, u64, u64), // start tick, runtime poll ticks, poll count
}
impl Future for Guest {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        // SAFETY: SYSTEM publishes the boxed record before the child is runnable,
        // and its independent reaper frees it only after this exact child joins.
        let job = unsafe { &*(this.job as *const Job) };
        #[cfg(feature = "wasi-rv64-cache")]
        let mut quanta = 0;
        loop {
            let terminal = if job.io.cancelled() {
                Some(if job.io.denied() {
                    WasiTerminal::Denied
                } else {
                    WasiTerminal::Cancelled
                })
            } else if job.authority.as_ref().is_some_and(|check| !check()) {
                Some(WasiTerminal::Denied)
            } else {
                None
            };
            if let Some(t) = terminal {
                this.instance = None;
                *job.result.lock() = Some(t);
                return Poll::Ready(());
            }
            for (i, cap) in job.caps.iter().enumerate() {
                if job.space.rights_of(*cap).is_err() {
                    this.instance = None;
                    *job.result.lock() = Some(WasiTerminal::Denied);
                    return Poll::Ready(());
                }
                let _ = i;
            }
            if this.instance.is_none() {
                match WasiInvocation::new(&job.bytes, &job.argv, invocation_limits()) {
                    Ok(instance) => {
                        #[cfg(feature = "wasi-rv64-cache")]
                        let instance = {
                            let mut instance = instance;
                            assert!(instance.enable_native_cache(Arc::new(NativePublisher)));
                            instance
                        };
                        this.instance = Some(instance);
                        #[cfg(feature = "wasi-benchmark")]
                        {
                            this.profile.0 = crate::sbi::time();
                        }
                        crate::println!("WASI running");
                    }
                    Err(error) => {
                        crate::println!("WASI admission rejected: {:?}", error);
                        *job.result.lock() =
                            Some(if error == vibeos_wasi_runtime::WasiError::Limit {
                                WasiTerminal::LimitExceeded
                            } else {
                                WasiTerminal::Denied
                            });
                        return Poll::Ready(());
                    }
                }
            }
            #[cfg(feature = "wasi-benchmark")]
            let poll_start = crate::sbi::time();
            let outcome = this
                .instance
                .as_mut()
                .unwrap()
                .poll(cx, &mut KernelIo(GuestIo(&job.io)));
            #[cfg(feature = "wasi-benchmark")]
            {
                let now = crate::sbi::time();
                this.profile.1 += now.wrapping_sub(poll_start);
                this.profile.2 += 1;
                if outcome.is_ready() {
                    crate::println!(
                        "WASI profile polls={} fuel={} runtime_ticks={} wall_ticks={} hz={}",
                        this.profile.2,
                        this.instance.as_ref().unwrap().consumed_fuel(),
                        this.profile.1,
                        now.wrapping_sub(this.profile.0),
                        exec::timebase_hz()
                    );
                }
            }
            #[cfg(feature = "wasi-rv64-cache")]
            {
                quanta += 1;
                // Keep each fuel boundary and authority check. Only avoid a full
                // scheduler round trip when no other work is runnable; host I/O
                // always returns to the executor. Bound even an idle-system batch.
                if outcome.is_pending()
                    && quanta < 32
                    && this.instance.as_ref().unwrap().yielded_for_fuel()
                    && exec::current_task_may_continue()
                {
                    continue;
                }
            }
            return match outcome {
                Poll::Pending => Poll::Pending,
                Poll::Ready(t) => {
                    #[cfg(feature = "wasi-rv64-cache")]
                    {
                        let (funcs, bytes, calls) =
                            this.instance.as_ref().unwrap().native_cache_stats();
                        crate::println!(
                            "WASI native funcs={} bytes={} calls={}",
                            funcs,
                            bytes,
                            calls
                        );
                    }
                    this.instance = None;
                    #[cfg(feature = "wasi-rv64-cache")]
                    crate::println!(
                        "WASI native teardown pool_pages={}",
                        crate::code_pool::stats().live_pages
                    );
                    *job.result.lock() = Some(t);
                    Poll::Ready(())
                }
            };
        }
    }
}
fn launch(
    bytes: &[u8],
    argv: &[String],
    io: Arc<CommandIo>,
    authority: Option<Box<dyn Fn() -> bool + Send + Sync>>,
) -> Result<(), u32> {
    // Local command input can belong to the caller's allocation domain.
    // Keep the asynchronous job's input in SYSTEM until the job retires.
    let _system = unsafe { heap::enter_domain(AllocationDomain::SYSTEM) };
    let mut owned = Vec::new();
    owned.try_reserve_exact(bytes.len()).map_err(|_| 124u32)?;
    owned.extend_from_slice(bytes);
    launch_owned(owned, argv, io, authority)
}

// The SSH request already owns its loaded snapshot in SYSTEM. Transfer it
// directly instead of retaining a second full module buffer during admission.
fn launch_owned(
    bytes: Vec<u8>,
    argv: &[String],
    io: Arc<CommandIo>,
    authority: Option<Box<dyn Fn() -> bool + Send + Sync>>,
) -> Result<(), u32> {
    if BUSY
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(75);
    }
    // Allocate control/input storage outside the guest's reclaimable domain.
    let mut system = unsafe { heap::enter_domain(AllocationDomain::SYSTEM) };
    #[cfg(not(feature = "wasmtime-command"))]
    let heap_budget = WasiLimits::default().allocation_bytes;
    // Code-pool pages are outside HEAP, so reserve their hard maximum from the
    // same invocation budget rather than allowing an additional MiB of memory.
    #[cfg(all(feature = "wasi-rv64-cache", not(feature = "wasmtime-command")))]
    let heap_budget = heap_budget - vibeos_wasi_runtime::native::CODE_BUDGET;
    #[cfg(feature = "wasmtime-command")]
    let heap_budget = crate::wasmtime_platform::invocation_heap_budget();
    let owner = match HEAP.create_owner(heap_budget) {
        Ok(o) => o,
        Err(_) => {
            BUSY.store(false, Ordering::Release);
            return Err(124);
        }
    };
    let arena = match HEAP.create_arena(owner) {
        Ok(a) => a,
        Err(_) => {
            let _ = HEAP.unregister_owner(owner);
            BUSY.store(false, Ordering::Release);
            return Err(124);
        }
    };
    let domain = AllocationDomain::new(owner, arena);
    let mut space = CSpace::new("wasi-command");
    let caps = [
        space.mint(Arc::new(Endpoint), Rights::READ),
        space.mint(Arc::new(Endpoint), Rights::WRITE),
        space.mint(Arc::new(Endpoint), Rights::WRITE),
    ];
    let job = Box::new(Job {
        bytes,
        argv: argv.to_vec(),
        io,
        space,
        caps,
        result: SpinLock::new(None),
        #[cfg(feature = "wasmtime-command")]
        native_signal: wasmtime_backend::PollSignal::new(),
        #[cfg(feature = "wasmtime-command-fuel-batch")]
        native_fuel: wasmtime_backend::FuelBatch::new(),
        #[cfg(feature = "wasmtime-threads")]
        threads: wasmtime_backend::Threads::new(),
        authority,
    });
    let raw = Box::into_raw(job) as usize;
    // SAFETY: Guest contains only this stable control-record key and an
    // arena-local interpreter. Its host bridge copies bytes into fixed SYSTEM
    // pipe arrays; no reference or owning pointer into the arena escapes.
    #[cfg(feature = "wasmtime-command")]
    let guest = { wasmtime_backend::register(domain, raw); wasmtime_backend::Guest::new(raw) };
    #[cfg(not(feature = "wasmtime-command"))]
    let guest = Guest { job: raw, instance: None, #[cfg(feature = "wasi-benchmark")] profile: (0, 0, 0) };
    #[cfg(not(feature = "wasmtime-threads"))]
    let child = unsafe {
        exec::spawn_reclaimable_owned(
            domain,
            "wasi-guest",
            guest,
        )
    };
    // Guest threads are siblings of this task placed on other harts; a fault
    // anywhere quiesces them before the arena is reclaimed raw.
    #[cfg(feature = "wasmtime-threads")]
    let child = unsafe { exec::spawn_reclaimable_owned_parallel(domain, "wasi-guest", guest) };
    let reaper = async move {
        let exit = {
            let mut joined = pin!(child.join());
            loop {
                let mut timer = pin!(exec::sleep_ms(10));
                let result = poll_fn(|cx| {
                    if let Poll::Ready(exit) = joined.as_mut().poll(cx) {
                        return Poll::Ready(Some(exit));
                    }
                    if timer.as_mut().poll(cx).is_ready() {
                        Poll::Ready(None)
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                if let Some(exit) = result {
                    break exit;
                }
                // A blocked guest has no interpreter quantum at which to
                // notice revocation. This SYSTEM supervisor wakes its I/O
                // wait on authority loss without making the guest busy-poll.
                let job = unsafe { &*(raw as *const Job) };
                if job.authority.as_ref().is_some_and(|check| !check()) {
                    job.io.deny();
                }
                // A thread parked in an atomic wait has no I/O wait to
                // interrupt: closing the pipes on cancellation (an SSH channel
                // that went away) wakes nobody, and its siblings stop at their
                // next fuel boundary without ever reaching the notify it waits
                // for. Wake every task so it observes the denial or
                // cancellation through `stopped` and the process can end.
                #[cfg(feature = "wasmtime-threads")]
                if job.io.cancelled() {
                    wasmtime_backend::notify_denied(raw);
                }
            }
        };
        // Sibling thread tasks share the arena. Main normally joins them; after
        // a main fault the executor tore them down. Join whatever remains so
        // retirement sees every handle released.
        #[cfg(feature = "wasmtime-threads")]
        wasmtime_backend::reap_threads(raw).await;
        // The join proves guest polling/destruction and executor fault reclaim
        // have completed. Only the reaper owns and retires the control record.
        #[cfg(feature = "wasmtime-command")]
        wasmtime_backend::retire(domain, raw);
        let mut job = unsafe { Box::from_raw(raw as *mut Job) };
        let t = job.result.lock().unwrap_or(
            if HEAP.account_stats(owner).is_some_and(|s| s.denials != 0) {
                WasiTerminal::LimitExceeded
            } else if exit.state() == exec::TaskState::Faulted {
                WasiTerminal::Trapped
            } else {
                WasiTerminal::Cancelled
            },
        );
        let leftover = HEAP.arena_stats(arena);
        let clean = if leftover.is_some() {
            HEAP.close_empty_domain(domain).is_ok()
        } else {
            true
        };
        let clean = clean && HEAP.unregister_owner(owner).is_ok();
        job.space.revoke_all();
        let caps = job.space.live_count();
        let clean = clean
            && caps == 0
            && HEAP.account_stats(owner).is_none()
            && HEAP.arena_stats(arena).is_none();
        let io = job.io.clone();
        drop(job);
        drop(child);
        if clean {
            BUSY.store(false, Ordering::Release);
        }
        io.complete(if clean { t } else { WasiTerminal::Trapped });
        if !clean {
            // Name what survived so an unclean lifecycle is diagnosable from
            // the log alone: arena bytes/allocations and owner accounting,
            // then every live block's size class, allocating call site (with
            // the benchmark image's `alloc-site-trace`) and first words, and
            // the executor's view. A failed close leaves the arena in place.
            let mut leftover_classes = [0usize; 8];
            let mut leftover_detail = [(0usize, 0usize, [0u64; 32]); 8];
            let leftover_count = HEAP.arena_live_classes(arena, &mut leftover_classes, &mut leftover_detail);
            crate::println!(
                "WASI unclean reclamation: arena={:?} owner={:?} live_classes={:?} ({} total)",
                leftover,
                HEAP.account_stats(owner),
                &leftover_classes[..leftover_count.min(leftover_classes.len())],
                leftover_count
            );
            for (index, (base, site, words)) in leftover_detail[..leftover_count.min(leftover_detail.len())].iter().enumerate() {
                crate::println!("WASI unclean block base={base:#x} class={} site={site:#x} words={words:x?}", leftover_classes[index]);
            }
            crate::println!(
                "WASI unclean executor: remote_detaches={} completed={} faulted={} cancelled={} domain={:?}",
                exec::parallel_remote_detaches(), exec::completed_count(), exec::faulted_count(), exec::cancelled_count(),
                exec::reclaimable_domain_snapshot(domain)
            );
            for task in exec::task_report() {
                crate::println!("WASI unclean live task id={} name={} state={:?} owner={:?} arena={:?} polls={}", task.id.0, task.name, task.state, task.owner, task.arena, task.polls);
            }
        }
        crate::println!(
            "WASI terminal={:?} reclaimed={} caps={} waiters={}",
            t,
            clean,
            caps,
            io.pending_waiters()
        );
    };
    // The periodic SYSTEM supervisor belongs with boot-hart housekeeping.
    // Letting idle workers steal it makes their future CPU-bound polls share
    // that hart with every 10 ms wakeup, defeating worker placement isolation.
    #[cfg(feature = "wasmtime-threads")]
    exec::spawn_pinned_on(exec::HartId::BOOT, "wasi-reaper", reaper);
    #[cfg(not(feature = "wasmtime-threads"))]
    exec::spawn_tracked("wasi-reaper", reaper);
    system.restore();
    Ok(())
}
struct CancelOnDrop(Arc<CommandIo>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
pub fn install(session: &mut vibeos_vsh::Session) {
    session.install_capability_host_command(
        "wasm-run",
        1,
        128,
        vibeos_vsh::StreamMode::Optional,
        planner,
        run_local,
    );
}
fn planner(args: &[ExpandedArgument]) -> Result<Vec<PathRequirement>, PlannerError> {
    if args.first().and_then(ExpandedArgument::path).is_none()
        || args[1..].iter().any(|a| a.value().is_none())
    {
        return Err(PlannerError {
            span: Span { start: 0, end: 0 },
            message: "usage: wasm-run @ROOT/file.wasm [arguments...]",
        });
    }
    Ok(alloc::vec![PathRequirement {
        argument: 0,
        rights: Rights::READ
    }])
}
fn run_local(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    Box::pin(async move {
        let Some(ResolvedArgument::CapabilityPath { root, tail, .. }) = ctx.args.first() else {
            return Err(Status::Usage);
        };
        let root_cap = *root;
        let path = vibeos_file_store::RelPath::parse(tail).map_err(|_| Status::Usage)?;
        let reader = ctx
            .lookup::<vibeos_file_store::FileTreeRoot>(root_cap, Rights::READ)?
            .with(|root| root.regular_reader(&path))
            .map_err(|_| Status::Denied)?;
        if reader.0.size > vibeos_wasi_runtime::profile::MODULE_BYTES as u64 {
            return Err(Status::BudgetExceeded);
        }
        let bytes = vibeos_wasi_command::load_reader(reader.1, reader.0.size)
            .await
            .map_err(|_| Status::Denied)?;
        let mut argv = alloc::vec![path.file_name().unwrap_or("command.wasm").to_string()];
        for arg in &ctx.args[1..] {
            let ResolvedArgument::Value(v) = arg else {
                return Err(Status::Usage);
            };
            argv.push(v.clone());
        }
        let io = {
            let _system = unsafe { heap::enter_domain(AllocationDomain::SYSTEM) };
            Arc::new(CommandIo::new())
        };
        let authority = {
            let _system = unsafe { heap::enter_domain(AllocationDomain::SYSTEM) };
            Box::new(ctx.authority_check(root_cap, Rights::READ))
        };
        launch(&bytes, &argv, io.clone(), Some(authority)).map_err(|n| {
            if n == 75 {
                Status::Unavailable
            } else {
                Status::BudgetExceeded
            }
        })?;
        let _cancel = CancelOnDrop(io.clone());
        let input = async {
            loop {
                match ctx.read_stdin_chunk().await {
                    Ok(Some(bytes)) => {
                        let mut offset = 0;
                        while offset < bytes.len() {
                            match poll_fn(|cx| io.stdin.write(cx, &bytes[offset..])).await {
                                Ok(n) => offset += n,
                                Err(_) => return,
                            }
                        }
                    }
                    _ => {
                        io.stdin.close();
                        return;
                    }
                }
            }
        };
        let output = async {
            let mut buffer = [0; 1024];
            loop {
                match poll_fn(|cx| io.stdout.read(cx, &mut buffer)).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if ctx.write_stdout(buffer[..n].to_vec()).await != Status::Success {
                            io.cancel();
                            return;
                        }
                    }
                }
            }
        };
        let error = async {
            let mut buffer = [0; 1024];
            loop {
                match poll_fn(|cx| io.stderr.read(cx, &mut buffer)).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if ctx.write_stderr(buffer[..n].to_vec()).await != Status::Success {
                            io.cancel();
                            return;
                        }
                    }
                }
            }
        };
        let mut input = pin!(input);
        let mut output = pin!(output);
        let mut error = pin!(error);
        let (mut i, mut o, mut e) = (false, false, false);
        let terminal = poll_fn(|cx| {
            if ctx.cancelled()
                || ctx
                    .lookup::<vibeos_file_store::FileTreeRoot>(root_cap, Rights::READ)
                    .is_err()
            {
                io.cancel();
            }
            if !i {
                i = input.as_mut().poll(cx).is_ready();
            }
            if !o {
                o = output.as_mut().poll(cx).is_ready();
            }
            if !e {
                e = error.as_mut().poll(cx).is_ready();
            }
            match io.poll_terminal(cx) {
                Poll::Ready(t) if o && e => Poll::Ready(t),
                _ => Poll::Pending,
            }
        })
        .await;
        match terminal {
            WasiTerminal::Exited(n) => {
                ctx.record_exit_code(n);
                if n == 0 {
                    Ok(String::new())
                } else {
                    Err(Status::Returned(u8::try_from(n).unwrap_or(1)))
                }
            }
            WasiTerminal::Cancelled => Err(Status::Cancelled),
            WasiTerminal::Denied => Err(Status::Denied),
            WasiTerminal::LimitExceeded => Err(Status::BudgetExceeded),
            _ => Err(Status::Faulted),
        }
    })
}

#[cfg(any(feature = "wasi-ssh", feature = "milkv-wasmtime", feature = "milkv-python"))]
pub fn permitted(
    profile: vibeos_sshd::AuthorizedProfile,
    request: &vibeos_wasi_command::Request,
) -> bool {
    #[cfg(any(feature = "milkv-wasmtime", feature = "milkv-python"))]
    let admitted = crate::ssh_provisioning::command_profile_current(profile);
    #[cfg(not(any(feature = "milkv-wasmtime", feature = "milkv-python")))]
    let admitted = profile.profile.get() == 1 && profile.generation == 1;
    admitted && match request {
        vibeos_wasi_command::Request::Upload { .. } => cfg!(any(feature = "wasi-ssh-upload", feature = "milkv-wasmtime", feature = "milkv-python")),
        vibeos_wasi_command::Request::Run { .. } => true,
    }
}
#[cfg(any(feature = "wasi-ssh", feature = "milkv-wasmtime", feature = "milkv-python"))]
struct RequestService(bool);
#[cfg(any(feature = "wasi-ssh", feature = "milkv-wasmtime", feature = "milkv-python"))]
impl Resource for RequestService {
    fn kind(&self) -> &'static str {
        if self.0 {
            "wasi-upload-service"
        } else {
            "wasi-execution-service"
        }
    }
    fn describe(&self) -> String {
        self.kind().into()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
#[cfg(any(feature = "wasi-ssh", feature = "milkv-wasmtime", feature = "milkv-python"))]
pub fn open(
    profile: vibeos_sshd::AuthorizedProfile,
    request: vibeos_wasi_command::Request,
) -> Result<Arc<CommandIo>, u32> {
    if !permitted(profile, &request) {
        return Err(126);
    }
    let mut system = unsafe { heap::enter_domain(AllocationDomain::SYSTEM) };
    let io = Arc::new(CommandIo::new());
    let task_io = io.clone();
    exec::spawn_tracked("wasi-ssh-request", async move {
        let result = async {
            let storage = crate::world::world().storage_v2.clone().ok_or(125u32)?;
            let root = loop {
                if task_io.cancelled() {
                    return Err(130);
                }
                match storage.selected_boot_store() {
                    None => {
                        exec::yield_now().await;
                        continue;
                    }
                    Some(crate::segment_store_platform::BootStoreSelection::StorageV2) => (),
                    Some(_) => return Err(125),
                }
                match storage
                    .recover_file_tree_root(0x5649_4245_4f53_2d46_494c_4554_5245_4501)
                    .await
                {
                    Ok(root) => break root,
                    Err(vibeos_file_store::FileError::Busy) => exec::yield_now().await,
                    Err(_) => return Err(125),
                }
            };
            if task_io.cancelled() {
                return Err(130);
            }
            if !permitted(profile, &request) {
                return Err(126);
            }
            // Translate the explicitly admitted SSH profile into least-rights
            // loader capabilities. This CSpace belongs to the trusted request,
            // not to the guest, whose CSpace still contains only stdio.
            let uploading = matches!(&request, vibeos_wasi_command::Request::Upload { .. });
            let rights = if uploading {
                Rights::READ.union(Rights::WRITE)
            } else {
                Rights::READ
            };
            let mut loader = CSpace::new("wasi-ssh-loader");
            let source = loader.mint(root, rights);
            let service = loader.mint(Arc::new(RequestService(uploading)), Rights::INVOKE);
            let service_lease = loader
                .lookup_lease::<RequestService>(service, Rights::INVOKE)
                .map_err(|_| 126u32)?;
            let root = loader
                .lookup_as::<vibeos_file_store::FileTreeRoot>(source, rights)
                .map_err(|_| 126u32)?;
            match request {
                vibeos_wasi_command::Request::Upload {
                    name,
                    length,
                    sha256,
                } => {
                    crate::println!("WASI upload receiving {}", name);
                    vibeos_wasi_command::upload(&root, &name, length, sha256, &task_io).await?;
                    Ok(false)
                }
                vibeos_wasi_command::Request::Run { name, args } => {
                    let path = vibeos_wasi_command::upload_path(&name)?;
                    let bytes = vibeos_wasi_command::load(&root, &path).await?;
                    if task_io.cancelled() {
                        return Err(130);
                    }
                    let mut argv = alloc::vec![name];
                    argv.extend(args);
                    let authority = Box::new(move || {
                        // Both handles are fresh private roots, validated by
                        // lookup_lease/lookup_as above. This closure exclusively
                        // owns their loader CSpace and never mutates it or
                        // exports either derivation. Retain it for the complete
                        // invocation, but do not re-walk invariant slots at
                        // every fuel boundary. The invocation lease retains
                        // the granted execution right; session denial and
                        // disconnect still revoke CommandIo at every boundary.
                        let _keep_loader_alive = &loader;
                        #[cfg(any(feature = "milkv-wasmtime", feature = "milkv-python"))]
                        if !crate::ssh_provisioning::command_profile_current(profile) {
                            return false;
                        }
                        service_lease.authorizes(Rights::INVOKE)
                    });
                    launch_owned(bytes, &argv, task_io.clone(), Some(authority))?;
                    Ok(true)
                }
            }
        }
        .await;
        match result {
            Ok(true) => (),
            Ok(false) => task_io.complete(WasiTerminal::Exited(0)),
            Err(n) => task_io.complete(WasiTerminal::Exited(n)),
        }
    });
    system.restore();
    Ok(io)
}

#[cfg(feature = "wasi-rv64-cache")]
#[derive(Debug)]
struct NativePublisher;
#[cfg(feature = "wasi-rv64-cache")]
struct NativeImage(crate::code_pool::ExecutableCode);
#[cfg(feature = "wasi-rv64-cache")]
impl core::fmt::Debug for NativeImage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeImage")
            .field("bytes", &self.0.byte_len())
            .finish()
    }
}
#[cfg(feature = "wasi-rv64-cache")]
// SAFETY: code_pool owns immutable execute-only pages through this handle and
// unseals/zeros them on Drop. Its fault reclaimer uses the exact guest domain.
unsafe impl vibeos_wasi_runtime::native::Executable for NativeImage {
    fn entry(&self) -> usize {
        self.0.entry()
    }
}
#[cfg(feature = "wasi-rv64-cache")]
// SAFETY: only the trusted IR compiler calls publish. The code pool copies into
// private RW-NX pages and completes local/remote W^X synchronization at seal.
unsafe impl vibeos_wasi_runtime::native::CodeMemory for NativePublisher {
    fn publish(&self, words: &[u32]) -> Option<Box<dyn vibeos_wasi_runtime::native::Executable>> {
        let mut code = crate::code_pool::WritableCode::allocate(words.len()).ok()?;
        code.words_mut().copy_from_slice(words);
        Some(Box::new(NativeImage(code.seal())))
    }
}
