//! Raw WASI command lifecycle. SYSTEM owns inputs, streams and the control
//! record; the audited child owns only its interpreter allocations. No guest
//! allocation or pointer is published outside the child's arena.
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
// A low-register read latches the high register globally; serialize the pair.
#[cfg(feature = "qemu-virt")]
static RTC_LOCK: SpinLock<()> = SpinLock::new(());
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
    fn clock_time(&mut self, id: u32, _precision: u64) -> Result<u64, WasiClockError> {
        match id {
            #[cfg(feature = "qemu-virt")]
            0 => {
                let _lock = RTC_LOCK.lock();
                // SAFETY: QEMU virt's BSP maps these two 32-bit RTC registers.
                // TIME_LOW latches TIME_HIGH; neither read changes the RTC time.
                let ns = unsafe {
                    let low = core::ptr::read_volatile(crate::platform::RTC_BASE as *const u32);
                    let high =
                        core::ptr::read_volatile((crate::platform::RTC_BASE + 4) as *const u32);
                    (u64::from(high) << 32) | u64::from(low)
                };
                Ok(ns)
            }
            1 => u64::try_from(
                u128::from(crate::sbi::time()) * 1_000_000_000 / u128::from(exec::timebase_hz()),
            )
            .map_err(|_| WasiClockError::Failed),
            _ => Err(WasiClockError::Unsupported),
        }
    }
    fn clock_resolution(&mut self, id: u32) -> Result<u64, WasiClockError> {
        match id {
            #[cfg(feature = "qemu-virt")]
            0 => Ok(1),
            1 => Ok(1_000_000_000u64.div_ceil(exec::timebase_hz())),
            _ => Err(WasiClockError::Unsupported),
        }
    }
}
fn invocation_limits() -> WasiLimits {
    WasiLimits {
        #[cfg(feature = "wasi-benchmark")]
        total_fuel: 10_000_000_000,
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
                    this.instance = Some(instance);
                    #[cfg(feature = "wasi-benchmark")]
                    {
                        this.profile.0 = crate::sbi::time();
                    }
                    crate::println!("WASI running");
                }
                Err(error) => {
                    crate::println!("WASI admission rejected: {:?}", error);
                    *job.result.lock() = Some(if error == vibeos_wasi_runtime::WasiError::Limit {
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
        match outcome {
            Poll::Pending => Poll::Pending,
            Poll::Ready(t) => {
                this.instance = None;
                *job.result.lock() = Some(t);
                Poll::Ready(())
            }
        }
    }
}
fn launch(
    bytes: &[u8],
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
    let owner = match HEAP.create_owner(WasiLimits::default().allocation_bytes) {
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
        bytes: bytes.to_vec(),
        argv: argv.to_vec(),
        io,
        space,
        caps,
        result: SpinLock::new(None),
        authority,
    });
    let raw = Box::into_raw(job) as usize;
    // SAFETY: Guest contains only this stable control-record key and an
    // arena-local interpreter. Its host bridge copies bytes into fixed SYSTEM
    // pipe arrays; no reference or owning pointer into the arena escapes.
    let child = unsafe {
        exec::spawn_reclaimable_owned(
            domain,
            "wasi-guest",
            Guest {
                job: raw,
                instance: None,
                #[cfg(feature = "wasi-benchmark")]
                profile: (0, 0, 0),
            },
        )
    };
    exec::spawn_tracked("wasi-reaper", async move {
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
            }
        };
        // The join proves guest polling/destruction and executor fault reclaim
        // have completed. Only the reaper owns and retires the control record.
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
        let clean = if HEAP.arena_stats(arena).is_some() {
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
        crate::println!(
            "WASI terminal={:?} reclaimed={} caps={} waiters={}",
            t,
            clean,
            caps,
            io.pending_waiters()
        );
    });
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
        if reader.0.size > 512 * 1024 {
            return Err(Status::BudgetExceeded);
        }
        let bytes = vibeos_wasi_command::load_reader(reader.1)
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

#[cfg(feature = "wasi-ssh")]
pub fn permitted(
    profile: vibeos_sshd::AuthorizedProfile,
    request: &vibeos_wasi_command::Request,
) -> bool {
    // Explicit QEMU acceptance profile, separate upload/run capability switches.
    profile.profile.get() == 1
        && profile.generation == 1
        && match request {
            vibeos_wasi_command::Request::Upload { .. } => cfg!(feature = "wasi-ssh-upload"),
            vibeos_wasi_command::Request::Run { .. } => true,
        }
}
#[cfg(feature = "wasi-ssh")]
struct RequestService(bool);
#[cfg(feature = "wasi-ssh")]
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
#[cfg(feature = "wasi-ssh")]
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
                        service_lease.authorizes(Rights::INVOKE)
                            && loader
                                .rights_of(source)
                                .is_ok_and(|r| r.contains(Rights::READ))
                            && loader
                                .rights_of(service)
                                .is_ok_and(|r| r.contains(Rights::INVOKE))
                    });
                    launch(&bytes, &argv, task_io.clone(), Some(authority))?;
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
