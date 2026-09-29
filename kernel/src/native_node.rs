//! Persistent supervisor for an admitted native Node invocation. Its lifetime
//! is independent of the VSH command future; cancellation requests normal
//! native termination and never drops a suspended C++ stack.
use alloc::{boxed::Box, ffi::CString, string::String, sync::Arc, vec::Vec};
use core::{future::{poll_fn, Future}, pin::pin, sync::atomic::{AtomicBool, Ordering}, task::Poll};
use vibeos_core::{exec, heap::{self, AllocationDomain}, sync::SpinLock};
use vibeos_wasi_command::CommandIo;
use vibeos_wasi_runtime::WasiTerminal;
use crate::{native_call::NativeAsync, native_files::FileGrant, native_tls::NativeSyncDomain};

static BUSY: AtomicBool = AtomicBool::new(false);
static DOMAIN: SpinLock<Option<Arc<NativeSyncDomain>>> = SpinLock::new(None);
struct Admission;
impl Drop for Admission {
    fn drop(&mut self) { BUSY.store(false, Ordering::Release); }
}

/// Callers construct grants and streams in SYSTEM, as they can outlive the
/// originating job. Arguments are copied into SYSTEM before publishing a task.
pub(super) fn launch(argv: &[String], eval: Option<&str>, files: FileGrant,
                     tools: Option<FileGrant>, io: Arc<CommandIo>) -> Result<(), vibeos_vsh::Status> {
    use vibeos_vsh::Status;
    if argv.is_empty() || argv.len() > 128 ||
       argv.iter().try_fold(0usize, |n, a| n.checked_add(a.len())).is_none_or(|n| n > 65536) ||
       eval.is_some_and(|s| s.len() > 1024 * 1024) {
        return Err(Status::BudgetExceeded);
    }
    let _system = unsafe { heap::enter_domain(AllocationDomain::SYSTEM) };
    let argv: Vec<CString> = argv.iter().map(|s| CString::new(s.as_bytes()))
        .collect::<Result<_, _>>().map_err(|_| Status::Usage)?;
    let eval = eval.map(|s| s.as_bytes().to_vec());
    let entropy = crate::world::world().native_entropy_probe_grant().ok_or(Status::Unavailable)?;
    if BUSY.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return Err(Status::Unavailable);
    }
    let admission = Admission;
    let domain = DOMAIN.lock().get_or_insert_with(NativeSyncDomain::new).clone();
    exec::spawn_pinned_on(exec::HartId::BOOT, "node-supervisor", async move {
        let _admission = admission;
        if !files.live() || tools.as_ref().is_some_and(|grant| !grant.live()) {
            drop(_admission);
            io.complete(WasiTerminal::Denied);
            return;
        }
        if io.cancelled() {
            drop(_admission);
            io.complete(WasiTerminal::Cancelled);
            return;
        }
        let entry = Box::new(move || {
            unsafe extern "C" {
                fn vibeos_node_run(argc: u32, argv: *const *const core::ffi::c_char,
                                   eval: *const core::ffi::c_char, eval_length: usize) -> i32;
            }
            let pointers: Vec<_> = argv.iter().map(|s| s.as_ptr()).collect();
            let (source, length) = eval.as_ref().map_or((core::ptr::null(), 0),
                |s| (s.as_ptr().cast(), s.len()));
            // All pointer owners remain on this retained stack until return.
            unsafe { vibeos_node_run(pointers.len() as u32, pointers.as_ptr(), source, length) as usize }
        });
        let Some(run) = NativeAsync::try_owned_entry(entry, 128 * 1024 * 1024, domain) else {
            drop(_admission);
            io.complete(WasiTerminal::LimitExceeded);
            return;
        };
        run.tls().set_files(files.clone());
        if let Some(tools) = tools.as_ref() { run.tls().set_tools(tools.clone()); }
        run.tls().set_entropy(entropy);
        run.tls().set_stdio(crate::native_stdio::StdioGrant::new(io.clone()));
        // No host environment is inherited; explicit empty initial environment.
        run.tls().set_environment(&[]).expect("empty Node environment");
        let monitor = async {
            loop {
                exec::sleep_ms(10).await;
                if !files.live() || tools.as_ref().is_some_and(|grant| !grant.live()) { io.deny(); }
            }
        };
        let mut monitor = pin!(monitor);
        let mut run = pin!(run.run());
        let (result, _) = poll_fn(|cx| {
            let _ = monitor.as_mut().poll(cx);
            match run.as_mut().poll(cx) {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => Poll::Pending,
            }
        }).await;
        // Completion is published only after NativeAsync has returned and its
        // protected stack/TLS/page-owner cleanup has run.
        // Release admission before waking a command on another hart, so a
        // sequential VSH command never observes the previous invocation busy.
        drop(_admission);
        io.complete(if io.denied() { WasiTerminal::Denied }
                    else if io.cancelled() { WasiTerminal::Cancelled }
                    else { WasiTerminal::Exited(result as u32) });
    });
    Ok(())
}

struct CancelOnDrop(Arc<CommandIo>);
impl Drop for CancelOnDrop { fn drop(&mut self) { self.0.cancel(); } }
use vibeos_vsh::{CapabilityCommandContext, CapabilityCommandFuture, ExpandedArgument,
                 PathRequirement, PlannerError, ResolvedArgument, Span, Status};
use vibeos_core::cap::Rights;

pub(super) fn install(session: &mut vibeos_vsh::Session) {
    session.install_capability_host_command("node", 3, 128,
        vibeos_vsh::StreamMode::Optional, planner, run_local);
    #[cfg(feature = "node-toolkit")]
    session.install_capability_host_command("tsc", 2, 128,
        vibeos_vsh::StreamMode::Optional, tool_planner, run_tsc);
    #[cfg(feature = "node-toolkit")]
    session.install_capability_host_command("tsx", 3, 128,
        vibeos_vsh::StreamMode::Optional, planner, run_tsx);
    #[cfg(feature = "node-toolkit-probe")]
    session.install_capability_host_command("node-tool-probe", 3, 128,
        vibeos_vsh::StreamMode::Optional, planner, run_tool_probe);
}
#[derive(Clone, Copy, PartialEq)]
enum CommandKind { Node, Compiler, #[cfg(feature = "node-toolkit")] Tsx, #[cfg(feature = "node-toolkit-probe")] ToolProbe }
#[cfg(feature = "node-toolkit")]
fn run_tsx(ctx: CapabilityCommandContext) -> CapabilityCommandFuture { run_command(ctx, CommandKind::Tsx) }
#[cfg(feature = "node-toolkit-probe")]
fn run_tool_probe(ctx: CapabilityCommandContext) -> CapabilityCommandFuture { run_command(ctx, CommandKind::ToolProbe) }
#[cfg(feature = "node-toolkit")]
fn tool_planner(args: &[ExpandedArgument]) -> Result<Vec<PathRequirement>, PlannerError> {
    if args.len() < 2 || args[0].value() != Some("--root") || args[1].path().is_none() ||
       args[2..].iter().any(|a| a.value().is_none()) {
        return Err(PlannerError { span: Span { start: 0, end: 0 },
            message: "usage: tsc --root @ROOT/project [compiler options]" });
    }
    Ok(alloc::vec![PathRequirement { argument: 1, rights: Rights::READ.union(Rights::WRITE) }])
}
#[cfg(feature = "node-toolkit")]
fn run_tsc(ctx: CapabilityCommandContext) -> CapabilityCommandFuture { run_command(ctx, CommandKind::Compiler) }
fn planner(args: &[ExpandedArgument]) -> Result<Vec<PathRequirement>, PlannerError> {
    if args.len() < 3 || args[0].value() != Some("--root") || args[1].path().is_none() ||
       args[2..].iter().any(|a| a.value().is_none()) ||
       (args[2].value() == Some("-e") && args.len() < 4) {
        return Err(PlannerError { span: Span { start: 0, end: 0 },
            message: "usage: node --root @ROOT/project main.js [args...] | -e source [args...]" });
    }
    Ok(alloc::vec![PathRequirement { argument: 1, rights: Rights::READ.union(Rights::WRITE) }])
}
fn run_local(ctx: CapabilityCommandContext) -> CapabilityCommandFuture {
    run_command(ctx, CommandKind::Node)
}
fn run_command(ctx: CapabilityCommandContext, kind: CommandKind) -> CapabilityCommandFuture {
    Box::pin(async move {
        let Some(ResolvedArgument::CapabilityPath { root, tail, .. }) = ctx.args.get(1) else {
            return Err(Status::Usage);
        };
        let root_cap = *root;
        let path = vibeos_file_store::RelPath::parse(tail).map_err(|_| Status::Usage)?;
        let mut values = Vec::new();
        for arg in &ctx.args[2..] {
            let ResolvedArgument::Value(value) = arg else { return Err(Status::Usage); };
            values.push(value.clone());
        }
        let mut argv = alloc::vec![String::from("node")];
        #[cfg(feature = "node-toolkit")]
        if kind == CommandKind::Tsx {
            if values.first().is_none_or(|s| s.starts_with('-') || s == "watch") {
                let _ = ctx.write_stderr(b"tsx: expected script; watch and subprocess modes are unavailable\n".to_vec()).await;
                return Err(Status::Unavailable);
            }
            values.insert(0, String::from("/.vibeos-tools/vibeos/tsx-launcher.mjs"));
        }
        let eval = if kind == CommandKind::Compiler {
            if values.iter().any(|arg| arg.eq_ignore_ascii_case("--watch") || arg.eq_ignore_ascii_case("-w")) {
                let _ = ctx.write_stderr(b"tsc: watch is unavailable in the VibeOS port\n".to_vec()).await;
                return Err(Status::Unavailable);
            }
            argv.push(String::from("/.vibeos-tools/node_modules/typescript/lib/tsc.js"));
            argv.extend(values.iter().cloned());
            None
        } else if values.first().is_some_and(|s| s == "-e") {
            if values.len() < 2 { return Err(Status::Usage); }
            argv.extend(values[2..].iter().cloned());
            Some(values[1].as_str())
        } else {
            if values.first().is_none_or(|s| s.starts_with('-')) { return Err(Status::Usage); }
            argv.extend(values.iter().cloned());
            None
        };
        #[cfg(feature = "node-toolkit")]
        let tools = if kind != CommandKind::Node { Some(crate::native_toolkit::grant().await.map_err(|_| Status::Unavailable)?) } else { None };
        #[cfg(not(feature = "node-toolkit"))]
        let tools = None;
        let io = {
            let _system = unsafe { heap::enter_domain(AllocationDomain::SYSTEM) };
            let provider = ctx.resource_lease_provider::<vibeos_file_store::FileTreeRoot>(
                root_cap, Rights::READ.union(Rights::WRITE));
            let grant = FileGrant::from_provider(move |rights| provider(rights).ok())
                .and_then(|grant| grant.directory(path)).ok_or(Status::Denied)?;
            let io = Arc::new(CommandIo::new());
            launch(&argv, eval, grant, tools, io.clone())?;
            io
        };
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
