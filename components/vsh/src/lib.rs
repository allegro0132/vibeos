//! Capability-native interactive shell frontend.
//!
//! This component owns parsing, planning, job execution, terminal line
//! discipline, the interactive loop, foreground cancellation, report
//! rendering, and declarative command registration. The kernel supplies only
//! byte-oriented console operations and capability-backed command adapters.

#![no_std]

extern crate alloc;

mod engine;
pub mod terminal;

pub use engine::*;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::future::{poll_fn, Future};
use core::pin::{pin, Pin};
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Poll;

use vibeos_core::sync::SpinLock;

pub type ReadByteFuture<'a> = Pin<Box<dyn Future<Output = u8> + Send + 'a>>;
pub type CommandHandler = fn(&[String]) -> Result<String, Status>;

pub enum InputEvent {
    Line(String),
    Interrupt,
    Eof,
}

/// Narrow console surface required by the unprivileged frontend.
pub trait Platform: Sync {
    fn prompt(&self, text: &'static str);
    fn read_byte(&self) -> ReadByteFuture<'_>;
    fn accept_byte(&self, byte: u8) -> Option<InputEvent>;
    fn write(&self, text: &str);
}

#[derive(Clone, Copy)]
pub struct CommandSpec {
    pub name: &'static str,
    pub min_args: usize,
    pub max_args: usize,
    pub handler: CommandHandler,
}

/// Install audited commands selected by boot policy. Registration happens in
/// this component; kernel code supplies only the capability-service adapters.
pub fn install_commands(session: &mut Session, commands: &[CommandSpec]) {
    for command in commands {
        session.install_host_command(
            command.name,
            command.min_args,
            command.max_args,
            command.handler,
        );
    }
}

pub async fn task(platform: &dyn Platform, mut session: Session) {
    platform.write("\nVibeOS vsh ready -- capability-native shell.\n\n");
    interactive(platform, &mut session, false).await;
}

/// Run an interactive session. The legacy diagnostic shell uses
/// `return_on_interrupt` to make Ctrl-C return to its parent prompt.
pub async fn interactive(
    platform: &dyn Platform,
    session: &mut Session,
    return_on_interrupt: bool,
) {
    loop {
        platform.prompt("vsh> ");
        match read_line(platform).await {
            Some(line) if !line.is_empty() => run_source(platform, &line, session).await,
            Some(_) => {}
            None if return_on_interrupt => return,
            None => {}
        }
    }
}

pub async fn run_source(platform: &dyn Platform, source: &str, session: &mut Session) {
    let cancel = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(SpinLock::new(None));
    let completed_task = completed.clone();
    let cancel_task = cancel.clone();
    let source = String::from(source);
    let mut foreground = core::mem::take(session);
    let handle = vibeos_core::exec::spawn_tracked("vsh-foreground", async move {
        let result = foreground.execute_cancellable(&source, cancel_task).await;
        *completed_task.lock() = Some((foreground, result));
    });

    loop {
        let mut join = pin!(handle.join());
        let mut input = platform.read_byte();
        let event = poll_fn(|cx| {
            if let Poll::Ready(exit) = join.as_mut().poll(cx) {
                return Poll::Ready(Ok(exit));
            }
            input.as_mut().poll(cx).map(Err)
        })
        .await;
        match event {
            Ok(_) => break,
            Err(0x03) => cancel.store(true, Ordering::Release),
            Err(_) => {}
        }
    }

    let (foreground, result) = completed
        .lock()
        .take()
        .expect("vsh foreground published no result");
    *session = foreground;
    let mut output = String::new();
    match result {
        Ok(reports) => {
            for report in reports {
                output.push_str(&report.output);
                if report.status != Status::Success {
                    output.push_str(&format!("  vsh job %{}: {:?}\n", report.id, report.status));
                }
            }
        }
        Err(error) => output.push_str(&format!(
            "  vsh: {} at bytes {}..{}\n",
            error.message, error.span.start, error.span.end
        )),
    }
    if !output.is_empty() {
        platform.write(&output);
    }
}

pub fn help(_args: &[String]) -> Result<String, Status> {
    let help = String::from(
        "  echo ...        write value arguments\n\
         \x20 wc              count stdin bytes, words, and lines\n\
         \x20 let NAME VALUE  set a session value\n\
         \x20 if/while        bounded control flow (`; then` / `; do`)\n\
         \x20 function N ...  define a value-only scoped function\n\
         \x20 echo \"$(...)\"  bounded command substitution\n\
         \x20 run-script @S   run a read-only manifested script\n\
         \x20 jobs            list session jobs\n\
         \x20 wait %N         join a job\n\
         \x20 cancel %N       cancel a job\n\
         \x20 ps              component lifecycle snapshots\n\
         \x20 caps [space]    sanitized capability summary\n\
         \x20 mem             bounded-memory accounts\n\
         \x20 quiet           mute background component output\n\
         \x20 verbose         restore background component output\n\
         \x20 poweroff        power off\n",
    );
    #[cfg(feature = "pci-usb-help")]
    let help = {
        let mut help = help;
        help.push_str(
            "  pci             list discovered PCI functions\n\
             \x20 usb info        list XHCI USB devices\n\
             \x20 usb read N      read one USB-storage sector\n\
             \x20 usb test        destructive CI test of sectors 7 and 8\n",
        );
        help
    };
    #[cfg(feature = "network")]
    let help = {
        let mut help = help;
        help.push_str(
            "  ip ...          show or configure IPv4 on net0\n\
             \x20 dhclient [-r]  acquire or stop DHCPv4\n",
        );
        help
    };
    Ok(help)
}

async fn read_line(platform: &dyn Platform) -> Option<String> {
    loop {
        match platform.accept_byte(platform.read_byte().await) {
            None => {}
            Some(InputEvent::Line(line)) => return Some(line),
            Some(InputEvent::Interrupt | InputEvent::Eof) => return None,
        }
    }
}
