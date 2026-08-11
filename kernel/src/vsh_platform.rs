//! Kernel capability adapters for the separately compiled VSH frontend.

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use vibeos_core::cap::{Cap, Rights};
#[cfg(feature = "milkv-ssh")]
use vibeos_vsh::AsyncCommandSpec;
use vibeos_vsh::{CommandSpec, InputEvent, Platform, Session, Status};

use crate::dev::ConsoleDev;
use crate::world::{world, Space};

pub struct VshPlatform {
    front: Option<(Arc<Space>, Cap)>,
}

impl VshPlatform {
    fn capability_front(space: Arc<Space>, console: Cap) -> Self {
        Self {
            front: Some((space, console)),
        }
    }

    #[cfg(feature = "legacy-shell")]
    fn diagnostic_uart() -> Self {
        Self { front: None }
    }
}

impl Platform for VshPlatform {
    fn prompt(&self, text: &'static str) {
        crate::tty::prompt(text);
    }

    fn set_completion_candidates(&self, candidates: &[String]) {
        crate::tty::set_completion_candidates(candidates);
    }

    fn read_byte(&self) -> vibeos_vsh::ReadByteFuture<'_> {
        Box::pin(crate::uart::read_byte())
    }

    fn accept_byte(&self, byte: u8) -> Option<InputEvent> {
        match crate::tty::input_byte(byte) {
            None => None,
            Some(crate::terminal::TerminalEvent::Line(line)) => Some(InputEvent::Line(line)),
            Some(crate::terminal::TerminalEvent::Interrupt) => Some(InputEvent::Interrupt),
            Some(crate::terminal::TerminalEvent::Eof) => Some(InputEvent::Eof),
        }
    }

    fn write(&self, text: &str) {
        let Some((space, console)) = &self.front else {
            crate::uart::_print(format_args!("{}", text));
            return;
        };
        match space
            .0
            .lock()
            .lookup_revocable::<ConsoleDev>(*console, Rights::WRITE)
        {
            Ok(token) => {
                let _ = token.try_with(|console| console.write(text));
            }
            Err(_) => crate::tty::cancel(),
        }
    }
}

pub async fn task(space: Arc<Space>, console: Cap, session: Session) {
    let platform = VshPlatform::capability_front(space, console);
    vibeos_vsh::task(&platform, session).await;
}

#[cfg(feature = "legacy-shell")]
pub async fn interactive_legacy(session: &mut Session) {
    let platform = VshPlatform::diagnostic_uart();
    vibeos_vsh::interactive(&platform, session, true).await;
}

#[cfg(feature = "legacy-shell")]
pub async fn run_legacy_source(source: &str, session: &mut Session) {
    let platform = VshPlatform::diagnostic_uart();
    vibeos_vsh::run_source(&platform, source, session).await;
}

pub fn install_standard_commands(session: &mut Session) {
    install_shared_commands(session);
    #[cfg(feature = "milkv-ssh")]
    vibeos_vsh::install_async_commands(session, SSH_UART_MUTATION_COMMANDS);
}

/// Install commands shared by the physical console and authenticated SSH.
fn install_shared_commands(session: &mut Session) {
    vibeos_vsh::install_commands(session, BASE_COMMANDS);
    #[cfg(feature = "qemu-virt")]
    vibeos_vsh::install_commands(session, QEMU_COMMANDS);
    #[cfg(feature = "milkv-duo")]
    vibeos_vsh::install_commands(session, MILKV_USB_COMMANDS);
    #[cfg(any(
        feature = "tcp-echo",
        feature = "net-shell",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance",
        feature = "milkv-ssh"
    ))]
    vibeos_vsh::install_commands(session, NETWORK_COMMANDS);
    #[cfg(feature = "milkv-ssh")]
    vibeos_vsh::install_commands(session, SSH_PROVISIONING_COMMANDS);
    #[cfg(feature = "milkv-ssh")]
    vibeos_vsh::install_async_commands(session, SSH_OBJECT_COMMANDS);
}

/// Install commands admitted to an authenticated public-key SSH session.
#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
pub fn install_remote_commands(session: &mut Session) {
    install_shared_commands(session);
    #[cfg(feature = "milkv-ssh")]
    vibeos_vsh::install_async_commands(session, SSH_REMOTE_MUTATION_COMMANDS);
}

/// The default password receives only the commands needed to replace itself
/// with a client public key. It never receives the standard remote profile.
#[cfg(feature = "milkv-ssh")]
pub fn install_ssh_onboarding_commands(session: &mut Session) {
    vibeos_vsh::install_commands(session, SSH_PROVISIONING_COMMANDS);
    vibeos_vsh::install_async_commands(session, SSH_OBJECT_COMMANDS);
    vibeos_vsh::install_async_commands(session, SSH_REMOTE_MUTATION_COMMANDS);
}

#[cfg(feature = "milkv-ssh")]
const SSH_PROVISIONING_COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "ssh-keygen",
        min_args: 0,
        max_args: 0,
        handler: crate::ssh_provisioning::vsh_keygen,
    },
    CommandSpec {
        name: "ssh-authorize",
        min_args: 2,
        max_args: 4,
        handler: crate::ssh_provisioning::vsh_authorize,
    },
];

#[cfg(feature = "milkv-ssh")]
const SSH_OBJECT_COMMANDS: &[AsyncCommandSpec] = &[AsyncCommandSpec {
    name: "cat",
    min_args: 1,
    max_args: 1,
    handler: crate::ssh_provisioning::vsh_keycat,
}];

/// Physical UART may remove authorization state; SSH sessions may not reopen
/// the globally known onboarding password.
#[cfg(feature = "milkv-ssh")]
const SSH_UART_MUTATION_COMMANDS: &[AsyncCommandSpec] = &[AsyncCommandSpec {
    name: "rm",
    min_args: 1,
    max_args: 1,
    handler: crate::ssh_provisioning::vsh_rm_uart,
}];

#[cfg(feature = "milkv-ssh")]
const SSH_REMOTE_MUTATION_COMMANDS: &[AsyncCommandSpec] = &[AsyncCommandSpec {
    name: "rm",
    min_args: 1,
    max_args: 1,
    handler: crate::ssh_provisioning::vsh_rm,
}];

const BASE_COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "help",
        min_args: 0,
        max_args: 0,
        handler: vibeos_vsh::help,
    },
    CommandSpec {
        name: "ps",
        min_args: 0,
        max_args: 0,
        handler: vsh_ps,
    },
    CommandSpec {
        name: "caps",
        min_args: 0,
        max_args: 1,
        handler: vsh_caps,
    },
    CommandSpec {
        name: "mem",
        min_args: 0,
        max_args: 0,
        handler: vsh_mem,
    },
    CommandSpec {
        name: "quiet",
        min_args: 0,
        max_args: 0,
        handler: vsh_quiet,
    },
    CommandSpec {
        name: "verbose",
        min_args: 0,
        max_args: 0,
        handler: vsh_verbose,
    },
    CommandSpec {
        name: "poweroff",
        min_args: 0,
        max_args: 0,
        handler: vsh_poweroff,
    },
];

#[cfg(feature = "qemu-virt")]
const QEMU_COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "pci",
        min_args: 0,
        max_args: 0,
        handler: vsh_pci,
    },
    CommandSpec {
        name: "usb",
        min_args: 0,
        max_args: 2,
        handler: vsh_usb,
    },
];

#[cfg(feature = "milkv-duo")]
const MILKV_USB_COMMANDS: &[CommandSpec] = &[CommandSpec {
    name: "lsusb",
    min_args: 0,
    max_args: 0,
    handler: vsh_lsusb,
}];

#[cfg(any(
    feature = "tcp-echo",
    feature = "net-shell",
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
const NETWORK_COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "ip",
        min_args: 2,
        max_args: 8,
        handler: crate::netstack_platform::vsh_ip,
    },
    CommandSpec {
        name: "dhclient",
        min_args: 0,
        max_args: 2,
        handler: crate::netstack_platform::vsh_dhclient,
    },
];

fn vsh_ps(_args: &[String]) -> Result<String, Status> {
    let mut output = String::from("COMPONENT TASK NAME CSPACE STATE POLLS BUDGET\n");
    for component in world().components() {
        let c = component.snapshot();
        output.push_str(&format!(
            "{} {} {} {} {} {} {}\n",
            c.id, c.task_id, c.name, c.cspace, c.state, c.polls, c.memory.budget_bytes
        ));
    }
    Ok(output)
}

fn vsh_caps(args: &[String]) -> Result<String, Status> {
    let default_space = if cfg!(feature = "legacy-shell") {
        "init"
    } else {
        "vsh"
    };
    let name = args.first().map(String::as_str).unwrap_or(default_space);
    let system = world();
    let Some(space) = system.spaces.get(name) else {
        return Err(Status::Unavailable);
    };
    let mut output = format!("CAPABILITIES {}\n", name);
    for (_handle, kind, rights, _description) in space.0.lock().list() {
        output.push_str(&format!("{} {}\n", kind, rights));
    }
    Ok(output)
}

fn vsh_mem(_args: &[String]) -> Result<String, Status> {
    let (live, peak, free) = crate::HEAP.stats();
    let mut output = format!("heap live={} peak={} remaining={}\n", live, peak, free);
    for component in world().components() {
        let c = component.snapshot();
        output.push_str(&format!(
            "{} live={} peak={} budget={} denied={}\n",
            c.name,
            c.memory.live_bytes,
            c.memory.peak_bytes,
            c.memory.budget_bytes,
            c.memory.denials
        ));
    }
    Ok(output)
}

#[cfg(feature = "qemu-virt")]
pub(crate) fn vsh_pci(_args: &[String]) -> Result<String, Status> {
    let mut output = String::from("BDF VID:DID CLASS IRQ BARS\n");
    for function in crate::pci::functions() {
        output.push_str(&format!(
            "{} {:04x}:{:04x} {:06x} {}",
            function.address,
            function.vendor_id,
            function.device_id,
            function.class_code(),
            function
                .interrupt_line
                .map_or(String::from("-"), |irq| format!("{}", irq)),
        ));
        for bar in function.bars {
            if let Some(address) = bar.address() {
                output.push_str(&format!(" {:#x}/{}", address, bar.size()));
            }
        }
        output.push('\n');
    }
    Ok(output)
}

#[cfg(feature = "qemu-virt")]
pub(crate) fn vsh_usb(args: &[String]) -> Result<String, Status> {
    use crate::xhci::DeviceKind;

    match args.first().map(String::as_str).unwrap_or("info") {
        "info" => {
            let Some(controller) = crate::xhci::info() else {
                return Ok(String::from("XHCI offline\n"));
            };
            let mut output = format!(
                "XHCI {:#06x} @ {:#x}: {} ports, {} connected, {} addressed\n",
                controller.version,
                controller.mmio_base,
                controller.max_ports,
                controller.connected_ports,
                controller.addressed_devices,
            );
            for device in crate::xhci::devices() {
                let kind = match device.kind {
                    DeviceKind::HidKeyboard => "hid-keyboard",
                    DeviceKind::MassStorage => "mass-storage",
                    DeviceKind::Unsupported => "unsupported",
                };
                output.push_str(&format!(
                    "port {} slot {} speed {} {:04x}:{:04x} {}",
                    device.port,
                    device.slot,
                    device.speed,
                    device.vendor_id,
                    device.product_id,
                    kind,
                ));
                if device.kind == DeviceKind::MassStorage {
                    output.push_str(&format!(" {} sectors", device.capacity_sectors));
                }
                output.push('\n');
            }
            Ok(output)
        }
        "read" => {
            let sector = args
                .get(1)
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(Status::Usage)?;
            let bytes = crate::xhci::read_sector(sector).map_err(|_| Status::Unavailable)?;
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(32)
                .min(32);
            Ok(format!(
                "usb sector {}: {}\n",
                sector,
                String::from_utf8_lossy(&bytes[..end]),
            ))
        }
        "test" => {
            const SEED: &[u8] = b"VIBEOS-USB-SECTOR-7-SEED-v1";
            const MARKER: &[u8] = b"VIBEOS-USB-SECTOR-8-WRITE-v1";
            let seed = crate::xhci::read_sector(7).map_err(|_| Status::Unavailable)?;
            if !seed.starts_with(SEED) {
                return Err(Status::Faulted);
            }
            let mut write = [0u8; 512];
            write[..MARKER.len()].copy_from_slice(MARKER);
            crate::xhci::write_sector(8, &write).map_err(|_| Status::Unavailable)?;
            let observed = crate::xhci::read_sector(8).map_err(|_| Status::Unavailable)?;
            if observed != write {
                return Err(Status::Faulted);
            }
            Ok(String::from(
                "USB STORAGE TEST OK (sector 7 read, sector 8 write/read)\n",
            ))
        }
        _ => Err(Status::Usage),
    }
}

#[cfg(feature = "milkv-duo")]
fn vsh_lsusb(_args: &[String]) -> Result<String, Status> {
    let Some(snapshot) = crate::dwc2_host::snapshot() else {
        return Ok(String::from("DWC2 offline\n"));
    };
    let port = if snapshot.connected {
        "connected"
    } else {
        "disconnected"
    };
    let mut output = format!(
        "Bus 001 DWC2 release={:#06x} irq={} channels={} port={} hprt={:#010x}\n",
        snapshot.info.release,
        snapshot.info.irq,
        snapshot.info.host_channels,
        port,
        snapshot.telemetry.hprt0,
    );
    let Some(device) = snapshot.device else {
        output.push_str(if snapshot.connected {
            "Bus 001 Device --- connected, not enumerated\n"
        } else {
            "Bus 001 Device --- none\n"
        });
        return Ok(output);
    };
    output.push_str(&format!(
        "Bus 001 Device {:03}: ID {:04x}:{:04x} speed={:?} usb={:#06x} class={:#04x} ep0={}\n",
        device.address,
        device.vendor_id,
        device.product_id,
        device.speed,
        device.usb_version,
        device.device_class,
        device.max_packet_size_0,
    ));
    if let Some(hub) = snapshot.hub {
        match (hub.active_port, hub.child_speed) {
            (Some(port), Some(speed)) => output.push_str(&format!(
                "  Hub ports={} downstream port={} speed={:?} status={:#06x}\n",
                hub.ports, port, speed, hub.port_status,
            )),
            _ => output.push_str(&format!(
                "  Hub ports={} no enabled downstream device\n",
                hub.ports,
            )),
        }
    }
    match snapshot.keyboard {
        Some(keyboard) => output.push_str(&format!(
            "  HID boot-keyboard interface={} endpoint={:#04x} mps={} interval={}ms\n",
            keyboard.interface,
            keyboard.endpoint_in,
            keyboard.max_packet_size,
            keyboard.interval_ms,
        )),
        None => output.push_str("  HID boot-keyboard not configured\n"),
    }
    Ok(output)
}

fn vsh_quiet(_args: &[String]) -> Result<String, Status> {
    crate::tty::set_quiet(true);
    Ok(String::from("background component output muted\n"))
}

fn vsh_verbose(_args: &[String]) -> Result<String, Status> {
    crate::tty::set_quiet(false);
    Ok(String::from("background component output restored\n"))
}

fn vsh_poweroff(_args: &[String]) -> Result<String, Status> {
    crate::sbi::shutdown(false)
}
