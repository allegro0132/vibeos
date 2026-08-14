//! Kernel capability adapters for the separately compiled VSH frontend.

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
#[cfg(feature = "milkv-duo")]
use core::fmt::Write as _;

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
    #[cfg(feature = "file-tree")]
    let session = {
        let mut session = session;
        bind_persistent_file_tree(&mut session).await;
        session
    };
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
    vibeos_vsh::install_lsblk_command(session);
    #[cfg(feature = "file-tree")]
    vibeos_vsh::install_file_commands(session);
    #[cfg(feature = "milkv-ssh")]
    vibeos_vsh::install_async_commands(session, SSH_UART_MUTATION_COMMANDS);
}

#[cfg(feature = "file-tree")]
pub async fn bind_persistent_file_tree(session: &mut Session) {
    const HOME_NAMESPACE: u128 = 0x5649_4245_4f53_2d46_494c_4554_5245_4501;
    let Some(storage) = world().storage_v2.clone() else {
        return;
    };
    loop {
        match storage.selected_boot_store() {
            None => vibeos_core::exec::yield_now().await,
            Some(crate::segment_store_platform::BootStoreSelection::StorageV2) => {
                let home = match storage.recover_file_tree_root(HOME_NAMESPACE).await {
                    Ok(home) => home,
                    Err(vibeos_file_store::FileError::Busy) => {
                        vibeos_core::exec::yield_now().await;
                        continue;
                    }
                    Err(error) => {
                        crate::uart::_print(format_args!(
                            "  file-tree persistent root unavailable: {error:?}\n"
                        ));
                        return;
                    }
                };
                session
                    .install_capability(
                        "home",
                        Arc::new(home),
                        Rights::READ
                            .union(Rights::WRITE)
                            .union(Rights::GRANT)
                            .union(Rights::REVOKE),
                    )
                    .expect("local persistent file-tree capability binding must be valid");
                return;
            }
            Some(selection) => {
                crate::uart::_print(format_args!(
                    "  file-tree not bound: boot policy selected {selection:?}\n"
                ));
                return;
            }
        }
    }
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
        feature = "milkv-ssh",
        feature = "iperf3-server",
        feature = "milkv-iperf3-server"
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
    feature = "milkv-ssh",
    feature = "iperf3-server",
    feature = "milkv-iperf3-server"
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
        name: "reboot",
        min_args: 0,
        max_args: 0,
        handler: vsh_reboot,
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
const MILKV_USB_COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "lsusb",
        min_args: 0,
        max_args: 0,
        handler: vsh_lsusb,
    },
    CommandSpec {
        name: "usb",
        min_args: 0,
        max_args: 2,
        handler: vsh_milkv_usb,
    },
];

#[cfg(any(
    feature = "tcp-echo",
    feature = "net-shell",
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh",
    feature = "iperf3-server",
    feature = "milkv-iperf3-server"
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
        "Bus 001 Device {:03}: ID {:04x}:{:04x} speed={:?} usb={:#06x} class={:#04x} ep0={} configurations={}\n",
        device.address,
        device.vendor_id,
        device.product_id,
        device.speed,
        device.usb_version,
        device.device_class,
        device.max_packet_size_0,
        device.configuration_count,
    ));
    if let Some(hub) = snapshot.hub {
        let child_count = snapshot.children.iter().flatten().count();
        output.push_str(&format!(
            "  Hub ports={} descendants={}\n",
            hub.ports, child_count,
        ));
        for child in snapshot.children.into_iter().flatten() {
            output.push_str(&format!(
                "Bus 001 Device {:03}: ID {:04x}:{:04x} speed={:?} usb={:#06x} class={:#04x} ep0={} configurations={} parent={:03} port={} status={:#06x}\n",
                child.device.address,
                child.device.vendor_id,
                child.device.product_id,
                child.device.speed,
                child.device.usb_version,
                child.device.device_class,
                child.device.max_packet_size_0,
                child.device.configuration_count,
                child.parent_hub_address,
                child.port,
                child.port_status,
            ));
            if let (Some(tt_hub), Some(tt_port)) = (child.tt_hub_address, child.tt_port) {
                output.push_str(&format!(
                    "  Transaction Translator hub={tt_hub:03} port={tt_port}\n"
                ));
            }
            if let Some(child_hub) = snapshot
                .hubs
                .iter()
                .flatten()
                .find(|candidate| candidate.address == child.device.address)
            {
                output.push_str(&format!(
                    "  Hub device={:03} ports={} depth={}\n",
                    child_hub.address, child_hub.ports, child.depth,
                ));
            }
        }
    }
    if let Some(address) = snapshot.configuration_device_address {
        output.push_str(&format!(
            "  Descriptor configurations for device={address:03}\n"
        ));
    }
    for (descriptor_index, configuration) in snapshot
        .configurations
        .into_iter()
        .enumerate()
        .filter_map(|(index, configuration)| {
            configuration.map(|configuration| (index, configuration))
        })
    {
        output.push_str(&format!(
            "  Configuration index={} value={} length={} interfaces={}\n",
            descriptor_index,
            configuration.value,
            configuration.total_length,
            configuration.declared_interfaces,
        ));
        for interface in configuration.interfaces.into_iter().flatten() {
            output.push_str(&format!(
                "    Interface {} alt={} class={:#04x} subclass={:#04x} protocol={:#04x}",
                interface.number,
                interface.alternate,
                interface.class,
                interface.subclass,
                interface.protocol,
            ));
            if let Some(endpoint) = interface.interrupt_in {
                output.push_str(&format!(
                    " report-len={} interrupt-in={:#04x} mps={} interval={}",
                    interface.hid_report_length,
                    endpoint,
                    interface.max_packet_size,
                    interface.interval,
                ));
            }
            if let Some(endpoint) = interface.bulk_in {
                output.push_str(&format!(
                    " bulk-in={:#04x} mps={}",
                    endpoint, interface.bulk_in_max_packet_size,
                ));
            }
            if let Some(endpoint) = interface.bulk_out {
                output.push_str(&format!(
                    " bulk-out={:#04x} mps={}",
                    endpoint, interface.bulk_out_max_packet_size,
                ));
            }
            output.push_str("\n");
            for endpoint in interface.endpoints.into_iter().flatten() {
                let transfer_type = match endpoint.attributes & 0x03 {
                    0 => "control",
                    1 => "isochronous",
                    2 => "bulk",
                    _ => "interrupt",
                };
                output.push_str(&format!(
                    "      Endpoint {:#04x} type={} attributes={:#04x} mps={} interval={}\n",
                    endpoint.address,
                    transfer_type,
                    endpoint.attributes,
                    endpoint.max_packet_size,
                    endpoint.interval,
                ));
            }
        }
    }
    if let Some(report) = snapshot.report_descriptor {
        output.push_str(&format!(
            "  HID report descriptor interface={} length={}/{}\n",
            report.interface,
            report.as_slice().len(),
            report.declared_length,
        ));
        for chunk in report.as_slice().chunks(16) {
            output.push_str("    ");
            for byte in chunk {
                output.push_str(&format!("{byte:02x} "));
            }
            output.push_str("\n");
        }
    }
    match snapshot.keyboard {
        Some(keyboard) => output.push_str(&format!(
            "  HID keyboard device={} protocol={:?} interface={} endpoint={:#04x} mps={} interval={}ms\n",
            snapshot.keyboard_device_address.unwrap_or(0),
            keyboard.protocol,
            keyboard.interface,
            keyboard.endpoint_in,
            keyboard.max_packet_size,
            keyboard.interval_ms,
        )),
        None => output.push_str("  HID keyboard not configured\n"),
    }
    if let Some(storage) = snapshot.mass_storage {
        output.push_str(&format!(
            "  Mass Storage device={} SCSI/Bulk-Only interface={} bulk-in={:#04x}/{} bulk-out={:#04x}/{} detected\n",
            snapshot.storage_device_address.unwrap_or(0),
            storage.interface,
            storage.endpoint_in,
            storage.max_packet_size_in,
            storage.endpoint_out,
            storage.max_packet_size_out,
        ));
    }
    if let Some(ecm) = snapshot.cdc_ecm {
        output.push_str(&format!(
            "  CDC ECM device={} configuration={} control-interface={} data-interface={} alt={} bulk-in={:#04x}/{} bulk-out={:#04x}/{} status={:?} mac={:?}\n",
            snapshot.cdc_ecm_device_address.unwrap_or(0),
            ecm.configuration,
            ecm.control_interface,
            ecm.data_interface,
            ecm.data_alternate,
            ecm.endpoint_in,
            ecm.max_packet_size_in,
            ecm.endpoint_out,
            ecm.max_packet_size_out,
            ecm.status_endpoint,
            ecm.mac_address,
        ));
    }
    Ok(output)
}

#[cfg(feature = "milkv-duo")]
fn vsh_milkv_usb(args: &[String]) -> Result<String, Status> {
    if args.first().is_some_and(|argument| argument == "net-rx") {
        if args.len() != 1 {
            return Err(Status::Usage);
        }
        let mut frame = [0; vibeos_driver_dwc2_host::MAX_ETHERNET_FRAME_BYTES];
        for _ in 0..100 {
            match crate::dwc2_host::receive_cdc_ecm(&mut frame) {
                Ok(length) => {
                    let mut output = format!("CDC-ECM received Ethernet frame length={length}\n");
                    for (line, chunk) in frame[..length].chunks(16).enumerate() {
                        write!(&mut output, "{:04x}  ", line * 16).map_err(|_| Status::Faulted)?;
                        for byte in chunk {
                            write!(&mut output, "{byte:02x} ").map_err(|_| Status::Faulted)?;
                        }
                        output.push('\n');
                    }
                    return Ok(output);
                }
                Err(vibeos_driver_dwc2_host::Error::Nak) => {}
                Err(_) => return Err(Status::Unavailable),
            }
        }
        return Ok(String::from(
            "CDC-ECM receive queue empty after 100 polls\n",
        ));
    }
    if args.first().is_some_and(|argument| argument == "read") {
        let sector = args
            .get(1)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(Status::Usage)?;
        let bytes = crate::dwc2_host::read_sector(sector).map_err(|_| Status::Unavailable)?;
        let mut output = format!("USB sector {sector}:\n");
        for (line, chunk) in bytes.chunks(16).enumerate() {
            write!(&mut output, "{:08x}  ", line * 16).map_err(|_| Status::Faulted)?;
            for byte in chunk {
                write!(&mut output, "{byte:02x} ").map_err(|_| Status::Faulted)?;
            }
            output.push_str(" | ");
            for byte in chunk {
                output.push(if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    '.'
                });
            }
            output.push('\n');
        }
        return Ok(output);
    }
    if args
        .first()
        .is_some_and(|argument| argument == "write-test")
    {
        const TEST_SECTOR: u64 = 4_000_000;
        if args.get(1).map(String::as_str) != Some("CONFIRM") || args.len() != 2 {
            return Err(Status::Usage);
        }

        let original =
            crate::dwc2_host::read_sector(TEST_SECTOR).map_err(|_| Status::Unavailable)?;
        let mut pattern = [0; 512];
        let prefix = b"VIBEOS USB WRITE TEST";
        pattern[..prefix.len()].copy_from_slice(prefix);
        pattern[24..32].copy_from_slice(&TEST_SECTOR.to_le_bytes());
        for (index, byte) in pattern[32..].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(0x5a);
        }

        if crate::dwc2_host::write_sector(TEST_SECTOR, &pattern).is_err() {
            let _ = crate::dwc2_host::write_sector(TEST_SECTOR, &original);
            return Err(Status::Unavailable);
        }
        let observed = match crate::dwc2_host::read_sector(TEST_SECTOR) {
            Ok(bytes) => bytes,
            Err(_) => {
                let _ = crate::dwc2_host::write_sector(TEST_SECTOR, &original);
                return Err(Status::Unavailable);
            }
        };
        if observed != pattern {
            let _ = crate::dwc2_host::write_sector(TEST_SECTOR, &original);
            return Err(Status::Faulted);
        }
        crate::dwc2_host::write_sector(TEST_SECTOR, &original).map_err(|_| Status::Unavailable)?;
        let restored =
            crate::dwc2_host::read_sector(TEST_SECTOR).map_err(|_| Status::Unavailable)?;
        if restored != original {
            return Err(Status::Faulted);
        }
        return Ok(format!(
            "USB sector {TEST_SECTOR} WRITE(10) readback passed; original data restored\n"
        ));
    }
    if args.first().is_some_and(|argument| argument != "info") || args.len() > 1 {
        return Err(Status::Usage);
    }
    let Some(storage) = crate::dwc2_host::snapshot().and_then(|snapshot| snapshot.mass_storage)
    else {
        return Ok(String::from("USB mass storage not detected\n"));
    };
    let (Some(sectors), Some(block_size)) = (storage.capacity_sectors, storage.block_size) else {
        return Ok(format!(
            "USB mass storage interface {} detected, capacity not configured\n",
            storage.interface,
        ));
    };
    Ok(format!(
        "USB mass storage SCSI/BOT interface={} bulk-in={:#04x}/{} bulk-out={:#04x}/{} sectors={} block-size={} bytes={}\n",
        storage.interface,
        storage.endpoint_in,
        storage.max_packet_size_in,
        storage.endpoint_out,
        storage.max_packet_size_out,
        sectors,
        block_size,
        sectors.saturating_mul(u64::from(block_size)),
    ))
}

fn vsh_quiet(_args: &[String]) -> Result<String, Status> {
    crate::tty::set_quiet(true);
    Ok(String::from("background component output muted\n"))
}

fn vsh_verbose(_args: &[String]) -> Result<String, Status> {
    crate::tty::set_quiet(false);
    Ok(String::from("background component output restored\n"))
}

fn vsh_reboot(_args: &[String]) -> Result<String, Status> {
    crate::sbi::reboot()
}

fn vsh_poweroff(_args: &[String]) -> Result<String, Status> {
    crate::sbi::shutdown(false)
}
