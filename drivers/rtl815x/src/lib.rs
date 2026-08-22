//! Transport-independent Realtek RTL815x personality handling.
//!
//! Native Ethernet traffic is standards-based CDC-ECM and remains in the USB
//! class layer. This crate owns the vendor/product classification and the
//! bounded BOT command which changes an RTL8151 virtual-CD personality into
//! its Ethernet personality.

#![cfg_attr(not(test), no_std)]

pub const REALTEK_VENDOR_ID: u16 = 0x0bda;
pub const RTL8151_INSTALL_MODE_PRODUCT_ID: u16 = 0x8151;
pub const RTL8152_PRODUCT_ID: u16 = 0x8152;
pub const RTL8153_PRODUCT_ID: u16 = 0x8153;
pub const RTL8156_PRODUCT_ID: u16 = 0x8156;

const INSTALL_MODE_MESSAGE: [u8; 31] = [
    0x55, 0x53, 0x42, 0x43, 0x08, 0x60, 0xd9, 0xa9, 0xc0, 0x00, 0x00, 0x00, 0x80, 0x00, 0x06, 0xe0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub const GET_REGISTERS_REQUEST_TYPE: u8 = 0xc0;
pub const GET_REGISTERS_REQUEST: u8 = 0x05;
const MCU_TYPE_PLA: u16 = 0x0100;
const PLA_PHYSTATUS: u16 = 0xe908;
const LINK_STATUS: u8 = 0x02;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkStatus {
    pub raw: u16,
    pub link_up: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Personality {
    InstallMode,
    Ethernet,
    Unsupported,
}

pub const fn classify(vendor_id: u16, product_id: u16) -> Personality {
    if vendor_id != REALTEK_VENDOR_ID {
        return Personality::Unsupported;
    }
    match product_id {
        RTL8151_INSTALL_MODE_PRODUCT_ID => Personality::InstallMode,
        RTL8152_PRODUCT_ID | RTL8153_PRODUCT_ID | RTL8156_PRODUCT_ID => Personality::Ethernet,
        _ => Personality::Unsupported,
    }
}

/// Narrow host-controller operations required by the install-mode protocol.
/// The host controller retains endpoint, topology, DMA and IRQ ownership.
pub trait InstallModeTransport {
    type Error;

    fn select_configuration(&mut self) -> Result<(), Self::Error>;
    fn reset_bulk_data_toggles(&mut self);
    fn send_command(&mut self, command: &[u8]) -> Result<(), Self::Error>;
    fn receive_status(&mut self, status: &mut [u8; 13]) -> Result<(), Self::Error>;
    fn settle_after_disconnect(&mut self);
}

/// Narrow vendor-register transport used only for RTL815x PHY status.
pub trait RegisterTransport {
    type Error;

    fn read_registers(
        &mut self,
        value: u16,
        index: u16,
        output: &mut [u8; 4],
    ) -> Result<(), Self::Error>;
}

/// Read the authoritative copper PHY carrier state.
///
/// RTL815x CDC firmware may report `NETWORK_CONNECTION=1` whenever its USB
/// data interface is enabled, even with no RJ45 cable. Linux's r8152 driver
/// instead reads the aligned PLA_PHYSTATUS dword and tests LINK_STATUS.
pub fn read_link_status<T: RegisterTransport>(transport: &mut T) -> Result<LinkStatus, T::Error> {
    let mut status = [0; 4];
    transport.read_registers(PLA_PHYSTATUS & !3, MCU_TYPE_PLA, &mut status)?;
    let offset = usize::from(PLA_PHYSTATUS & 3);
    let raw = u16::from_le_bytes([status[offset], status[offset + 1]]);
    Ok(LinkStatus {
        raw,
        link_up: raw != u16::MAX && raw as u8 & LINK_STATUS != 0,
    })
}

/// Switch one positively identified RTL8151 install-mode function.
///
/// Devices commonly disconnect before returning the BOT CSW, so status-read
/// failure is intentionally ignored only after the complete command has been
/// accepted by bulk OUT.
pub fn switch_install_mode<T: InstallModeTransport>(transport: &mut T) -> Result<(), T::Error> {
    transport.select_configuration()?;
    transport.reset_bulk_data_toggles();
    transport.send_command(&INSTALL_MODE_MESSAGE)?;
    let mut status = [0; 13];
    let _ = transport.receive_status(&mut status);
    transport.settle_after_disconnect();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeTransport {
        calls: [u8; 5],
        count: usize,
        command: [u8; 31],
        fail_status: bool,
    }

    struct FakeRegisters {
        value: u16,
        index: u16,
        status: [u8; 4],
    }

    impl RegisterTransport for FakeRegisters {
        type Error = ();

        fn read_registers(
            &mut self,
            value: u16,
            index: u16,
            output: &mut [u8; 4],
        ) -> Result<(), Self::Error> {
            self.value = value;
            self.index = index;
            *output = self.status;
            Ok(())
        }
    }

    impl FakeTransport {
        fn called(&mut self, operation: u8) {
            self.calls[self.count] = operation;
            self.count += 1;
        }
    }

    impl InstallModeTransport for FakeTransport {
        type Error = ();

        fn select_configuration(&mut self) -> Result<(), Self::Error> {
            self.called(1);
            Ok(())
        }

        fn reset_bulk_data_toggles(&mut self) {
            self.called(2);
        }

        fn send_command(&mut self, command: &[u8]) -> Result<(), Self::Error> {
            self.called(3);
            self.command.copy_from_slice(command);
            Ok(())
        }

        fn receive_status(&mut self, _status: &mut [u8; 13]) -> Result<(), Self::Error> {
            self.called(4);
            if self.fail_status {
                Err(())
            } else {
                Ok(())
            }
        }

        fn settle_after_disconnect(&mut self) {
            self.called(5);
        }
    }

    #[test]
    fn classifies_only_known_realtek_personalities() {
        assert_eq!(
            classify(REALTEK_VENDOR_ID, RTL8151_INSTALL_MODE_PRODUCT_ID),
            Personality::InstallMode
        );
        assert_eq!(
            classify(REALTEK_VENDOR_ID, RTL8153_PRODUCT_ID),
            Personality::Ethernet
        );
        assert_eq!(
            classify(0x1234, RTL8153_PRODUCT_ID),
            Personality::Unsupported
        );
    }

    #[test]
    fn sends_the_exact_modeswitch_command_and_tolerates_early_disconnect() {
        let mut transport = FakeTransport {
            fail_status: true,
            ..FakeTransport::default()
        };
        switch_install_mode(&mut transport).unwrap();
        assert_eq!(transport.calls, [1, 2, 3, 4, 5]);
        assert_eq!(&transport.command[..4], b"USBC");
        assert_eq!(transport.command[12], 0x80);
        assert_eq!(transport.command[15], 0xe0);
    }

    #[test]
    fn reads_real_phy_carrier_from_pla_phystatus() {
        let mut down = FakeRegisters {
            value: 0,
            index: 0,
            status: [0, 0, 0, 0],
        };
        assert_eq!(
            read_link_status(&mut down),
            Ok(LinkStatus {
                raw: 0,
                link_up: false
            })
        );
        assert_eq!(down.value, 0xe908);
        assert_eq!(down.index, 0x0100);

        let mut up = FakeRegisters {
            status: [LINK_STATUS, 0, 0, 0],
            ..down
        };
        assert_eq!(
            read_link_status(&mut up),
            Ok(LinkStatus {
                raw: 2,
                link_up: true
            })
        );

        let mut invalid = FakeRegisters {
            status: [0xff; 4],
            ..up
        };
        assert_eq!(
            read_link_status(&mut invalid),
            Ok(LinkStatus {
                raw: u16::MAX,
                link_up: false
            })
        );
    }
}
