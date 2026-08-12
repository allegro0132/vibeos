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
}
