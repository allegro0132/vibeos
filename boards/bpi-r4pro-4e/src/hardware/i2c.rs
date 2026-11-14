//! Single owner of GPIO I2C2 and its PCA9545 mux (lamps and both SFP cages).
//! Each transaction selects exactly one channel under the bus lock. No await
//! is allowed while holding Bus; callers never rely on a previous selection.
use core::ptr::{read_volatile, write_volatile};
use vibeos_core::sync::SpinLock;
use vibeos_runtime_aarch64::bare;
/// Pin controller, pins 64..=95: direction (1 = output), output, input.
const DIRECTION: usize = 0x1001_f020;
const OUTPUT: usize = 0x1001_f120;
const INPUT: usize = 0x1001_f220;
/// Function of pins 64..=71 and 72..=79 (four bits per pin; 0 = GPIO).
const MODE_64: usize = 0x1001_f380;
const MODE_72: usize = 0x1001_f390;
const SCL: u32 = 1 << (71 - 64);
const SDA: u32 = 1 << (72 - 64);
const SWITCH: u8 = 0x70;
/// Half an SCL period, in counter ticks (100 kHz bus).
fn half() {
    let until = bare::counter() + bare::counter_frequency().div_ceil(200_000);
    while bare::counter() < until {
        core::hint::spin_loop();
    }
}
fn input() -> u32 {
    unsafe { read_volatile(INPUT as *const u32) }
}
/// Release `line` to the pull-up, or pull it low.
fn drive(line: u32, high: bool) {
    unsafe {
        let direction = read_volatile(DIRECTION as *const u32);
        if high {
            write_volatile(DIRECTION as *mut u32, direction & !line);
        } else {
            write_volatile(
                OUTPUT as *mut u32,
                read_volatile(OUTPUT as *const u32) & !line,
            );
            write_volatile(DIRECTION as *mut u32, direction | line);
        }
    }
}
/// Release SCL and wait (bounded) for it to rise: a device may hold it.
fn clock_high() -> bool {
    drive(SCL, true);
    let deadline = bare::counter() + bare::counter_frequency() / 1000;
    while input() & SCL == 0 {
        if bare::counter() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
    half();
    true
}
/// Start condition, or repeated start from SCL low.
fn begin() -> bool {
    drive(SDA, true);
    half();
    if !clock_high() || input() & SDA == 0 {
        return false;
    }
    drive(SDA, false);
    half();
    drive(SCL, false);
    true
}
/// Stop condition.
fn end() {
    drive(SDA, false);
    half();
    let _ = clock_high();
    drive(SDA, true);
    half();
}
/// Send one byte; whether the device acknowledged it.
fn send(byte: u8) -> bool {
    for bit in (0..8).rev() {
        drive(SDA, byte >> bit & 1 != 0);
        half();
        if !clock_high() {
            return false;
        }
        drive(SCL, false);
    }
    drive(SDA, true);
    half();
    let ack = clock_high() && input() & SDA == 0;
    drive(SCL, false);
    ack
}
/// ACK intermediate bytes; NACK the final byte.
fn receive(last: bool) -> Option<u8> {
    drive(SDA, true);
    let mut byte = 0;
    for _ in 0..8 {
        half();
        if !clock_high() {
            return None;
        }
        byte = byte << 1 | u8::from(input() & SDA != 0);
        drive(SCL, false);
    }
    drive(SDA, last);
    half();
    let ok = clock_high();
    drive(SCL, false);
    drive(SDA, true);
    ok.then_some(byte)
}
fn write(address: u8, bytes: &[u8]) -> Result<(), ()> {
    let sent = begin() && send(address << 1) && bytes.iter().all(|byte| send(*byte));
    end();
    if sent {
        Ok(())
    } else {
        Err(())
    }
}
fn read(address: u8, register: u8) -> Result<u8, ()> {
    let value =
        if begin() && send(address << 1) && send(register) && begin() && send(address << 1 | 1) {
            receive(true)
        } else {
            None
        };
    end();
    value.ok_or(())
}
/// Free a bus a device may have been left holding mid-byte: clock until
/// it lets SDA go, then end with a stop.
fn recover() {
    drive(SDA, true);
    drive(SCL, true);
    half();
    for _ in 0..9 {
        if input() & SDA != 0 {
            break;
        }
        drive(SCL, false);
        half();
        let _ = clock_high();
    }
    drive(SCL, false);
    half();
    end();
}

static BUS: SpinLock<()> = SpinLock::new(());

pub struct Bus {
    _private: (),
}
impl Bus {
    pub fn write(&mut self, address: u8, bytes: &[u8]) -> Result<(), ()> {
        write(address, bytes)
    }
    pub fn read(&mut self, address: u8, register: u8) -> Result<u8, ()> {
        read(address, register)
    }
    pub fn read_block(&mut self, address: u8, register: u8, out: &mut [u8]) -> Result<(), ()> {
        if out.is_empty() || out.len() > 256 - usize::from(register) {
            return Err(());
        }
        let result = (|| {
            if !(begin()
                && send(address << 1)
                && send(register)
                && begin()
                && send(address << 1 | 1))
            {
                return Err(());
            }
            let length = out.len();
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = receive(i + 1 == length).ok_or(())?;
            }
            Ok(())
        })();
        end();
        result
    }
}

pub(super) fn with_channel<T>(
    channel: u8,
    action: impl FnOnce(&mut Bus) -> Result<T, ()>,
) -> Result<T, ()> {
    if channel > 3 {
        return Err(());
    }
    let _lock = BUS.lock();
    unsafe {
        write_volatile(
            MODE_64 as *mut u32,
            read_volatile(MODE_64 as *const u32) & !(0xf << 28),
        );
        write_volatile(
            MODE_72 as *mut u32,
            read_volatile(MODE_72 as *const u32) & !0xf,
        );
    }
    recover();
    let result = write(SWITCH, &[1 << channel]).and_then(|_| action(&mut Bus { _private: () }));
    // Disconnect modules after each transaction, including failures. Do not
    // leave a removed or malfunctioning module selected for the next client.
    let deselect = write(SWITCH, &[0]);
    match result {
        Err(()) => Err(()),
        Ok(value) => deselect.map(|_| value),
    }
}
