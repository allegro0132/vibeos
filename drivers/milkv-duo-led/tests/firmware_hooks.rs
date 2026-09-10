//! Exercise the actual firmware hook helpers using mapped plain-memory registers.
//! The dummy board is never initialized; tests supply their own MMIO description.
use vibeos_hal::{AddressRange,StatusLedDescription};
struct Board;
struct Info{status_led:Option<StatusLedDescription>}
trait BoardContract{const INFO:Info;}
impl BoardContract for Board{const INFO:Info=Info{status_led:None};}
#[path="../../../firmware/milkv-duo/src/platform.rs"]mod platform;
static LOG:std::sync::Mutex<String>=std::sync::Mutex::new(String::new());
fn write(s:&str){LOG.lock().unwrap().push_str(s);}
fn print(args:core::fmt::Arguments<'_>){use std::fmt::Write;write!(LOG.lock().unwrap(),"{args}").unwrap();}
#[test]
fn firmware_preserves_unconfirmed_led_diagnostic_and_gpio_bits(){
    let mut gpio=[0u32;64];let mut mux=[0u32;128];
    gpio[0]=0xa0000000;gpio[1]=0x10;gpio[0x50/4]=0x600;mux[0x12c/4]=0xff;
    let description=StatusLedDescription{
        gpio:AddressRange::new(gpio.as_mut_ptr()as usize,gpio.as_mut_ptr()as usize+256),
        pinmux:AddressRange::new(mux.as_mut_ptr()as usize,mux.as_mut_ptr()as usize+512),
        pinmux_register_offset:0x12c,pinmux_function_mask:7,pinmux_gpio_function:3,gpio_bit:24,active_high:true,
    };
    let led=unsafe{platform::initialize_led(description,write)};
    assert!(!led.on());assert!(led.output_asserted());
    assert_eq!((gpio[0],gpio[1],mux[0x12c/4]),(0xa1000000,0x01000010,0xfb));
    platform::report_led(led,print);
    assert_eq!(&*LOG.lock().unwrap(),"[VibeOS] blue status LED output asserted (input unconfirmed)\r\n  led       blue GPIOC24 output asserted (input unconfirmed) (pinmux 0xfb, dir 0x01000010, data 0xa1000000, input 0x00000600)\n");
}
