#![no_std]
//! GMAC4/5 EQoS controller encodings. No board clocks, PHY wiring or cache ISA.
//! The ring state machine handles publication and quarantine; a concrete
//! controller/cache backend and platform integration are still required.
pub mod descriptor;
pub mod mdio;
pub mod ring;
