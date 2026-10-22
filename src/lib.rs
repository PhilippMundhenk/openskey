//! openskey: an open, leak-free reimplementation of Brother's `brscan-skey`
//! Scan-to-PC key daemon. Library crate shared by the `openskey` daemon and the
//! `mock-device` test harness.

pub mod button;
pub mod config;
pub mod hold;
pub mod registration;
pub mod snmp;
pub mod status;
