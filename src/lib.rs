//! openskey: an open, leak-free reimplementation of Brother's `brscan-skey`
//! Scan-to-PC key daemon. Library crate shared by the `openskey` daemon and the
//! `mock-device` test harness; the binaries are only the loops around it.

pub mod button;
pub mod config;
pub mod daemon;
pub mod hold;
pub mod mock;
pub mod registration;
pub mod snmp;
pub mod status;
