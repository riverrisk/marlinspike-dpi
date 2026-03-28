//! Stovetop — frame-level inspection for padding, stuffing, and integrity anomalies.
//!
//! The stovetop module hooks into the DPI engine at two points:
//! - **Pre-dissector**: frame-level checks (runt detection, padding analysis,
//!   truncation, FCS validation) run on every Ethernet frame before it is
//!   dispatched to protocol decoders.
//! - **Per-dissector**: protocol-specific integrity checks (DNP3 CRC, HDLC
//!   byte-stuffing) run inside individual decoders.
//!
//! All findings are emitted as `BronzeEvent::ParseAnomaly` with the decoder
//! field prefixed `"stovetop:"`.

pub mod config;
pub mod findings;
pub mod frame_inspector;
pub mod integrity;
pub mod padding;
