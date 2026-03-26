//! marlinspike-dpi — the standalone MarlinSpike DPI engine.
//!
//! Transforms Iron captures (`pcap` or `pcapng`) into Bronze (structured
//! protocol records).
//!
//! The `fm_dpi` Rust library name is retained for compatibility with existing
//! integrations.
//!
//! `marlinspike-dpi` is consumable directly from Rust today:
//!
//! ```no_run
//! use fm_dpi::DpiEngine;
//!
//! let bytes = std::fs::read("capture.pcap")?;
//! let mut engine = DpiEngine::new();
//! let bronze = engine.process_capture("capture-1", std::io::Cursor::new(bytes))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! For non-Rust consumers, enable the `ffi` feature and build
//! `marlinspike-dpi` as a `cdylib` or `staticlib`. The exported C ABI accepts
//! capture bytes and returns a JSON payload containing the Bronze checkpoint
//! plus Bronze events. The legacy `fm_dpi_process_pcapng_json` symbol name is
//! preserved for compatibility even though the implementation now accepts both
//! classic PCAP and PCAPNG input.

pub mod bronze;
pub mod dedup;
pub mod dissectors;
pub mod engine;
pub mod registry;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use crate::bronze::{
    BRONZE_SCHEMA_VERSION, BronzeBatch, BronzeEvent, BronzeEventFamily, EventEnvelope,
    SegmentCheckpoint, activity_records,
};
pub use crate::engine::{BronzeSink, DpiEngine, DpiError, DpiSegmentOutput, SegmentMeta};
