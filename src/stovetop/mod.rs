//! Stovetop — frame-level integrity inspection. Looks at the stuffing.
//!
//! Runs pre-dissector on every Ethernet frame to catch structural anomalies
//! that protocol parsers ignore:
//!
//! | Check | Tag | What It Catches |
//! |-------|-----|-----------------|
//! | Runt frame | `stovetop:runt` | Frames below 60-byte Ethernet minimum |
//! | Oversized frame | `stovetop:oversized` | Frames exceeding standard/jumbo limits |
//! | Capture truncation | `stovetop:truncated` | `captured_len < orig_len` |
//! | Non-zero padding | `stovetop:padding` | Data in Ethernet padding region (covert channels) |
//! | FCS validation | `stovetop:fcs` | Invalid Ethernet CRC-32 frame check sequence |
//!
//! Protocol-level integrity (DNP3 DLL CRC-16) is available via
//! [`integrity::validate_dnp3_dll_crcs`].
//!
//! All findings are emitted as [`BronzeEventFamily::ParseAnomaly`].

pub mod config;
pub mod findings;
pub mod frame_inspector;
pub mod integrity;
pub mod padding;
