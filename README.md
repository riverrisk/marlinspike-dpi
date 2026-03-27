# marlinspike-dpi

`marlinspike-dpi` is a standalone OT/ICS packet analysis engine for turning
raw captures into structured Bronze events.

It is the reusable DPI core shared by MarlinSpike and Fathom, but it now lives
in its own repository so it can be versioned, vendored, and embedded
independently.

It consumes passive packet captures and emits:

- protocol transactions
- asset observations
- topology observations
- parse anomalies
- extracted artifacts

The engine is usable as:

- a Rust library
- a CLI binary
- an optional C ABI / FFI surface

## What It Targets

The current active decoder set includes:

- `arp`
- `lldp`
- `cdp`
- `stp`
- `bacnet`
- `dns`
- `dhcp`
- `snmp`
- `http`
- `tls`
- `modbus`
- `dnp3`
- `iec104`
- `omron_fins`
- `hart_ip`
- `ethernet_ip`
- `opc_ua`
- `iec61850`
- `s7comm`
- `ethercat`
- `profinet`
- `ntp`
- `mqtt`
- `syslog`
- `ftp`
- `ssh`
- `radius`

## Scope

`marlinspike-dpi` is the packet-dissection layer, not the full analyst product.

It is responsible for:

- reading capture files
- decoding supported protocols
- normalizing observations into Bronze events
- preserving a compact, portable JSON boundary for non-Rust consumers

It is not responsible for:

- Purdue inference
- attack-priority scoring
- beaconing / DNS-exfil / responder-grade breach triage
- web rendering or project workflow

Those higher-level behaviors stay in MarlinSpike and other downstream consumers.

## Supported Inputs

The engine accepts:

- classic `pcap` captures with Ethernet linktype
- `pcapng` captures

Current constraints:

- classic `pcap` support is Ethernet-only right now
- unsupported linktypes fail fast with a clear error

## CLI

Build and run:

```bash
cargo run -- --input capture.pcapng --pretty
```

Or write JSON to a file:

```bash
cargo run -- \
  --input capture.pcap \
  --capture-id engagement-a-01 \
  --output bronze.json \
  --pretty
```

### CLI Contract

Inputs:

- `--input <path>`: classic PCAP or PCAPNG capture
- `--capture-id <id>`: optional stable identifier stamped into Bronze output
- `--output <path>`: optional JSON output path; stdout when omitted
- `--pretty`: pretty-print JSON

Output envelope:

- `engine`: stable engine name (`marlinspike-dpi`)
- `version`: crate version
- `input`: source metadata
- `output.checkpoint`: capture summary and counters
- `output.events`: Bronze v2 event array

## Library Usage

```rust
use fm_dpi::DpiEngine;

let bytes = std::fs::read("capture.pcap")?;
let mut engine = DpiEngine::new();
let events = engine.process_capture("capture-1", std::io::Cursor::new(bytes))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

If you want checkpoint metadata as well:

```rust
use fm_dpi::{DpiEngine, SegmentMeta};

let bytes = std::fs::read("capture.pcapng")?;
let mut engine = DpiEngine::new();
let output = engine.process_capture_to_vec(&SegmentMeta::new("capture-1"), std::io::Cursor::new(bytes))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## FFI

Enable the `ffi` feature to build a `cdylib` / `staticlib`.

The exported compatibility symbol `fm_dpi_process_pcapng_json` now accepts either classic PCAP or PCAPNG bytes. The historical symbol name is preserved so existing Fathom integrations do not break.

## ICS Defense Corpus Validation

The repository carries a checked-in ICS Defense roadmap manifest at
`corpus/ics-defense-manifest.yaml` plus a validation runner.

Run it against a local checkout of the public `ICS-Pcaps` archive:

```bash
cargo run --bin ics-defense-corpus -- \
  validate \
  --corpus-root /path/to/ICS-Pcaps
```

Useful options:

- `--filter <text>` to run only a subset of fixtures
- `--allow-missing` to skip optional fixtures in a partial corpus checkout

## Why This Crate Exists

This crate keeps DPI separate from the analyst workbench:

- MarlinSpike can call it as an external Stage 2 parser
- Fathom can embed it directly in Rust-native pipelines
- other consumers can use JSON or FFI without reimplementing protocol parsing

That separation is intentional. `marlinspike-dpi` is the reusable packet-analysis core; MarlinSpike is the responder-facing workbench built on top of it.

## Publishing Notes

- The crate is GitHub-ready as a standalone repository.
- Cargo publication is intentionally disabled with `publish = false`.
- The current license marker remains `Proprietary`, matching the source repo.
