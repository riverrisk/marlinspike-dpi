# marlinspike-dpi

`marlinspike-dpi` is the standalone DPI engine used by MarlinSpike and consumable by other passive OT/ICS analysis pipelines.

It consumes passive packet captures and emits Bronze v2 protocol events, asset observations, topology observations, parse anomalies, and extracted artifacts. The crate is deliberately usable on its own as:

- a Rust library
- a CLI binary
- an optional C ABI / FFI surface

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
cargo run -p marlinspike-dpi -- --input capture.pcapng --pretty
```

Or write JSON to a file:

```bash
cargo run -p marlinspike-dpi -- \
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

The exported compatibility symbol `fm_dpi_process_pcapng_json` now accepts either classic PCAP or PCAPNG bytes. The historical symbol name is preserved so existing integrations do not break.

## Why This Crate Exists

This crate keeps DPI separate from the analyst workbench:

- MarlinSpike can call it as an external Stage 2 parser
- other Rust applications can embed it directly in native pipelines
- other consumers can use JSON or FFI without reimplementing protocol parsing

That separation is intentional. `marlinspike-dpi` is the reusable packet-analysis core; MarlinSpike is the responder-facing workbench built on top of it.
