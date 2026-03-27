# marlinspike-dpi

Pure-Rust deep packet inspection engine for OT/ICS and IT network monitoring.

Consumes passive packet captures (PCAP / PCAPNG) and emits structured Bronze v2 events: protocol transactions, asset observations, topology observations, parse anomalies, and extracted artifacts. No libpcap, no C dependencies.

Usable as:

- a **Rust library** (`fm_dpi`)
- a **CLI binary** (`marlinspike-dpi`)
- an optional **C FFI** surface (feature `ffi`)

## Protocol Coverage

### OT / ICS Protocols

| Protocol | Transport | Port / EtherType | Parsing Depth |
|----------|-----------|-----------------|---------------|
| Modbus/TCP | TCP | 502 | MBAP header, function codes, register read/write, exception codes, device identification (FC 43) |
| DNP3 | TCP | 20000 | DLL + transport + application layer, function codes, source/dest address, role inference |
| IEC 60870-5-104 | TCP | 2404 | APCI frame types (I/S/U), ASDU type ID, cause of transmission, IOA |
| IEC 61850 MMS | TCP | 102 | ISO-on-TCP + COTP + MMS service identification, TSAP extraction, visible strings |
| IEC 61850 GOOSE | L2 | 0x88B8 | Application ID, dataset references |
| IEC 61850 SV | L2 | 0x88BA | Application ID, sample data |
| EtherNet/IP | TCP | 44818 | Encapsulation commands, session handle, CIP identity objects |
| OPC UA | TCP | 4840, 12001 | Message type/chunk, secure channel ID, sequence/request IDs |
| S7comm | TCP | 102 | TPKT/COTP/S7 PDU, ROSCTR, function codes, parameter/data blocks |
| PROFINET | UDP/L2 | 34964 / 0x8892 | Frame ID classification, DCP service parsing, cyclic IO, alarms |
| BACnet/IP | UDP/LLC | 47808 | BVLC + NPDU + APDU type, confirmed/unconfirmed services, device instance |
| HART-IP | TCP/UDP | 5094 | Session initiate, passthrough commands, device identity |
| OMRON FINS | TCP/UDP | 9600 | FINS header, command codes, memory area read/write |
| EtherCAT | L2 | 0x88A4 | Datagram headers, ADP/ADO addressing, working counters, vendor/product hints |
| MRP | L2 | 0x88E3 | MRP_Test/TopologyChange/LinkDown/LinkUp TLVs, domain UUID, ring state |
| PRP | L2 | 0x88FB | Supervision frames (PRP_Node/RedBox/VDAN/HSR_Node), RCT trailer detection |

### IT / Infrastructure Protocols

| Protocol | Transport | Port / EtherType | Parsing Depth |
|----------|-----------|-----------------|---------------|
| DNS | UDP/TCP | 53, 5353 (mDNS) | Full RFC 1035: queries, answers, A/AAAA/PTR/TXT/SRV records, compression pointers. mDNS device enrichment (AirPlay, Google Cast, Roku, printers, HomeKit, Sonos, Hue, ESPHome) |
| DHCP | UDP | 67, 68 | BOOTP header + options: message type, hostname, vendor class, client ID, server ID, offered/requested IP |
| HTTP | TCP | 80, 8080 | Request line (method, URI, host), response status, Content-Type, Content-Length |
| TLS | TCP | 443, 4840 | Client Hello SNI extraction, cipher suites, TLS version |
| SNMP | UDP | 161, 162 | BER decoder: v1/v2c/v3, community string, PDU types (get/set/response/trap), var-binds, sysName/sysDescr/sysObjectID |
| SSH | TCP | 22 | Banner extraction: protocol version, software version, OS hint from comments |
| FTP | TCP | 21 | Commands (STOR/RETR/USER/QUIT), reply codes, server banner (220) for device fingerprinting |
| NTP | UDP | 123 | Version, mode (client/server/broadcast), stratum, reference ID, root delay/dispersion |
| MQTT | TCP | 1883, 8883 | CONNECT (client_id, username, protocol version, clean session), PUBLISH (topic, QoS, retain), SUBSCRIBE (topic) |
| Syslog | UDP | 514 | RFC 3164 + RFC 5424: facility, severity, hostname, app name, message |
| RADIUS | UDP | 1812, 1813 | Access-Request/Accept/Reject/Accounting, username, NAS-IP, NAS-Identifier, calling/called station ID |

### L2 / Link Layer Protocols

| Protocol | Match | Parsing Depth |
|----------|-------|---------------|
| ARP | EtherType 0x0806 | Operation, sender/target MAC+IP |
| LLDP | EtherType 0x88CC | Chassis ID, port ID, TTL, system name/description, capabilities |
| CDP | SNAP 00:00:0C / 0x2000 | Device ID, port, platform, software version, capabilities, native VLAN, duplex |
| STP/RSTP | LLC 0x42/0x42 | Root/bridge ID, root path cost, port ID, timers, flags |
| MSTP | LLC 0x42/0x42 (version >= 3) | MST config name, revision level, MSTI records (regional root, path cost, priority) |
| PVST+ | SNAP 00:00:0C / 0x010B | Standard BPDU fields + originating VLAN ID |
| LACP | EtherType 0x8809 | Actor/partner: system MAC, priority, key, port, state flags (activity, synchronization, collecting, distributing) |
| VTP | SNAP 00:00:0C / 0x2003 | Version, message type, domain name, revision, VLAN list |
| PRP | EtherType 0x88FB | Supervision type, source/RedBox MAC, sequence number |
| MRP | EtherType 0x88E3 | Frame type, domain UUID, ring state (open/closed), priority |

**33 protocol dissectors** total. Pure Rust, no C dependencies.

## Bronze v2 Event Model

Every packet processed produces zero or more `BronzeEvent`s, each wrapping an `EventEnvelope` (packet metadata) and one of five event families:

| Family | Purpose | Example |
|--------|---------|---------|
| **ProtocolTransaction** | Request-response pair or single operation | Modbus read_holding_registers, DNS query/response |
| **AssetObservation** | Device/service identification | LLDP system name, DHCP hostname, SSH banner |
| **TopologyObservation** | Network relationship | ARP neighbor, LACP bond, STP root path, MRP ring |
| **ParseAnomaly** | Malformed or invalid packet | Bad MBAP length, truncated DNP3 frame |
| **ExtractedArtifact** | Binary payload extraction | Modbus write data, DNP3 application payload |

### EventEnvelope

Every event carries full packet context: timestamp, src/dst MAC, src/dst IP, src/dst port, VLAN ID, transport protocol, frame index, segment hash, and byte/packet counts.

## Deduplication

Multi-collector deployments produce overlapping captures. The engine deduplicates using SHA256 over `(quantized_timestamp, src_ip, dst_ip, src_port, dst_port, family_key)` with a 5-second sliding window and 1-second quantization bucket.

## Supported Inputs

- Classic PCAP (little/big endian, microsecond/nanosecond timestamps)
- PCAPNG
- Ethernet linktype only (unsupported linktypes fail fast)

## CLI

```bash
marlinspike-dpi --input capture.pcapng --pretty
```

```bash
marlinspike-dpi \
  --input capture.pcap \
  --capture-id engagement-a-01 \
  --output bronze.json \
  --pretty
```

Options:

- `--input <path>` — PCAP or PCAPNG capture file
- `--capture-id <id>` — stable identifier stamped into Bronze output (defaults to filename)
- `--output <path>` — JSON output path (stdout when omitted)
- `--pretty` — pretty-print JSON

Output envelope:

```json
{
  "engine": "marlinspike-dpi",
  "version": "0.6.0",
  "input": { "path": "...", "capture_id": "...", "size_bytes": 12345 },
  "output": {
    "checkpoint": {
      "capture_id": "...",
      "schema_version": "v2",
      "segment_hash": "abc123...",
      "frames_processed": 1000,
      "events_emitted": 42
    },
    "events": [ ... ]
  }
}
```

## Library Usage

```rust
use fm_dpi::DpiEngine;

let bytes = std::fs::read("capture.pcap")?;
let mut engine = DpiEngine::new();
let events = engine.process_capture("capture-1", std::io::Cursor::new(bytes))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

With checkpoint metadata:

```rust
use fm_dpi::{DpiEngine, SegmentMeta};

let bytes = std::fs::read("capture.pcapng")?;
let mut engine = DpiEngine::new();
let output = engine.process_capture_to_vec(&SegmentMeta::new("capture-1"), std::io::Cursor::new(bytes))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## FFI

Enable the `ffi` feature to build a `cdylib` / `staticlib`:

```bash
cargo build --features ffi
```

Exported symbols:

```c
// Process capture bytes, return JSON.
FmDpiProcessResult fm_dpi_process_pcapng_json(
    const char *capture_id,
    const uint8_t *data_ptr,
    size_t data_len
);

void fm_dpi_string_free(char *ptr);
const char *fm_dpi_version();
```

Accepts both PCAP and PCAPNG despite the legacy symbol name. Returns a JSON envelope with `output` or `error` fields.

## ICS Defense Corpus Validation

Run the engine against the public ICS-Pcaps archive:

```bash
cargo run -p marlinspike-dpi --bin ics-defense-corpus -- \
  validate \
  --corpus-root /path/to/ICS-Pcaps
```

Options: `--filter <text>` to subset fixtures, `--allow-missing` for partial checkouts.

## Architecture

```
Iron (PCAP/PCAPNG bytes)
  → capture format detection (magic bytes)
  → per-packet: Ethernet → VLAN → IP → TCP/UDP header parsing
  → route to decoders by DecoderInterest (EtherType, TcpPort, UdpPort, LLC, SNAP)
  → decoder calls dissector.parse(), synthesizes BronzeEvent(s)
  → SHA256 dedup filter (5s window)
  → batch (256 events) → output
```

Two-tier design:

- **Dissectors** (`src/dissectors/*.rs`) — stateless protocol parsers implementing `ProtocolDissector` trait. Extract binary fields from payload bytes.
- **Decoders** (`src/engine.rs`) — stateful session managers implementing `SessionDecoder` trait. Correlate request/response pairs, manage session state, emit Bronze events.

## Why This Crate Exists

This crate keeps DPI separate from the analyst workbench:

- MarlinSpike can call it as an external Stage 2 parser
- Fathom can embed it directly in Rust-native pipelines
- Other consumers can use JSON or FFI without reimplementing protocol parsing

`marlinspike-dpi` is the reusable packet-analysis core; MarlinSpike is the responder-facing workbench built on top of it.
