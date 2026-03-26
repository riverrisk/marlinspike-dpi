//! Bronze v2 streaming DPI engine.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::bronze::{
    AssetObservation, BRONZE_SCHEMA_VERSION, BronzeBatch, BronzeEvent, BronzeEventFamily,
    EventEnvelope, ExtractedArtifact, ObjectValue, ParseAnomaly, ProtocolTransaction,
    SegmentCheckpoint, TopologyObservation, TransportProtocol,
};
use crate::dedup::DedupEngine;
use crate::dissectors::{
    arp::ArpDissector, cdp::CdpDissector, dhcp::DhcpDissector, dnp3::Dnp3Dissector,
    dns::DnsDissector, ethernet_ip::EthernetIpDissector, http::HttpDissector, lldp::LldpDissector,
    modbus::ModbusDissector, opc_ua::OpcUaDissector, profinet::ProfinetDissector,
    s7comm::S7commDissector, snmp::SnmpDissector, stp::StpDissector,
};
use crate::registry::{
    ArpFields, CdpFields, DhcpFields, Dnp3Fields, DnsFields, EthernetIpFields, HttpFields,
    LldpFields, ModbusFields, OpcUaFields, PacketContext, ProfinetFields, ProtocolData,
    ProtocolDissector, S7commFields, SnmpFields, StpFields, format_mac,
};

#[derive(Debug, thiserror::Error)]
pub enum DpiError {
    #[error("capture read error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid capture format: {0}")]
    InvalidCapture(&'static str),

    #[error("serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentMeta {
    pub capture_id: String,
}

impl SegmentMeta {
    pub fn new(capture_id: impl Into<String>) -> Self {
        Self {
            capture_id: capture_id.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiSegmentOutput {
    pub checkpoint: SegmentCheckpoint,
    pub events: Vec<BronzeEvent>,
}

pub trait BronzeSink {
    fn push_batch(&mut self, batch: BronzeBatch) -> Result<(), DpiError>;
}

#[derive(Default)]
struct VecBronzeSink {
    events: Vec<BronzeEvent>,
}

impl BronzeSink for VecBronzeSink {
    fn push_batch(&mut self, batch: BronzeBatch) -> Result<(), DpiError> {
        self.events.extend(batch.events);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderInterest {
    EtherType(u16),
    TcpPort(u16),
    UdpPort(u16),
    Llc { dsap: u8, ssap: u8 },
    Snap { oui: [u8; 3], pid: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LlcInfo {
    dsap: u8,
    ssap: u8,
    snap_oui: Option<[u8; 3]>,
    snap_pid: Option<u16>,
}

#[derive(Debug, Clone)]
struct StreamChunk<'a> {
    capture_id: &'a str,
    segment_hash: &'a str,
    interface_id: u32,
    frame_index: u64,
    timestamp: DateTime<Utc>,
    context: PacketContext,
    ethertype: u16,
    llc: Option<LlcInfo>,
    transport: TransportProtocol,
    payload: &'a [u8],
    session_key: String,
    captured_len: u64,
}

trait SessionDecoder: Send {
    fn name(&self) -> &'static str;
    fn interest(&self) -> &'static [DecoderInterest];
    fn on_datagram(&mut self, _chunk: &StreamChunk<'_>, _out: &mut Vec<BronzeEvent>) {}
    fn on_stream_chunk(&mut self, _chunk: &StreamChunk<'_>, _out: &mut Vec<BronzeEvent>) {}
    fn on_gap(
        &mut self,
        _session_key: &str,
        _timestamp: DateTime<Utc>,
        _out: &mut Vec<BronzeEvent>,
    ) {
    }
    fn on_idle_flush(&mut self, _timestamp: DateTime<Utc>, _out: &mut Vec<BronzeEvent>) {}
    fn evict_idle(&mut self, _timestamp: DateTime<Utc>, _out: &mut Vec<BronzeEvent>) {}
}

pub struct DpiEngine {
    dedup: DedupEngine,
    decoders: Vec<Box<dyn SessionDecoder>>,
    batch_size: usize,
}

impl DpiEngine {
    pub fn new() -> Self {
        Self {
            dedup: DedupEngine::new(
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(1),
            ),
            decoders: vec![
                Box::new(ArpDecoder::default()),
                Box::new(LldpDecoder::default()),
                Box::new(CdpDecoder::default()),
                Box::new(StpDecoder::default()),
                Box::new(DnsDecoder::default()),
                Box::new(DhcpDecoder::default()),
                Box::new(SnmpDecoder::default()),
                Box::new(HttpDecoder::default()),
                Box::new(TlsDecoder),
                Box::new(ModbusDecoder::default()),
                Box::new(Dnp3DecoderWrapper::default()),
                Box::new(EthernetIpDecoderWrapper::default()),
                Box::new(OpcUaDecoderWrapper::default()),
                Box::new(S7commDecoderWrapper::default()),
                Box::new(ProfinetDecoderWrapper::default()),
            ],
            batch_size: 256,
        }
    }

    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    pub fn process_segment_to_vec<R: Read + Seek>(
        &mut self,
        meta: &SegmentMeta,
        reader: R,
    ) -> Result<DpiSegmentOutput, DpiError> {
        let mut sink = VecBronzeSink::default();
        let checkpoint = self.process_segment(meta, reader, &mut sink)?;
        Ok(DpiSegmentOutput {
            checkpoint,
            events: sink.events,
        })
    }

    pub fn process_capture_to_vec<R: Read + Seek>(
        &mut self,
        meta: &SegmentMeta,
        reader: R,
    ) -> Result<DpiSegmentOutput, DpiError> {
        self.process_segment_to_vec(meta, reader)
    }

    pub fn process_segment<R: Read + Seek, S: BronzeSink>(
        &mut self,
        meta: &SegmentMeta,
        mut reader: R,
        sink: &mut S,
    ) -> Result<SegmentCheckpoint, DpiError> {
        let segment_hash = compute_segment_hash(&mut reader)?;
        let mut pending_events = Vec::new();
        let mut frames_processed = 0u64;
        let mut events_emitted = 0u64;
        let mut last_timestamp = Utc::now();

        read_capture_packets(&mut reader, |packet| {
            frames_processed += 1;
            let frame_events = self.process_packet_record(
                meta,
                &segment_hash,
                packet.interface_id,
                frames_processed,
                packet.timestamp,
                packet.captured_len,
                &packet.data,
            )?;
            if let Some(ts) = frame_events.first().map(|event| event.envelope.timestamp) {
                last_timestamp = ts;
            }

            for event in frame_events {
                if self.should_emit(&event) {
                    pending_events.push(event);
                }
            }

            for decoder in &mut self.decoders {
                decoder.evict_idle(last_timestamp, &mut pending_events);
            }

            if pending_events.len() >= self.batch_size {
                events_emitted += flush_batch(
                    meta.capture_id.clone(),
                    segment_hash.clone(),
                    &mut pending_events,
                    frames_processed,
                    sink,
                )? as u64;
            }
            Ok(())
        })?;

        for decoder in &mut self.decoders {
            decoder.on_idle_flush(last_timestamp, &mut pending_events);
            decoder.evict_idle(last_timestamp, &mut pending_events);
        }

        let final_pending = pending_events.len() as u64;
        if !pending_events.is_empty() {
            events_emitted += flush_batch(
                meta.capture_id.clone(),
                segment_hash.clone(),
                &mut pending_events,
                frames_processed,
                sink,
            )? as u64;
        }

        Ok(SegmentCheckpoint {
            capture_id: meta.capture_id.clone(),
            schema_version: BRONZE_SCHEMA_VERSION.to_string(),
            segment_hash,
            frames_processed,
            events_emitted: events_emitted.max(final_pending),
        })
    }

    pub fn process_pcapng<R: Read + Seek>(
        &mut self,
        capture_id: impl Into<String>,
        reader: R,
    ) -> Result<Vec<BronzeEvent>, DpiError> {
        Ok(self
            .process_segment_to_vec(&SegmentMeta::new(capture_id), reader)?
            .events)
    }

    pub fn process_capture<R: Read + Seek>(
        &mut self,
        capture_id: impl Into<String>,
        reader: R,
    ) -> Result<Vec<BronzeEvent>, DpiError> {
        Ok(self
            .process_capture_to_vec(&SegmentMeta::new(capture_id), reader)?
            .events)
    }

    fn process_packet_record(
        &mut self,
        meta: &SegmentMeta,
        segment_hash: &str,
        interface_id: u32,
        frame_index: u64,
        timestamp: DateTime<Utc>,
        captured_len: usize,
        pkt_data: &[u8],
    ) -> Result<Vec<BronzeEvent>, DpiError> {
        let timestamp_ns = timestamp
            .timestamp_nanos_opt()
            .unwrap_or_else(|| timestamp.timestamp_micros() * 1_000)
            as u64;

        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        let mut vlan_id = None;
        let (mut ethertype, mut l2_payload) = if pkt_data.len() >= 14 {
            dst_mac.copy_from_slice(&pkt_data[0..6]);
            src_mac.copy_from_slice(&pkt_data[6..12]);

            let outer_ethertype = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
            let mut ethertype = outer_ethertype;
            let mut l2_payload = &pkt_data[14..];
            if outer_ethertype == 0x8100 && l2_payload.len() >= 4 {
                vlan_id = Some(u16::from_be_bytes([l2_payload[0], l2_payload[1]]) & 0x0FFF);
                ethertype = u16::from_be_bytes([l2_payload[2], l2_payload[3]]);
                l2_payload = &l2_payload[4..];
            }
            (ethertype, l2_payload)
        } else {
            (0, &[][..])
        };

        if !matches!(ethertype, 0x0800 | 0x0806 | 0x88CC) {
            let prefixed = if ethertype <= 1500 {
                detect_prefixed_l3_payload(l2_payload).or_else(|| detect_prefixed_l3_payload(pkt_data))
            } else {
                detect_prefixed_l3_payload(pkt_data)
            };
            if let Some((prefixed_ethertype, prefixed_payload)) = prefixed {
                // RiverFlow namespace capture can present packets with a small
                // pseudo-header ahead of the real L3 payload, either directly
                // or nested inside an 802.3-length frame. When there is no
                // outer Ethernet identity, leave src/dst MAC zeroed and let
                // IP/ARP-level identity drive asset correlation.
                src_mac = [0u8; 6];
                dst_mac = [0u8; 6];
                ethertype = prefixed_ethertype;
                l2_payload = prefixed_payload;
            }
        }

        if l2_payload.is_empty() {
            return Ok(vec![parse_anomaly_event(
                meta.capture_id.clone(),
                empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                "engine",
                "medium",
                "ethernet frame shorter than 14 bytes",
                pkt_data,
            )]);
        }

        let base_context = PacketContext {
            src_mac,
            dst_mac,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            vlan_id,
            timestamp: timestamp_ns,
        };

        let mut out = Vec::new();

        match ethertype {
            0x0806 | 0x88CC => {
                let chunk = StreamChunk {
                    capture_id: &meta.capture_id,
                    segment_hash,
                    interface_id,
                    frame_index,
                    timestamp,
                    context: base_context,
                    ethertype,
                    llc: None,
                    transport: if ethertype == 0x0806 {
                        TransportProtocol::Arp
                    } else {
                        TransportProtocol::Ethernet
                    },
                    payload: l2_payload,
                    session_key: make_layer2_session_key(
                        &src_mac,
                        &dst_mac,
                        &format!("ethertype:{ethertype:04x}"),
                    ),
                    captured_len: captured_len as u64,
                };

                for decoder in &mut self.decoders {
                    if interest_matches(decoder.interest(), &chunk) {
                        decoder.on_datagram(&chunk, &mut out);
                    }
                }
            }
            0x0800 => {
                if l2_payload.len() < 20 {
                    out.push(parse_anomaly_event(
                        meta.capture_id.clone(),
                        empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                        "engine",
                        "medium",
                        "ipv4 packet shorter than minimum header",
                        l2_payload,
                    ));
                    return Ok(out);
                }

                let ihl = ((l2_payload[0] & 0x0F) as usize) * 4;
                if ihl < 20 || l2_payload.len() < ihl {
                    out.push(parse_anomaly_event(
                        meta.capture_id.clone(),
                        empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                        "engine",
                        "medium",
                        "invalid ipv4 header length",
                        l2_payload,
                    ));
                    return Ok(out);
                }

                let ip_proto = l2_payload[9];
                let src_ip = IpAddr::V4(Ipv4Addr::new(
                    l2_payload[12],
                    l2_payload[13],
                    l2_payload[14],
                    l2_payload[15],
                ));
                let dst_ip = IpAddr::V4(Ipv4Addr::new(
                    l2_payload[16],
                    l2_payload[17],
                    l2_payload[18],
                    l2_payload[19],
                ));
                let transport_payload = &l2_payload[ihl..];

                match ip_proto {
                    6 => {
                        if transport_payload.len() < 20 {
                            out.push(parse_anomaly_event(
                                meta.capture_id.clone(),
                                empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                                "engine",
                                "medium",
                                "tcp header shorter than minimum length",
                                transport_payload,
                            ));
                            return Ok(out);
                        }

                        let src_port =
                            u16::from_be_bytes([transport_payload[0], transport_payload[1]]);
                        let dst_port =
                            u16::from_be_bytes([transport_payload[2], transport_payload[3]]);
                        let data_offset = ((transport_payload[12] >> 4) as usize) * 4;
                        if data_offset < 20 || transport_payload.len() < data_offset {
                            out.push(parse_anomaly_event(
                                meta.capture_id.clone(),
                                empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                                "engine",
                                "medium",
                                "invalid tcp data offset",
                                transport_payload,
                            ));
                            return Ok(out);
                        }

                        let payload = &transport_payload[data_offset..];
                        let session_key =
                            make_ip_session_key(src_ip, dst_ip, src_port, dst_port, "tcp");
                        let chunk = StreamChunk {
                            capture_id: &meta.capture_id,
                            segment_hash,
                            interface_id,
                            frame_index,
                            timestamp,
                            context: PacketContext {
                                src_mac,
                                dst_mac,
                                src_ip,
                                dst_ip,
                                src_port,
                                dst_port,
                                vlan_id,
                                timestamp: timestamp_ns,
                            },
                            ethertype,
                            llc: None,
                            transport: TransportProtocol::Tcp,
                            payload,
                            session_key,
                            captured_len: captured_len as u64,
                        };

                        for decoder in &mut self.decoders {
                            if interest_matches(decoder.interest(), &chunk) {
                                decoder.on_stream_chunk(&chunk, &mut out);
                            }
                        }
                    }
                    17 => {
                        if transport_payload.len() < 8 {
                            out.push(parse_anomaly_event(
                                meta.capture_id.clone(),
                                empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                                "engine",
                                "medium",
                                "udp header shorter than minimum length",
                                transport_payload,
                            ));
                            return Ok(out);
                        }

                        let src_port =
                            u16::from_be_bytes([transport_payload[0], transport_payload[1]]);
                        let dst_port =
                            u16::from_be_bytes([transport_payload[2], transport_payload[3]]);
                        let payload = &transport_payload[8..];
                        let session_key =
                            make_ip_session_key(src_ip, dst_ip, src_port, dst_port, "udp");
                        let chunk = StreamChunk {
                            capture_id: &meta.capture_id,
                            segment_hash,
                            interface_id,
                            frame_index,
                            timestamp,
                            context: PacketContext {
                                src_mac,
                                dst_mac,
                                src_ip,
                                dst_ip,
                                src_port,
                                dst_port,
                                vlan_id,
                                timestamp: timestamp_ns,
                            },
                            ethertype,
                            llc: None,
                            transport: TransportProtocol::Udp,
                            payload,
                            session_key,
                            captured_len: captured_len as u64,
                        };

                        for decoder in &mut self.decoders {
                            if interest_matches(decoder.interest(), &chunk) {
                                decoder.on_datagram(&chunk, &mut out);
                            }
                        }
                    }
                    1 => {
                        out.push(parse_anomaly_event(
                            meta.capture_id.clone(),
                            build_envelope(
                                &base_context,
                                interface_id,
                                frame_index,
                                timestamp,
                                segment_hash,
                                TransportProtocol::Icmp,
                                None,
                                captured_len as u64,
                                make_ip_session_key(src_ip, dst_ip, 0, 0, "icmp"),
                            ),
                            "engine",
                            "low",
                            "icmp observed without dedicated decoder",
                            transport_payload,
                        ));
                    }
                    _ => {
                        out.push(parse_anomaly_event(
                            meta.capture_id.clone(),
                            build_envelope(
                                &base_context,
                                interface_id,
                                frame_index,
                                timestamp,
                                segment_hash,
                                TransportProtocol::Ipv4,
                                Some("ip"),
                                captured_len as u64,
                                make_ip_session_key(src_ip, dst_ip, 0, 0, "ip"),
                            ),
                            "engine",
                            "low",
                            "unsupported ipv4 transport protocol",
                            transport_payload,
                        ));
                    }
                }
            }
            value if value <= 1500 => {
                if l2_payload.len() < 3 {
                    out.push(parse_anomaly_event(
                        meta.capture_id.clone(),
                        empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                        "engine",
                        "medium",
                        "802.3 llc frame shorter than minimum header",
                        l2_payload,
                    ));
                    return Ok(out);
                }

                let dsap = l2_payload[0];
                let ssap = l2_payload[1];
                let control = l2_payload[2];

                let (payload, llc, session_key) = if dsap == 0xAA
                    && ssap == 0xAA
                    && control == 0x03
                    && l2_payload.len() >= 8
                {
                    let oui = [l2_payload[3], l2_payload[4], l2_payload[5]];
                    let pid = u16::from_be_bytes([l2_payload[6], l2_payload[7]]);
                    (
                        &l2_payload[8..],
                        Some(LlcInfo {
                            dsap,
                            ssap,
                            snap_oui: Some(oui),
                            snap_pid: Some(pid),
                        }),
                        make_layer2_session_key(
                            &src_mac,
                            &dst_mac,
                            &format!("snap:{:02x}{:02x}{:02x}:{pid:04x}", oui[0], oui[1], oui[2]),
                        ),
                    )
                } else {
                    (
                        &l2_payload[3..],
                        Some(LlcInfo {
                            dsap,
                            ssap,
                            snap_oui: None,
                            snap_pid: None,
                        }),
                        make_layer2_session_key(
                            &src_mac,
                            &dst_mac,
                            &format!("llc:{dsap:02x}:{ssap:02x}"),
                        ),
                    )
                };

                let chunk = StreamChunk {
                    capture_id: &meta.capture_id,
                    segment_hash,
                    interface_id,
                    frame_index,
                    timestamp,
                    context: base_context.clone(),
                    ethertype: value,
                    llc,
                    transport: TransportProtocol::Ethernet,
                    payload,
                    session_key,
                    captured_len: captured_len as u64,
                };

                let mut matched = false;
                for decoder in &mut self.decoders {
                    if interest_matches(decoder.interest(), &chunk) {
                        matched = true;
                        decoder.on_datagram(&chunk, &mut out);
                    }
                }

                if !matched {
                    out.push(parse_anomaly_event(
                        meta.capture_id.clone(),
                        build_envelope(
                            &base_context,
                            interface_id,
                            frame_index,
                            timestamp,
                            segment_hash,
                            TransportProtocol::Ethernet,
                            None,
                            captured_len as u64,
                            chunk.session_key,
                        ),
                        "engine",
                        "low",
                        "unsupported 802.3 llc protocol",
                        l2_payload,
                    ));
                }
            }
            _ => {
                out.push(parse_anomaly_event(
                    meta.capture_id.clone(),
                    empty_envelope(interface_id, frame_index, timestamp, segment_hash),
                    "engine",
                    "low",
                    "unsupported ethertype",
                    l2_payload,
                ));
            }
        }

        Ok(out)
    }

    fn should_emit(&mut self, event: &BronzeEvent) -> bool {
        let src = event.src_ip().or(event.src_mac()).unwrap_or("unknown");
        let dst = event.dst_ip().or(event.dst_mac()).unwrap_or("unknown");
        let family_key = match &event.family {
            BronzeEventFamily::ProtocolTransaction(tx) => format!(
                "protocol_transaction:{}:{}",
                event.protocol().unwrap_or("unknown"),
                tx.operation
            ),
            BronzeEventFamily::AssetObservation(obs) => format!(
                "asset_observation:{}:{}",
                event.protocol().unwrap_or("unknown"),
                obs.asset_key
            ),
            BronzeEventFamily::TopologyObservation(obs) => format!(
                "topology_observation:{}:{}:{}:{}",
                event.protocol().unwrap_or("unknown"),
                obs.observation_type,
                obs.local_id,
                obs.remote_id.as_deref().unwrap_or("none")
            ),
            BronzeEventFamily::ParseAnomaly(anomaly) => {
                format!("parse_anomaly:{}:{}", anomaly.decoder, anomaly.reason)
            }
            BronzeEventFamily::ExtractedArtifact(artifact) => format!(
                "extracted_artifact:{}:{}",
                artifact.artifact_type, artifact.artifact_key
            ),
        };
        !self.dedup.is_duplicate(
            event
                .envelope
                .timestamp
                .timestamp_nanos_opt()
                .unwrap_or_default() as u64,
            src,
            dst,
            event.envelope.src_port.unwrap_or(0),
            event.envelope.dst_port.unwrap_or(0),
            &family_key,
        )
    }
}

impl Default for DpiEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureFormat {
    Pcapng,
    Pcap(PcapFlavor),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PcapFlavor {
    LittleMicro,
    BigMicro,
    LittleNano,
    BigNano,
}

impl PcapFlavor {
    fn is_little_endian(self) -> bool {
        matches!(self, Self::LittleMicro | Self::LittleNano)
    }

    fn timestamp_unit_nanos(self) -> u64 {
        match self {
            Self::LittleMicro | Self::BigMicro => 1_000,
            Self::LittleNano | Self::BigNano => 1,
        }
    }
}

#[derive(Debug, Clone)]
struct PacketRecord {
    interface_id: u32,
    timestamp: DateTime<Utc>,
    captured_len: usize,
    data: Vec<u8>,
}

fn flush_batch<S: BronzeSink>(
    capture_id: String,
    segment_hash: String,
    pending_events: &mut Vec<BronzeEvent>,
    frames_processed: u64,
    sink: &mut S,
) -> Result<usize, DpiError> {
    if pending_events.is_empty() {
        return Ok(0);
    }

    let checkpoint = SegmentCheckpoint {
        capture_id: capture_id.clone(),
        schema_version: BRONZE_SCHEMA_VERSION.to_string(),
        segment_hash: segment_hash.clone(),
        frames_processed,
        events_emitted: pending_events.len() as u64,
    };

    let batch = BronzeBatch {
        capture_id,
        schema_version: BRONZE_SCHEMA_VERSION.to_string(),
        segment_hash,
        events: std::mem::take(pending_events),
        checkpoint,
    };
    let count = batch.events.len();
    sink.push_batch(batch)?;
    Ok(count)
}

fn compute_segment_hash<R: Read + Seek>(reader: &mut R) -> Result<String, DpiError> {
    let start = reader.stream_position()?;
    reader.seek(SeekFrom::Start(start))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    reader.seek(SeekFrom::Start(start))?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_capture_packets<R: Read + Seek, F>(reader: &mut R, mut on_packet: F) -> Result<(), DpiError>
where
    F: FnMut(PacketRecord) -> Result<(), DpiError>,
{
    let start = reader.stream_position()?;
    let format = detect_capture_format(reader)?;
    reader.seek(SeekFrom::Start(start))?;

    match format {
        CaptureFormat::Pcapng => loop {
            let Some(block) = read_pcapng_block(reader)? else {
                break;
            };
            if let Some(packet) = pcapng_packet_record(&block)? {
                on_packet(packet)?;
            }
        },
        CaptureFormat::Pcap(flavor) => {
            read_pcap_global_header(reader, flavor)?;
            loop {
                let Some(packet) = read_pcap_packet(reader, flavor)? else {
                    break;
                };
                on_packet(packet)?;
            }
        }
    }

    Ok(())
}

fn detect_prefixed_l3_payload(pkt_data: &[u8]) -> Option<(u16, &[u8])> {
    for offset in [6usize, 4usize] {
        let Some(payload) = pkt_data.get(offset..) else {
            continue;
        };
        if payload.len() >= 20 && payload[0] >> 4 == 4 {
            return Some((0x0800, payload));
        }
        if payload.len() >= 8 && payload.starts_with(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04]) {
            return Some((0x0806, payload));
        }
    }
    None
}

fn detect_capture_format<R: Read + Seek>(reader: &mut R) -> Result<CaptureFormat, DpiError> {
    let start = reader.stream_position()?;
    let mut magic = [0u8; 4];
    if !read_exact_or_eof(reader, &mut magic)? {
        return Err(DpiError::InvalidCapture("capture file is empty"));
    }
    reader.seek(SeekFrom::Start(start))?;

    match magic {
        [0x0A, 0x0D, 0x0D, 0x0A] => Ok(CaptureFormat::Pcapng),
        [0xD4, 0xC3, 0xB2, 0xA1] => Ok(CaptureFormat::Pcap(PcapFlavor::LittleMicro)),
        [0xA1, 0xB2, 0xC3, 0xD4] => Ok(CaptureFormat::Pcap(PcapFlavor::BigMicro)),
        [0x4D, 0x3C, 0xB2, 0xA1] => Ok(CaptureFormat::Pcap(PcapFlavor::LittleNano)),
        [0xA1, 0xB2, 0x3C, 0x4D] => Ok(CaptureFormat::Pcap(PcapFlavor::BigNano)),
        _ => Err(DpiError::InvalidCapture("unrecognized capture magic bytes")),
    }
}

fn read_pcapng_block<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, DpiError> {
    let mut header = [0u8; 8];
    if !read_exact_or_eof(reader, &mut header)? {
        return Ok(None);
    }

    let block_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if block_len < 12 {
        return Err(DpiError::InvalidCapture(
            "pcapng block smaller than minimum",
        ));
    }

    let mut rest = vec![0u8; block_len - 8];
    reader.read_exact(&mut rest)?;
    let mut block = Vec::with_capacity(block_len);
    block.extend_from_slice(&header);
    block.extend_from_slice(&rest);
    Ok(Some(block))
}

fn pcapng_packet_record(block: &[u8]) -> Result<Option<PacketRecord>, DpiError> {
    if block.len() < 12 {
        return Err(DpiError::InvalidCapture("pcapng block shorter than header"));
    }

    let block_type = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    if block_type != 0x0000_0006 {
        return Ok(None);
    }
    if block.len() < 32 {
        return Err(DpiError::InvalidCapture(
            "enhanced packet block shorter than minimum",
        ));
    }

    let interface_id = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
    let ts_high = u32::from_le_bytes([block[12], block[13], block[14], block[15]]) as u64;
    let ts_low = u32::from_le_bytes([block[16], block[17], block[18], block[19]]) as u64;
    let captured_len = u32::from_le_bytes([block[20], block[21], block[22], block[23]]) as usize;
    let timestamp_us = (ts_high << 32) | ts_low;
    let timestamp = Utc
        .timestamp_opt(
            (timestamp_us / 1_000_000) as i64,
            ((timestamp_us % 1_000_000) * 1_000) as u32,
        )
        .single()
        .unwrap_or_else(Utc::now);

    let pkt_start = 28usize;
    if pkt_start + captured_len > block.len().saturating_sub(4) {
        return Err(DpiError::InvalidCapture(
            "enhanced packet block length exceeds packet data",
        ));
    }

    Ok(Some(PacketRecord {
        interface_id,
        timestamp,
        captured_len,
        data: block[pkt_start..pkt_start + captured_len].to_vec(),
    }))
}

fn read_pcap_global_header<R: Read>(reader: &mut R, flavor: PcapFlavor) -> Result<(), DpiError> {
    let mut header = [0u8; 24];
    reader.read_exact(&mut header)?;
    let read_u16 = |bytes: [u8; 2]| -> u16 {
        if flavor.is_little_endian() {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    };
    let read_u32 = |bytes: [u8; 4]| -> u32 {
        if flavor.is_little_endian() {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };

    let version_major = read_u16([header[4], header[5]]);
    let version_minor = read_u16([header[6], header[7]]);
    if version_major != 2 || version_minor != 4 {
        return Err(DpiError::InvalidCapture(
            "unsupported classic pcap version (expected 2.4)",
        ));
    }

    let network = read_u32([header[20], header[21], header[22], header[23]]);
    if network != 1 {
        return Err(DpiError::InvalidCapture(
            "unsupported classic pcap linktype (expected ethernet)",
        ));
    }

    Ok(())
}

fn read_pcap_packet<R: Read>(
    reader: &mut R,
    flavor: PcapFlavor,
) -> Result<Option<PacketRecord>, DpiError> {
    let mut header = [0u8; 16];
    if !read_exact_or_eof(reader, &mut header)? {
        return Ok(None);
    }

    let read_u32 = |bytes: [u8; 4]| -> u32 {
        if flavor.is_little_endian() {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };

    let ts_sec = read_u32([header[0], header[1], header[2], header[3]]) as i64;
    let ts_frac = read_u32([header[4], header[5], header[6], header[7]]) as u64;
    let incl_len = read_u32([header[8], header[9], header[10], header[11]]) as usize;
    let _orig_len = read_u32([header[12], header[13], header[14], header[15]]);
    let unit_nanos = flavor.timestamp_unit_nanos();
    let nanos_total = ts_frac
        .checked_mul(unit_nanos)
        .ok_or(DpiError::InvalidCapture("classic pcap timestamp overflow"))?;
    let seconds = ts_sec + (nanos_total / 1_000_000_000) as i64;
    let nanos = (nanos_total % 1_000_000_000) as u32;
    let timestamp = Utc
        .timestamp_opt(seconds, nanos)
        .single()
        .ok_or(DpiError::InvalidCapture(
            "classic pcap timestamp out of range",
        ))?;

    let mut data = vec![0u8; incl_len];
    reader.read_exact(&mut data)?;
    Ok(Some(PacketRecord {
        interface_id: 0,
        timestamp,
        captured_len: incl_len,
        data,
    }))
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool, io::Error> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let read = reader.read(&mut buf[offset..])?;
        if read == 0 {
            if offset == 0 {
                return Ok(false);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof while reading capture header",
            ));
        }
        offset += read;
    }
    Ok(true)
}

fn interest_matches(interests: &[DecoderInterest], chunk: &StreamChunk<'_>) -> bool {
    interests.iter().any(|interest| match interest {
        DecoderInterest::EtherType(value) => chunk.ethertype == *value,
        DecoderInterest::TcpPort(port) => {
            chunk.transport == TransportProtocol::Tcp
                && (chunk.context.src_port == *port || chunk.context.dst_port == *port)
        }
        DecoderInterest::UdpPort(port) => {
            chunk.transport == TransportProtocol::Udp
                && (chunk.context.src_port == *port || chunk.context.dst_port == *port)
        }
        DecoderInterest::Llc { dsap, ssap } => chunk
            .llc
            .map(|llc| llc.dsap == *dsap && llc.ssap == *ssap)
            .unwrap_or(false),
        DecoderInterest::Snap { oui, pid } => chunk
            .llc
            .map(|llc| llc.snap_oui == Some(*oui) && llc.snap_pid == Some(*pid))
            .unwrap_or(false),
    })
}

fn build_envelope(
    context: &PacketContext,
    interface_id: u32,
    frame_index: u64,
    timestamp: DateTime<Utc>,
    segment_hash: &str,
    transport: TransportProtocol,
    protocol: Option<&str>,
    captured_len: u64,
    session_key: String,
) -> EventEnvelope {
    EventEnvelope {
        timestamp,
        interface_id,
        segment_hash: segment_hash.to_string(),
        frame_index,
        session_key,
        src_mac: Some(format_mac(&context.src_mac)),
        dst_mac: Some(format_mac(&context.dst_mac)),
        src_ip: ip_to_string(context.src_ip),
        dst_ip: ip_to_string(context.dst_ip),
        src_port: non_zero_u16(context.src_port),
        dst_port: non_zero_u16(context.dst_port),
        vlan_id: context.vlan_id,
        transport,
        protocol: protocol.map(str::to_string),
        bytes_count: captured_len,
        packet_count: 1,
    }
}

fn empty_envelope(
    interface_id: u32,
    frame_index: u64,
    timestamp: DateTime<Utc>,
    segment_hash: &str,
) -> EventEnvelope {
    EventEnvelope {
        timestamp,
        interface_id,
        segment_hash: segment_hash.to_string(),
        frame_index,
        session_key: String::new(),
        src_mac: None,
        dst_mac: None,
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        vlan_id: None,
        transport: TransportProtocol::Unknown,
        protocol: None,
        bytes_count: 0,
        packet_count: 0,
    }
}

fn ip_to_string(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) if v4 == Ipv4Addr::UNSPECIFIED => None,
        _ => Some(ip.to_string()),
    }
}

fn non_zero_u16(value: u16) -> Option<u16> {
    if value == 0 { None } else { Some(value) }
}

fn make_layer2_session_key(src_mac: &[u8; 6], dst_mac: &[u8; 6], protocol_key: &str) -> String {
    let mut peers = [format_mac(src_mac), format_mac(dst_mac)];
    peers.sort();
    format!("l2:{}:{}:{protocol_key}", peers[0], peers[1])
}

fn make_ip_session_key(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    transport: &str,
) -> String {
    let left = format!("{src_ip}:{src_port}");
    let right = format!("{dst_ip}:{dst_port}");
    if left <= right {
        format!("{transport}:{left}:{right}")
    } else {
        format!("{transport}:{right}:{left}")
    }
}

fn new_event(
    capture_id: String,
    envelope: EventEnvelope,
    family: BronzeEventFamily,
) -> BronzeEvent {
    BronzeEvent {
        event_id: Uuid::new_v4().to_string(),
        capture_id,
        schema_version: BRONZE_SCHEMA_VERSION.to_string(),
        envelope,
        family,
    }
}

fn parse_anomaly_event(
    capture_id: String,
    envelope: EventEnvelope,
    decoder: &str,
    severity: &str,
    reason: &str,
    raw_excerpt: &[u8],
) -> BronzeEvent {
    new_event(
        capture_id,
        envelope,
        BronzeEventFamily::ParseAnomaly(ParseAnomaly {
            decoder: decoder.to_string(),
            severity: severity.to_string(),
            reason: reason.to_string(),
            raw_excerpt_hex: hex::encode(&raw_excerpt[..raw_excerpt.len().min(32)]),
        }),
    )
}

fn artifact_event(
    capture_id: String,
    envelope: EventEnvelope,
    artifact_type: &str,
    artifact_key: &str,
    mime_type: Option<&str>,
    description: Option<&str>,
    bytes: &[u8],
) -> BronzeEvent {
    let sha256 = Sha256::digest(bytes);
    new_event(
        capture_id,
        envelope,
        BronzeEventFamily::ExtractedArtifact(ExtractedArtifact {
            artifact_type: artifact_type.to_string(),
            artifact_key: artifact_key.to_string(),
            sha256: format!("{sha256:x}"),
            mime_type: mime_type.map(str::to_string),
            content_hex: hex::encode(bytes),
            description: description.map(str::to_string),
        }),
    )
}

#[derive(Default)]
struct ArpDecoder {
    dissector: ArpDissector,
}

impl SessionDecoder for ArpDecoder {
    fn name(&self) -> &'static str {
        "arp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x0806)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Arp(ArpFields {
                sender_mac,
                sender_ip,
                target_mac,
                target_ip,
                operation,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Arp,
                    Some("arp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let sender_ip = format!(
                    "{}.{}.{}.{}",
                    sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]
                );
                let target_ip = format!(
                    "{}.{}.{}.{}",
                    target_ip[0], target_ip[1], target_ip[2], target_ip[3]
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&sender_mac),
                        role: None,
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["arp".to_string()],
                        identifiers: BTreeMap::from([
                            ("mac".to_string(), format_mac(&sender_mac)),
                            ("ip".to_string(), sender_ip.clone()),
                        ]),
                    }),
                ));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: if operation == 2 {
                            "arp_reply".to_string()
                        } else {
                            "arp_request".to_string()
                        },
                        local_id: sender_ip,
                        remote_id: Some(target_ip),
                        description: Some(format!(
                            "ARP op={operation} {} -> {}",
                            format_mac(&sender_mac),
                            format_mac(&target_mac)
                        )),
                        capabilities: Vec::new(),
                        metadata: BTreeMap::new(),
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Arp,
                    Some("arp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse arp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct LldpDecoder {
    dissector: LldpDissector,
}

impl SessionDecoder for LldpDecoder {
    fn name(&self) -> &'static str {
        "lldp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::EtherType(0x88CC)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Lldp(LldpFields {
                chassis_id,
                port_id,
                system_name,
                system_description,
                capabilities,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("lldp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: chassis_id.clone(),
                        role: Some("switch".to_string()),
                        vendor: (!system_name.is_empty()).then_some(system_name.clone()),
                        model: (!system_description.is_empty())
                            .then_some(system_description.clone()),
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["lldp".to_string()],
                        identifiers: BTreeMap::from([
                            ("chassis_id".to_string(), chassis_id.clone()),
                            ("port_id".to_string(), port_id.clone()),
                        ]),
                    }),
                ));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "lldp_neighbor".to_string(),
                        local_id: format_mac(&chunk.context.src_mac),
                        remote_id: Some(chassis_id),
                        description: Some(port_id),
                        capabilities,
                        metadata: BTreeMap::new(),
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("lldp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse lldp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct CdpDecoder {
    dissector: CdpDissector,
}

impl SessionDecoder for CdpDecoder {
    fn name(&self) -> &'static str {
        "cdp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Snap {
            oui: [0x00, 0x00, 0x0C],
            pid: 0x2000,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Cdp(CdpFields {
                device_id,
                port_id,
                platform,
                software_version,
                capabilities,
                native_vlan,
                duplex,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("cdp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let role = if capabilities.iter().any(|c| c == "switch") {
                    Some("switch".to_string())
                } else if capabilities.iter().any(|c| c == "router") {
                    Some("router".to_string())
                } else {
                    None
                };
                let mut identifiers = BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("device_id".to_string(), device_id.clone()),
                ]);
                if !port_id.is_empty() {
                    identifiers.insert("port_id".to_string(), port_id.clone());
                }
                if let Some(vlan) = native_vlan {
                    identifiers.insert("native_vlan".to_string(), vlan.to_string());
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: device_id.clone(),
                        role,
                        vendor: Some("Cisco".to_string()),
                        model: platform,
                        firmware: software_version,
                        hostnames: vec![device_id.clone()],
                        protocols: vec!["cdp".to_string()],
                        identifiers,
                    }),
                ));

                let mut metadata = BTreeMap::new();
                if let Some(vlan) = native_vlan {
                    metadata.insert("native_vlan".to_string(), vlan.to_string());
                }
                if let Some(duplex) = duplex {
                    metadata.insert("duplex".to_string(), duplex);
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "cdp_neighbor".to_string(),
                        local_id: format_mac(&chunk.context.src_mac),
                        remote_id: Some(device_id),
                        description: (!port_id.is_empty()).then_some(port_id),
                        capabilities,
                        metadata,
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("cdp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse cdp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct StpDecoder {
    dissector: StpDissector,
}

impl SessionDecoder for StpDecoder {
    fn name(&self) -> &'static str {
        "stp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::Llc {
            dsap: 0x42,
            ssap: 0x42,
        }]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Stp(StpFields {
                protocol_version,
                bpdu_type,
                flags,
                root_id,
                root_path_cost,
                bridge_id,
                port_id,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("stp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut identifiers = BTreeMap::from([
                    ("mac".to_string(), format_mac(&chunk.context.src_mac)),
                    ("bridge_id".to_string(), bridge_id.clone()),
                    ("root_id".to_string(), root_id.clone()),
                    ("port_id".to_string(), format!("{port_id:#06x}")),
                ]);
                identifiers.insert("root_path_cost".to_string(), root_path_cost.to_string());
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: bridge_id.clone(),
                        role: Some("switch".to_string()),
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames: Vec::new(),
                        protocols: vec!["stp".to_string()],
                        identifiers,
                    }),
                ));

                let mut metadata = BTreeMap::new();
                metadata.insert("protocol_version".to_string(), protocol_version.to_string());
                metadata.insert("bpdu_type".to_string(), format!("{bpdu_type:#04x}"));
                metadata.insert("flags".to_string(), format!("{flags:#04x}"));
                metadata.insert("root_path_cost".to_string(), root_path_cost.to_string());
                metadata.insert("port_id".to_string(), format!("{port_id:#06x}"));
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope,
                    BronzeEventFamily::TopologyObservation(TopologyObservation {
                        observation_type: "stp_topology".to_string(),
                        local_id: bridge_id,
                        remote_id: Some(root_id),
                        description: Some("spanning_tree_bpdu".to_string()),
                        capabilities: Vec::new(),
                        metadata,
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Ethernet,
                    Some("stp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse stp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct DnsDecoder {
    dissector: DnsDissector,
}

impl SessionDecoder for DnsDecoder {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::UdpPort(53),
            DecoderInterest::TcpPort(53),
            DecoderInterest::UdpPort(5353), // mDNS — same wire format, local hostnames
        ]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let payload = dns_payload(chunk);
        match self.dissector.parse(payload, &chunk.context) {
            Some(ProtocolData::Dns(DnsFields {
                is_response,
                transaction_id,
                queries,
                answers,
                records,
            })) => {
                let mut attributes = BTreeMap::new();
                attributes.insert("transaction_id".to_string(), transaction_id.to_string());
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    chunk.transport,
                    Some("dns"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: if is_response {
                            "response".to_string()
                        } else {
                            "query".to_string()
                        },
                        status: if is_response {
                            "response".to_string()
                        } else {
                            "request".to_string()
                        },
                        request_summary: (!queries.is_empty()).then_some(queries.join(", ")),
                        response_summary: (!answers.is_empty()).then_some(answers.join(", ")),
                        object_refs: queries.clone(),
                        values: answers
                            .iter()
                            .map(|answer| ObjectValue {
                                object_ref: "answer".to_string(),
                                value: Some(answer.clone()),
                            })
                            .collect(),
                        attributes,
                    }),
                ));
                if is_response {
                    use crate::registry::{DnsRecordData, DnsRecordType};

                    let is_mdns = chunk.context.dst_port == 5353 || chunk.context.src_port == 5353;

                    // ── Standard DNS: pair queries with answers ──
                    if !is_mdns {
                        for (query, answer) in queries.iter().zip(answers.iter()) {
                            let hostname = dns_hostname_from_query(query);
                            if let Some(ip) = dns_ip_from_answer(answer) {
                                out.push(new_event(
                                    chunk.capture_id.to_string(),
                                    envelope.clone(),
                                    BronzeEventFamily::AssetObservation(AssetObservation {
                                        asset_key: ip.clone(),
                                        role: None,
                                        vendor: None,
                                        model: None,
                                        firmware: None,
                                        hostnames: vec![hostname],
                                        protocols: vec!["dns".to_string()],
                                        identifiers: BTreeMap::from([("ip".to_string(), ip)]),
                                    }),
                                ));
                            }
                        }
                    }

                    // ── mDNS: use structured records for rich extraction ──
                    if is_mdns {
                        let src_ip = chunk.context.src_ip.to_string();

                        // Collect A record bindings: hostname.local → IP
                        let mut hostname_ips: Vec<(String, String)> = Vec::new();
                        for rec in &records {
                            if let DnsRecordData::A(ip) = &rec.data {
                                if rec.name.ends_with(".local") {
                                    hostname_ips.push((rec.name.clone(), ip.clone()));
                                }
                            }
                        }

                        // Emit hostname observations from A records
                        for (hostname, ip) in &hostname_ips {
                            // Skip service discovery names
                            if hostname.contains("._tcp.") || hostname.contains("._udp.") {
                                continue;
                            }
                            out.push(new_event(
                                chunk.capture_id.to_string(),
                                envelope.clone(),
                                BronzeEventFamily::AssetObservation(AssetObservation {
                                    asset_key: ip.clone(),
                                    role: None,
                                    vendor: None,
                                    model: None,
                                    firmware: None,
                                    hostnames: vec![hostname.clone()],
                                    protocols: vec!["mdns".to_string()],
                                    identifiers: BTreeMap::from([("ip".to_string(), ip.clone())]),
                                }),
                            ));
                        }

                        // If no A records matched, enrich src_ip with the
                        // first clean .local PTR name
                        if hostname_ips.is_empty() {
                            for rec in &records {
                                if let DnsRecordData::Ptr(name) = &rec.data {
                                    if name.ends_with(".local")
                                        && !name.contains("._tcp.")
                                        && !name.contains("._udp.")
                                        && !rec.name.contains(".ip6.arpa")
                                    {
                                        out.push(new_event(
                                            chunk.capture_id.to_string(),
                                            envelope.clone(),
                                            BronzeEventFamily::AssetObservation(AssetObservation {
                                                asset_key: src_ip.clone(),
                                                role: None,
                                                vendor: None,
                                                model: None,
                                                firmware: None,
                                                hostnames: vec![name.clone()],
                                                protocols: vec!["mdns".to_string()],
                                                identifiers: BTreeMap::from([(
                                                    "ip".to_string(),
                                                    src_ip.clone(),
                                                )]),
                                            }),
                                        ));
                                        break;
                                    }
                                }
                            }
                        }

                        // Extract device metadata from TXT records.
                        // Covers: AirPlay, RAOP, Google Cast, Roku, printers (IPP),
                        // HomeKit (HAP), Sonos, Hue, ESPHome, Samsung, Home Assistant.
                        let mut mdns_vendor: Option<String> = None;
                        let mut mdns_model: Option<String> = None;
                        let mut mdns_firmware: Option<String> = None;
                        let mut mdns_device_name: Option<String> = None;
                        let mut service_types: Vec<String> = Vec::new();

                        for rec in &records {
                            // Track which service types are advertised
                            if rec.rtype == DnsRecordType::PTR {
                                if let DnsRecordData::Ptr(instance) = &rec.data {
                                    if rec.name.contains("._tcp.") || rec.name.contains("._udp.") {
                                        service_types.push(rec.name.clone());
                                    }
                                    // Extract friendly name from service instance
                                    // e.g. "Bathroom TV._airplay._tcp.local" → "Bathroom TV"
                                    if let Some(name) = instance.split("._").next().filter(|n| {
                                        !n.is_empty()
                                            && n.len() > 2
                                            && (n.contains(' ') || n.len() > 6)
                                    }) {
                                        // Skip UUID-style names
                                        if !name.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
                                        {
                                            if mdns_device_name.is_none() {
                                                mdns_device_name = Some(name.to_string());
                                            }
                                        }
                                    }
                                }
                            }

                            if let DnsRecordData::Txt(entries) = &rec.data {
                                for entry in entries {
                                    let Some((key, val)) = entry.split_once('=') else {
                                        continue;
                                    };
                                    if val.is_empty() {
                                        continue;
                                    }
                                    match key {
                                        // Vendor / manufacturer
                                        "manufacturer" | "usb_MFG" | "integrator" => {
                                            if mdns_vendor.is_none() {
                                                mdns_vendor = Some(val.to_string());
                                            }
                                        }
                                        // Model (priority order handled by first-wins)
                                        "md" | "model" | "am" | "mdl" | "modelid" | "usb_MDL"
                                        | "mn" => {
                                            if mdns_model.is_none() {
                                                mdns_model = Some(val.to_string());
                                            }
                                        }
                                        // Printer type string (very descriptive)
                                        "ty" | "product" => {
                                            if mdns_model.is_none() {
                                                let cleaned =
                                                    val.trim_matches(|c| c == '(' || c == ')');
                                                mdns_model = Some(cleaned.to_string());
                                            }
                                        }
                                        // Friendly name
                                        "fn" | "n" | "friendly_name" | "name" => {
                                            mdns_device_name = Some(val.to_string());
                                        }
                                        // Firmware / software version
                                        "fv" | "srcvers" | "vs" | "vers" | "swversion"
                                        | "version" => {
                                            if mdns_firmware.is_none() {
                                                mdns_firmware = Some(val.to_string());
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }

                        // Infer vendor from service type when TXT doesn't have it
                        if mdns_vendor.is_none() {
                            for svc in &service_types {
                                if svc.contains("_googlecast.") {
                                    mdns_vendor = Some("Google".into());
                                    break;
                                }
                                if svc.contains("_sonos.") {
                                    mdns_vendor = Some("Sonos".into());
                                    break;
                                }
                                if svc.contains("_hue.") {
                                    mdns_vendor = Some("Philips".into());
                                    break;
                                }
                                if svc.contains("_samsungtv.") {
                                    mdns_vendor = Some("Samsung".into());
                                    break;
                                }
                                if svc.contains("_amzn-wplay.") {
                                    mdns_vendor = Some("Amazon".into());
                                    break;
                                }
                            }
                        }

                        // Emit enriched observation with vendor/model/firmware if found
                        if mdns_vendor.is_some()
                            || mdns_model.is_some()
                            || mdns_device_name.is_some()
                            || mdns_firmware.is_some()
                        {
                            let mut identifiers = BTreeMap::new();
                            identifiers.insert("ip".to_string(), src_ip.clone());
                            if let Some(ref name) = mdns_device_name {
                                identifiers.insert("device_name".to_string(), name.clone());
                            }
                            // Use device name as hostname if we have one
                            let hostnames = mdns_device_name
                                .as_ref()
                                .map(|n| vec![n.clone()])
                                .unwrap_or_default();
                            out.push(new_event(
                                chunk.capture_id.to_string(),
                                envelope.clone(),
                                BronzeEventFamily::AssetObservation(AssetObservation {
                                    asset_key: src_ip.clone(),
                                    role: None,
                                    vendor: mdns_vendor,
                                    model: mdns_model,
                                    firmware: mdns_firmware,
                                    hostnames,
                                    protocols: vec!["mdns".to_string()],
                                    identifiers,
                                }),
                            ));
                        }

                        // Reverse PTR records (in-addr.arpa)
                        for rec in &records {
                            if rec.name.ends_with(".in-addr.arpa") {
                                if let DnsRecordData::Ptr(ptr_name) = &rec.data {
                                    let octets: Vec<&str> = rec
                                        .name
                                        .trim_end_matches(".in-addr.arpa")
                                        .split('.')
                                        .collect();
                                    if octets.len() == 4 {
                                        let reversed_ip = format!(
                                            "{}.{}.{}.{}",
                                            octets[3], octets[2], octets[1], octets[0]
                                        );
                                        out.push(new_event(
                                            chunk.capture_id.to_string(),
                                            envelope.clone(),
                                            BronzeEventFamily::AssetObservation(AssetObservation {
                                                asset_key: reversed_ip.clone(),
                                                role: None,
                                                vendor: None,
                                                model: None,
                                                firmware: None,
                                                hostnames: vec![ptr_name.clone()],
                                                protocols: vec!["mdns".to_string()],
                                                identifiers: BTreeMap::from([(
                                                    "ip".to_string(),
                                                    reversed_ip,
                                                )]),
                                            }),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    chunk.transport,
                    Some("dns"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse dns payload",
                payload,
            )),
        }
    }
}

#[derive(Default)]
struct DhcpDecoder {
    dissector: DhcpDissector,
}

impl SessionDecoder for DhcpDecoder {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(67), DecoderInterest::UdpPort(68)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Dhcp(DhcpFields {
                op,
                xid,
                client_mac,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                message_type,
                hostname,
                client_id,
                vendor_class,
                requested_ip,
                server_id,
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("dhcp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let operation = dhcp_message_type_name(message_type);
                let mut attributes = BTreeMap::new();
                attributes.insert("xid".to_string(), format!("{xid:#010x}"));
                attributes.insert("bootp_op".to_string(), op.to_string());
                if let Some(ip) = requested_ip.clone() {
                    attributes.insert("requested_ip".to_string(), ip);
                }
                if let Some(ip) = yiaddr.clone() {
                    attributes.insert("your_ip".to_string(), ip);
                }
                if let Some(ip) = server_id.clone() {
                    attributes.insert("server_id".to_string(), ip);
                }
                if let Some(ip) = giaddr.clone() {
                    attributes.insert("relay_ip".to_string(), ip);
                }
                if let Some(vendor_class) = vendor_class.clone() {
                    attributes.insert("vendor_class".to_string(), vendor_class);
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: operation.to_string(),
                        status: dhcp_status(&chunk.context).to_string(),
                        request_summary: hostname.as_ref().map(|name| format!("{name} via DHCP")),
                        response_summary: yiaddr.clone(),
                        object_refs: requested_ip
                            .clone()
                            .or_else(|| yiaddr.clone())
                            .into_iter()
                            .collect(),
                        values: Vec::new(),
                        attributes,
                    }),
                ));

                let mut identifiers =
                    BTreeMap::from([("mac".to_string(), format_mac(&client_mac))]);
                if let Some(ip) = yiaddr.clone().or(ciaddr.clone()).or(requested_ip.clone()) {
                    identifiers.insert("ip".to_string(), ip);
                }
                if let Some(client_id) = client_id.clone() {
                    identifiers.insert("client_id".to_string(), client_id);
                }
                if let Some(vendor_class) = vendor_class.clone() {
                    identifiers.insert("vendor_class".to_string(), vendor_class);
                }
                let hostnames = hostname.clone().into_iter().collect();
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::AssetObservation(AssetObservation {
                        asset_key: format_mac(&client_mac),
                        role: None,
                        vendor: None,
                        model: None,
                        firmware: None,
                        hostnames,
                        protocols: vec!["dhcp".to_string()],
                        identifiers,
                    }),
                ));

                if let Some(server_ip) = server_id.clone().or(siaddr.clone()) {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: server_ip.clone(),
                            role: Some("server".to_string()),
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: Vec::new(),
                            protocols: vec!["dhcp".to_string()],
                            identifiers: BTreeMap::from([("ip".to_string(), server_ip)]),
                        }),
                    ));
                }

                if server_id.is_some() || giaddr.is_some() {
                    let mut metadata = BTreeMap::new();
                    if let Some(ip) = yiaddr.or(requested_ip) {
                        metadata.insert("lease_ip".to_string(), ip);
                    }
                    if let Some(ip) = giaddr.clone() {
                        metadata.insert("relay_ip".to_string(), ip);
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::TopologyObservation(TopologyObservation {
                            observation_type: "dhcp_lease".to_string(),
                            local_id: format_mac(&client_mac),
                            remote_id: server_id.or(giaddr),
                            description: Some(operation.to_string()),
                            capabilities: Vec::new(),
                            metadata,
                        }),
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("dhcp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse dhcp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct SnmpDecoder {
    dissector: SnmpDissector,
}

impl SessionDecoder for SnmpDecoder {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(161), DecoderInterest::UdpPort(162)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Snmp(SnmpFields {
                version,
                pdu_type,
                request_id,
                var_binds,
                sys_name,
                sys_descr,
                sys_object_id,
                engine_id,
                ..
            })) => {
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("snmp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::from([("version".to_string(), version.clone())]);
                if let Some(id) = request_id {
                    attributes.insert("request_id".to_string(), id.to_string());
                }
                if let Some(engine_id) = engine_id.clone() {
                    attributes.insert("engine_id".to_string(), engine_id);
                }
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: normalize_operation_name(&pdu_type, "snmp_message"),
                        status: snmp_status(&pdu_type),
                        request_summary: (!var_binds.is_empty()).then(|| {
                            var_binds
                                .iter()
                                .map(|vb| vb.oid.clone())
                                .collect::<Vec<_>>()
                                .join(", ")
                        }),
                        response_summary: sys_name.clone().or(sys_descr.clone()),
                        object_refs: var_binds.iter().map(|vb| vb.oid.clone()).collect(),
                        values: var_binds
                            .iter()
                            .map(|vb| ObjectValue {
                                object_ref: vb.oid.clone(),
                                value: vb.value.clone(),
                            })
                            .collect(),
                        attributes,
                    }),
                ));

                if sys_name.is_some()
                    || sys_descr.is_some()
                    || sys_object_id.is_some()
                    || engine_id.is_some()
                {
                    let asset_ip = if chunk.context.src_port == 161 || chunk.context.src_port == 162
                    {
                        chunk.context.src_ip.to_string()
                    } else {
                        chunk.context.dst_ip.to_string()
                    };
                    let mut identifiers = BTreeMap::from([("ip".to_string(), asset_ip.clone())]);
                    if let Some(object_id) = sys_object_id.clone() {
                        identifiers.insert("sys_object_id".to_string(), object_id);
                    }
                    if let Some(engine_id) = engine_id {
                        identifiers.insert("engine_id".to_string(), engine_id);
                    }
                    if let Some(sys_descr) = sys_descr.clone() {
                        identifiers.insert("sys_descr".to_string(), sys_descr);
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key: asset_ip,
                            role: None,
                            vendor: None,
                            model: None,
                            firmware: None,
                            hostnames: sys_name.into_iter().collect(),
                            protocols: vec!["snmp".to_string()],
                            identifiers,
                        }),
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("snmp"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse snmp payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct HttpDecoder {
    dissector: HttpDissector,
}

impl SessionDecoder for HttpDecoder {
    fn name(&self) -> &'static str {
        "http"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(80), DecoderInterest::TcpPort(8080)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        if chunk.payload.is_empty() {
            return;
        }
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Http(HttpFields {
                method,
                host,
                uri,
                status_code,
                content_type,
                content_length,
            })) => {
                let mut attributes = BTreeMap::new();
                attributes.insert("content_type".to_string(), content_type);
                attributes.insert("content_length".to_string(), content_length.to_string());
                if !host.is_empty() {
                    attributes.insert("host".to_string(), host);
                }
                let is_request = !method.is_empty();
                let operation = if is_request {
                    method.clone()
                } else {
                    "response".to_string()
                };
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        TransportProtocol::Tcp,
                        Some("http"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    ),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status: if status_code > 0 {
                            status_code.to_string()
                        } else {
                            "request".to_string()
                        },
                        request_summary: is_request.then_some(uri.clone()),
                        response_summary: (status_code > 0).then_some(status_code.to_string()),
                        object_refs: (!uri.is_empty()).then_some(uri).into_iter().collect(),
                        values: Vec::new(),
                        attributes,
                    }),
                ));
            }
            _ => {}
        }
    }
}

struct TlsDecoder;

impl SessionDecoder for TlsDecoder {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[
            DecoderInterest::TcpPort(443),
            DecoderInterest::TcpPort(4840),
        ]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        let Some(tls) = parse_tls_client_hello(chunk.payload) else {
            return;
        };
        let mut attributes = BTreeMap::new();
        attributes.insert("version".to_string(), tls.version.clone());
        if let Some(ref cipher) = tls.cipher_suite {
            attributes.insert("cipher_suite".to_string(), cipher.clone());
        }
        let envelope = build_envelope(
            &chunk.context,
            chunk.interface_id,
            chunk.frame_index,
            chunk.timestamp,
            chunk.segment_hash,
            TransportProtocol::Tcp,
            Some("tls"),
            chunk.captured_len,
            chunk.session_key.clone(),
        );
        out.push(new_event(
            chunk.capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                operation: "client_hello".to_string(),
                status: "observed".to_string(),
                request_summary: tls.sni.clone(),
                response_summary: None,
                object_refs: tls.sni.clone().into_iter().collect(),
                values: Vec::new(),
                attributes,
            }),
        ));
        if let Some(sni) = tls.sni {
            out.push(new_event(
                chunk.capture_id.to_string(),
                envelope,
                BronzeEventFamily::AssetObservation(AssetObservation {
                    asset_key: chunk.context.dst_ip.to_string(),
                    role: None,
                    vendor: None,
                    model: None,
                    firmware: None,
                    hostnames: vec![sni],
                    protocols: vec!["tls".to_string()],
                    identifiers: BTreeMap::from([(
                        "ip".to_string(),
                        chunk.context.dst_ip.to_string(),
                    )]),
                }),
            ));
        }
    }
}

#[derive(Default)]
struct Dnp3DecoderWrapper {
    dissector: Dnp3Dissector,
}

impl SessionDecoder for Dnp3DecoderWrapper {
    fn name(&self) -> &'static str {
        "dnp3"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(20000)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Dnp3(Dnp3Fields {
                source_address,
                destination_address,
                function_code,
                application_data,
            })) => {
                let operation = dnp3_function_name(function_code);
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("dnp3"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let mut attributes = BTreeMap::new();
                attributes.insert("source_address".to_string(), source_address.to_string());
                attributes.insert(
                    "destination_address".to_string(),
                    destination_address.to_string(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: operation.to_string(),
                        status: if function_code >= 0x80 {
                            "response".to_string()
                        } else {
                            "request".to_string()
                        },
                        request_summary: Some(format!(
                            "{operation} {source_address}->{destination_address}"
                        )),
                        response_summary: None,
                        object_refs: vec![format!("dnp3_fc:{function_code:#04x}")],
                        values: Vec::new(),
                        attributes,
                    }),
                ));
                for event in dnp3_role_observations(
                    chunk.capture_id,
                    &envelope,
                    &chunk.context,
                    source_address,
                    destination_address,
                    function_code,
                ) {
                    out.push(event);
                }
                if is_dnp3_artifact(function_code) && !application_data.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "dnp3_application_data",
                        &format!("{}:{function_code:#04x}", chunk.session_key),
                        Some("application/octet-stream"),
                        Some("DNP3 application payload"),
                        &application_data,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("dnp3"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse dnp3 payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Default)]
struct EthernetIpDecoderWrapper {
    dissector: EthernetIpDissector,
}

impl SessionDecoder for EthernetIpDecoderWrapper {
    fn name(&self) -> &'static str {
        "ethernet_ip"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(44818)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::EthernetIp(EthernetIpFields {
                command,
                session_handle,
                cip_data,
            })) => {
                let command_name = ethernet_ip_command_name(command);
                let mut attributes = BTreeMap::new();
                attributes.insert("session_handle".to_string(), session_handle.to_string());
                attributes.insert(
                    "encapsulation_command".to_string(),
                    format!("{command:#06x}"),
                );
                if let Some(service) = cip_service_name(&cip_data) {
                    attributes.insert("cip_service".to_string(), service.to_string());
                }
                if let Some(identity) = parse_cip_identity_claim(command, &cip_data) {
                    attributes.insert("cip_vendor_id".to_string(), identity.vendor_id.to_string());
                    attributes.insert(
                        "cip_product_code".to_string(),
                        identity.product_code.to_string(),
                    );
                    attributes.insert(
                        "cip_serial_number".to_string(),
                        identity.serial_number.to_string(),
                    );
                    attributes.insert("cip_revision".to_string(), identity.revision.clone());
                }
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ethernet_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: command_name.to_string(),
                        status: if chunk.context.dst_port == 44818 {
                            "request".to_string()
                        } else {
                            "response".to_string()
                        },
                        request_summary: Some(format!("{command_name} session={session_handle}")),
                        response_summary: None,
                        object_refs: cip_object_refs(&cip_data),
                        values: Vec::new(),
                        attributes,
                    }),
                ));
                for identity in parse_cip_identity_claims(command, &cip_data) {
                    let asset_key = identity
                        .ip_address
                        .clone()
                        .unwrap_or_else(|| chunk.context.src_ip.to_string());
                    let mut identifiers = BTreeMap::from([
                        ("ip".to_string(), asset_key.clone()),
                        ("cip_vendor_id".to_string(), identity.vendor_id.to_string()),
                        (
                            "cip_device_type".to_string(),
                            identity.device_type.to_string(),
                        ),
                        (
                            "cip_product_code".to_string(),
                            identity.product_code.to_string(),
                        ),
                        (
                            "cip_serial_number".to_string(),
                            identity.serial_number.to_string(),
                        ),
                    ]);
                    identifiers.insert("cip_revision".to_string(), identity.revision.clone());
                    identifiers.insert("cip_status".to_string(), identity.status.to_string());
                    if let Some(state) = identity.state {
                        identifiers.insert("cip_state".to_string(), state.to_string());
                    }
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope.clone(),
                        BronzeEventFamily::AssetObservation(AssetObservation {
                            asset_key,
                            role: cip_role_from_device_type(identity.device_type)
                                .map(str::to_string),
                            vendor: cip_vendor_name(identity.vendor_id).map(str::to_string),
                            model: Some(identity.product_name.clone()),
                            firmware: Some(identity.revision.clone()),
                            hostnames: Vec::new(),
                            protocols: vec!["ethernet_ip".to_string(), "cip".to_string()],
                            identifiers,
                        }),
                    ));
                }
                if matches!(command, 0x006F | 0x0070) && !cip_data.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "cip_payload",
                        &format!("{session_handle}:{}", chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("EtherNet/IP CIP payload"),
                        &cip_data,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("ethernet_ip"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse ethernet/ip payload",
                chunk.payload,
            )),
        }
    }
}

struct OpcUaDecoderWrapper {
    dissector: OpcUaDissector,
}

impl Default for OpcUaDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: OpcUaDissector,
        }
    }
}

impl SessionDecoder for OpcUaDecoderWrapper {
    fn name(&self) -> &'static str {
        "opc_ua"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(4840)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::OpcUa(OpcUaFields {
                message_type,
                request_id,
                service_type,
            })) => {
                let mut attributes = BTreeMap::new();
                attributes.insert("message_type".to_string(), message_type.clone());
                attributes.insert("service_type".to_string(), service_type.clone());
                if request_id != 0 {
                    attributes.insert("request_id".to_string(), request_id.to_string());
                }

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    build_envelope(
                        &chunk.context,
                        chunk.interface_id,
                        chunk.frame_index,
                        chunk.timestamp,
                        chunk.segment_hash,
                        TransportProtocol::Tcp,
                        Some("opc_ua"),
                        chunk.captured_len,
                        chunk.session_key.clone(),
                    ),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: opc_ua_operation_name(&service_type),
                        status: if service_type.starts_with("Error") {
                            "error".to_string()
                        } else if chunk.context.dst_port == 4840 {
                            "request".to_string()
                        } else {
                            "response".to_string()
                        },
                        request_summary: Some(format!("{message_type} {service_type}")),
                        response_summary: None,
                        object_refs: if request_id == 0 {
                            vec![format!("opcua_message:{message_type}")]
                        } else {
                            vec![format!("opcua_request:{request_id}")]
                        },
                        values: Vec::new(),
                        attributes,
                    }),
                ));
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("opc_ua"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse opc ua payload",
                chunk.payload,
            )),
        }
    }
}

struct S7commDecoderWrapper {
    dissector: S7commDissector,
}

impl Default for S7commDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: S7commDissector,
        }
    }
}

impl SessionDecoder for S7commDecoderWrapper {
    fn name(&self) -> &'static str {
        "s7comm"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(102)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::S7comm(S7commFields {
                rosctr,
                function,
                parameter,
                data,
            })) => {
                let operation = s7comm_function_name(function).to_string();
                let mut attributes = BTreeMap::new();
                attributes.insert("rosctr".to_string(), format!("{rosctr:#04x}"));
                attributes.insert(
                    "rosctr_name".to_string(),
                    s7comm_rosctr_name(rosctr).to_string(),
                );
                attributes.insert("function".to_string(), format!("{function:#04x}"));
                attributes.insert("parameter_length".to_string(), parameter.len().to_string());
                attributes.insert("data_length".to_string(), data.len().to_string());

                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("s7comm"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation,
                        status: s7comm_status(rosctr, &chunk.context).to_string(),
                        request_summary: Some(format!(
                            "{} {}",
                            s7comm_rosctr_name(rosctr),
                            s7comm_function_name(function)
                        )),
                        response_summary: None,
                        object_refs: vec![
                            format!("s7_function:{function:#04x}"),
                            format!("s7_rosctr:{rosctr:#04x}"),
                        ],
                        values: Vec::new(),
                        attributes,
                    }),
                ));

                if !data.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "s7comm_data",
                        &format!("{}:{function:#04x}", chunk.session_key),
                        Some("application/octet-stream"),
                        Some("S7comm data payload"),
                        &data,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("s7comm"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse s7comm payload",
                chunk.payload,
            )),
        }
    }
}

struct ProfinetDecoderWrapper {
    dissector: ProfinetDissector,
}

impl Default for ProfinetDecoderWrapper {
    fn default() -> Self {
        Self {
            dissector: ProfinetDissector,
        }
    }
}

impl SessionDecoder for ProfinetDecoderWrapper {
    fn name(&self) -> &'static str {
        "profinet"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::UdpPort(34964)]
    }

    fn on_datagram(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Profinet(ProfinetFields {
                frame_id,
                service_type,
                payload,
            })) => {
                let mut attributes = BTreeMap::new();
                attributes.insert("frame_id".to_string(), format!("{frame_id:#06x}"));
                attributes.insert("service_type".to_string(), service_type.clone());
                attributes.insert("payload_length".to_string(), payload.len().to_string());

                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("profinet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );

                out.push(new_event(
                    chunk.capture_id.to_string(),
                    envelope.clone(),
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: profinet_operation_name(&service_type),
                        status: if service_type.contains("Response") {
                            "response".to_string()
                        } else if service_type.contains("Request")
                            || chunk.context.dst_port == 34964
                        {
                            "request".to_string()
                        } else {
                            "observed".to_string()
                        },
                        request_summary: Some(format!("{service_type} frame={frame_id:#06x}")),
                        response_summary: None,
                        object_refs: vec![format!("profinet_frame:{frame_id:#06x}")],
                        values: Vec::new(),
                        attributes,
                    }),
                ));

                if !payload.is_empty() {
                    out.push(artifact_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        "profinet_payload",
                        &format!("{frame_id:#06x}:{}", chunk.frame_index),
                        Some("application/octet-stream"),
                        Some("PROFINET payload"),
                        &payload,
                    ));
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Udp,
                    Some("profinet"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse profinet payload",
                chunk.payload,
            )),
        }
    }
}

#[derive(Clone)]
struct PendingModbus {
    capture_id: String,
    envelope: EventEnvelope,
    transaction_id: u16,
    unit_id: u8,
    operation: String,
    request_summary: String,
    object_refs: Vec<String>,
    values: Vec<ObjectValue>,
    attributes: BTreeMap<String, String>,
    raw_payload: Vec<u8>,
    last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct CipIdentityClaim {
    vendor_id: u16,
    device_type: u16,
    product_code: u16,
    revision: String,
    serial_number: u32,
    product_name: String,
    status: u16,
    state: Option<u8>,
    ip_address: Option<String>,
}

#[derive(Default)]
struct ModbusDecoder {
    dissector: ModbusDissector,
    pending: HashMap<String, PendingModbus>,
}

impl SessionDecoder for ModbusDecoder {
    fn name(&self) -> &'static str {
        "modbus"
    }

    fn interest(&self) -> &'static [DecoderInterest] {
        &[DecoderInterest::TcpPort(502)]
    }

    fn on_stream_chunk(&mut self, chunk: &StreamChunk<'_>, out: &mut Vec<BronzeEvent>) {
        match self.dissector.parse(chunk.payload, &chunk.context) {
            Some(ProtocolData::Modbus(fields)) => {
                let operation = modbus_function_name(fields.function_code).to_string();
                let is_request = chunk.context.dst_port == 502 && chunk.context.src_port != 502;
                let envelope = build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("modbus"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                );
                let key = format!(
                    "{}:{}:{}",
                    chunk.session_key, fields.transaction_id, fields.unit_id
                );
                if is_request {
                    self.pending.insert(
                        key,
                        PendingModbus {
                            capture_id: chunk.capture_id.to_string(),
                            envelope,
                            transaction_id: fields.transaction_id,
                            unit_id: fields.unit_id,
                            operation: operation.clone(),
                            request_summary: modbus_summary(&fields),
                            object_refs: modbus_object_refs(&fields),
                            values: modbus_values(&fields),
                            attributes: modbus_attributes(&fields),
                            raw_payload: chunk.payload.to_vec(),
                            last_seen: chunk.timestamp,
                        },
                    );
                } else if let Some(pending) = self.pending.remove(&key) {
                    let mut values = pending.values.clone();
                    values.extend(modbus_values(&fields));
                    let mut attributes = pending.attributes.clone();
                    attributes.extend(modbus_attributes(&fields));
                    let mut merged_envelope = pending.envelope.clone();
                    merged_envelope.bytes_count += envelope.bytes_count;
                    merged_envelope.packet_count += 1;

                    out.push(new_event(
                        pending.capture_id.clone(),
                        merged_envelope.clone(),
                        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                            operation: pending.operation.clone(),
                            status: if fields.is_exception {
                                format!("exception:{}", fields.exception_code)
                            } else {
                                "ok".to_string()
                            },
                            request_summary: Some(pending.request_summary),
                            response_summary: Some(modbus_summary(&fields)),
                            object_refs: pending.object_refs.clone(),
                            values,
                            attributes,
                        }),
                    ));
                    if !fields.device_identification.is_empty() {
                        out.push(modbus_identity_observation(
                            pending.capture_id.clone(),
                            merged_envelope.clone(),
                            chunk.context.src_ip.to_string(),
                            fields.unit_id,
                            &fields.device_identification,
                        ));
                    }
                    if is_modbus_write(fields.function_code) {
                        out.push(artifact_event(
                            pending.capture_id,
                            merged_envelope,
                            "modbus_write_payload",
                            &format!(
                                "{}:{}:{}",
                                chunk.session_key, fields.transaction_id, fields.unit_id
                            ),
                            Some("application/octet-stream"),
                            Some("Modbus write request payload"),
                            &pending.raw_payload,
                        ));
                    }
                } else {
                    out.push(new_event(
                        chunk.capture_id.to_string(),
                        envelope,
                        BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                            operation,
                            status: "response_without_request".to_string(),
                            request_summary: None,
                            response_summary: Some(modbus_summary(&fields)),
                            object_refs: modbus_object_refs(&fields),
                            values: modbus_values(&fields),
                            attributes: modbus_attributes(&fields),
                        }),
                    ));
                    if !fields.device_identification.is_empty() {
                        out.push(modbus_identity_observation(
                            chunk.capture_id.to_string(),
                            build_envelope(
                                &chunk.context,
                                chunk.interface_id,
                                chunk.frame_index,
                                chunk.timestamp,
                                chunk.segment_hash,
                                TransportProtocol::Tcp,
                                Some("modbus"),
                                chunk.captured_len,
                                chunk.session_key.clone(),
                            ),
                            chunk.context.src_ip.to_string(),
                            fields.unit_id,
                            &fields.device_identification,
                        ));
                    }
                }
            }
            _ => out.push(parse_anomaly_event(
                chunk.capture_id.to_string(),
                build_envelope(
                    &chunk.context,
                    chunk.interface_id,
                    chunk.frame_index,
                    chunk.timestamp,
                    chunk.segment_hash,
                    TransportProtocol::Tcp,
                    Some("modbus"),
                    chunk.captured_len,
                    chunk.session_key.clone(),
                ),
                self.name(),
                "medium",
                "failed to parse modbus payload",
                chunk.payload,
            )),
        }
    }

    fn on_idle_flush(&mut self, timestamp: DateTime<Utc>, out: &mut Vec<BronzeEvent>) {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter_map(|(key, pending)| {
                if (timestamp - pending.last_seen).num_seconds() >= 0 {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        for key in expired {
            if let Some(pending) = self.pending.remove(&key) {
                out.push(new_event(
                    pending.capture_id,
                    pending.envelope,
                    BronzeEventFamily::ProtocolTransaction(ProtocolTransaction {
                        operation: pending.operation,
                        status: "partial_request".to_string(),
                        request_summary: Some(pending.request_summary),
                        response_summary: None,
                        object_refs: pending.object_refs,
                        values: pending.values,
                        attributes: pending.attributes,
                    }),
                ));
            }
        }
    }
}

fn dns_payload<'a>(chunk: &'a StreamChunk<'_>) -> &'a [u8] {
    if chunk.transport == TransportProtocol::Tcp && chunk.payload.len() > 2 {
        let advertised = u16::from_be_bytes([chunk.payload[0], chunk.payload[1]]) as usize;
        if advertised + 2 <= chunk.payload.len() {
            return &chunk.payload[2..2 + advertised];
        }
    }
    chunk.payload
}

fn dns_hostname_from_query(query: &str) -> String {
    query.split_whitespace().next().unwrap_or(query).to_string()
}

fn dns_ip_from_answer(answer: &str) -> Option<String> {
    let candidate = answer.split_whitespace().last()?;
    candidate
        .parse::<IpAddr>()
        .ok()
        .map(|_| candidate.to_string())
}

fn dhcp_message_type_name(message_type: Option<u8>) -> &'static str {
    match message_type {
        Some(1) => "discover",
        Some(2) => "offer",
        Some(3) => "request",
        Some(4) => "decline",
        Some(5) => "ack",
        Some(6) => "nak",
        Some(7) => "release",
        Some(8) => "inform",
        _ => "bootp",
    }
}

fn dhcp_status(context: &PacketContext) -> &'static str {
    if context.dst_port == 67 {
        "request"
    } else if context.src_port == 67 {
        "response"
    } else {
        "observed"
    }
}

fn snmp_status(pdu_type: &str) -> String {
    if pdu_type.contains("response") {
        "response".to_string()
    } else if pdu_type.contains("trap") || pdu_type.contains("inform") || pdu_type == "report" {
        "observed".to_string()
    } else {
        "request".to_string()
    }
}

fn dnp3_function_name(code: u8) -> &'static str {
    match code {
        0x01 => "read",
        0x02 => "write",
        0x03 => "select",
        0x04 => "operate",
        0x05 => "direct_operate",
        0x06 => "direct_operate_no_ack",
        0x81 => "response",
        0x82 => "unsolicited_response",
        _ => "dnp3_message",
    }
}

fn is_dnp3_artifact(code: u8) -> bool {
    matches!(code, 0x02 | 0x03 | 0x04 | 0x05 | 0x06)
}

fn dnp3_role_observations(
    capture_id: &str,
    envelope: &EventEnvelope,
    context: &PacketContext,
    source_address: u16,
    destination_address: u16,
    function_code: u8,
) -> Vec<BronzeEvent> {
    let (src_role, dst_role, observation_type) =
        if function_code >= 0x80 || context.src_port == 20000 {
            ("outstation", "master", "dnp3_response")
        } else {
            ("master", "outstation", "dnp3_request")
        };

    vec![
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.src_ip.to_string(),
                role: Some(src_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["dnp3".to_string()],
                identifiers: BTreeMap::from([
                    ("ip".to_string(), context.src_ip.to_string()),
                    ("dnp3_address".to_string(), source_address.to_string()),
                ]),
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::AssetObservation(AssetObservation {
                asset_key: context.dst_ip.to_string(),
                role: Some(dst_role.to_string()),
                vendor: None,
                model: None,
                firmware: None,
                hostnames: Vec::new(),
                protocols: vec!["dnp3".to_string()],
                identifiers: BTreeMap::from([
                    ("ip".to_string(), context.dst_ip.to_string()),
                    ("dnp3_address".to_string(), destination_address.to_string()),
                ]),
            }),
        ),
        new_event(
            capture_id.to_string(),
            envelope.clone(),
            BronzeEventFamily::TopologyObservation(TopologyObservation {
                observation_type: observation_type.to_string(),
                local_id: source_address.to_string(),
                remote_id: Some(destination_address.to_string()),
                description: Some(dnp3_function_name(function_code).to_string()),
                capabilities: Vec::new(),
                metadata: BTreeMap::from([
                    ("src_ip".to_string(), context.src_ip.to_string()),
                    ("dst_ip".to_string(), context.dst_ip.to_string()),
                ]),
            }),
        ),
    ]
}

fn opc_ua_operation_name(service_type: &str) -> String {
    normalize_operation_name(service_type, "opc_ua_message")
}

fn s7comm_rosctr_name(code: u8) -> &'static str {
    match code {
        0x01 => "job",
        0x02 => "ack",
        0x03 => "ack_data",
        0x07 => "userdata",
        _ => "unknown",
    }
}

fn s7comm_function_name(code: u8) -> &'static str {
    match code {
        0x00 => "cpu_services",
        0x04 => "read_var",
        0x05 => "write_var",
        0x1A => "request_download",
        0x1B => "download_block",
        0x1C => "download_ended",
        0x1D => "start_upload",
        0x1E => "upload",
        0x1F => "end_upload",
        0x28 => "pi_service",
        0x29 => "plc_stop",
        0xF0 => "setup_communication",
        _ => "s7comm_message",
    }
}

fn s7comm_status(rosctr: u8, context: &PacketContext) -> &'static str {
    match rosctr {
        0x02 | 0x03 => "response",
        0x01 if context.dst_port == 102 => "request",
        0x01 => "observed",
        _ => "observed",
    }
}

fn profinet_operation_name(service_type: &str) -> String {
    normalize_operation_name(service_type, "profinet_frame")
}

fn normalize_operation_name(label: &str, fallback: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = true;

    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }

    while normalized.ends_with('_') {
        normalized.pop();
    }

    if normalized.is_empty() {
        fallback.to_string()
    } else {
        normalized
    }
}

fn ethernet_ip_command_name(command: u16) -> &'static str {
    match command {
        0x0001 => "nop",
        0x0004 => "list_services",
        0x0063 => "list_identity",
        0x0064 => "list_interfaces",
        0x0065 => "register_session",
        0x0066 => "unregister_session",
        0x006F => "send_rr_data",
        0x0070 => "send_unit_data",
        _ => "encapsulation_command",
    }
}

fn cip_service_name(cip_data: &[u8]) -> Option<&'static str> {
    let service = cip_explicit_message(cip_data)
        .and_then(|message| message.first().copied())
        .or_else(|| cip_data.iter().find(|byte| **byte != 0).copied())?;
    match service & 0x7F {
        0x01 => Some("get_attributes_all"),
        0x4C => Some("read_tag_service"),
        0x4D => Some("write_tag_service"),
        0x0E => Some("get_attribute_single"),
        0x10 => Some("set_attribute_single"),
        0x54 => Some("forward_open"),
        0x52 => Some("unconnected_send"),
        _ => None,
    }
}

fn cip_object_refs(cip_data: &[u8]) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(service) = cip_service_name(cip_data) {
        refs.push(format!("cip_service:{service}"));
    }
    if parse_cip_identity_response(cip_data).is_some() {
        refs.push("cip_object:identity".to_string());
    }
    refs
}

fn parse_cip_identity_claim(command: u16, cip_data: &[u8]) -> Option<CipIdentityClaim> {
    parse_cip_identity_claims(command, cip_data)
        .into_iter()
        .next()
}

fn parse_cip_identity_claims(command: u16, cip_data: &[u8]) -> Vec<CipIdentityClaim> {
    match command {
        0x0063 => parse_enip_list_identity(cip_data),
        0x006F | 0x0070 => parse_cip_identity_response(cip_data).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn parse_enip_list_identity(data: &[u8]) -> Vec<CipIdentityClaim> {
    if data.len() < 2 {
        return Vec::new();
    }
    let item_count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;
    let mut claims = Vec::new();
    for _ in 0..item_count {
        if offset + 4 > data.len() {
            break;
        }
        let item_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let item_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > data.len() {
            break;
        }
        let item = &data[offset..offset + item_len];
        if item_type == 0x000C {
            if let Some(claim) = parse_list_identity_item(item) {
                claims.push(claim);
            }
        }
        offset += item_len;
    }
    claims
}

fn parse_list_identity_item(item: &[u8]) -> Option<CipIdentityClaim> {
    if item.len() < 34 {
        return None;
    }
    let vendor_id = u16::from_le_bytes([item[18], item[19]]);
    let device_type = u16::from_le_bytes([item[20], item[21]]);
    let product_code = u16::from_le_bytes([item[22], item[23]]);
    let revision = format!("{}.{}", item[24], item[25]);
    let status = u16::from_le_bytes([item[26], item[27]]);
    let serial_number = u32::from_le_bytes([item[28], item[29], item[30], item[31]]);
    let name_len = item[32] as usize;
    if 33 + name_len > item.len() {
        return None;
    }
    let product_name = String::from_utf8_lossy(&item[33..33 + name_len]).to_string();
    let state = item.get(33 + name_len).copied();
    let ip_address = if item.len() >= 10 {
        Some(format!("{}.{}.{}.{}", item[6], item[7], item[8], item[9]))
    } else {
        None
    };
    Some(CipIdentityClaim {
        vendor_id,
        device_type,
        product_code,
        revision,
        serial_number,
        product_name,
        status,
        state,
        ip_address,
    })
}

fn parse_cip_identity_response(cip_data: &[u8]) -> Option<CipIdentityClaim> {
    let message = cip_explicit_message(cip_data)?;
    if message.len() < 4 || message[0] != 0x81 || message[2] != 0 {
        return None;
    }
    let additional_status_words = message[3] as usize;
    let data_offset = 4 + additional_status_words * 2;
    if data_offset + 15 > message.len() {
        return None;
    }
    let body = &message[data_offset..];
    let vendor_id = u16::from_le_bytes([body[0], body[1]]);
    let device_type = u16::from_le_bytes([body[2], body[3]]);
    let product_code = u16::from_le_bytes([body[4], body[5]]);
    let revision = format!("{}.{}", body[6], body[7]);
    let status = u16::from_le_bytes([body[8], body[9]]);
    let serial_number = u32::from_le_bytes([body[10], body[11], body[12], body[13]]);
    let name_len = body[14] as usize;
    if 15 + name_len > body.len() {
        return None;
    }
    let product_name = String::from_utf8_lossy(&body[15..15 + name_len]).to_string();
    let state = body.get(15 + name_len).copied();
    Some(CipIdentityClaim {
        vendor_id,
        device_type,
        product_code,
        revision,
        serial_number,
        product_name,
        status,
        state,
        ip_address: None,
    })
}

fn cip_explicit_message(cip_data: &[u8]) -> Option<&[u8]> {
    if cip_data.len() < 8 {
        return None;
    }
    let item_count = u16::from_le_bytes([cip_data[6], cip_data[7]]) as usize;
    let mut offset = 8;
    for _ in 0..item_count {
        if offset + 4 > cip_data.len() {
            return None;
        }
        let item_type = u16::from_le_bytes([cip_data[offset], cip_data[offset + 1]]);
        let item_len = u16::from_le_bytes([cip_data[offset + 2], cip_data[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > cip_data.len() {
            return None;
        }
        let item = &cip_data[offset..offset + item_len];
        if matches!(item_type, 0x00B1 | 0x00B2) {
            return Some(item);
        }
        offset += item_len;
    }
    None
}

fn cip_vendor_name(vendor_id: u16) -> Option<&'static str> {
    match vendor_id {
        1 => Some("Rockwell Automation/Allen-Bradley"),
        _ => None,
    }
}

fn cip_role_from_device_type(device_type: u16) -> Option<&'static str> {
    match device_type {
        0x000E => Some("plc"),
        0x000C => Some("adapter"),
        _ => None,
    }
}

fn modbus_function_name(code: u8) -> &'static str {
    match code {
        1 => "read_coils",
        3 => "read_holding_registers",
        5 => "write_single_coil",
        6 => "write_single_register",
        15 => "write_multiple_coils",
        16 => "write_multiple_registers",
        43 => "read_device_identification",
        _ => "modbus_function",
    }
}

fn is_modbus_write(code: u8) -> bool {
    matches!(code, 5 | 6 | 15 | 16)
}

fn modbus_object_refs(fields: &ModbusFields) -> Vec<String> {
    let mut refs: Vec<String> = fields
        .registers
        .iter()
        .map(|(address, _)| format!("register:{address}"))
        .collect();
    if !fields.device_identification.is_empty() {
        refs.push("modbus_device_identification".to_string());
    }
    refs
}

fn modbus_values(fields: &ModbusFields) -> Vec<ObjectValue> {
    fields
        .registers
        .iter()
        .map(|(address, value)| ObjectValue {
            object_ref: format!("register:{address}"),
            value: Some(value.to_string()),
        })
        .collect()
}

fn modbus_attributes(fields: &ModbusFields) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    attributes.insert("unit_id".to_string(), fields.unit_id.to_string());
    attributes.insert(
        "transaction_id".to_string(),
        fields.transaction_id.to_string(),
    );
    attributes.insert(
        "function_code".to_string(),
        fields.function_code.to_string(),
    );
    for (key, value) in &fields.device_identification {
        attributes.insert(format!("device_id_{key}"), value.clone());
    }
    attributes
}

fn modbus_summary(fields: &ModbusFields) -> String {
    if fields.is_exception {
        return format!(
            "{} exception {}",
            modbus_function_name(fields.function_code),
            fields.exception_code
        );
    }
    if fields.function_code == 43 && !fields.device_identification.is_empty() {
        return fields
            .device_identification
            .get("model_name")
            .or_else(|| fields.device_identification.get("product_name"))
            .or_else(|| fields.device_identification.get("product_code"))
            .cloned()
            .unwrap_or_else(|| "device_identification".to_string());
    }
    if fields.registers.is_empty() {
        modbus_function_name(fields.function_code).to_string()
    } else {
        format!(
            "{} {}",
            modbus_function_name(fields.function_code),
            fields
                .registers
                .iter()
                .map(|(address, value)| format!("{address}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn modbus_identity_observation(
    capture_id: String,
    envelope: EventEnvelope,
    asset_ip: String,
    unit_id: u8,
    device_identification: &BTreeMap<String, String>,
) -> BronzeEvent {
    let mut identifiers = BTreeMap::from([
        ("ip".to_string(), asset_ip.clone()),
        ("unit_id".to_string(), unit_id.to_string()),
    ]);
    for (key, value) in device_identification {
        identifiers.insert(format!("modbus_{key}"), value.clone());
    }
    new_event(
        capture_id,
        envelope,
        BronzeEventFamily::AssetObservation(AssetObservation {
            asset_key: asset_ip,
            role: Some("server".to_string()),
            vendor: device_identification.get("vendor_name").cloned(),
            model: device_identification
                .get("model_name")
                .cloned()
                .or_else(|| device_identification.get("product_name").cloned())
                .or_else(|| device_identification.get("product_code").cloned()),
            firmware: device_identification.get("revision").cloned(),
            hostnames: Vec::new(),
            protocols: vec!["modbus".to_string()],
            identifiers,
        }),
    )
}

#[derive(Debug)]
struct ParsedTls {
    version: String,
    sni: Option<String>,
    cipher_suite: Option<String>,
}

fn parse_tls_client_hello(payload: &[u8]) -> Option<ParsedTls> {
    if payload.len() < 9 {
        return None;
    }
    let content_type = payload[0];
    if content_type != 22 {
        return None;
    }
    let version = format!("TLS {:02x}{:02x}", payload[1], payload[2]);
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len || payload[5] != 1 {
        return None;
    }

    let mut offset = 9; // record header + handshake header
    if payload.len() < offset + 34 {
        return None;
    }
    offset += 2; // client version
    offset += 32; // random
    let session_id_len = *payload.get(offset)? as usize;
    offset += 1 + session_id_len;
    let cipher_len =
        u16::from_be_bytes([*payload.get(offset)?, *payload.get(offset + 1)?]) as usize;
    offset += 2;
    let cipher_suite = if cipher_len >= 2 && offset + 2 <= payload.len() {
        Some(format!(
            "0x{:02x}{:02x}",
            payload[offset],
            payload[offset + 1]
        ))
    } else {
        None
    };
    offset += cipher_len;
    let compression_len = *payload.get(offset)? as usize;
    offset += 1 + compression_len;
    let ext_len = u16::from_be_bytes([*payload.get(offset)?, *payload.get(offset + 1)?]) as usize;
    offset += 2;
    let ext_end = offset.checked_add(ext_len)?.min(payload.len());

    let mut sni = None;
    while offset + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let item_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;
        if offset + item_len > ext_end {
            break;
        }
        if ext_type == 0x0000 && item_len >= 5 {
            let list_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            if list_len + 2 <= item_len && payload[offset + 2] == 0 {
                let name_len =
                    u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;
                if offset + 5 + name_len <= ext_end {
                    sni = std::str::from_utf8(&payload[offset + 5..offset + 5 + name_len])
                        .ok()
                        .map(str::to_string);
                }
            }
        }
        offset += item_len;
    }

    Some(ParsedTls {
        version,
        sni,
        cipher_suite,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_epb(packet: &[u8], timestamp_us: u64) -> Vec<u8> {
        let mut block = Vec::new();
        let block_len = 32 + packet.len() + ((4 - packet.len() % 4) % 4);
        block.extend_from_slice(&0x0000_0006u32.to_le_bytes());
        block.extend_from_slice(&(block_len as u32).to_le_bytes());
        block.extend_from_slice(&0u32.to_le_bytes()); // interface id
        block.extend_from_slice(&((timestamp_us >> 32) as u32).to_le_bytes());
        block.extend_from_slice(&(timestamp_us as u32).to_le_bytes());
        block.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        block.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        block.extend_from_slice(packet);
        while block.len() < block_len - 4 {
            block.push(0);
        }
        block.extend_from_slice(&(block_len as u32).to_le_bytes());
        block
    }

    fn build_pcapng(packet: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        data.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        data.extend_from_slice(&build_epb(packet, 1_700_000_000_000_000));
        data
    }

    fn build_pcap(packet: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&65535u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        data.extend_from_slice(&100_000u32.to_le_bytes());
        data.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        data.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        data.extend_from_slice(packet);
        data
    }

    fn ethernet_ipv4_tcp(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        vlan_id: Option<u16>,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        if let Some(vlan_id) = vlan_id {
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&(vlan_id & 0x0FFF).to_be_bytes());
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
        } else {
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
        }

        let total_len = 20 + 20 + payload.len();
        frame.extend_from_slice(&[
            0x45,
            0x00,
            ((total_len >> 8) & 0xFF) as u8,
            (total_len & 0xFF) as u8,
            0x00,
            0x01,
            0x00,
            0x00,
            64,
            6,
            0,
            0,
        ]);
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.push(0x50);
        frame.push(0x18);
        frame.extend_from_slice(&0x2000u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ethernet_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let total_len = 20 + 8 + payload.len();
        frame.extend_from_slice(&[
            0x45,
            0x00,
            ((total_len >> 8) & 0xFF) as u8,
            (total_len & 0xFF) as u8,
            0x00,
            0x01,
            0x00,
            0x00,
            64,
            17,
            0,
            0,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
        ]);
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn prefixed_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x00, 0x07, 0x00, 0x03];
        frame.extend_from_slice(&ethernet_ipv4_udp(src_port, dst_port, payload)[14..]);
        frame
    }

    fn six_byte_prefixed_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x00, 0x07, 0x00, 0x03, 0x00, 0x00];
        frame.extend_from_slice(&ethernet_ipv4_udp(src_port, dst_port, payload)[14..]);
        frame
    }

    fn ethernet_with_prefixed_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            0x00, 0x10, 0x00, 0x2a, 0x00, 0x5f, // dst mac
            0x00, 0x10, 0x00, 0x2b, 0x00, 0x5f, // src mac
        ];
        frame.extend_from_slice(&0x0001u16.to_be_bytes());
        frame.extend_from_slice(&six_byte_prefixed_ipv4_udp(src_port, dst_port, payload));
        frame
    }

    fn ethernet_llc(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        dsap: u8,
        ssap: u8,
        control: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&((3 + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[dsap, ssap, control]);
        frame.extend_from_slice(payload);
        frame
    }

    fn ethernet_llc_snap(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        oui: [u8; 3],
        pid: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03]);
        frame.extend_from_slice(&oui);
        frame.extend_from_slice(&pid.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn build_dhcp_discover() -> Vec<u8> {
        let mut data = vec![0u8; 240];
        data[0] = 1;
        data[1] = 1;
        data[2] = 6;
        data[4..8].copy_from_slice(&0x3903_f326u32.to_be_bytes());
        data[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        data.extend_from_slice(&[
            53, 1, 1, 12, 6, b'p', b'l', b'c', b'-', b'0', b'1', 60, 7, b'S', b'i', b'e', b'm',
            b'e', b'n', b's', 61, 7, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 50, 4, 10, 0, 0, 42,
            255,
        ]);
        data
    }

    fn snmp_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.push(value.len() as u8);
        out.extend_from_slice(value);
        out
    }

    fn snmp_seq(children: Vec<u8>) -> Vec<u8> {
        snmp_tlv(0x30, &children)
    }

    fn snmp_int(v: i64) -> Vec<u8> {
        let mut bytes = v.to_be_bytes().to_vec();
        while bytes.len() > 1
            && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
                || (bytes[0] == 0xFF && bytes[1] & 0x80 != 0))
        {
            bytes.remove(0);
        }
        snmp_tlv(0x02, &bytes)
    }

    fn snmp_octets(s: &[u8]) -> Vec<u8> {
        snmp_tlv(0x04, s)
    }

    fn snmp_oid(arcs: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((arcs[0] * 40 + arcs[1]) as u8);
        for &arc in &arcs[2..] {
            let mut stack = vec![(arc & 0x7F) as u8];
            let mut value = arc >> 7;
            while value > 0 {
                stack.push(((value & 0x7F) as u8) | 0x80);
                value >>= 7;
            }
            stack.reverse();
            out.extend_from_slice(&stack);
        }
        snmp_tlv(0x06, &out)
    }

    fn snmp_varbind(oid_arcs: &[u32], value: Vec<u8>) -> Vec<u8> {
        snmp_seq([snmp_oid(oid_arcs), value].concat())
    }

    fn build_snmp_get_response() -> Vec<u8> {
        let sys_name = snmp_varbind(&[1, 3, 6, 1, 2, 1, 1, 5, 0], snmp_octets(b"switch-01"));
        let sys_descr = snmp_varbind(
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
            snmp_octets(b"Industrial Ethernet Switch"),
        );
        let varbinds = snmp_seq([sys_name, sys_descr].concat());
        let pdu = snmp_tlv(
            0xA2,
            &[snmp_int(1), snmp_int(0), snmp_int(0), varbinds].concat(),
        );
        snmp_seq([snmp_int(1), snmp_octets(b"public"), pdu].concat())
    }

    fn push_cdp_tlv(pkt: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
        let len = (value.len() + 4) as u16;
        pkt.extend_from_slice(&tlv_type.to_be_bytes());
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(value);
    }

    fn build_cdp_payload() -> Vec<u8> {
        let mut pkt = vec![0x02, 0xB4, 0x00, 0x00];
        push_cdp_tlv(&mut pkt, 0x0001, b"dist-sw-01");
        push_cdp_tlv(&mut pkt, 0x0003, b"GigabitEthernet1/0/24");
        push_cdp_tlv(&mut pkt, 0x0004, &0x0000_0009u32.to_be_bytes());
        push_cdp_tlv(&mut pkt, 0x0005, b"Cisco IOS XE");
        push_cdp_tlv(&mut pkt, 0x0006, b"Catalyst 9300");
        push_cdp_tlv(&mut pkt, 0x000a, &20u16.to_be_bytes());
        push_cdp_tlv(&mut pkt, 0x000b, &[1]);
        pkt
    }

    fn build_stp_bpdu() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0000u16.to_be_bytes());
        pkt.push(0x02);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.extend_from_slice(&[0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&0x0000_0A0Bu32.to_be_bytes());
        pkt.extend_from_slice(&[0x80, 0x00, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        pkt.extend_from_slice(&0x8001u16.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes());
        pkt.extend_from_slice(&0x1400u16.to_be_bytes());
        pkt.extend_from_slice(&0x0200u16.to_be_bytes());
        pkt.extend_from_slice(&0x0F00u16.to_be_bytes());
        pkt
    }

    fn build_enip_encap(command: u16, session_handle: u32, data: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(24 + data.len());
        pkt.extend_from_slice(&command.to_le_bytes());
        pkt.extend_from_slice(&(data.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&session_handle.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(&[0u8; 8]);
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(data);
        pkt
    }

    fn build_enip_list_identity_response() -> Vec<u8> {
        let product_name = b"1756-L85E";
        let mut item = Vec::new();
        item.extend_from_slice(&1u16.to_le_bytes());
        item.extend_from_slice(&2u16.to_le_bytes());
        item.extend_from_slice(&44818u16.to_be_bytes());
        item.extend_from_slice(&[10, 0, 0, 2]);
        item.extend_from_slice(&[0u8; 8]);
        item.extend_from_slice(&1u16.to_le_bytes());
        item.extend_from_slice(&0x000Eu16.to_le_bytes());
        item.extend_from_slice(&321u16.to_le_bytes());
        item.extend_from_slice(&[20, 11]);
        item.extend_from_slice(&0x1234u16.to_le_bytes());
        item.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        item.push(product_name.len() as u8);
        item.extend_from_slice(product_name);
        item.push(3);

        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0x000Cu16.to_le_bytes());
        data.extend_from_slice(&(item.len() as u16).to_le_bytes());
        data.extend_from_slice(&item);
        build_enip_encap(0x0063, 0, &data)
    }

    fn build_enip_send_rr_data_identity_response() -> Vec<u8> {
        let product_name = b"1734-AENTR";
        let mut cip = Vec::new();
        cip.extend_from_slice(&[0x81, 0x00, 0x00, 0x00]);
        cip.extend_from_slice(&1u16.to_le_bytes());
        cip.extend_from_slice(&0x000Cu16.to_le_bytes());
        cip.extend_from_slice(&77u16.to_le_bytes());
        cip.extend_from_slice(&[5, 12]);
        cip.extend_from_slice(&0x0000u16.to_le_bytes());
        cip.extend_from_slice(&0x5566_7788u32.to_le_bytes());
        cip.push(product_name.len() as u8);
        cip.extend_from_slice(product_name);
        cip.push(3);

        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x00B2u16.to_le_bytes());
        data.extend_from_slice(&(cip.len() as u16).to_le_bytes());
        data.extend_from_slice(&cip);
        build_enip_encap(0x006F, 0x1234_5678, &data)
    }

    fn build_modbus_device_identification_request() -> Vec<u8> {
        vec![
            0x00, 0x05, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x05, // length
            0x01, // unit id
            0x2B, // function code
            0x0E, // MEI type
            0x01, // read device id code
            0x00, // object id
        ]
    }

    fn build_modbus_device_identification_response() -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x05, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x00, // length placeholder
            0x01, // unit id
            0x2B, // function code
            0x0E, // MEI type
            0x01, // read device id code
            0x01, // conformity level
            0x00, // more follows
            0x00, // next object id
            0x03, // object count
            0x00, 0x09, // vendor name
        ];
        pkt.extend_from_slice(b"Schneider");
        pkt.extend_from_slice(&[0x05, 0x07]);
        pkt.extend_from_slice(b"M580CPU");
        pkt.extend_from_slice(&[0x02, 0x04]);
        pkt.extend_from_slice(b"2.30");
        let mbap_length = (pkt.len() - 6) as u16;
        pkt[4..6].copy_from_slice(&mbap_length.to_be_bytes());
        pkt
    }

    fn build_dnp3_read_request() -> Vec<u8> {
        vec![
            0x05, 0x64, 0x08, 0xC4, 0x01, 0x00, 0x03, 0x00, 0xAA, 0xBB, 0xC0, 0xC0, 0x01, 0x01,
            0x02, 0x00, 0x06,
        ]
    }

    fn build_opc_ua_hello() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"HEL");
        payload.push(b'F');
        payload.extend_from_slice(&32u32.to_le_bytes());
        payload.extend_from_slice(&[0x00; 24]);
        payload
    }

    fn build_s7_setup_communication() -> Vec<u8> {
        let function = 0xF0u8;
        let param_extra = [0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0];
        let mut parameter = vec![function];
        parameter.extend_from_slice(&param_extra);

        let mut pkt = Vec::new();
        let tpkt_total = (4 + 1 + 2 + 10 + parameter.len()) as u16;
        pkt.push(0x03);
        pkt.push(0x00);
        pkt.extend_from_slice(&tpkt_total.to_be_bytes());
        pkt.push(2);
        pkt.push(0xF0);
        pkt.push(0x80);
        pkt.push(0x32);
        pkt.push(0x01);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&(parameter.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&parameter);
        pkt
    }

    fn build_profinet_identify_request() -> Vec<u8> {
        vec![
            0xFE, 0xFE, // frame id
            0x05, // service id identify
            0x00, // request
            0x00, 0x00, 0x00, 0x01, // xid
            0x00, 0x80, // response delay
            0x00, 0x04, // data length
            0x01, 0x02, 0x03, 0x04, // block payload
        ]
    }

    #[test]
    fn processes_vlan_modbus_request_and_response() {
        let mut engine = DpiEngine::new();
        let request = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x02,
        ];
        let response = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x04, 0x00, 0x0A, 0x00, 0x14,
        ];
        let mut pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49152,
            502,
            &request,
            Some(100),
        ));
        pcapng.extend_from_slice(&build_epb(
            &ethernet_ipv4_tcp(
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                502,
                49152,
                &response,
                Some(100),
            ),
            1_700_000_000_100_000,
        ));

        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("capture-1"), std::io::Cursor::new(pcapng))
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if tx.operation == "read_holding_registers" && tx.status == "ok"
            )),
            "expected paired modbus transaction"
        );
        assert!(
            output
                .events
                .iter()
                .any(|event| event.envelope.vlan_id == Some(100)),
            "expected vlan id to survive into bronze"
        );
    }

    #[test]
    fn processes_classic_pcap_modbus_request() {
        let mut engine = DpiEngine::new();
        let request = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x02,
        ];
        let pcap = build_pcap(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49152,
            502,
            &request,
            None,
        ));

        let output = engine
            .process_capture_to_vec(
                &SegmentMeta::new("capture-pcap"),
                std::io::Cursor::new(pcap),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if tx.operation == "read_holding_registers"
                        && tx.status == "partial_request"
            )),
            "expected modbus transaction from classic pcap"
        );
        assert_eq!(output.checkpoint.frames_processed, 1);
    }

    #[test]
    fn emits_dns_asset_observation() {
        let mut engine = DpiEngine::new();
        let dns_response = vec![
            0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        let pcapng = build_pcapng(&ethernet_ipv4_udp(53, 53000, &dns_response));

        let output = engine
            .process_segment_to_vec(&SegmentMeta::new("capture-2"), std::io::Cursor::new(pcapng))
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if obs.hostnames.iter().any(|host| host == "example.com")
            )),
            "expected dns-derived asset observation"
        );
    }

    #[test]
    fn emits_dns_from_prefixed_ipv4_namespace_capture() {
        let mut engine = DpiEngine::new();
        let dns_response = vec![
            0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        let pcapng = build_pcapng(&prefixed_ipv4_udp(53, 53000, &dns_response));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-prefixed-ipv4"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("dns") && tx.status == "response"
            )),
            "expected dns transaction from prefixed namespace packet"
        );
        assert!(
            output
                .events
                .iter()
                .any(|event| event.envelope.src_ip.as_deref() == Some("10.0.0.1")
                    && event.envelope.dst_ip.as_deref() == Some("10.0.0.2")),
            "expected IP envelope to survive prefixed namespace packet"
        );
    }

    #[test]
    fn emits_dns_from_six_byte_prefixed_namespace_capture() {
        let mut engine = DpiEngine::new();
        let dns_response = vec![
            0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        let pcapng = build_pcapng(&six_byte_prefixed_ipv4_udp(53, 53000, &dns_response));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-prefixed-ipv4-6"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("dns") && tx.status == "response"
            )),
            "expected dns transaction from six-byte prefixed namespace packet"
        );
    }

    #[test]
    fn emits_dns_from_8023_nested_prefixed_namespace_capture() {
        let mut engine = DpiEngine::new();
        let dns_response = vec![
            0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        let pcapng = build_pcapng(&ethernet_with_prefixed_ipv4_udp(53, 53000, &dns_response));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-prefixed-ipv4-8023"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("dns") && tx.status == "response"
            )),
            "expected dns transaction from 802.3 nested namespace packet"
        );
    }

    #[test]
    fn emits_dhcp_transaction_and_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_udp(68, 67, &build_dhcp_discover()));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-dhcp"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("dhcp")
                        && tx.operation == "discover"
                        && tx.status == "request"
            )),
            "expected dhcp transaction"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("dhcp")
                        && obs.hostnames.iter().any(|host| host == "plc-01")
            )),
            "expected dhcp-derived asset observation"
        );
    }

    #[test]
    fn emits_snmp_transaction_and_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_udp(161, 40000, &build_snmp_get_response()));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-snmp"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("snmp")
                        && tx.operation == "get_response"
                        && tx.status == "response"
            )),
            "expected snmp transaction"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("snmp")
                        && obs.hostnames.iter().any(|host| host == "switch-01")
            )),
            "expected snmp-derived asset observation"
        );
    }

    #[test]
    fn emits_cdp_topology_and_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_llc_snap(
            [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC],
            [0x00, 0x25, 0x90, 0xAA, 0xBB, 0xCC],
            [0x00, 0x00, 0x0C],
            0x2000,
            &build_cdp_payload(),
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-cdp"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::TopologyObservation(obs)
                    if event.protocol() == Some("cdp")
                        && obs.observation_type == "cdp_neighbor"
            )),
            "expected cdp topology observation"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("cdp")
                        && obs.hostnames.iter().any(|host| host == "dist-sw-01")
            )),
            "expected cdp asset observation"
        );
    }

    #[test]
    fn emits_stp_topology_and_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_llc(
            [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00],
            [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
            0x42,
            0x42,
            0x03,
            &build_stp_bpdu(),
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-stp"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::TopologyObservation(obs)
                    if event.protocol() == Some("stp")
                        && obs.observation_type == "stp_topology"
            )),
            "expected stp topology observation"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("stp")
                        && obs.identifiers.contains_key("bridge_id")
            )),
            "expected stp asset observation"
        );
    }

    #[test]
    fn emits_enip_list_identity_asset_observation() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            44818,
            49000,
            &build_enip_list_identity_response(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-enip-list-identity"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("ethernet_ip")
                        && obs.vendor.as_deref() == Some("Rockwell Automation/Allen-Bradley")
                        && obs.model.as_deref() == Some("1756-L85E")
                        && obs.firmware.as_deref() == Some("20.11")
                        && obs.protocols.iter().any(|p| p == "cip")
            )),
            "expected list identity asset observation"
        );
    }

    #[test]
    fn emits_modbus_device_identification_asset_observation() {
        let mut engine = DpiEngine::new();
        let mut pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49152,
            502,
            &build_modbus_device_identification_request(),
            None,
        ));
        pcapng.extend_from_slice(&build_epb(
            &ethernet_ipv4_tcp(
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                502,
                49152,
                &build_modbus_device_identification_response(),
                None,
            ),
            1_700_000_000_100_000,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-modbus-device-id"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("modbus")
                        && obs.vendor.as_deref() == Some("Schneider")
                        && obs.model.as_deref() == Some("M580CPU")
                        && obs.firmware.as_deref() == Some("2.30")
            )),
            "expected modbus device identification asset observation"
        );
    }

    #[test]
    fn emits_cip_identity_asset_observation_under_enip() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            44818,
            49001,
            &build_enip_send_rr_data_identity_response(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-enip-cip-identity"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("ethernet_ip")
                        && tx.operation == "send_rr_data"
                        && tx.object_refs.iter().any(|r| r == "cip_object:identity")
            )),
            "expected enip transaction with cip identity object ref"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("ethernet_ip")
                        && obs.model.as_deref() == Some("1734-AENTR")
                        && obs.firmware.as_deref() == Some("5.12")
                        && obs.identifiers.get("cip_serial_number").map(String::as_str)
                            == Some("1432778632")
            )),
            "expected cip identity asset observation"
        );
    }

    #[test]
    fn emits_dnp3_role_asset_observations() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49152,
            20000,
            &build_dnp3_read_request(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-dnp3-role"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("dnp3")
                        && obs.asset_key == "10.0.0.1"
                        && obs.role.as_deref() == Some("master")
            )),
            "expected dnp3 master observation"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::AssetObservation(obs)
                    if event.protocol() == Some("dnp3")
                        && obs.asset_key == "10.0.0.2"
                        && obs.role.as_deref() == Some("outstation")
            )),
            "expected dnp3 outstation observation"
        );
    }

    #[test]
    fn emits_opc_ua_transaction() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49500,
            4840,
            &build_opc_ua_hello(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-opcua"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("opc_ua")
                        && tx.operation == "hello"
                        && tx.status == "request"
            )),
            "expected opc ua transaction"
        );
    }

    #[test]
    fn emits_s7comm_transaction() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_tcp(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            49300,
            102,
            &build_s7_setup_communication(),
            None,
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-s7"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("s7comm")
                        && tx.operation == "setup_communication"
                        && tx.status == "request"
            )),
            "expected s7comm transaction"
        );
    }

    #[test]
    fn emits_profinet_transaction_and_artifact() {
        let mut engine = DpiEngine::new();
        let pcapng = build_pcapng(&ethernet_ipv4_udp(
            40000,
            34964,
            &build_profinet_identify_request(),
        ));

        let output = engine
            .process_segment_to_vec(
                &SegmentMeta::new("capture-profinet"),
                std::io::Cursor::new(pcapng),
            )
            .unwrap();

        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ProtocolTransaction(tx)
                    if event.protocol() == Some("profinet")
                        && tx.operation == "dcp_identify_request"
                        && tx.status == "request"
            )),
            "expected profinet transaction"
        );
        assert!(
            output.events.iter().any(|event| matches!(
                &event.family,
                BronzeEventFamily::ExtractedArtifact(artifact)
                    if artifact.artifact_type == "profinet_payload"
            )),
            "expected profinet artifact"
        );
    }
}
