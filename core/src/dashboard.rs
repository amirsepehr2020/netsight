use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::device::DeviceRegistry;
use crate::live_timeline::LiveTimeline;
use crate::model::CaptureState;
use crate::traffic::{FlowSummary, TrafficAggregator};

#[derive(Debug, Clone, Serialize)]
pub struct DashboardDevice {
    pub id: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: Option<String>,
    pub packets: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub active_connections: u32,
    pub services: Vec<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardFlow {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardTimelineSample {
    pub timestamp_ms: u128,
    pub device: String,
    pub service: String,
    pub protocol: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub connections: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardTraffic { pub packets: u64, pub bytes: u64, pub active_flows: usize }

#[derive(Debug, Clone, Serialize)]
pub struct DashboardSnapshot {
    pub state: CaptureState,
    pub capture_device: String,
    pub updated_at_ms: u128,
    pub traffic: DashboardTraffic,
    pub devices: Vec<DashboardDevice>,
    pub flows: Vec<DashboardFlow>,
    pub timeline: Vec<DashboardTimelineSample>,
}

impl DashboardSnapshot {
    pub fn new(state: CaptureState, capture_device: impl Into<String>) -> Self {
        Self { state, capture_device: capture_device.into(), updated_at_ms: now_ms(), traffic: DashboardTraffic { packets: 0, bytes: 0, active_flows: 0 }, devices: Vec::new(), flows: Vec::new(), timeline: Vec::new() }
    }

    pub fn from_runtime(state: CaptureState, capture_device: impl Into<String>, devices: &DeviceRegistry, traffic: &TrafficAggregator, timeline: &LiveTimeline) -> Self {
        let t = traffic.snapshot();
        let devices = devices.list().into_iter().map(|d| DashboardDevice {
            id: d.id, ip: d.ips.first().map(ToString::to_string), hostname: d.hostname, vendor: d.vendor,
            device_type: d.device_type, packets: d.traffic.packets, bytes_up: d.traffic.bytes_up,
            bytes_down: d.traffic.bytes_down, active_connections: d.active_connections, services: d.services, confidence: d.confidence,
        }).collect();
        let flows = traffic.flows().into_iter().map(flow_row).collect();
        let timeline = timeline.timeline().samples().map(|s| DashboardTimelineSample {
            timestamp_ms: s.timestamp.duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or_default(),
            device: s.device.clone(), service: s.service.clone(), protocol: s.protocol.clone(), bytes_up: s.bytes_up, bytes_down: s.bytes_down, connections: s.connections,
        }).collect();
        Self { state, capture_device: capture_device.into(), updated_at_ms: now_ms(), traffic: DashboardTraffic { packets: t.packets, bytes: t.bytes, active_flows: t.active_flows }, devices, flows, timeline }
    }

    pub fn to_json(&self) -> serde_json::Result<String> { serde_json::to_string(self) }
}

fn flow_row(f: FlowSummary) -> DashboardFlow {
    DashboardFlow { source: f.source.to_string(), destination: f.destination.to_string(), protocol: f.protocol, source_port: f.source_port, destination_port: f.destination_port, packets: f.packets, bytes: f.bytes }
}
fn now_ms() -> u128 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or_default() }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceObservation, DeviceRegistry};
    use crate::packet::normalize_ethernet;
    use crate::traffic::FlowKey;
    use std::net::IpAddr;
    use std::time::Duration;

    #[test]
    fn snapshot_serializes_live_capture_state_for_ui() {
        let snapshot = DashboardSnapshot::new(CaptureState::Running, "Wi-Fi");
        let json = snapshot.to_json().unwrap();
        assert!(json.contains("\"state\":\"Running\""));
        assert!(json.contains("\"capture_device\":\"Wi-Fi\""));
        assert!(json.contains("\"devices\":[]"));
        assert!(json.contains("\"flows\":[]"));
    }

    #[test]
    fn runtime_snapshot_contains_device_flow_and_timeline() {
        let now = SystemTime::now();
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let remote: IpAddr = "1.1.1.1".parse().unwrap();
        let mut devices = DeviceRegistry::new(Duration::from_secs(300), 10);
        let id = devices.observe(DeviceObservation::new(now, ip));
        devices.record_traffic(&id, 128, true);
        let mut traffic = TrafficAggregator::new();
        traffic.record(FlowKey { source: ip, destination: remote, protocol: "TCP".into(), source_port: Some(50000), destination_port: Some(443) }, 128);
        let mut p = vec![0u8; 14 + 20 + 20];
        p[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); p[14] = 0x45; p[23] = 6;
        p[26..30].copy_from_slice(&[192,168,1,10]); p[30..34].copy_from_slice(&[1,1,1,1]);
        p[34..36].copy_from_slice(&50000u16.to_be_bytes()); p[36..38].copy_from_slice(&443u16.to_be_bytes()); p[46] = 0x50;
        let timestamp_micros = now.duration_since(UNIX_EPOCH).unwrap().as_micros() as i64;
        let packet = normalize_ethernet(timestamp_micros, p.len() as u32, p.len() as u32, &p).unwrap();
        let mut timeline = LiveTimeline::new(Duration::from_secs(60), 100);
        timeline.ingest(&packet, id, "HTTPS");
        let snapshot = DashboardSnapshot::from_runtime(CaptureState::Running, "Wi-Fi", &devices, &traffic, &timeline);
        assert_eq!(snapshot.devices.len(), 1); assert_eq!(snapshot.flows.len(), 1); assert_eq!(snapshot.timeline.len(), 1); assert_eq!(snapshot.traffic.bytes, 128);
    }
}