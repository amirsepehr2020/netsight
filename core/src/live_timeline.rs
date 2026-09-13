use std::time::{Duration, UNIX_EPOCH};

use crate::packet::NormalizedPacket;
use crate::timeline::{TrafficSample, TrafficTimeline};

/// Bridges normalized live packets into the bounded dashboard timeline.
#[derive(Debug)]
pub struct LiveTimeline {
    timeline: TrafficTimeline,
}

impl LiveTimeline {
    pub fn new(retention: Duration, max_samples: usize) -> Self {
        Self { timeline: TrafficTimeline::new(retention, max_samples) }
    }

    pub fn ingest(&mut self, packet: &NormalizedPacket, device: impl Into<String>, service: impl Into<String>) {
        let timestamp = if packet.timestamp_micros >= 0 {
            UNIX_EPOCH + Duration::from_micros(packet.timestamp_micros as u64)
        } else { UNIX_EPOCH };
        let bytes = packet.captured_len as u64;
        self.timeline.push(TrafficSample {
            timestamp,
            device: device.into(),
            service: service.into(),
            protocol: protocol_name(packet),
            bytes_up: bytes,
            bytes_down: 0,
            connections: 1,
        });
    }

    pub fn timeline(&self) -> &TrafficTimeline { &self.timeline }
    pub fn timeline_mut(&mut self) -> &mut TrafficTimeline { &mut self.timeline }
}

fn protocol_name(packet: &NormalizedPacket) -> String {
    match packet.transport {
        Some(crate::packet::TransportProtocol::Tcp) => "TCP".into(),
        Some(crate::packet::TransportProtocol::Udp) => "UDP".into(),
        Some(crate::packet::TransportProtocol::Other(n)) => format!("IP/{n}"),
        None => "IP".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{NormalizedPacket, TransportProtocol};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn ingest_adds_live_sample() {
        let packet = NormalizedPacket {
            timestamp_micros: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as i64,
            captured_len: 128,
            original_len: 128,
            source_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            destination_ip: Some(IpAddr::V4(Ipv4Addr::new(8,8,8,8))),
            source_port: Some(50000), destination_port: Some(443),
            transport: Some(TransportProtocol::Tcp), payload_len: 80,
        };
        let mut live = LiveTimeline::new(Duration::from_secs(60), 10);
        live.ingest(&packet, "device-1", "Unknown HTTPS");
        let sample = live.timeline().samples().next().unwrap();
        assert_eq!(sample.protocol, "TCP");
        assert_eq!(sample.total_bytes(), 128);
    }
}
