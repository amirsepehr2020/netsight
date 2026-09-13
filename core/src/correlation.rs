use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::traffic::FlowKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    Active,
    Idle,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowObservation {
    pub device: IpAddr,
    pub key: FlowKey,
    pub packet_count: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub hostname: Option<String>,
    pub service: Option<String>,
    pub service_confidence: u8,
    pub dns_name: Option<String>,
    pub tls_server_name: Option<String>,
    pub last_seen: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedFlow {
    pub device: IpAddr,
    pub key: FlowKey,
    pub packets: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub service: Option<String>,
    pub confidence: u8,
    pub dns_name: Option<String>,
    pub tls_server_name: Option<String>,
    pub state: FlowState,
    pub last_seen: SystemTime,
}

#[derive(Debug)]
pub struct NetworkFlowTracker {
    flows: HashMap<FlowKey, CorrelatedFlow>,
    idle_after: Duration,
}

impl NetworkFlowTracker {
    pub fn new(idle_after: Duration) -> Self {
        Self { flows: HashMap::new(), idle_after }
    }

    pub fn observe(&mut self, observation: FlowObservation) {
        let entry = self.flows.entry(observation.key.clone()).or_insert_with(|| CorrelatedFlow {
            device: observation.device,
            key: observation.key.clone(),
            packets: 0,
            bytes_up: 0,
            bytes_down: 0,
            service: None,
            confidence: 0,
            dns_name: None,
            tls_server_name: None,
            state: FlowState::Active,
            last_seen: observation.last_seen,
        });

        entry.device = observation.device;
        entry.packets = entry.packets.saturating_add(observation.packet_count);
        entry.bytes_up = entry.bytes_up.saturating_add(observation.bytes_up);
        entry.bytes_down = entry.bytes_down.saturating_add(observation.bytes_down);
        entry.service = observation.service.or_else(|| entry.service.clone());
        entry.confidence = entry.confidence.max(observation.service_confidence);
        entry.dns_name = observation.dns_name.or_else(|| entry.dns_name.clone());
        entry.tls_server_name = observation.tls_server_name.or_else(|| entry.tls_server_name.clone());
        entry.last_seen = observation.last_seen;
        entry.state = FlowState::Active;
    }

    pub fn refresh_states(&mut self, now: SystemTime) {
        for flow in self.flows.values_mut() {
            flow.state = match now.duration_since(flow.last_seen) {
                Ok(age) if age >= self.idle_after => FlowState::Idle,
                _ => FlowState::Active,
            };
        }
    }

    pub fn active_for_device(&self, device: IpAddr) -> Vec<&CorrelatedFlow> {
        self.flows.values()
            .filter(|flow| flow.device == device && flow.state == FlowState::Active)
            .collect()
    }

    pub fn all(&self) -> impl Iterator<Item = &CorrelatedFlow> {
        self.flows.values()
    }

    pub fn remove_idle(&mut self, now: SystemTime) -> usize {
        let before = self.flows.len();
        self.flows.retain(|_, flow| match now.duration_since(flow.last_seen) {
            Ok(age) => age < self.idle_after,
            Err(_) => true,
        });
        before - self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> FlowKey {
        FlowKey {
            source: "192.168.1.20".parse().unwrap(),
            destination: "142.250.72.14".parse().unwrap(),
            protocol: "TCP".into(),
            source_port: Some(50001),
            destination_port: Some(443),
        }
    }

    #[test]
    fn correlates_device_flow_and_service_metadata() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut tracker = NetworkFlowTracker::new(Duration::from_secs(30));
        tracker.observe(FlowObservation {
            device: "192.168.1.20".parse().unwrap(),
            key: key(),
            packet_count: 3,
            bytes_up: 500,
            bytes_down: 2000,
            hostname: Some("youtube.com".into()),
            service: Some("YouTube".into()),
            service_confidence: 98,
            dns_name: Some("youtube.com".into()),
            tls_server_name: Some("youtube.com".into()),
            last_seen: now,
        });

        let flows = tracker.active_for_device("192.168.1.20".parse().unwrap());
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].service.as_deref(), Some("YouTube"));
        assert_eq!(flows[0].bytes_down, 2000);
        assert_eq!(flows[0].confidence, 98);
    }

    #[test]
    fn idle_flows_are_not_reported_as_active() {
        let seen = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(50);
        let mut tracker = NetworkFlowTracker::new(Duration::from_secs(30));
        tracker.observe(FlowObservation {
            device: "192.168.1.20".parse().unwrap(), key: key(), packet_count: 1,
            bytes_up: 10, bytes_down: 20, hostname: None, service: None,
            service_confidence: 0, dns_name: None, tls_server_name: None, last_seen: seen,
        });
        tracker.refresh_states(now);
        assert!(tracker.active_for_device("192.168.1.20".parse().unwrap()).is_empty());
        assert_eq!(tracker.remove_idle(now), 1);
    }
}
