use std::collections::HashMap;
use std::net::IpAddr;

use crate::model::CaptureState;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: String,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrafficSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub active_flows: usize,
}

#[derive(Debug, Default)]
pub struct TrafficAggregator {
    flows: HashMap<FlowKey, FlowStats>,
    packets: u64,
    bytes: u64,
}

impl TrafficAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, key: FlowKey, bytes: u64) {
        let stats = self.flows.entry(key).or_default();
        stats.packets += 1;
        stats.bytes += bytes;
        self.packets += 1;
        self.bytes += bytes;
    }

    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            packets: self.packets,
            bytes: self.bytes,
            active_flows: self.flows.len(),
        }
    }

    pub fn flow(&self, key: &FlowKey) -> Option<&FlowStats> {
        self.flows.get(key)
    }

    pub fn reset(&mut self) {
        self.flows.clear();
        self.packets = 0;
        self.bytes = 0;
    }

    pub fn capture_state_compatible(state: CaptureState) -> bool {
        matches!(state, CaptureState::Capturing | CaptureState::Stopping)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> FlowKey {
        FlowKey {
            source: "192.168.1.10".parse().unwrap(),
            destination: "1.1.1.1".parse().unwrap(),
            protocol: "TCP".into(),
            source_port: Some(50000),
            destination_port: Some(443),
        }
    }

    #[test]
    fn aggregates_packets_and_bytes() {
        let mut aggregator = TrafficAggregator::new();
        aggregator.record(key(), 1200);
        aggregator.record(key(), 800);

        assert_eq!(aggregator.snapshot(), TrafficSnapshot { packets: 2, bytes: 2000, active_flows: 1 });
        assert_eq!(aggregator.flow(&key()).unwrap().packets, 2);
        assert_eq!(aggregator.flow(&key()).unwrap().bytes, 2000);
    }

    #[test]
    fn reset_clears_all_state() {
        let mut aggregator = TrafficAggregator::new();
        aggregator.record(key(), 42);
        aggregator.reset();
        assert_eq!(aggregator.snapshot(), TrafficSnapshot::default());
    }
}
