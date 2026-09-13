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
pub struct FlowStats { pub packets: u64, pub bytes: u64 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSummary {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: String,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrafficSnapshot { pub packets: u64, pub bytes: u64, pub active_flows: usize }

#[derive(Debug, Default)]
pub struct TrafficAggregator { flows: HashMap<FlowKey, FlowStats>, packets: u64, bytes: u64 }

impl TrafficAggregator {
    pub fn new() -> Self { Self::default() }
    pub fn record(&mut self, key: FlowKey, bytes: u64) { let s=self.flows.entry(key).or_default(); s.packets+=1; s.bytes+=bytes; self.packets+=1; self.bytes+=bytes; }
    pub fn snapshot(&self) -> TrafficSnapshot { TrafficSnapshot { packets:self.packets, bytes:self.bytes, active_flows:self.flows.len() } }
    pub fn flow(&self, key:&FlowKey)->Option<&FlowStats>{self.flows.get(key)}
    pub fn flows(&self) -> Vec<FlowSummary> {
        let mut result = self.flows.iter().map(|(key, stats)| FlowSummary {
            source: key.source,
            destination: key.destination,
            protocol: key.protocol.clone(),
            source_port: key.source_port,
            destination_port: key.destination_port,
            packets: stats.packets,
            bytes: stats.bytes,
        }).collect::<Vec<_>>();
        result.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        result
    }
    pub fn reset(&mut self){self.flows.clear();self.packets=0;self.bytes=0;}
    pub fn capture_state_compatible(state: CaptureState)->bool{matches!(state,CaptureState::Running|CaptureState::Stopping)}
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key()->FlowKey{FlowKey{source:"192.168.1.10".parse().unwrap(),destination:"1.1.1.1".parse().unwrap(),protocol:"TCP".into(),source_port:Some(50000),destination_port:Some(443)}}
    #[test] fn aggregates_packets_and_bytes(){let mut a=TrafficAggregator::new();a.record(key(),1200);a.record(key(),800);assert_eq!(a.snapshot(),TrafficSnapshot{packets:2,bytes:2000,active_flows:1});assert_eq!(a.flow(&key()).unwrap().packets,2);assert_eq!(a.flow(&key()).unwrap().bytes,2000);}
    #[test] fn reset_clears_all_state(){let mut a=TrafficAggregator::new();a.record(key(),42);a.reset();assert_eq!(a.snapshot(),TrafficSnapshot::default());}
    #[test] fn capture_state_uses_running_model(){assert!(TrafficAggregator::capture_state_compatible(CaptureState::Running));assert!(!TrafficAggregator::capture_state_compatible(CaptureState::Idle));}
    #[test] fn lists_flows_largest_first(){let mut a=TrafficAggregator::new();let mut second=key();second.destination_port=Some(80);a.record(key(),10);a.record(second,50);let flows=a.flows();assert_eq!(flows[0].bytes,50);assert_eq!(flows[0].destination_port,Some(80));}
}