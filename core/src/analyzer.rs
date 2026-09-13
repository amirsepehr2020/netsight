use std::net::IpAddr;

use crate::service_detection::{identify_service, ServiceMatch};
use crate::traffic::{FlowKey, TrafficAggregator, TrafficSnapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFlow {
    pub key: FlowKey,
    pub bytes: u64,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzedFlow {
    pub key: FlowKey,
    pub bytes: u64,
    pub service: &'static str,
    pub confidence: u8,
    pub evidence: Vec<&'static str>,
}

impl AnalyzedFlow {
    fn from_observation(observed: ObservedFlow) -> Self {
        let destination_port = observed.key.destination_port.unwrap_or_default();
        let ServiceMatch { service, confidence, evidence } =
            identify_service(observed.hostname.as_deref(), destination_port);

        Self {
            key: observed.key,
            bytes: observed.bytes,
            service,
            confidence,
            evidence,
        }
    }
}

#[derive(Debug, Default)]
pub struct AnalysisPipeline {
    traffic: TrafficAggregator,
    analyzed: Vec<AnalyzedFlow>,
}

impl AnalysisPipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, flow: ObservedFlow) -> &AnalyzedFlow {
        self.traffic.record(flow.key.clone(), flow.bytes);
        self.analyzed.push(AnalyzedFlow::from_observation(flow));
        self.analyzed.last().expect("analysis record was just inserted")
    }

    pub fn snapshot(&self) -> TrafficSnapshot {
        self.traffic.snapshot()
    }

    pub fn flows(&self) -> &[AnalyzedFlow] {
        &self.analyzed
    }

    pub fn clear(&mut self) {
        self.traffic.reset();
        self.analyzed.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(hostname: Option<&str>) -> ObservedFlow {
        ObservedFlow {
            key: FlowKey {
                source: "192.168.1.20".parse::<IpAddr>().unwrap(),
                destination: "142.250.72.14".parse::<IpAddr>().unwrap(),
                protocol: "TCP".into(),
                source_port: Some(50001),
                destination_port: Some(443),
            },
            bytes: 2048,
            hostname: hostname.map(str::to_owned),
        }
    }

    #[test]
    fn correlates_flow_with_service() {
        let mut pipeline = AnalysisPipeline::new();
        let result = pipeline.observe(flow(Some("www.youtube.com")));

        assert_eq!(result.service, "YouTube");
        assert!(result.confidence >= 95);
        assert_eq!(pipeline.snapshot().bytes, 2048);
    }

    #[test]
    fn keeps_unknown_services_unknown() {
        let mut pipeline = AnalysisPipeline::new();
        let result = pipeline.observe(flow(Some("example.invalid")));

        assert_eq!(result.service, "Unknown");
        assert!(result.confidence < 50);
    }
}
