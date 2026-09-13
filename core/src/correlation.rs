use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsObservation {
    pub domain: String,
    pub addresses: Vec<IpAddr>,
    pub observed_at: SystemTime,
    pub ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsObservation {
    pub destination: IpAddr,
    pub server_name: Option<String>,
    pub observed_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedEndpoint {
    pub destination: IpAddr,
    pub domain: Option<String>,
    pub tls_server_name: Option<String>,
    pub confidence: u8,
}

#[derive(Debug, Default)]
pub struct CorrelationEngine {
    dns_by_ip: HashMap<IpAddr, Vec<DnsObservation>>,
}

impl CorrelationEngine {
    pub fn observe_dns(&mut self, observation: DnsObservation) {
        for address in &observation.addresses {
            self.dns_by_ip.entry(*address).or_default().push(observation.clone());
        }
    }

    pub fn correlate(&self, tls: &TlsObservation) -> CorrelatedEndpoint {
        let domain = self.active_domain(tls.destination, tls.observed_at);
        let tls_name = tls.server_name.clone();
        let confidence = match (&domain, &tls_name) {
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => 100,
            (Some(_), Some(_)) => 92,
            (Some(_), None) => 75,
            (None, Some(_)) => 65,
            (None, None) => 0,
        };

        CorrelatedEndpoint {
            destination: tls.destination,
            domain,
            tls_server_name: tls_name,
            confidence,
        }
    }

    fn active_domain(&self, address: IpAddr, at: SystemTime) -> Option<String> {
        self.dns_by_ip.get(&address)?.iter().rev().find_map(|entry| {
            let expires = entry.observed_at.checked_add(entry.ttl)?;
            if at <= expires { Some(entry.domain.clone()) } else { None }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr { "142.250.72.14".parse().unwrap() }

    #[test]
    fn dns_and_matching_tls_produce_high_confidence() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let mut engine = CorrelationEngine::default();
        engine.observe_dns(DnsObservation {
            domain: "youtube.com".into(),
            addresses: vec![ip()],
            observed_at: now,
            ttl: Duration::from_secs(300),
        });

        let result = engine.correlate(&TlsObservation {
            destination: ip(),
            server_name: Some("youtube.com".into()),
            observed_at: now + Duration::from_secs(2),
        });

        assert_eq!(result.domain.as_deref(), Some("youtube.com"));
        assert_eq!(result.confidence, 100);
    }

    #[test]
    fn expired_dns_is_not_used() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let mut engine = CorrelationEngine::default();
        engine.observe_dns(DnsObservation {
            domain: "example.com".into(),
            addresses: vec![ip()],
            observed_at: now,
            ttl: Duration::from_secs(1),
        });

        let result = engine.correlate(&TlsObservation {
            destination: ip(),
            server_name: None,
            observed_at: now + Duration::from_secs(2),
        });

        assert!(result.domain.is_none());
        assert_eq!(result.confidence, 0);
    }
}
