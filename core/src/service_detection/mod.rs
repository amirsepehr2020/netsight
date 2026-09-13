//! Service attribution from observable network metadata.
//! No TLS decryption or private payload inspection is performed.

mod registry;

pub use registry::{domain_matches, normalize_hostname, ServiceRule, RULES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol { Dns, Http, Https, Tcp, Udp, Unknown }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMatch {
    pub service: &'static str,
    pub confidence: u8,
    pub evidence: Vec<&'static str>,
}

pub fn identify_service(hostname: Option<&str>, destination_port: u16) -> ServiceMatch {
    let host = hostname.map(normalize_hostname).unwrap_or_default();
    for rule in RULES {
        if rule.domains.iter().any(|domain| domain_matches(&host, domain)) {
            let port_evidence = rule.ports.contains(&destination_port);
            return ServiceMatch {
                service: rule.service,
                confidence: if port_evidence { 98 } else { 88 },
                evidence: if port_evidence { vec!["hostname", "destination-port"] } else { vec!["hostname"] },
            };
        }
    }
    ServiceMatch {
        service: "Unknown",
        confidence: if destination_port == 443 { 35 } else { 20 },
        evidence: vec!["destination-port"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_matches_case_insensitively() {
        let result = identify_service(Some("R3---SN.GOOGLEVIDEO.COM."), 443);
        assert_eq!(result.service, "YouTube");
        assert_eq!(result.confidence, 98);
    }

    #[test]
    fn preserves_low_confidence_for_unknown_https() {
        let result = identify_service(Some("example.invalid."), 443);
        assert_eq!(result.service, "Unknown");
        assert!(result.confidence < 50);
    }

    #[test]
    fn nonstandard_port_does_not_discard_hostname_evidence() {
        let result = identify_service(Some("api.github.com"), 8443);
        assert_eq!(result.service, "GitHub");
        assert_eq!(result.confidence, 88);
    }
}
