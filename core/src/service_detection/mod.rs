//! Service identification primitives for NetSight.
//!
//! This module deliberately identifies services from observable network metadata
//! only. It does not decrypt TLS or inspect private application payloads.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Dns,
    Http,
    Https,
    Tcp,
    Udp,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMatch {
    pub service: &'static str,
    pub confidence: u8,
    pub evidence: Vec<&'static str>,
}

pub fn identify_service(hostname: Option<&str>, destination_port: u16) -> ServiceMatch {
    let host = hostname.unwrap_or("").to_ascii_lowercase();
    let candidates = [
        ("YouTube", ["youtube.com", "googlevideo.com"].as_slice()),
        ("Google", ["google.com", "googleapis.com", "gstatic.com"].as_slice()),
        ("GitHub", ["github.com", "githubusercontent.com"].as_slice()),
        ("Discord", ["discord.com", "discordapp.com", "discord.gg"].as_slice()),
        ("Steam", ["steampowered.com", "steamcontent.com", "steamstatic.com"].as_slice()),
        ("Microsoft", ["microsoft.com", "windows.com", "live.com"].as_slice()),
    ];

    for (service, domains) in candidates {
        if domains.iter().any(|d| host == *d || host.ends_with(&format!(".{d}"))) {
            return ServiceMatch {
                service,
                confidence: if destination_port == 443 || destination_port == 80 { 98 } else { 90 },
                evidence: vec!["hostname", "destination-port"],
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
    fn detects_youtube_subdomain() {
        let result = identify_service(Some("r3---sn.googlevideo.com"), 443);
        assert_eq!(result.service, "YouTube");
        assert!(result.confidence >= 95);
    }

    #[test]
    fn unknown_https_is_not_misclassified() {
        let result = identify_service(Some("example.invalid"), 443);
        assert_eq!(result.service, "Unknown");
        assert!(result.confidence < 50);
    }
}
