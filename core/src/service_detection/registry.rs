//! Deterministic service registry used by the attribution engine.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRule {
    pub service: &'static str,
    pub domains: &'static [&'static str],
    pub ports: &'static [u16],
}

pub const RULES: &[ServiceRule] = &[
    ServiceRule { service: "YouTube", domains: &["youtube.com", "googlevideo.com", "ytimg.com"], ports: &[80, 443] },
    ServiceRule { service: "Google", domains: &["google.com", "googleapis.com", "gstatic.com"], ports: &[80, 443] },
    ServiceRule { service: "GitHub", domains: &["github.com", "githubusercontent.com", "githubassets.com"], ports: &[80, 443, 22] },
    ServiceRule { service: "Discord", domains: &["discord.com", "discordapp.com", "discord.gg"], ports: &[80, 443] },
    ServiceRule { service: "Steam", domains: &["steampowered.com", "steamcontent.com", "steamstatic.com"], ports: &[80, 443] },
    ServiceRule { service: "Microsoft", domains: &["microsoft.com", "windows.com", "live.com"], ports: &[80, 443] },
];

pub fn normalize_hostname(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn domain_matches(hostname: &str, domain: &str) -> bool {
    hostname == domain || hostname.ends_with(&format!(".{domain}"))
}
