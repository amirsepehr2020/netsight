use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug)]
pub struct Detection<'a> {
    pub service: &'a str,
    pub confidence: u8,
}

const RULES: &[(&str, &str, &str, u8)] = &[
    ("youtube.com", "YouTube", "domain", 98),
    ("googlevideo.com", "YouTube", "domain", 98),
    ("ytimg.com", "YouTube", "domain", 98),
    ("google.com", "Google", "domain", 98),
    ("gstatic.com", "Google", "domain", 98),
    ("github.com", "GitHub", "domain", 98),
    ("githubusercontent.com", "GitHub", "domain", 98),
    ("discord.com", "Discord", "domain", 98),
    ("discord.gg", "Discord", "domain", 98),
    ("instagram.com", "Instagram", "domain", 98),
    ("cdninstagram.com", "Instagram", "domain", 98),
    ("facebook.com", "Facebook", "domain", 98),
    ("microsoft.com", "Microsoft", "domain", 98),
    ("live.com", "Microsoft", "domain", 98),
    ("steampowered.com", "Steam", "domain", 98),
    ("steamcontent.com", "Steam", "domain", 98),
    ("telegram.org", "Telegram", "domain", 98),
    ("t.me", "Telegram", "domain", 98),
    ("cloudflare.com", "Cloudflare", "domain", 98),
    ("cloudfront.net", "Amazon CloudFront", "domain", 95),
    ("amazonaws.com", "Amazon Web Services", "domain", 95),
    ("apple.com", "Apple", "domain", 98),
    ("icloud.com", "iCloud", "domain", 98),
    ("spotify.com", "Spotify", "domain", 98),
    ("netflix.com", "Netflix", "domain", 98),
];

pub fn domain(domain: &str) -> Detection<'static> {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if let Some((_, name, _, confidence)) = RULES.iter().find(|(suffix, _, _, _)| d == *suffix || d.ends_with(&format!(".{suffix}"))) {
        return Detection { service: name, confidence: *confidence };
    }
    Detection { service: "Unknown domain", confidence: 72 }
}

pub fn port(port: u16, protocol: &str) -> Detection<'static> {
    match (protocol, port) {
        ("UDP", 53) => Detection { service: "DNS", confidence: 90 },
        ("TCP", 80) => Detection { service: "HTTP", confidence: 88 },
        ("TCP", 443) => Detection { service: "HTTPS", confidence: 75 },
        ("TCP", 22) => Detection { service: "SSH", confidence: 88 },
        ("TCP", 25) => Detection { service: "SMTP", confidence: 88 },
        ("TCP", 993) => Detection { service: "IMAPS", confidence: 88 },
        ("TCP", 995) => Detection { service: "POP3S", confidence: 88 },
        _ => Detection { service: "Unknown", confidence: 0 },
    }
}

pub fn ip_hint(ip: &str) -> Option<Detection<'static>> {
    let parsed = ip.parse::<Ipv4Addr>().ok()?;
    let octets = parsed.octets();
    if octets[0] == 8 && octets[1] == 8 { return Some(Detection { service: "Google DNS", confidence: 86 }); }
    if octets[0] == 1 && octets[1] == 1 { return Some(Detection { service: "Cloudflare DNS", confidence: 86 }); }
    None
}
