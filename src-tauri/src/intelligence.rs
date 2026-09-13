use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug)]
pub struct Detection<'a> { pub service: &'a str, pub confidence: u8 }

const RULES: &[(&str, &str, u8)] = &[
    ("youtube.com", "YouTube", 98), ("googlevideo.com", "YouTube", 98), ("ytimg.com", "YouTube", 98),
    ("google.com", "Google", 98), ("gstatic.com", "Google", 98), ("github.com", "GitHub", 98), ("githubusercontent.com", "GitHub", 98),
    ("discord.com", "Discord", 98), ("discord.gg", "Discord", 98), ("instagram.com", "Instagram", 98), ("cdninstagram.com", "Instagram", 98),
    ("facebook.com", "Facebook", 98), ("microsoft.com", "Microsoft", 98), ("live.com", "Microsoft", 98),
    ("steampowered.com", "Steam", 98), ("steamcontent.com", "Steam", 98), ("telegram.org", "Telegram", 98), ("t.me", "Telegram", 98),
    ("cloudflare.com", "Cloudflare", 98), ("cloudfront.net", "Amazon CloudFront", 95), ("amazonaws.com", "Amazon Web Services", 95),
    ("apple.com", "Apple", 98), ("icloud.com", "iCloud", 98), ("spotify.com", "Spotify", 98), ("netflix.com", "Netflix", 98),
];

pub fn domain(domain: &str) -> Detection<'static> {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if let Some((_, name, confidence)) = RULES.iter().find(|(suffix, _, _)| d == *suffix || d.ends_with(&format!(".{suffix}"))) {
        return Detection { service: name, confidence: *confidence };
    }
    Detection { service: "Unknown", confidence: 0 }
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
    let [a, b, _, _] = parsed.octets();
    if a == 8 && b == 8 { return Some(Detection { service: "Google DNS", confidence: 86 }); }
    if a == 1 && b == 1 { return Some(Detection { service: "Cloudflare DNS", confidence: 86 }); }
    None
}
