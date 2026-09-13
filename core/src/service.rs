use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceEvidence {
    pub kind: String,
    pub value: String,
    pub weight: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceResult {
    pub service_id: String,
    pub display_name: String,
    pub confidence: f32,
    pub evidence: Vec<ServiceEvidence>,
}

#[derive(Debug, Clone, Default)]
pub struct ServiceIdentifier {
    rules: Vec<ServiceRule>,
}

#[derive(Debug, Clone)]
struct ServiceRule {
    id: &'static str,
    name: &'static str,
    domains: &'static [&'static str],
}

impl Default for ServiceIdentifier {
    fn default() -> Self {
        Self {
            rules: vec![
                ServiceRule { id: "youtube", name: "YouTube", domains: &["youtube.com", "googlevideo.com", "ytimg.com"] },
                ServiceRule { id: "discord", name: "Discord", domains: &["discord.com", "discordapp.com", "discord.gg"] },
                ServiceRule { id: "github", name: "GitHub", domains: &["github.com", "githubusercontent.com"] },
                ServiceRule { id: "steam", name: "Steam", domains: &["steampowered.com", "steamcommunity.com", "steamcontent.com"] },
                ServiceRule { id: "google", name: "Google", domains: &["google.com", "googleapis.com", "gstatic.com"] },
            ],
        }
    }
}

impl ServiceIdentifier {
    pub fn identify(&self, observed_domains: &[String]) -> Option<ServiceResult> {
        let mut best: Option<ServiceResult> = None;

        for rule in &self.rules {
            let mut evidence = Vec::new();
            for domain in observed_domains {
                let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
                if rule.domains.iter().any(|candidate| {
                    normalized == *candidate || normalized.ends_with(&format!(".{candidate}"))
                }) {
                    evidence.push(ServiceEvidence {
                        kind: "dns_domain".into(),
                        value: normalized,
                        weight: 1.0,
                    });
                }
            }

            if evidence.is_empty() {
                continue;
            }

            let confidence = (0.70 + (evidence.len().min(3) as f32 * 0.10)).min(0.99);
            let result = ServiceResult {
                service_id: rule.id.into(),
                display_name: rule.name.into(),
                confidence,
                evidence,
            };

            if best.as_ref().map(|current| result.confidence > current.confidence).unwrap_or(true) {
                best = Some(result);
            }
        }

        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_youtube_from_subdomain() {
        let engine = ServiceIdentifier::default();
        let result = engine.identify(&["r1---sn.example.googlevideo.com".into()]).unwrap();
        assert_eq!(result.service_id, "youtube");
        assert!(result.confidence >= 0.8);
    }

    #[test]
    fn unknown_domains_do_not_get_fabricated_identity() {
        let engine = ServiceIdentifier::default();
        assert!(engine.identify(&["unknown.invalid".into()]).is_none());
    }

    #[test]
    fn matching_is_case_insensitive() {
        let engine = ServiceIdentifier::default();
        let result = engine.identify(&["WWW.GITHUB.COM".into()]).unwrap();
        assert_eq!(result.service_id, "github");
    }
}
