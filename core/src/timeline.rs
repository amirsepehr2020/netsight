use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

/// A compact time-series sample suitable for a live traffic dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSample {
    pub timestamp: SystemTime,
    pub device: String,
    pub service: String,
    pub protocol: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub connections: u32,
}

impl TrafficSample {
    pub fn total_bytes(&self) -> u64 {
        self.bytes_up.saturating_add(self.bytes_down)
    }
}

/// Bounded rolling timeline. Old samples are evicted automatically.
#[derive(Debug, Clone)]
pub struct TrafficTimeline {
    retention: Duration,
    max_samples: usize,
    samples: VecDeque<TrafficSample>,
}

impl TrafficTimeline {
    pub fn new(retention: Duration, max_samples: usize) -> Self {
        Self {
            retention,
            max_samples: max_samples.max(1),
            samples: VecDeque::new(),
        }
    }

    pub fn push(&mut self, sample: TrafficSample) {
        self.samples.push_back(sample);
        while self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
        self.prune(SystemTime::now());
    }

    pub fn prune(&mut self, now: SystemTime) {
        while let Some(front) = self.samples.front() {
            let expired = now.duration_since(front.timestamp).map(|age| age > self.retention).unwrap_or(false);
            if expired {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn samples(&self) -> impl Iterator<Item = &TrafficSample> {
        self.samples.iter()
    }

    pub fn len(&self) -> usize { self.samples.len() }
    pub fn is_empty(&self) -> bool { self.samples.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ts: SystemTime, device: &str, up: u64, down: u64) -> TrafficSample {
        TrafficSample {
            timestamp: ts,
            device: device.into(),
            service: "YouTube".into(),
            protocol: "TLS".into(),
            bytes_up: up,
            bytes_down: down,
            connections: 1,
        }
    }

    #[test]
    fn bounded_timeline_evicts_oldest_by_capacity() {
        let now = SystemTime::now();
        let mut timeline = TrafficTimeline::new(Duration::from_secs(60), 2);
        timeline.push(sample(now, "a", 1, 2));
        timeline.push(sample(now, "b", 3, 4));
        timeline.push(sample(now, "c", 5, 6));
        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline.samples().next().unwrap().device, "b");
    }

    #[test]
    fn prune_removes_expired_samples() {
        let now = SystemTime::now();
        let mut timeline = TrafficTimeline::new(Duration::from_secs(10), 10);
        timeline.push(sample(now - Duration::from_secs(11), "old", 1, 1));
        timeline.push(sample(now, "new", 1, 1));
        timeline.prune(now);
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline.samples().next().unwrap().device, "new");
    }
}
