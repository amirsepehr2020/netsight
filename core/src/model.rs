use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureState {
    Idle,
    Starting,
    Running,
    Stopping,
    Failed,
}

impl Default for CaptureState {
    fn default() -> Self { Self::Idle }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticLevel {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    pub code: String,
    pub level: DiagnosticLevel,
    pub message: String,
}

impl DiagnosticEvent {
    pub fn new(code: impl Into<String>, level: DiagnosticLevel, message: impl Into<String>) -> Self {
        Self { code: code.into(), level, message: message.into() }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureHealth {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub bytes_received: u64,
    pub malformed_packets: u64,
    pub queue_depth: u64,
    pub queue_capacity: u64,
    pub capture_errors: u64,
}

impl CaptureHealth {
    pub fn drop_rate_percent(&self) -> f64 {
        let total = self.packets_received.saturating_add(self.packets_dropped);
        if total == 0 { 0.0 } else { self.packets_dropped as f64 * 100.0 / total as f64 }
    }

    pub fn queue_utilization_percent(&self) -> f64 {
        if self.queue_capacity == 0 { 0.0 } else { self.queue_depth as f64 * 100.0 / self.queue_capacity as f64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_rates_are_safe_for_empty_and_full_queues() {
        let empty = CaptureHealth::default();
        assert_eq!(empty.drop_rate_percent(), 0.0);
        assert_eq!(empty.queue_utilization_percent(), 0.0);

        let health = CaptureHealth { packets_received: 900, packets_dropped: 100, queue_depth: 50, queue_capacity: 100, ..Default::default() };
        assert!((health.drop_rate_percent() - 10.0).abs() < f64::EPSILON);
        assert!((health.queue_utilization_percent() - 50.0).abs() < f64::EPSILON);
    }
}
