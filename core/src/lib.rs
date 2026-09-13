pub mod dashboard;
pub mod device;
pub mod live_timeline;
pub mod model;
pub mod packet;
pub mod session;
pub mod timeline;
pub mod traffic;

#[cfg(test)]
mod tests {
    use super::model::{CaptureHealth, CaptureState, DiagnosticEvent, DiagnosticLevel};

    #[test]
    fn diagnostic_event_is_constructible() {
        let event = DiagnosticEvent::new("CAPTURE-0001", DiagnosticLevel::Info, "capture initialized");
        assert_eq!(event.code, "CAPTURE-0001");
        assert_eq!(event.level, DiagnosticLevel::Info);
    }

    #[test]
    fn capture_state_starts_idle() {
        assert_eq!(CaptureState::Idle, CaptureState::default());
    }

    #[test]
    fn capture_health_reports_pressure() {
        let health = CaptureHealth { packets_received: 10, packets_dropped: 1, queue_depth: 8, queue_capacity: 10, ..Default::default() };
        assert!((health.drop_rate_percent() - 9.0909090909).abs() < 0.000001);
        assert_eq!(health.queue_utilization_percent(), 80.0);
    }
}

#[cfg(test)]
mod session_tests;
