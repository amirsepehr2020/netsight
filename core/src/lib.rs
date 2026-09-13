pub mod analyzer;
pub mod correlation;
pub mod model;
pub mod service_detection;
pub mod traffic;

#[cfg(test)]
mod tests {
    use super::model::{CaptureState, DiagnosticEvent, DiagnosticLevel};

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
}
