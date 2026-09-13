pub mod device;
pub mod live_timeline;
pub mod model;
pub mod packet;
pub mod persistence;
pub mod timeline;
pub mod traffic;

#[cfg(test)]
mod tests {
    use super::model::{CaptureState, DiagnosticEvent, DiagnosticLevel};

    #[test]
    fn diagnostic_event_is_constructible() {
        let event = DiagnosticEvent::new("CAPTURE-0001", DiagnosticLevel::Info, "capture initialized");
        assert_eq!(event.code, "CAPTURE-0001");
    }

    #[test]
    fn capture_state_starts_idle() {
        assert_eq!(CaptureState::Idle, CaptureState::default());
    }
}
