#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CaptureState;

    #[test]
    fn snapshot_serializes_live_capture_state_for_ui() {
        let snapshot = DashboardSnapshot::new(CaptureState::Running, "Wi-Fi");
        let json = snapshot.to_json().unwrap();
        assert!(json.contains("\"state\":\"Running\""));
        assert!(json.contains("\"capture_device\":\"Wi-Fi\""));
        assert!(json.contains("\"devices\":[]"));
        assert!(json.contains("\"flows\":[]"));
    }
}
