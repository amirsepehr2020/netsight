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
