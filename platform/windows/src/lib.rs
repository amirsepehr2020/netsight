pub mod capture;
pub mod network;

use netsight_core::model::CaptureState;

pub fn initial_capture_state() -> CaptureState { CaptureState::Idle }

pub use capture::{CaptureConfig, CaptureDevice, CapturedPacket, CaptureEvent, CaptureStats};
#[cfg(windows)]
pub use capture::CaptureSession;
pub use capture::list_capture_devices;
pub use network::{discover_network_context, discover_wifi_context, NetworkAdapter, WifiContext};
