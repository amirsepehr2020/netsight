pub mod network;

use netsight_core::model::CaptureState;

pub fn initial_capture_state() -> CaptureState {
    CaptureState::Idle
}

pub use network::{discover_network_context, discover_wifi_context, NetworkAdapter, WifiContext};
