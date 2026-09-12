use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub capture_interface: Option<String>,
    pub auto_capture: bool,
    pub privacy_mode: bool,
    pub max_packets: u32,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            capture_interface: None,
            auto_capture: true,
            privacy_mode: true,
            max_packets: 250,
        }
    }
}

#[derive(Clone, Default)]
pub struct SettingsStore(pub Arc<Mutex<AppSettings>>);

impl SettingsStore {
    pub fn get(&self) -> AppSettings {
        self.0.lock().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn set(&self, settings: AppSettings) -> AppSettings {
        if let Ok(mut current) = self.0.lock() {
            *current = settings;
            current.clone()
        } else {
            AppSettings::default()
        }
    }
}
