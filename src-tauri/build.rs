use std::{env, fs, path::PathBuf};

fn main() {
    // Tauri's Windows resource step expects src-tauri/icons/icon.ico.
    // Keep the repository text-only while generating a valid fallback icon
    // during CI/build; the branded SVG assets remain the source of truth for the UI.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
    let icons_dir = manifest_dir.join("icons");
    let icon_path = icons_dir.join("icon.ico");

    if !icon_path.exists() {
        fs::create_dir_all(&icons_dir).expect("failed to create icons directory");
        const ICON: &[u8] = &[
            0,0,1,0,1,0,32,32,0,0,0,0,32,0,109,0,0,0,22,0,0,0,
            137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82,0,0,0,32,
            0,0,0,32,8,6,0,0,0,115,122,122,244,0,0,0,52,73,68,65,84,
            120,156,237,206,65,17,0,48,8,4,177,163,158,234,127,106,9,
            3,69,6,159,172,129,77,221,126,63,139,157,205,57,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,64,146,12,219,120,3,39,230,234,
            203,161,0,0,0,0,73,69,78,68,174,66,96,130,
        ];
        fs::write(&icon_path, ICON).expect("failed to write Windows icon");
    }

    tauri_build::build();
}
