use std::{env, fs, path::PathBuf};

fn main() {
    // Generate a minimal, valid 32-bit ICO for CI builds when no checked-in
    // icon is present. The previous PNG-backed placeholder had invalid CRC data.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
    let icons_dir = manifest_dir.join("icons");
    let icon_path = icons_dir.join("icon.ico");

    if !icon_path.exists() {
        fs::create_dir_all(&icons_dir).expect("failed to create icons directory");
        const ICON: &[u8] = &[
            0,0,1,0,1,0,1,1,0,0,1,0,32,0,48,0,0,0,22,0,0,0,
            40,0,0,0,1,0,0,0,2,0,0,0,1,0,32,0,0,0,0,0,4,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,193,242,53,255,0,0,0,0,
        ];
        fs::write(&icon_path, ICON).expect("failed to write Windows icon");
    }

    tauri_build::build();
}
