# NetSight Windows Release

Current release candidate: **0.1.0-rc.1**.

## Payload

- `netsight-desktop.exe` — native Windows shell
- `netsight-agent.exe` — capture/analysis agent
- `ui/` — bundled NetSight interface
- `netsight.ico` — generated from the canonical NetSight app icon

## Prerequisites

- Windows 10/11 x64
- Npcap 1.79 or newer, installed before capture
- Microsoft Edge WebView2 Evergreen Runtime

The installer checks for Npcap and WebView2. It does not silently install third-party networking components.

## Release pipeline

`.github/workflows/release-windows.yml` builds both binaries, stages the UI, converts the canonical SVG app icon to ICO, creates the Inno Setup installer, and publishes a prerelease when a `v*` tag is pushed.

## RC status

The RC is release-engineering complete at the repository level. A distributable installer is produced by the Windows GitHub Actions runner; final acceptance still requires a real Windows machine with Npcap and WebView2, followed by capture, install/uninstall, shortcut, adapter selection, and upgrade tests.
