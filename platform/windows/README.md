# NetSight Windows Desktop

The Windows release contains two native processes:

- `netsight-desktop.exe` — native Tao/WebView2 application shell.
- `netsight-agent.exe` — Npcap capture and local dashboard bridge.

## Runtime prerequisites

- Windows 10/11 x64
- WebView2 Runtime
- Npcap with capture permissions

The desktop shell enumerates Npcap adapters, starts the agent with the selected adapter through `NETSIGHT_CAPTURE_DEVICE`, and hosts the existing NetSight dashboard in a native WebView2 window at `127.0.0.1:8765`.

## Build

```powershell
cargo build --release --bin netsight-desktop --bin netsight-agent --target x86_64-pc-windows-msvc
```

The release package must ship both executables together. The desktop shell terminates its agent child when the native window closes.
