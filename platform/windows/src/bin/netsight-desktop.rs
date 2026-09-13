#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod desktop {
    use anyhow::{Context, Result};
    use std::process::{Command, Stdio};
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::WindowBuilder;
    use wry::WebViewBuilder;

    const DASHBOARD_URL: &str = "http://127.0.0.1:8765/";

    pub fn run() -> Result<()> {
        let adapter = select_adapter().context("unable to select a Windows capture adapter")?;
        let agent = start_agent(&adapter).context("unable to start the NetSight capture agent")?;

        let event_loop = EventLoop::new();
        let window = WindowBuilder::new()
            .with_title("NetSight")
            .with_inner_size(tao::dpi::LogicalSize::new(1440.0, 920.0))
            .with_min_inner_size(tao::dpi::LogicalSize::new(1100.0, 700.0))
            .build(&event_loop)
            .context("unable to create NetSight native window")?;

        let _webview = WebViewBuilder::new(&window)
            .with_url(DASHBOARD_URL)
            .context("unable to load NetSight dashboard")?
            .build()
            .context("unable to initialize Windows WebView2")?;

        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;
            match event {
                Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                    let _ = agent.kill();
                    let _ = agent.wait();
                    *control_flow = ControlFlow::Exit;
                }
                _ => {}
            }
        });
    }

    fn select_adapter() -> Result<String> {
        let exe = std::env::current_exe()?;
        let output = Command::new(exe)
            .arg("--list-adapters")
            .output()
            .context("failed to enumerate capture adapters")?;
        if !output.status.success() {
            anyhow::bail!("adapter enumeration failed: {}", String::from_utf8_lossy(&output.stderr));
        }
        let adapters: Vec<Adapter> = serde_json::from_slice(&output.stdout)
            .context("invalid adapter list returned by NetSight agent")?;
        adapters
            .into_iter()
            .next()
            .map(|a| a.name)
            .context("no Npcap capture adapter was found; install Npcap first")
    }

    fn start_agent(adapter: &str) -> Result<std::process::Child> {
        let exe = std::env::current_exe()?;
        let agent = exe.with_file_name("netsight-agent.exe");
        let child = Command::new(agent)
            .env("NETSIGHT_CAPTURE_DEVICE", adapter)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to launch netsight-agent.exe")?;
        Ok(child)
    }

    #[derive(serde::Deserialize)]
    struct Adapter { name: String }
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--list-adapters") {
        let adapters = netsight_windows::list_capture_devices()?;
        let value: Vec<serde_json::Value> = adapters
            .into_iter()
            .map(|d| serde_json::json!({"name": d.name}))
            .collect();
        println!("{}", serde_json::to_string(&value)?);
        return Ok(());
    }
    desktop::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("netsight-desktop is supported on Windows with WebView2 and Npcap.");
}