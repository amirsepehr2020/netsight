#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod desktop {
    use anyhow::{Context, Result};
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::Duration;
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::WindowBuilder;
    use wry::WebViewBuilder;
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

    const DASHBOARD_URL: &str = "http://127.0.0.1:8765/";

    pub fn run() -> Result<()> {
        let mut agent = start_agent().context("unable to start the NetSight capture agent")?;
        thread::sleep(Duration::from_millis(350));
        if let Some(status) = agent.try_wait().context("unable to inspect NetSight agent")? {
            let message = format!(
                "NetSight could not start its capture agent.\n\nExit status: {status}\n\nMake sure Npcap is installed and available, then start NetSight again."
            );
            show_error("NetSight startup failed", &message);
            anyhow::bail!(message);
        }

        let event_loop = EventLoop::new();
        let window = WindowBuilder::new()
            .with_title("NetSight")
            .with_inner_size(tao::dpi::LogicalSize::new(1440.0, 920.0))
            .with_min_inner_size(tao::dpi::LogicalSize::new(1100.0, 700.0))
            .build(&event_loop)
            .context("unable to create NetSight native window")?;

        let _webview = match WebViewBuilder::new().with_url(DASHBOARD_URL).build(&window) {
            Ok(webview) => webview,
            Err(error) => {
                let _ = agent.kill();
                let _ = agent.wait();
                let message = format!(
                    "NetSight could not initialize Microsoft WebView2.\n\n{error}\n\nInstall or repair the WebView2 Runtime, then start NetSight again."
                );
                show_error("NetSight startup failed", &message);
                return Err(error).context("unable to initialize Windows WebView2");
            }
        };

        event_loop.run(move |event, _target, control_flow| {
            *control_flow = ControlFlow::Wait;
            if let Event::WindowEvent { event: WindowEvent::CloseRequested, .. } = event {
                let _ = agent.kill();
                let _ = agent.wait();
                *control_flow = ControlFlow::Exit;
            }
        });
    }

    fn start_agent() -> Result<Child> {
        let exe = std::env::current_exe()?;
        let agent = exe.with_file_name("netsight-agent.exe");
        Command::new(agent)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to launch netsight-agent.exe")
    }

    fn show_error(title: &str, message: &str) {
        let wide = |value: &str| value.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let title = wide(title);
        let message = wide(message);
        unsafe {
            MessageBoxW(std::ptr::null_mut(), message.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
        }
    }
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    desktop::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("netsight-desktop is supported on Windows with WebView2 and Npcap.");
}
