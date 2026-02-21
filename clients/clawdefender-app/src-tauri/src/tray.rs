use std::sync::Mutex;

use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{TrayIcon, TrayIconBuilder},
    AppHandle, Emitter, Manager,
};

use crate::daemon;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Status variants
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayStatus {
    /// Everything is healthy – green.
    Protected,
    /// Minor issues or learning mode – yellow.
    Warning,
    /// Daemon down or critical alert – red.
    Error,
}

// ---------------------------------------------------------------------------
// Global tray handle (set once during setup, read from updater)
// ---------------------------------------------------------------------------

static TRAY_HANDLE: Mutex<Option<TrayIcon>> = Mutex::new(None);

/// Update the tray icon and tooltip to reflect the current status.
pub fn update_tray(app: &AppHandle, status: TrayStatus, tooltip: &str) {
    let icon = make_status_icon(status);
    if let Ok(guard) = TRAY_HANDLE.lock() {
        if let Some(tray) = guard.as_ref() {
            let _ = tray.set_icon(Some(icon));
            let _ = tray.set_tooltip(Some(tooltip));
        }
    }

    // Also update the menu header text.
    let label = match status {
        TrayStatus::Protected => "ClawDefender — Protected",
        TrayStatus::Warning => "ClawDefender — Warning",
        TrayStatus::Error => "ClawDefender — Not Running",
    };
    // Re-build menu with updated header (Tauri v2 menus are immutable, so
    // we replace the whole menu).
    if let Ok(menu) = build_menu(app, label) {
        if let Ok(guard) = TRAY_HANDLE.lock() {
            if let Some(tray) = guard.as_ref() {
                let _ = tray.set_menu(Some(menu));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Setup (called once from lib.rs)
// ---------------------------------------------------------------------------

pub fn setup_tray(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let menu = build_menu(app, "ClawDefender — Starting…")?;
    let icon = make_status_icon(TrayStatus::Warning); // yellow while loading

    let tray = TrayIconBuilder::new()
        .icon(icon)
        .icon_as_template(false) // we need color, not monochrome
        .tooltip("ClawDefender")
        .menu(&menu)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "open_dashboard" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "view_audit" => {
                // Show the main window and emit a navigation event so the
                // frontend routes to the audit log page.
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
                let _ = app.emit("clawdefender://navigate", "/audit");
            }
            "quit" => {
                // Attempt to stop the daemon if the GUI started it.
                let should_stop = app
                    .try_state::<AppState>()
                    .and_then(|state| state.daemon_started_by_gui.lock().ok().map(|g| *g))
                    .unwrap_or(false);

                if should_stop {
                    tracing::info!("Stopping daemon before quit (started by GUI)");
                    let _ = daemon::stop_daemon_process();
                }

                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click { .. } = event {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    // Store the handle so `update_tray` can mutate it later.
    if let Ok(mut guard) = TRAY_HANDLE.lock() {
        *guard = Some(tray);
    }

    // Spawn a background task that polls daemon status and updates the tray.
    let handle = app.clone();
    std::thread::spawn(move || tray_poll_loop(handle));

    Ok(())
}

// ---------------------------------------------------------------------------
// Background poller — reads from AppState (kept fresh by the connection monitor)
// ---------------------------------------------------------------------------

fn tray_poll_loop(app: AppHandle) {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3));

        let (status, tooltip) = probe_status(&app);
        update_tray(&app, status, &tooltip);
    }
}

/// Determine tray status by reading AppState (updated by the connection monitor)
/// with a fallback to a direct socket probe.
fn probe_status(app: &AppHandle) -> (TrayStatus, String) {
    // Prefer reading from AppState (kept fresh by the connection monitor)
    if let Some(state) = app.try_state::<AppState>() {
        if let Ok(connected) = state.daemon_connected.lock() {
            if *connected {
                return (TrayStatus::Protected, "ClawDefender — Protected".into());
            }
        }
    }

    // Fallback: direct socket probe using the canonical path from daemon module
    let socket_path = daemon::socket_path();
    if !socket_path.exists() {
        return (
            TrayStatus::Error,
            "ClawDefender — Daemon not running".into(),
        );
    }

    match std::os::unix::net::UnixStream::connect(&socket_path) {
        Ok(_stream) => (TrayStatus::Protected, "ClawDefender — Protected".into()),
        Err(_) => (
            TrayStatus::Error,
            "ClawDefender — Daemon not running".into(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Menu builder (reused for updates)
// ---------------------------------------------------------------------------

fn build_menu(
    app: &AppHandle,
    header: &str,
) -> Result<tauri::menu::Menu<tauri::Wry>, Box<dyn std::error::Error>> {
    let open_dashboard = MenuItemBuilder::with_id("open_dashboard", "Open Dashboard…")
        .build(app)?;
    let view_audit = MenuItemBuilder::with_id("view_audit", "View Audit Log…").build(app)?;
    let quit =
        MenuItemBuilder::with_id("quit", "Quit ClawDefender").build(app)?;

    let menu = MenuBuilder::new(app)
        .text("header", header)
        .separator()
        .item(&open_dashboard)
        .item(&view_audit)
        .separator()
        .item(&quit)
        .build()?;

    Ok(menu)
}

// ---------------------------------------------------------------------------
// Icon generation — 22×22 RGBA filled circle with status color
// ---------------------------------------------------------------------------

const ICON_SIZE: u32 = 22;

fn make_status_icon(status: TrayStatus) -> Image<'static> {
    let (r, g, b) = match status {
        TrayStatus::Protected => (0x34, 0xD3, 0x99), // green
        TrayStatus::Warning => (0xFB, 0xBF, 0x24),   // amber/yellow
        TrayStatus::Error => (0xEF, 0x44, 0x44),      // red
    };

    let mut pixels = vec![0u8; (ICON_SIZE * ICON_SIZE * 4) as usize];
    let cx = ICON_SIZE as f64 / 2.0;
    let cy = ICON_SIZE as f64 / 2.0;
    let radius = (ICON_SIZE as f64 / 2.0) - 1.0;

    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let dx = x as f64 + 0.5 - cx;
            let dy = y as f64 + 0.5 - cy;
            let dist = (dx * dx + dy * dy).sqrt();

            // Anti-aliased edge: fade over 1px.
            let alpha = if dist <= radius - 0.5 {
                255
            } else if dist <= radius + 0.5 {
                ((radius + 0.5 - dist) * 255.0) as u8
            } else {
                0
            };

            let idx = ((y * ICON_SIZE + x) * 4) as usize;
            pixels[idx] = r;
            pixels[idx + 1] = g;
            pixels[idx + 2] = b;
            pixels[idx + 3] = alpha;
        }
    }

    Image::new_owned(pixels, ICON_SIZE, ICON_SIZE)
}
