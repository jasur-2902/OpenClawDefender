use std::sync::Mutex;

use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{TrayIcon, TrayIconBuilder},
    AppHandle, Emitter, Manager,
};

use crate::daemon;
use crate::state::AppState;

/// Data extracted from AppState for building the tray menu.
struct TrayMenuData {
    servers_proxied: u32,
    pending_prompts: usize,
    blocked_today: usize,
    daemon_connected: bool,
}

fn collect_tray_data(app: &AppHandle) -> TrayMenuData {
    let mut data = TrayMenuData {
        servers_proxied: 0,
        pending_prompts: 0,
        blocked_today: 0,
        daemon_connected: false,
    };

    if let Some(state) = app.try_state::<AppState>() {
        if let Ok(connected) = state.daemon_connected.lock() {
            data.daemon_connected = *connected;
        }
        if let Ok(cached) = state.cached_status.lock() {
            if let Some(ref status) = *cached {
                data.servers_proxied = status.servers_proxied;
            }
        }
        if let Ok(prompts) = state.pending_prompts.lock() {
            data.pending_prompts = prompts.len();
        }
        if let Ok(events) = state.event_buffer.lock() {
            let cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
            data.blocked_today = events
                .iter()
                .filter(|e| {
                    let dominated = matches!(
                        e.decision.as_str(),
                        "denied" | "blocked" | "block"
                    );
                    if !dominated {
                        return false;
                    }
                    chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                        .map(|t| t >= cutoff)
                        .unwrap_or(false)
                })
                .count();
        }
    }

    data
}

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
pub fn update_tray(app: &AppHandle, status: TrayStatus) {
    let data = collect_tray_data(app);
    let icon = make_status_icon(status);

    let tooltip = match status {
        TrayStatus::Protected => {
            format!("ClawDefender — Protected ({} servers)", data.servers_proxied)
        }
        TrayStatus::Warning => "ClawDefender — Warning".to_string(),
        TrayStatus::Error => "ClawDefender — Not Running".to_string(),
    };

    if let Ok(guard) = TRAY_HANDLE.lock() {
        if let Some(tray) = guard.as_ref() {
            let _ = tray.set_icon(Some(icon));
            let _ = tray.set_tooltip(Some(&tooltip));
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
    if let Ok(menu) = build_menu(app, label, &data) {
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
    let initial_data = TrayMenuData {
        servers_proxied: 0,
        pending_prompts: 0,
        blocked_today: 0,
        daemon_connected: false,
    };
    let menu = build_menu(app, "ClawDefender — Starting\u{2026}", &initial_data)?;
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
            "view_timeline" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
                let _ = app.emit("clawdefender://navigate", "/timeline");
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
            "toggle_protection" => {
                let connected = app
                    .try_state::<AppState>()
                    .and_then(|state| state.daemon_connected.lock().ok().map(|g| *g))
                    .unwrap_or(false);

                if connected {
                    tracing::info!("Pausing protection (stopping daemon)");
                    let _ = daemon::stop_daemon_process();
                } else {
                    tracing::info!("Resuming protection (starting daemon)");
                    let _ = daemon::start_daemon_process();
                }
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

        let status = probe_status(&app);
        update_tray(&app, status);
    }
}

/// Determine tray status by reading AppState (updated by the connection monitor)
/// with a fallback to a direct socket probe.
fn probe_status(app: &AppHandle) -> TrayStatus {
    // Prefer reading from AppState (kept fresh by the connection monitor)
    if let Some(state) = app.try_state::<AppState>() {
        if let Ok(connected) = state.daemon_connected.lock() {
            if *connected {
                return TrayStatus::Protected;
            }
        }
    }

    // Fallback: direct socket probe using the canonical path from daemon module
    let socket_path = daemon::socket_path();
    if !socket_path.exists() {
        return TrayStatus::Error;
    }

    match std::os::unix::net::UnixStream::connect(&socket_path) {
        Ok(_stream) => TrayStatus::Protected,
        Err(_) => TrayStatus::Error,
    }
}

// ---------------------------------------------------------------------------
// Menu builder (reused for updates)
// ---------------------------------------------------------------------------

fn build_menu(
    app: &AppHandle,
    header: &str,
    data: &TrayMenuData,
) -> Result<tauri::menu::Menu<tauri::Wry>, Box<dyn std::error::Error>> {
    let servers_label = format!("{} servers protected", data.servers_proxied);
    let servers_info = MenuItemBuilder::with_id("info_servers", &servers_label)
        .enabled(false)
        .build(app)?;

    let open_dashboard = MenuItemBuilder::with_id("open_dashboard", "Open Dashboard\u{2026}")
        .build(app)?;
    let view_timeline = MenuItemBuilder::with_id("view_timeline", "View Timeline\u{2026}")
        .build(app)?;
    let view_audit = MenuItemBuilder::with_id("view_audit", "View Audit Log\u{2026}")
        .build(app)?;

    let pause_label = if data.daemon_connected {
        "Pause Protection"
    } else {
        "Resume Protection"
    };
    let pause_resume = MenuItemBuilder::with_id("toggle_protection", pause_label).build(app)?;

    let quit = MenuItemBuilder::with_id("quit", "Quit ClawDefender").build(app)?;

    let mut builder = MenuBuilder::new(app)
        .text("header", header)
        .item(&servers_info)
        .separator();

    // Show pending prompts if any
    if data.pending_prompts > 0 {
        let prompts_label = format!("\u{26A0} {} prompts waiting", data.pending_prompts);
        let prompts_item = MenuItemBuilder::with_id("info_prompts", &prompts_label)
            .enabled(false)
            .build(app)?;
        builder = builder.item(&prompts_item);
    }

    // Show blocked count
    let blocked_label = format!("{} blocked today", data.blocked_today);
    let blocked_item = MenuItemBuilder::with_id("info_blocked", &blocked_label)
        .enabled(false)
        .build(app)?;
    builder = builder.item(&blocked_item);

    let menu = builder
        .separator()
        .item(&open_dashboard)
        .item(&view_timeline)
        .item(&view_audit)
        .separator()
        .item(&pause_resume)
        .separator()
        .item(&quit)
        .build()?;

    Ok(menu)
}

// ---------------------------------------------------------------------------
// Icon generation — 22×22 RGBA shield shape with status color
// ---------------------------------------------------------------------------

const ICON_SIZE: u32 = 22;

/// Test whether point (px, py) lies inside a shield shape centered at (cx, cy)
/// with the given half-width and height.  The shield has a flat top, straight
/// sides that taper, and a pointed bottom.
fn point_in_shield(px: f64, py: f64, cx: f64, cy: f64, half_w: f64, height: f64) -> f64 {
    let top = cy - height * 0.45;
    let bottom = cy + height * 0.55;
    let mid_y = top + (bottom - top) * 0.55; // where taper begins

    // Normalised y position
    if py < top || py > bottom {
        return -1.0; // outside
    }

    // Determine the half-width of the shield at this y
    let hw = if py <= mid_y {
        // Upper portion: nearly straight sides, slight outward curve
        let t = (py - top) / (mid_y - top);
        half_w * (0.95 + 0.05 * (t * std::f64::consts::PI).sin())
    } else {
        // Lower portion: taper to a point
        let t = (py - mid_y) / (bottom - mid_y);
        half_w * (1.0 - t)
    };

    // Signed distance from edge (positive = inside)
    hw - (px - cx).abs()
}

fn make_status_icon(status: TrayStatus) -> Image<'static> {
    let (r, g, b) = match status {
        TrayStatus::Protected => (0x34, 0xD3, 0x99), // green
        TrayStatus::Warning => (0xFB, 0xBF, 0x24),   // amber/yellow
        TrayStatus::Error => (0xEF, 0x44, 0x44),      // red
    };

    // Border color: slightly darker version of the fill
    let (br, bg, bb) = (
        (r as f64 * 0.7) as u8,
        (g as f64 * 0.7) as u8,
        (b as f64 * 0.7) as u8,
    );

    let mut pixels = vec![0u8; (ICON_SIZE * ICON_SIZE * 4) as usize];
    let cx = ICON_SIZE as f64 / 2.0;
    let cy = ICON_SIZE as f64 / 2.0;
    let half_w = (ICON_SIZE as f64 / 2.0) - 1.5;
    let height = ICON_SIZE as f64 - 2.0;

    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let px = x as f64 + 0.5;
            let py = y as f64 + 0.5;
            let dist = point_in_shield(px, py, cx, cy, half_w, height);

            let idx = ((y * ICON_SIZE + x) * 4) as usize;

            if dist < -0.5 {
                // Outside — transparent
                continue;
            }

            if dist < 0.5 {
                // Anti-aliased edge (border zone)
                let alpha = ((dist + 0.5) * 255.0).clamp(0.0, 255.0) as u8;
                pixels[idx] = br;
                pixels[idx + 1] = bg;
                pixels[idx + 2] = bb;
                pixels[idx + 3] = alpha;
            } else if dist < 1.8 {
                // Border ring
                pixels[idx] = br;
                pixels[idx + 1] = bg;
                pixels[idx + 2] = bb;
                pixels[idx + 3] = 255;
            } else {
                // Fill
                pixels[idx] = r;
                pixels[idx + 1] = g;
                pixels[idx + 2] = b;
                pixels[idx + 3] = 255;
            }
        }
    }

    Image::new_owned(pixels, ICON_SIZE, ICON_SIZE)
}
