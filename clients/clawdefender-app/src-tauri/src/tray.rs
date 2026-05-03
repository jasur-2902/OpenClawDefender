use std::sync::Mutex;

use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{TrayIcon, TrayIconBuilder},
    AppHandle, Emitter, Manager,
};

use crate::daemon;
use crate::state::{AppState, MonitoringMode};

/// Data extracted from AppState for building the tray menu.
struct TrayMenuData {
    servers_proxied: u32,
    pending_prompts: usize,
    blocked_today: usize,
    daemon_connected: bool,
    cpu_percent: f32,
    memory_mb: u64,
    events_per_sec: f64,
    monitoring_mode: MonitoringMode,
    is_paused: bool,
    pause_remaining_min: u64,
}

fn collect_tray_data(app: &AppHandle) -> TrayMenuData {
    let mut data = TrayMenuData {
        servers_proxied: 0,
        pending_prompts: 0,
        blocked_today: 0,
        daemon_connected: false,
        cpu_percent: 0.0,
        memory_mb: 0,
        events_per_sec: 0.0,
        monitoring_mode: MonitoringMode::Balanced,
        is_paused: false,
        pause_remaining_min: 0,
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

            // Estimate events per second from recent buffer
            let recent_cutoff = chrono::Utc::now() - chrono::Duration::seconds(5);
            let recent_count = events.iter().rev().take(100).filter(|e| {
                chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                    .map(|t| t >= recent_cutoff)
                    .unwrap_or(false)
            }).count();
            data.events_per_sec = recent_count as f64 / 5.0;
        }
        if let Ok(mode) = state.monitoring_mode.lock() {
            data.monitoring_mode = *mode;
        }
        if let Ok(pause) = state.pause_until.lock() {
            if let Some(until) = *pause {
                let now = chrono::Utc::now();
                if now < until {
                    data.is_paused = true;
                    data.pause_remaining_min = ((until - now).num_seconds().max(0) as u64) / 60;
                }
            }
        }

        // Quick process stats for tray display
        {
            use sysinfo::{System, Pid};
            let mut sys = System::new();
            let pid = Pid::from_u32(std::process::id());
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
            if let Some(proc_info) = sys.process(pid) {
                data.cpu_percent = proc_info.cpu_usage();
                data.memory_mb = proc_info.memory() / (1024 * 1024);
            }
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
            format!("RookBot — Protected ({} servers)", data.servers_proxied)
        }
        TrayStatus::Warning => "RookBot — Warning".to_string(),
        TrayStatus::Error => "RookBot — Not Running".to_string(),
    };

    if let Ok(guard) = TRAY_HANDLE.lock() {
        if let Some(tray) = guard.as_ref() {
            let _ = tray.set_icon(Some(icon));
            let _ = tray.set_tooltip(Some(&tooltip));
        }
    }

    // Also update the menu header text.
    let label = match status {
        TrayStatus::Protected => "RookBot — Protected",
        TrayStatus::Warning => "RookBot — Warning",
        TrayStatus::Error => "RookBot — Not Running",
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
        cpu_percent: 0.0,
        memory_mb: 0,
        events_per_sec: 0.0,
        monitoring_mode: MonitoringMode::Balanced,
        is_paused: false,
        pause_remaining_min: 0,
    };
    let menu = build_menu(app, "RookBot — Starting\u{2026}", &initial_data)?;
    let icon = make_status_icon(TrayStatus::Warning); // yellow while loading

    let tray = TrayIconBuilder::new()
        .icon(icon)
        .icon_as_template(false) // we need color, not monochrome
        .tooltip("RookBot")
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
                let _ = app.emit("rookbot://navigate", "/timeline");
            }
            "view_audit" => {
                // Show the main window and emit a navigation event so the
                // frontend routes to the audit log page.
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
                let _ = app.emit("rookbot://navigate", "/audit");
            }
            "toggle_protection" => {
                // Check if monitoring is currently paused
                let is_paused = app
                    .try_state::<AppState>()
                    .and_then(|state| {
                        state.pause_until.lock().ok().map(|p| {
                            p.map(|until| chrono::Utc::now() < until).unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);

                if is_paused {
                    // Resume monitoring
                    if let Some(state) = app.try_state::<AppState>() {
                        if let Ok(mut p) = state.pause_until.lock() {
                            *p = None;
                        }
                    }
                    tracing::info!("Monitoring resumed from tray");
                } else {
                    let connected = app
                        .try_state::<AppState>()
                        .and_then(|state| state.daemon_connected.lock().ok().map(|g| *g))
                        .unwrap_or(false);

                    if connected {
                        // Pause for 1 hour
                        let resume_at = chrono::Utc::now() + chrono::Duration::hours(1);
                        if let Some(state) = app.try_state::<AppState>() {
                            if let Ok(mut p) = state.pause_until.lock() {
                                *p = Some(resume_at);
                            }
                        }
                        tracing::info!("Monitoring paused for 1 hour from tray");
                    } else {
                        tracing::info!("Resuming protection (starting daemon)");
                        let _ = daemon::start_daemon_process();
                    }
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

    // Resource usage line
    let resource_label = format!(
        "CPU: {:.1}%  Mem: {} MB",
        data.cpu_percent, data.memory_mb
    );
    let resource_info = MenuItemBuilder::with_id("info_resources", &resource_label)
        .enabled(false)
        .build(app)?;

    let events_label = format!("Events: {:.0}/sec", data.events_per_sec);
    let events_info = MenuItemBuilder::with_id("info_events", &events_label)
        .enabled(false)
        .build(app)?;

    // Mode and pause status
    let mode_label = format!("Mode: {}", data.monitoring_mode);
    let mode_info = MenuItemBuilder::with_id("info_mode", &mode_label)
        .enabled(false)
        .build(app)?;

    let open_dashboard = MenuItemBuilder::with_id("open_dashboard", "Open Dashboard\u{2026}")
        .build(app)?;
    let view_timeline = MenuItemBuilder::with_id("view_timeline", "View Timeline\u{2026}")
        .build(app)?;
    let view_audit = MenuItemBuilder::with_id("view_audit", "View Audit Log\u{2026}")
        .build(app)?;

    let pause_label = if data.is_paused {
        format!("Resume Monitoring ({}m left)", data.pause_remaining_min)
    } else if data.daemon_connected {
        "Pause for 1 hour".to_string()
    } else {
        "Resume Protection".to_string()
    };
    let pause_resume = MenuItemBuilder::with_id("toggle_protection", &pause_label).build(app)?;

    let quit = MenuItemBuilder::with_id("quit", "Quit RookBot").build(app)?;

    let mut builder = MenuBuilder::new(app)
        .text("header", header)
        .item(&resource_info)
        .item(&events_info)
        .separator()
        .item(&mode_info)
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

    // Show pause indicator
    if data.is_paused {
        let paused_item = MenuItemBuilder::with_id("info_paused", "Monitoring paused")
            .enabled(false)
            .build(app)?;
        builder = builder.item(&paused_item);
    }

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
// Icon generation — shield+rook tray icon colorized per status
// ---------------------------------------------------------------------------

/// Embed the shield+rook tray icon PNG (44×44 retina) at compile time.
/// The template uses two shades of black: the shield body (#000) and the
/// rook cutout (#444).  We colorize them to the status color at runtime.
const TRAY_TEMPLATE: &[u8] = include_bytes!("../icons/icon-tray.png");

fn make_status_icon(status: TrayStatus) -> Image<'static> {
    let (r, g, b) = match status {
        TrayStatus::Protected => (0x34, 0xD3, 0x99), // green
        TrayStatus::Warning => (0xFB, 0xBF, 0x24),   // amber/yellow
        TrayStatus::Error => (0xEF, 0x44, 0x44),      // red
    };

    // Darker shade for the rook silhouette inside the shield
    let (dr, dg, db) = (
        (r as f64 * 0.40) as u8,
        (g as f64 * 0.40) as u8,
        (b as f64 * 0.40) as u8,
    );

    let template = Image::from_bytes(TRAY_TEMPLATE).expect("embedded tray PNG is valid");
    let rgba = template.rgba();
    let w = template.width();
    let h = template.height();

    let mut pixels = rgba.to_vec();
    for chunk in pixels.chunks_exact_mut(4) {
        let alpha = chunk[3];
        if alpha > 0 {
            // The rook cutout is lighter gray (#444), the shield is black (#000).
            // Use brightness to distinguish them.
            let brightness = chunk[0].max(chunk[1]).max(chunk[2]);
            if brightness > 0x20 {
                // Rook interior — darker shade
                chunk[0] = dr;
                chunk[1] = dg;
                chunk[2] = db;
            } else {
                // Shield body — full status color
                chunk[0] = r;
                chunk[1] = g;
                chunk[2] = b;
            }
        }
    }

    Image::new_owned(pixels, w, h)
}
