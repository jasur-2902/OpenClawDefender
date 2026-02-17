use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

/// Create or show the main dashboard window
pub fn create_main_window(app: &AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok(());
    }

    WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
        .title("ClawDefender")
        .inner_size(1200.0, 800.0)
        .min_inner_size(800.0, 600.0)
        .center()
        .resizable(true)
        .build()
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Create the prompt window (floating, always-on-top)
pub fn create_prompt_window(app: &AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("prompt") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok(());
    }

    WebviewWindowBuilder::new(app, "prompt", WebviewUrl::App("/prompt".into()))
        .title("Security Prompt")
        .inner_size(480.0, 400.0)
        .resizable(false)
        .always_on_top(true)
        .center()
        .build()
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Create the alert window (floating, always-on-top)
pub fn create_alert_window(app: &AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("alert") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok(());
    }

    WebviewWindowBuilder::new(app, "alert", WebviewUrl::App("/alert".into()))
        .title("Security Alert")
        .inner_size(500.0, 450.0)
        .resizable(false)
        .always_on_top(true)
        .center()
        .build()
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Hide the main window (minimize to tray instead of closing)
pub fn hide_main_window(app: &AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.hide().map_err(|e| e.to_string())?;
    }
    Ok(())
}
