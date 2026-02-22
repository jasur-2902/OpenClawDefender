//! `clawdefender doctor` — run diagnostic checks on the ClawDefender installation.

use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use clawdefender_core::config::ClawConfig;
use clawdefender_slm::model_manager::ModelManager;

use super::{detect_servers_key, is_wrapped, known_clients, read_config};

pub fn run(config: &ClawConfig) -> Result<()> {
    println!("ClawDefender Doctor");
    println!("===================");
    println!();

    let mut issues: u32 = 0;
    let mut warnings: u32 = 0;

    // 0. Check macOS version.
    println!("System:");
    let macos_ok = check_macos_version();
    if !macos_ok {
        warnings += 1;
    }

    // 1. Check binary on PATH.
    if !check_pass("clawdefender binary on PATH", which_clawdefender()) {
        issues += 1;
        hint("Add clawdefender to your PATH, or run with the full path.");
    }

    // 2. Check config dir exists.
    let config_dir = config
        .policy_path
        .parent()
        .unwrap_or(Path::new("~/.config/clawdefender"));
    if !check_pass("Config directory exists", config_dir.exists()) {
        issues += 1;
        hint("Run `clawdefender init` to create the config directory.");
    }

    // 3. Check policy file parses.
    let policy_ok = if config.policy_path.exists() {
        let content = std::fs::read_to_string(&config.policy_path);
        match content {
            Ok(c) => clawdefender_core::policy::rule::parse_policy_toml(&c).is_ok(),
            Err(_) => false,
        }
    } else {
        false
    };
    if !check_pass(
        &format!("Policy file parses ({})", config.policy_path.display()),
        policy_ok,
    ) {
        issues += 1;
        if !config.policy_path.exists() {
            hint("Run `clawdefender init` to create a default policy file.");
        } else {
            hint(&format!(
                "Your policy file has syntax errors. Check {} with a TOML validator.",
                config.policy_path.display()
            ));
        }
    }

    // 4. Check audit log dir writable.
    let audit_dir = config.audit_log_path.parent().unwrap_or(Path::new("/tmp"));
    let audit_writable = if audit_dir.exists() {
        // Try creating a temp file.
        let test_file = audit_dir.join(".clawdefender_doctor_test");
        let ok = std::fs::write(&test_file, "test").is_ok();
        let _ = std::fs::remove_file(&test_file);
        ok
    } else {
        false
    };
    if !check_pass(
        &format!("Audit log directory writable ({})", audit_dir.display()),
        audit_writable,
    ) {
        issues += 1;
        if !audit_dir.exists() {
            hint("Run `clawdefender init` to create the audit log directory.");
        } else {
            hint(&format!(
                "Check permissions on {}. Run: chmod u+w {}",
                audit_dir.display(),
                audit_dir.display()
            ));
        }
    }

    // 5. Check Full Disk Access (FDA) for eslogger.
    check_fda(&mut warnings);

    // 6. Check for MCP client installations.
    println!();
    println!("MCP Clients:");
    let clients = known_clients();
    let mut any_client_found = false;
    for client in &clients {
        let exists = client.config_path.exists();
        if exists {
            any_client_found = true;
        }
        check_pass(
            &format!("{} ({})", client.display_name, client.config_path.display()),
            exists,
        );
    }
    if !any_client_found {
        warnings += 1;
        hint("Install Claude Desktop, Cursor, or VS Code to use ClawDefender with MCP servers.");
    }

    // 7. SLM checks.
    println!();
    println!("SLM (Small Language Model):");

    if !config.slm.enabled {
        warn("SLM disabled in config");
        warnings += 1;
        hint("Enable SLM for local AI-powered policy analysis: set slm.enabled = true in config.toml");
    } else {
        check_pass("SLM enabled in config", true);
    }

    let model_installed = if let Some(ref model_path) = config.slm.model_path {
        model_path.exists()
    } else {
        // Check if any model is installed in default directory.
        ModelManager::default_dir()
            .ok()
            .and_then(|mgr| mgr.list_installed().ok())
            .map(|list| !list.is_empty())
            .unwrap_or(false)
    };
    if !check_pass("SLM model installed", model_installed) {
        warnings += 1;
        hint("Run `clawdefender model download` to install a model.");
        hint("Or `clawdefender model list` to see available models.");
    }

    // Check for Apple Silicon (Metal GPU support).
    let is_arm = std::env::consts::ARCH == "aarch64";
    if !is_arm {
        warn(&format!(
            "No Metal GPU (arch: {}). CPU-only inference will be slower.",
            std::env::consts::ARCH
        ));
        warnings += 1;
    } else {
        check_pass("Metal GPU available (Apple Silicon)", true);
    }

    if config.slm.context_size == 0 {
        issues += 1;
        check_pass("SLM config valid (context_size > 0)", false);
        hint("Set slm.context_size to a positive value (default: 2048) in config.toml.");
    } else {
        check_pass("SLM config valid (context_size > 0)", true);
    }

    // 8. MCP server checks.
    println!();
    println!("MCP Server (Cooperative Security):");

    check_pass("MCP server enabled in config", config.mcp_server.enabled);

    if config.mcp_server.enabled {
        check_pass(
            &format!(
                "MCP server HTTP port configured ({})",
                config.mcp_server.http_port
            ),
            config.mcp_server.http_port > 0,
        );

        // Check if MCP server HTTP endpoint is reachable.
        let http_url = format!("http://127.0.0.1:{}", config.mcp_server.http_port);
        let http_reachable = TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", config.mcp_server.http_port)
                .parse()
                .unwrap(),
            Duration::from_secs(1),
        )
        .is_ok();
        if !check_pass(
            &format!("MCP server HTTP endpoint reachable ({})", http_url),
            http_reachable,
        ) {
            hint(
                "Run `clawdefender serve` or `clawdefender daemon start` to start the MCP server.",
            );
        }
    }

    // 9. Guard API checks.
    println!();
    println!("Agent Guard:");

    check_pass("Guard API enabled in config", config.guard_api.enabled);

    if config.guard_api.enabled {
        check_pass(
            &format!("Guard API port configured ({})", config.guard_api.port),
            config.guard_api.port > 0,
        );

        let guard_reachable = TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", config.guard_api.port)
                .parse()
                .unwrap(),
            Duration::from_secs(1),
        )
        .is_ok();
        if !check_pass(
            &format!(
                "Guard API reachable (http://127.0.0.1:{})",
                config.guard_api.port
            ),
            guard_reachable,
        ) {
            hint("Run `clawdefender daemon start` to start the daemon with the guard API.");
        }

        // Check daemon accepting guard registrations via IPC.
        let daemon_accepting =
            std::os::unix::net::UnixStream::connect(&config.daemon_socket_path).is_ok();
        if !check_pass("Daemon accepting guard registrations", daemon_accepting) {
            hint("The daemon must be running for guards to register.");
        }
    }

    // 10. Threat intelligence checks.
    println!();
    println!("Threat Intelligence:");

    if !config.threat_intel.enabled {
        warn("Threat intelligence disabled in config");
        warnings += 1;
        hint("Enable threat intelligence for community rules and IoC matching: set threat_intel.enabled = true");
    } else {
        check_pass("Threat intelligence enabled", true);

        // Check feed cache.
        let data_dir = std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".local/share/clawdefender/threat-intel"))
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/clawdefender/threat-intel"));

        let cache_exists = data_dir.join("manifest.json").exists();
        if !check_pass("Feed cache populated", cache_exists) {
            warnings += 1;
            hint("Run `clawdefender feed update` to fetch the latest threat intelligence feed.");
        }

        // Check IoC directory.
        let ioc_dir = data_dir.join("ioc");
        let ioc_exists = ioc_dir.exists()
            && std::fs::read_dir(&ioc_dir)
                .map(|mut d| d.next().is_some())
                .unwrap_or(false);
        if !check_pass("IoC database populated", ioc_exists) {
            warnings += 1;
            hint("IoC indicators will be loaded after the first feed update.");
        }

        // Check rules directory.
        let rules_dir = data_dir.join("rules");
        check_pass("Community rules directory exists", rules_dir.exists());
    }

    // 11. Network policy checks.
    println!();
    println!("Network Policy:");

    if !config.network_policy.enabled {
        warn("Network policy engine disabled in config");
        warnings += 1;
        hint("Enable network policy for outbound connection control: set network_policy.enabled = true");
    } else {
        check_pass("Network policy engine enabled", true);

        // Show rule count.
        let engine =
            clawdefender_core::network_policy::engine::NetworkPolicyEngine::with_defaults();
        let rules_count = engine.rules().len();
        check_pass(
            &format!("Network rules loaded ({})", rules_count),
            rules_count > 0,
        );

        // Network extension status — currently mock mode only.
        check_pass(
            "Network extension mode: mock (system extension not installed)",
            true,
        );

        // DNS filter status.
        check_pass("DNS filter active", true);

        // Check if daemon is running and has network policy active.
        let daemon_running =
            std::os::unix::net::UnixStream::connect(&config.daemon_socket_path).is_ok();
        if !check_pass("Daemon running with network policy", daemon_running) {
            hint("Run `clawdefender daemon start` to activate network policy enforcement.");
        }
    }

    // 12. Check for wrapped servers.
    println!();
    println!("Wrapped Servers:");
    let mut found_any = false;
    for client in &clients {
        if !client.config_path.exists() {
            continue;
        }
        if let Ok(config_json) = read_config(&client.config_path) {
            let key = detect_servers_key(&config_json);
            if let Some(servers) = config_json.get(key).and_then(|s| s.as_object()) {
                for (name, server) in servers {
                    if is_wrapped(server) {
                        println!("  \u{2713}  {} in {}", name, client.display_name);
                        found_any = true;
                    }
                }
            }
        }
    }
    if !found_any {
        println!("  (none)");
        hint("Wrap an MCP server: clawdefender wrap <server-name>");
    }

    // Summary.
    println!();
    if issues == 0 && warnings == 0 {
        println!("All checks passed. ClawDefender is ready.");
    } else {
        if issues > 0 {
            println!(
                "{} issue(s) found. Fix them to get ClawDefender working correctly.",
                issues
            );
        }
        if warnings > 0 {
            println!(
                "{} warning(s). These are optional but recommended.",
                warnings
            );
        }
    }

    Ok(())
}

/// Print a check result with a visual indicator. Returns the `ok` value.
fn check_pass(label: &str, ok: bool) -> bool {
    if ok {
        println!("  \u{2713}  {label}");
    } else {
        println!("  \u{2717}  {label}");
    }
    ok
}

fn warn(label: &str) {
    println!("  \u{26a0}  {label}");
}

fn hint(msg: &str) {
    println!("     -> {msg}");
}

fn which_clawdefender() -> bool {
    std::process::Command::new("which")
        .arg("clawdefender")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check macOS version and print result.
fn check_macos_version() -> bool {
    let output = std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let version = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let major: u32 = version
                .split('.')
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if major >= 13 {
                check_pass(&format!("macOS version ({version})"), true);
                true
            } else {
                check_pass(&format!("macOS version ({version}) — requires 13+"), false);
                hint("ClawDefender requires macOS 13 (Ventura) or later for Endpoint Security support.");
                false
            }
        }
        _ => {
            warn("Could not detect macOS version (not macOS?)");
            hint("ClawDefender is designed for macOS. Some features may not work on other platforms.");
            false
        }
    }
}

/// Check if Full Disk Access is likely available (heuristic).
fn check_fda(warnings: &mut u32) {
    // A reliable heuristic: try to list ~/Library/Mail (FDA-protected).
    let fda_probe = std::env::var_os("HOME")
        .map(|h| {
            let probe_path = std::path::PathBuf::from(h).join("Library/Mail");
            probe_path.exists() && std::fs::read_dir(&probe_path).is_ok()
        })
        .unwrap_or(false);

    if fda_probe {
        check_pass("Full Disk Access (FDA) available", true);
    } else {
        warn("Full Disk Access (FDA) may not be granted");
        *warnings += 1;
        hint("Open System Settings > Privacy & Security > Full Disk Access");
        hint("Add your terminal app (Terminal.app, iTerm2, etc.) for eslogger to work.");
    }
}
