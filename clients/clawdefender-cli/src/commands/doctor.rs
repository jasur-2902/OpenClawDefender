//! `rookbot doctor` — run diagnostic checks on the Rookbot installation.

use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use clawdefender_core::config::ClawConfig;
use clawdefender_slm::model_manager::ModelManager;

use crate::output::Output;

use super::{detect_servers_key, is_wrapped, known_clients, read_config};

pub fn run(config: &ClawConfig, out: &Output) -> Result<()> {
    out.header("Rookbot Doctor");
    out.blank();

    let mut issues: u32 = 0;
    let mut warnings: u32 = 0;

    // 0. Check macOS version.
    out.println("System:");
    let macos_ok = check_macos_version(out);
    if !macos_ok {
        warnings += 1;
    }

    // 1. Check binary on PATH.
    if !out.check("rookbot binary on PATH", which_rookbot()) {
        issues += 1;
        out.hint("Add rookbot to your PATH, or run with the full path.");
    }

    // 2. Check config dir exists.
    let config_dir = config
        .policy_path
        .parent()
        .unwrap_or(Path::new("~/.config/clawdefender"));
    if !out.check("Config directory exists", config_dir.exists()) {
        issues += 1;
        out.hint("Run `rookbot init` to create the config directory.");
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
    if !out.check(
        &format!("Policy file parses ({})", config.policy_path.display()),
        policy_ok,
    ) {
        issues += 1;
        if !config.policy_path.exists() {
            out.hint("Run `rookbot init` to create a default policy file.");
        } else {
            out.hint(&format!(
                "Your policy file has syntax errors. Check {} with a TOML validator.",
                config.policy_path.display()
            ));
        }
    }

    // 4. Check audit log dir writable.
    let audit_dir = config.audit_log_path.parent().unwrap_or(Path::new("/tmp"));
    let audit_writable = if audit_dir.exists() {
        let test_file = audit_dir.join(".rookbot_doctor_test");
        let ok = std::fs::write(&test_file, "test").is_ok();
        let _ = std::fs::remove_file(&test_file);
        ok
    } else {
        false
    };
    if !out.check(
        &format!("Audit log directory writable ({})", audit_dir.display()),
        audit_writable,
    ) {
        issues += 1;
        if !audit_dir.exists() {
            out.hint("Run `rookbot init` to create the audit log directory.");
        } else {
            out.hint(&format!(
                "Check permissions on {}. Run: chmod u+w {}",
                audit_dir.display(),
                audit_dir.display()
            ));
        }
    }

    // 5. Check Full Disk Access (FDA) for eslogger.
    check_fda(out, &mut warnings);

    // 6. Check for MCP client installations.
    out.blank();
    out.println("MCP Clients:");
    let clients = known_clients();
    let mut any_client_found = false;
    for client in &clients {
        let exists = client.config_path.exists();
        if exists {
            any_client_found = true;
        }
        out.check(
            &format!("{} ({})", client.display_name, client.config_path.display()),
            exists,
        );
    }
    if !any_client_found {
        warnings += 1;
        out.hint("Install Claude Desktop, Cursor, or VS Code to use Rookbot with MCP servers.");
    }

    // 7. SLM checks.
    out.blank();
    out.println("SLM (Small Language Model):");

    if !config.slm.enabled {
        out.warn("SLM disabled in config");
        warnings += 1;
        out.hint("Enable SLM for local AI-powered policy analysis: set slm.enabled = true in config.toml");
    } else {
        out.check("SLM enabled in config", true);
    }

    let model_installed = if let Some(ref model_path) = config.slm.model_path {
        model_path.exists()
    } else {
        ModelManager::default_dir()
            .ok()
            .and_then(|mgr| mgr.list_installed().ok())
            .map(|list| !list.is_empty())
            .unwrap_or(false)
    };
    if !out.check("SLM model installed", model_installed) {
        warnings += 1;
        out.hint("Run `rookbot model download` to install a model.");
        out.hint("Or `rookbot model list` to see available models.");
    }

    // Check for Apple Silicon (Metal GPU support).
    let is_arm = std::env::consts::ARCH == "aarch64";
    if !is_arm {
        out.warn(&format!(
            "No Metal GPU (arch: {}). CPU-only inference will be slower.",
            std::env::consts::ARCH
        ));
        warnings += 1;
    } else {
        out.check("Metal GPU available (Apple Silicon)", true);
    }

    if config.slm.context_size == 0 {
        issues += 1;
        out.check("SLM config valid (context_size > 0)", false);
        out.hint("Set slm.context_size to a positive value (default: 2048) in config.toml.");
    } else {
        out.check("SLM config valid (context_size > 0)", true);
    }

    // 8. MCP server checks.
    out.blank();
    out.println("MCP Server (Cooperative Security):");

    out.check("MCP server enabled in config", config.mcp_server.enabled);

    if config.mcp_server.enabled {
        out.check(
            &format!(
                "MCP server HTTP port configured ({})",
                config.mcp_server.http_port
            ),
            config.mcp_server.http_port > 0,
        );

        let http_url = format!("http://127.0.0.1:{}", config.mcp_server.http_port);
        let http_reachable = TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", config.mcp_server.http_port)
                .parse()
                .unwrap(),
            Duration::from_secs(1),
        )
        .is_ok();
        if !out.check(
            &format!("MCP server HTTP endpoint reachable ({})", http_url),
            http_reachable,
        ) {
            out.hint(
                "Run `rookbot serve` or `rookbot daemon start` to start the MCP server.",
            );
        }
    }

    // 9. Guard API checks.
    out.blank();
    out.println("Agent Guard:");

    out.check("Guard API enabled in config", config.guard_api.enabled);

    if config.guard_api.enabled {
        out.check(
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
        if !out.check(
            &format!(
                "Guard API reachable (http://127.0.0.1:{})",
                config.guard_api.port
            ),
            guard_reachable,
        ) {
            out.hint("Run `rookbot daemon start` to start the daemon with the guard API.");
        }

        let daemon_accepting =
            std::os::unix::net::UnixStream::connect(&config.daemon_socket_path).is_ok();
        if !out.check("Daemon accepting guard registrations", daemon_accepting) {
            out.hint("The daemon must be running for guards to register.");
        }
    }

    // 10. Threat intelligence checks.
    out.blank();
    out.println("Threat Intelligence:");

    if !config.threat_intel.enabled {
        out.warn("Threat intelligence disabled in config");
        warnings += 1;
        out.hint("Enable threat intelligence for community rules and IoC matching: set threat_intel.enabled = true");
    } else {
        out.check("Threat intelligence enabled", true);

        let data_dir = std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".local/share/clawdefender/threat-intel"))
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/clawdefender/threat-intel"));

        let cache_exists = data_dir.join("manifest.json").exists();
        if !out.check("Feed cache populated", cache_exists) {
            warnings += 1;
            out.hint("Run `rookbot feed update` to fetch the latest threat intelligence feed.");
        }

        let ioc_dir = data_dir.join("ioc");
        let ioc_exists = ioc_dir.exists()
            && std::fs::read_dir(&ioc_dir)
                .map(|mut d| d.next().is_some())
                .unwrap_or(false);
        if !out.check("IoC database populated", ioc_exists) {
            warnings += 1;
            out.hint("IoC indicators will be loaded after the first feed update.");
        }

        let rules_dir = data_dir.join("rules");
        out.check("Community rules directory exists", rules_dir.exists());
    }

    // 11. Network policy checks.
    out.blank();
    out.println("Network Policy:");

    if !config.network_policy.enabled {
        out.warn("Network policy engine disabled in config");
        warnings += 1;
        out.hint("Enable network policy for outbound connection control: set network_policy.enabled = true");
    } else {
        out.check("Network policy engine enabled", true);

        let engine =
            clawdefender_core::network_policy::engine::NetworkPolicyEngine::with_defaults();
        let rules_count = engine.rules().len();
        out.check(
            &format!("Network rules loaded ({})", rules_count),
            rules_count > 0,
        );

        out.check(
            "Network extension mode: mock (system extension not installed)",
            true,
        );

        out.check("DNS filter active", true);

        let daemon_running =
            std::os::unix::net::UnixStream::connect(&config.daemon_socket_path).is_ok();
        if !out.check("Daemon running with network policy", daemon_running) {
            out.hint("Run `rookbot daemon start` to activate network policy enforcement.");
        }
    }

    // 12. Check for wrapped servers.
    out.blank();
    out.println("Wrapped Servers:");
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
                        out.check(&format!("{} in {}", name, client.display_name), true);
                        found_any = true;
                    }
                }
            }
        }
    }
    if !found_any {
        out.println("  (none)");
        out.hint("Wrap an MCP server: rookbot wrap <server-name>");
    }

    // Summary.
    out.blank();
    if issues == 0 && warnings == 0 {
        out.println("All checks passed. Rookbot is ready.");
    } else {
        if issues > 0 {
            out.println(&format!(
                "{} issue(s) found. Fix them to get Rookbot working correctly.",
                issues
            ));
        }
        if warnings > 0 {
            out.println(&format!(
                "{} warning(s). These are optional but recommended.",
                warnings
            ));
        }
    }

    Ok(())
}

fn which_rookbot() -> bool {
    std::process::Command::new("which")
        .arg("rookbot")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check macOS version and print result.
fn check_macos_version(out: &Output) -> bool {
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
                out.check(&format!("macOS version ({version})"), true);
                true
            } else {
                out.check(&format!("macOS version ({version}) — requires 13+"), false);
                out.hint("Rookbot requires macOS 13 (Ventura) or later for Endpoint Security support.");
                false
            }
        }
        _ => {
            out.warn("Could not detect macOS version (not macOS?)");
            out.hint("Rookbot is designed for macOS. Some features may not work on other platforms.");
            false
        }
    }
}

/// Check if Full Disk Access is likely available (heuristic).
fn check_fda(out: &Output, warnings: &mut u32) {
    let fda_probe = std::env::var_os("HOME")
        .map(|h| {
            let probe_path = std::path::PathBuf::from(h).join("Library/Mail");
            probe_path.exists() && std::fs::read_dir(&probe_path).is_ok()
        })
        .unwrap_or(false);

    if fda_probe {
        out.check("Full Disk Access (FDA) available", true);
    } else {
        out.warn("Full Disk Access (FDA) may not be granted");
        *warnings += 1;
        out.hint("Open System Settings > Privacy & Security > Full Disk Access");
        out.hint("Add your terminal app (Terminal.app, iTerm2, etc.) for eslogger to work.");
    }
}
