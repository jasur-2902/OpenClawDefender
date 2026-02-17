//! Platform detection for the auto-installer.

use std::path::PathBuf;

/// Detected operating system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Os {
    MacOS,
    Linux,
    Windows,
}

impl std::fmt::Display for Os {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Os::MacOS => write!(f, "macos"),
            Os::Linux => write!(f, "linux"),
            Os::Windows => write!(f, "windows"),
        }
    }
}

/// Detected CPU architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arch {
    Arm64,
    X86_64,
    Unknown(String),
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::Arm64 => write!(f, "arm64"),
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::Unknown(s) => write!(f, "{s}"),
        }
    }
}

/// Detected user shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shell {
    Zsh,
    Bash,
    Fish,
    Unknown(String),
}

impl std::fmt::Display for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shell::Zsh => write!(f, "zsh"),
            Shell::Bash => write!(f, "bash"),
            Shell::Fish => write!(f, "fish"),
            Shell::Unknown(s) => write!(f, "{s}"),
        }
    }
}

/// Information about the current platform.
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub os: Os,
    pub arch: Arch,
    pub has_homebrew: bool,
    pub shell: Shell,
    pub shell_config_path: PathBuf,
}

impl PlatformInfo {
    /// Detect the current platform information.
    pub fn detect() -> Self {
        let os = Self::detect_os();
        let arch = Self::detect_arch();
        let has_homebrew = Self::detect_homebrew();
        let shell = Self::detect_shell();
        let shell_config_path = Self::detect_shell_config(&shell);

        Self {
            os,
            arch,
            has_homebrew,
            shell,
            shell_config_path,
        }
    }

    /// Returns the platform string used in download URLs (e.g., "macos-arm64").
    pub fn platform_string(&self) -> String {
        format!("{}-{}", self.os, self.arch)
    }

    fn detect_os() -> Os {
        if cfg!(target_os = "macos") {
            Os::MacOS
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else if cfg!(target_os = "windows") {
            Os::Windows
        } else {
            Os::Linux // fallback
        }
    }

    fn detect_arch() -> Arch {
        if cfg!(target_arch = "aarch64") {
            Arch::Arm64
        } else if cfg!(target_arch = "x86_64") {
            Arch::X86_64
        } else {
            Arch::Unknown(std::env::consts::ARCH.to_string())
        }
    }

    fn detect_homebrew() -> bool {
        std::process::Command::new("brew")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn detect_shell() -> Shell {
        if let Ok(shell_env) = std::env::var("SHELL") {
            if shell_env.contains("zsh") {
                return Shell::Zsh;
            } else if shell_env.contains("bash") {
                return Shell::Bash;
            } else if shell_env.contains("fish") {
                return Shell::Fish;
            } else {
                return Shell::Unknown(shell_env);
            }
        }
        Shell::Unknown("unknown".to_string())
    }

    fn detect_shell_config(shell: &Shell) -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        match shell {
            Shell::Zsh => home.join(".zshrc"),
            Shell::Bash => {
                // Prefer .bashrc, fall back to .bash_profile
                let bashrc = home.join(".bashrc");
                if bashrc.exists() {
                    bashrc
                } else {
                    home.join(".bash_profile")
                }
            }
            Shell::Fish => home.join(".config/fish/config.fish"),
            Shell::Unknown(_) => home.join(".profile"),
        }
    }
}
