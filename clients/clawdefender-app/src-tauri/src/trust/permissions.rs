use serde::{Deserialize, Serialize};

use super::levels::TrustLevel;

/// Permission categories that trust levels control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    ToolCall,
    FileReadProject,
    FileReadExternal,
    FileWrite,
    ShellExec,
    NetworkAccess,
    SensitivePaths,
}

impl Permission {
    /// The TOML rule category suffix for this permission.
    pub fn category(self) -> &'static str {
        match self {
            Permission::ToolCall => "tool-call",
            Permission::FileReadProject => "file-read-project",
            Permission::FileReadExternal => "file-read-external",
            Permission::FileWrite => "file-write",
            Permission::ShellExec => "shell-exec",
            Permission::NetworkAccess => "network-access",
            Permission::SensitivePaths => "sensitive-paths",
        }
    }

    /// Human-readable label for this permission.
    pub fn label(self) -> &'static str {
        match self {
            Permission::ToolCall => "MCP tool calls",
            Permission::FileReadProject => "Read files in project",
            Permission::FileReadExternal => "Read files elsewhere",
            Permission::FileWrite => "Write files",
            Permission::ShellExec => "Run commands",
            Permission::NetworkAccess => "Access the internet",
            Permission::SensitivePaths => "Read sensitive files",
        }
    }

    /// Brief description for the frontend.
    pub fn description(self) -> &'static str {
        match self {
            Permission::ToolCall => "Control whether this tool can make MCP calls",
            Permission::FileReadProject => "Read files within the current project directory",
            Permission::FileReadExternal => "Read files outside the project directory",
            Permission::FileWrite => "Create or modify files on disk",
            Permission::ShellExec => "Execute shell commands",
            Permission::NetworkAccess => "Make outbound network connections",
            Permission::SensitivePaths => "Access to ~/.ssh, ~/.aws, .env and other secrets",
        }
    }

    /// Whether this permission is always locked (cannot be overridden).
    pub fn is_locked(self) -> bool {
        matches!(self, Permission::SensitivePaths)
    }

    /// Parse from the category string used in rule keys.
    pub fn from_category(s: &str) -> Option<Permission> {
        match s {
            "tool-call" => Some(Permission::ToolCall),
            "file-read-project" => Some(Permission::FileReadProject),
            "file-read-external" => Some(Permission::FileReadExternal),
            "file-write" => Some(Permission::FileWrite),
            "shell-exec" => Some(Permission::ShellExec),
            "network-access" => Some(Permission::NetworkAccess),
            "sensitive-paths" => Some(Permission::SensitivePaths),
            _ => None,
        }
    }

    /// Parse from the frontend permission ID (underscore format).
    pub fn from_frontend_id(s: &str) -> Option<Permission> {
        match s {
            "tool_call" => Some(Permission::ToolCall),
            "file_read_project" => Some(Permission::FileReadProject),
            "file_read_external" => Some(Permission::FileReadExternal),
            "file_write" => Some(Permission::FileWrite),
            "shell_exec" => Some(Permission::ShellExec),
            "network_access" => Some(Permission::NetworkAccess),
            "sensitive_paths" => Some(Permission::SensitivePaths),
            _ => None,
        }
    }

    /// Frontend permission ID (underscore format).
    pub fn frontend_id(self) -> &'static str {
        match self {
            Permission::ToolCall => "tool_call",
            Permission::FileReadProject => "file_read_project",
            Permission::FileReadExternal => "file_read_external",
            Permission::FileWrite => "file_write",
            Permission::ShellExec => "shell_exec",
            Permission::NetworkAccess => "network_access",
            Permission::SensitivePaths => "sensitive_paths",
        }
    }

    /// All configurable permissions (excludes SensitivePaths from user overrides list).
    pub fn configurable() -> &'static [Permission] {
        &[
            Permission::ToolCall,
            Permission::FileReadProject,
            Permission::FileReadExternal,
            Permission::FileWrite,
            Permission::ShellExec,
            Permission::NetworkAccess,
        ]
    }

    /// All permissions including locked ones.
    pub fn all() -> &'static [Permission] {
        &[
            Permission::ToolCall,
            Permission::FileReadProject,
            Permission::FileReadExternal,
            Permission::FileWrite,
            Permission::ShellExec,
            Permission::NetworkAccess,
            Permission::SensitivePaths,
        ]
    }
}

/// The canonical action for each permission at each trust level.
pub fn canonical_action(level: TrustLevel, perm: Permission) -> &'static str {
    if perm == Permission::SensitivePaths {
        return "block";
    }
    match level {
        TrustLevel::Trusted => match perm {
            Permission::ToolCall => "allow",
            Permission::FileReadProject => "allow",
            Permission::FileReadExternal => "allow",
            Permission::FileWrite => "allow",
            Permission::ShellExec => "prompt",
            Permission::NetworkAccess => "allow",
            Permission::SensitivePaths => "block",
        },
        TrustLevel::Standard => match perm {
            Permission::ToolCall => "prompt",
            Permission::FileReadProject => "allow",
            Permission::FileReadExternal => "prompt",
            Permission::FileWrite => "prompt",
            Permission::ShellExec => "prompt",
            Permission::NetworkAccess => "prompt",
            Permission::SensitivePaths => "block",
        },
        TrustLevel::Cautious => match perm {
            Permission::ToolCall => "prompt",
            Permission::FileReadProject => "allow",
            Permission::FileReadExternal => "prompt",
            Permission::FileWrite => "block",
            Permission::ShellExec => "block",
            Permission::NetworkAccess => "prompt",
            Permission::SensitivePaths => "block",
        },
        TrustLevel::Restricted => match perm {
            Permission::ToolCall => "block",
            Permission::FileReadProject => "prompt",
            Permission::FileReadExternal => "block",
            Permission::FileWrite => "block",
            Permission::ShellExec => "block",
            Permission::NetworkAccess => "block",
            Permission::SensitivePaths => "block",
        },
        TrustLevel::Custom => match perm {
            // Custom falls back to Standard defaults
            Permission::ToolCall => "prompt",
            Permission::FileReadProject => "allow",
            Permission::FileReadExternal => "prompt",
            Permission::FileWrite => "prompt",
            Permission::ShellExec => "prompt",
            Permission::NetworkAccess => "prompt",
            Permission::SensitivePaths => "block",
        },
    }
}
