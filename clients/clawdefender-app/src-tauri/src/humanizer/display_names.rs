use std::collections::HashMap;

/// Registry for resolving raw MCP identifiers into human-friendly display names.
#[derive(Debug, Clone)]
pub struct DisplayNameRegistry {
    server_map: HashMap<&'static str, &'static str>,
    tool_map: HashMap<&'static str, &'static str>,
}

impl Default for DisplayNameRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DisplayNameRegistry {
    pub fn new() -> Self {
        let mut server_map = HashMap::new();
        server_map.insert("filesystem-server", "{client}'s file access tool");
        server_map.insert("filesystem", "{client}'s file access tool");
        server_map.insert("server-fetch", "{client}'s web browsing tool");
        server_map.insert("server-git", "{client}'s Git tool");
        server_map.insert("server-postgres", "{client}'s database tool");
        server_map.insert("server-brave-search", "{client}'s search tool");
        server_map.insert("server-sequential-thinking", "{client}'s reasoning tool");
        server_map.insert("server-github", "{client}'s GitHub tool");
        server_map.insert("server-slack", "{client}'s Slack tool");
        server_map.insert("server-memory", "{client}'s memory tool");
        server_map.insert("server-puppeteer", "{client}'s browser automation tool");

        let mut tool_map = HashMap::new();
        tool_map.insert("read_file", "read a file");
        tool_map.insert("write_file", "write to a file");
        tool_map.insert("create_file", "create a file");
        tool_map.insert("execute_command", "run a command");
        tool_map.insert("run_command", "run a command");
        tool_map.insert("list_directory", "browse a folder");
        tool_map.insert("search_files", "search for files");
        tool_map.insert("move_file", "move a file");
        tool_map.insert("delete_file", "delete a file");
        tool_map.insert("fetch", "make an HTTP request");
        tool_map.insert("http_request", "make an HTTP request");
        tool_map.insert("query", "run a database query");
        tool_map.insert("sql_query", "run a database query");
        tool_map.insert("git_status", "check git status");
        tool_map.insert("git_diff", "check git changes");
        tool_map.insert("git_commit", "make a git commit");
        tool_map.insert("list_tools", "list available tools");
        tool_map.insert("create_directory", "create a folder");

        Self {
            server_map,
            tool_map,
        }
    }

    /// Resolve a raw server name to a human-friendly display name.
    /// If `client` is None, uses "Your AI tool" as the client name.
    pub fn resolve_server(&self, server_name: &str, client: Option<&str>) -> String {
        let client_label = client.unwrap_or("Your AI tool");

        if let Some(template) = self.server_map.get(server_name) {
            return template.replace("{client}", client_label);
        }

        // Fallback: clean up common prefixes
        let cleaned = server_name
            .trim_start_matches("mcp-server-")
            .trim_start_matches("server-")
            .trim_start_matches("mcp-");

        if cleaned != server_name {
            format!("{} (via {})", cleaned, client_label)
        } else {
            format!("{} (via {})", server_name, client_label)
        }
    }

    /// Resolve a raw tool name to a human-readable action description.
    pub fn resolve_tool(&self, tool_name: &str) -> String {
        if let Some(desc) = self.tool_map.get(tool_name) {
            return desc.to_string();
        }
        // Fallback: convert snake_case to spaces
        tool_name.replace('_', " ")
    }

    /// Resolve a resource URI/path to a human-readable description.
    pub fn resolve_resource(&self, resource: &str) -> String {
        let home = std::env::var("HOME").unwrap_or_default();

        // SSH keys
        if resource.contains(".ssh/id_rsa")
            || resource.contains(".ssh/id_ed25519")
            || resource.contains(".ssh/id_ecdsa")
        {
            return "your SSH keys".to_string();
        }

        // AWS credentials
        if resource.contains(".aws/credentials") || resource.contains(".aws/config") {
            return "your AWS credentials".to_string();
        }

        // Env files
        if resource.ends_with(".env") || resource.contains(".env.") {
            return format_path_short(resource, &home);
        }

        // Browser data
        if resource.contains("Cookies")
            || resource.contains("Login Data")
            || resource.contains("cookies.sqlite")
            || resource.contains("logins.json")
        {
            return "your browser credentials".to_string();
        }

        // System files
        if resource.starts_with("/etc/") {
            return "a system file".to_string();
        }

        // Project files
        if !home.is_empty() {
            if resource.contains("/Projects/")
                || resource.contains("/workspace/")
                || resource.contains("/src/")
                || resource.contains("/code/")
            {
                return format!("a file in your project ({})", format_path_short(resource, &home));
            }
        }

        format_path_short(resource, &home)
    }
}

/// Shorten a path for display by replacing $HOME with ~.
fn format_path_short(path: &str, home: &str) -> String {
    if !home.is_empty() && path.starts_with(home) {
        format!("~{}", &path[home.len()..])
    } else {
        path.to_string()
    }
}
