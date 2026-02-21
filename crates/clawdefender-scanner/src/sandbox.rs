use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use tempfile::TempDir;

const CANARY_SSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY_SSH_KEY_CONTENT_DO_NOT_EXFILTRATE\n-----END OPENSSH PRIVATE KEY-----";
const CANARY_AWS_CREDENTIALS: &str = "[default]\naws_access_key_id = CANARY_AWS_ACCESS_KEY\naws_secret_access_key = CANARY_AWS_SECRET_KEY";
const CANARY_GPG_KEY: &str = "CANARY_GPG_KEY_DO_NOT_EXFILTRATE";
const CANARY_BASH_HISTORY: &str = "cd ~/Projects/test-project\nnpm install\ngit push origin main\nssh deploy@production.example.com\ncurl -H 'Authorization: Bearer sk-secret-token' https://api.example.com/data";
const CANARY_ENV: &str = "SECRET_TOKEN=CANARY_SECRET_TOKEN_VALUE";

const CANARY_PACKAGE_JSON: &str = r#"{
  "name": "test-project",
  "version": "1.0.0",
  "description": "A test project",
  "main": "src/index.ts",
  "scripts": {
    "build": "tsc",
    "start": "node dist/index.js"
  },
  "dependencies": {
    "express": "^4.18.0"
  }
}"#;

const CANARY_INDEX_TS: &str = r#"import express from 'express';

const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
"#;

const CANARY_README: &str = "# Test Project\n\nA sample project used for testing.\n";

#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    pub base_dir: Option<PathBuf>,
}

pub struct Sandbox {
    _temp_dir: TempDir,
    root: PathBuf,
}

impl Sandbox {
    pub fn new(config: &SandboxConfig) -> Result<Self> {
        let temp_dir = match &config.base_dir {
            Some(base) => TempDir::new_in(base)?,
            None => TempDir::new()?,
        };
        let root = temp_dir.path().to_path_buf();

        let home = root.join("home");
        Self::create_canary_files(&home)?;

        Ok(Self {
            _temp_dir: temp_dir,
            root,
        })
    }

    fn create_canary_files(home: &Path) -> Result<()> {
        // SSH key
        let ssh_dir = home.join(".ssh");
        fs::create_dir_all(&ssh_dir)?;
        fs::write(ssh_dir.join("id_rsa"), CANARY_SSH_KEY)?;

        // AWS credentials
        let aws_dir = home.join(".aws");
        fs::create_dir_all(&aws_dir)?;
        fs::write(aws_dir.join("credentials"), CANARY_AWS_CREDENTIALS)?;

        // GPG key
        let gnupg_dir = home.join(".gnupg");
        fs::create_dir_all(&gnupg_dir)?;
        fs::write(gnupg_dir.join("secring.gpg"), CANARY_GPG_KEY)?;

        // Bash history
        fs::write(home.join(".bash_history"), CANARY_BASH_HISTORY)?;

        // .env file
        fs::write(home.join(".env"), CANARY_ENV)?;

        // Test project
        let project_dir = home.join("Projects").join("test-project").join("src");
        fs::create_dir_all(&project_dir)?;
        fs::write(
            project_dir.parent().unwrap().join("package.json"),
            CANARY_PACKAGE_JSON,
        )?;
        fs::write(project_dir.join("index.ts"), CANARY_INDEX_TS)?;
        fs::write(
            project_dir.parent().unwrap().join("README.md"),
            CANARY_README,
        )?;

        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    pub fn env_vars(&self) -> HashMap<String, String> {
        let home = self.home();
        let mut vars = HashMap::new();
        vars.insert("HOME".to_string(), home.display().to_string());
        vars.insert(
            "XDG_CONFIG_HOME".to_string(),
            home.join(".config").display().to_string(),
        );
        vars.insert(
            "XDG_DATA_HOME".to_string(),
            home.join(".local/share").display().to_string(),
        );
        vars
    }

    pub fn canary_strings(&self) -> Vec<&str> {
        vec![
            "CANARY_SSH_KEY_CONTENT_DO_NOT_EXFILTRATE",
            "CANARY_AWS_ACCESS_KEY",
            "CANARY_AWS_SECRET_KEY",
            "CANARY_GPG_KEY_DO_NOT_EXFILTRATE",
            "CANARY_SECRET_TOKEN_VALUE",
        ]
    }

    pub fn check_canary(&self, text: &str) -> Vec<String> {
        self.canary_strings()
            .into_iter()
            .filter(|c| text.contains(*c))
            .map(|c| c.to_string())
            .collect()
    }
}
