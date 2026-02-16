//! Eslogger child process manager.
//!
//! Manages the lifecycle of the `eslogger` subprocess that streams Endpoint
//! Security events as NDJSON.

#[cfg(target_os = "macos")]
mod platform {
    use anyhow::{Context, Result};
    use clawdefender_core::event::os::OsEvent;
    use futures::stream::{Stream, StreamExt};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::{Child, Command};
    use tokio_stream::wrappers::LinesStream;
    use tracing::{debug, warn};

    use crate::eslogger::parser::parse_event;

    /// Manages a running eslogger child process.
    pub struct EsloggerManager {
        child: Option<Child>,
        subscribed_events: Vec<String>,
    }

    impl EsloggerManager {
        /// Spawn a new eslogger process subscribing to the given event types.
        pub fn spawn(events: &[&str]) -> Result<Self> {
            let subscribed = events.iter().map(|e| e.to_string()).collect::<Vec<_>>();

            let mut cmd = Command::new("sudo");
            cmd.arg("eslogger");
            for event in events {
                cmd.arg(event);
            }
            cmd.arg("--format").arg("json");
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::null());
            cmd.kill_on_drop(true);

            let child = cmd.spawn().context("failed to spawn eslogger process")?;
            debug!(events = ?subscribed, "eslogger process spawned");

            Ok(Self {
                child: Some(child),
                subscribed_events: subscribed,
            })
        }

        /// Returns a stream of parsed OsEvents from the eslogger stdout.
        pub fn event_stream(
            &mut self,
        ) -> Result<impl Stream<Item = Result<OsEvent, anyhow::Error>>> {
            let child = self
                .child
                .as_mut()
                .context("eslogger child process not available")?;
            let stdout = child
                .stdout
                .take()
                .context("eslogger stdout already taken")?;

            let reader = BufReader::new(stdout);
            let lines = LinesStream::new(reader.lines());

            let stream = lines.filter_map(|line_result: Result<String, std::io::Error>| async move {
                match line_result {
                    Ok(line) => {
                        if line.trim().is_empty() {
                            return None;
                        }
                        match parse_event(&line) {
                            Ok(es_event) => {
                                Some(Ok(OsEvent::from(es_event)))
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to parse eslogger line");
                                None
                            }
                        }
                    }
                    Err(e) => Some(Err(anyhow::Error::from(e))),
                }
            });

            Ok(stream)
        }

        /// Kill the eslogger child process.
        pub async fn kill(&mut self) -> Result<()> {
            if let Some(ref mut child) = self.child {
                child.kill().await.context("failed to kill eslogger")?;
                debug!("eslogger process killed");
            }
            self.child = None;
            Ok(())
        }

        /// Check whether the eslogger child process is still alive.
        pub fn is_alive(&mut self) -> bool {
            match self.child {
                Some(ref mut child) => child.try_wait().ok().flatten().is_none(),
                None => false,
            }
        }

        /// Returns the event types this manager subscribes to.
        pub fn subscribed_events(&self) -> &[String] {
            &self.subscribed_events
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use anyhow::Result;

    /// Manages a running eslogger child process.
    pub struct EsloggerManager {
        subscribed_events: Vec<String>,
    }

    impl EsloggerManager {
        /// Spawn a new eslogger process. Not available on non-macOS platforms.
        pub fn spawn(events: &[&str]) -> Result<Self> {
            let _ = events;
            anyhow::bail!("eslogger is only available on macOS with Endpoint Security entitlements")
        }

        /// Check whether the eslogger child process is still alive.
        pub fn is_alive(&self) -> bool {
            false
        }

        /// Returns the event types this manager subscribes to.
        pub fn subscribed_events(&self) -> &[String] {
            &self.subscribed_events
        }
    }
}

pub use platform::EsloggerManager;
