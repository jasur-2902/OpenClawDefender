//! Eslogger child process manager.
//!
//! Manages the lifecycle of the `eslogger` subprocess that streams Endpoint
//! Security events as NDJSON, with pre-filtering, crash recovery, FDA
//! detection, and graceful shutdown.

#[cfg(target_os = "macos")]
mod platform {
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result};
    use clawdefender_core::event::os::OsEvent;
    use futures::stream::StreamExt;
    use nix::sys::signal::{self, Signal};
    use nix::unistd::Pid;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::{Child, Command};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::LinesStream;
    use tracing::{debug, error, info, warn};

    use crate::eslogger::filter::EventPreFilter;
    use crate::eslogger::parser::parse_event;

    /// Default channel capacity for the event output channel.
    const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;

    /// Maximum backoff delay for crash recovery.
    const MAX_BACKOFF: Duration = Duration::from_secs(60);

    /// Backoff resets after this duration of stable running.
    const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(300);

    /// Initial backoff delay.
    const INITIAL_BACKOFF: Duration = Duration::from_secs(2);

    /// Stale timeout: restart if no events for this long while process is alive.
    const STALE_EVENT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Manages a running eslogger child process with crash recovery and filtering.
    pub struct EsloggerManager {
        subscribed_events: Vec<String>,
        shutdown: Arc<AtomicBool>,
    }

    impl EsloggerManager {
        /// Check macOS version is >= 13.0. Returns an error if not.
        pub async fn check_macos_version() -> Result<()> {
            let output = tokio::process::Command::new("sw_vers")
                .arg("-productVersion")
                .output()
                .await
                .context("failed to run sw_vers")?;

            let version_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            parse_and_check_version(&version_str)
        }

        /// Check that the eslogger binary exists at the expected path.
        pub fn check_eslogger_binary() -> Result<()> {
            let path = Path::new("/usr/bin/eslogger");
            if path.exists() {
                Ok(())
            } else {
                anyhow::bail!(
                    "eslogger binary not found at /usr/bin/eslogger. \
                     Ensure macOS 13.0+ is installed."
                )
            }
        }

        /// Check whether Full Disk Access is granted by attempting to read a
        /// TCC-protected path.
        pub fn check_fda() -> bool {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/root".to_string());
            let tcc_path = format!("{home}/Library/Mail");
            // If we can read the directory, FDA is likely granted
            std::fs::read_dir(&tcc_path).is_ok()
        }

        /// Return human-readable FDA setup instructions.
        pub fn fda_instructions() -> String {
            "Full Disk Access is required for eslogger to monitor system events.\n\
             \n\
             To grant Full Disk Access:\n\
             1. Open System Settings (System Preferences on older macOS)\n\
             2. Go to Privacy & Security > Full Disk Access\n\
             3. Click the lock icon and authenticate\n\
             4. Add the ClawDefender daemon (or Terminal.app for development)\n\
             5. Restart ClawDefender"
                .to_string()
        }

        /// Spawn a new eslogger process with pre-filtering, crash recovery, and
        /// channel-based output.
        ///
        /// Returns a receiver for filtered OS events.
        pub fn spawn(
            events: &[&str],
            channel_capacity: Option<usize>,
            ignore_processes: &[String],
            ignore_paths: &[String],
        ) -> Result<(Self, mpsc::Receiver<OsEvent>)> {
            let subscribed = events.iter().map(|e| e.to_string()).collect::<Vec<_>>();
            let capacity = channel_capacity.unwrap_or(DEFAULT_CHANNEL_CAPACITY);
            let shutdown = Arc::new(AtomicBool::new(false));

            let manager = Self {
                subscribed_events: subscribed.clone(),
                shutdown: shutdown.clone(),
            };

            let (tx, rx) = mpsc::channel(capacity);

            // Spawn the supervisor task that handles crash recovery
            let events_clone = subscribed;
            let ignore_procs = ignore_processes.to_vec();
            let ignore_paths = ignore_paths.to_vec();
            tokio::spawn(async move {
                supervisor_loop(events_clone, tx, shutdown, &ignore_procs, &ignore_paths).await;
            });

            Ok((manager, rx))
        }

        /// Signal the eslogger process to shut down gracefully.
        pub fn shutdown(&self) {
            self.shutdown.store(true, Ordering::SeqCst);
        }

        /// Check whether the manager has been signalled to shut down.
        pub fn is_shutting_down(&self) -> bool {
            self.shutdown.load(Ordering::SeqCst)
        }

        /// Returns the event types this manager subscribes to.
        pub fn subscribed_events(&self) -> &[String] {
            &self.subscribed_events
        }
    }

    /// Spawn the eslogger child process.
    fn spawn_eslogger(events: &[String]) -> Result<Child> {
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
        debug!(events = ?events, "eslogger process spawned");
        Ok(child)
    }

    /// Supervisor loop that spawns eslogger, reads events, applies pre-filtering,
    /// and restarts on crashes with exponential backoff.
    async fn supervisor_loop(
        events: Vec<String>,
        tx: mpsc::Sender<OsEvent>,
        shutdown: Arc<AtomicBool>,
        ignore_processes: &[String],
        ignore_paths: &[String],
    ) {
        let mut backoff = ExponentialBackoff::new(INITIAL_BACKOFF, MAX_BACKOFF, BACKOFF_RESET_AFTER);

        loop {
            if shutdown.load(Ordering::SeqCst) {
                info!("eslogger supervisor shutting down");
                return;
            }

            let child = match spawn_eslogger(&events) {
                Ok(c) => c,
                Err(e) => {
                    error!(error = %e, "failed to spawn eslogger");
                    let delay = backoff.next_delay();
                    warn!(delay_secs = delay.as_secs(), "backing off before retry");
                    tokio::time::sleep(delay).await;
                    continue;
                }
            };

            let spawn_time = Instant::now();
            let exit_reason =
                run_eslogger_session(child, &tx, &shutdown, ignore_processes, ignore_paths).await;

            if shutdown.load(Ordering::SeqCst) {
                info!("eslogger supervisor shutting down after session end");
                return;
            }

            match exit_reason {
                SessionExit::ProcessDied(code) => {
                    warn!(exit_code = ?code, "eslogger process exited unexpectedly");
                }
                SessionExit::Stale => {
                    warn!("eslogger appears stale (no events), restarting");
                }
                SessionExit::ChannelClosed => {
                    info!("event channel closed, stopping supervisor");
                    return;
                }
            }

            // Reset backoff if the process ran stably
            if spawn_time.elapsed() > BACKOFF_RESET_AFTER {
                backoff.reset();
            }

            let delay = backoff.next_delay();
            warn!(delay_secs = delay.as_secs(), "restarting eslogger after delay");
            tokio::time::sleep(delay).await;
        }
    }

    enum SessionExit {
        ProcessDied(Option<i32>),
        Stale,
        ChannelClosed,
    }

    /// Run a single eslogger session: read events, filter, send to channel.
    /// Returns the reason the session ended.
    async fn run_eslogger_session(
        mut child: Child,
        tx: &mpsc::Sender<OsEvent>,
        shutdown: &Arc<AtomicBool>,
        ignore_processes: &[String],
        ignore_paths: &[String],
    ) -> SessionExit {
        let child_pid = child.id();

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                error!("eslogger stdout not available");
                return SessionExit::ProcessDied(None);
            }
        };

        let reader = BufReader::new(stdout);
        let mut lines = LinesStream::new(reader.lines());
        let mut filter = EventPreFilter::new(ignore_processes, ignore_paths);
        let mut last_event_time = Instant::now();
        let mut overflow_count: u64 = 0;

        // Spawn a task to wait for the child process to exit
        let (exit_tx, mut exit_rx) = mpsc::channel::<Option<i32>>(1);
        tokio::spawn(async move {
            match child.wait().await {
                Ok(status) => {
                    let _ = exit_tx.send(status.code()).await;
                }
                Err(e) => {
                    error!(error = %e, "error waiting for eslogger child");
                    let _ = exit_tx.send(None).await;
                }
            }
        });

        loop {
            if shutdown.load(Ordering::SeqCst) {
                // Graceful shutdown: SIGTERM, wait 3s, SIGKILL
                if let Some(pid) = child_pid {
                    graceful_kill(pid as i32);
                }
                return SessionExit::ProcessDied(None);
            }

            tokio::select! {
                exit_code = exit_rx.recv() => {
                    return SessionExit::ProcessDied(exit_code.flatten());
                }
                line_result = lines.next() => {
                    match line_result {
                        Some(Ok(line)) => {
                            if line.trim().is_empty() {
                                continue;
                            }
                            match parse_event(&line) {
                                Ok(es_event) => {
                                    let os_event = OsEvent::from(es_event);
                                    if filter.should_pass(&os_event) {
                                        last_event_time = Instant::now();
                                        match tx.try_send(os_event) {
                                            Ok(()) => {}
                                            Err(mpsc::error::TrySendError::Full(_)) => {
                                                overflow_count += 1;
                                                if overflow_count % 1000 == 1 {
                                                    warn!(
                                                        overflow_count,
                                                        "event channel full, dropping events"
                                                    );
                                                }
                                            }
                                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                                return SessionExit::ChannelClosed;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "failed to parse eslogger line");
                                }
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "error reading eslogger stdout");
                        }
                        None => {
                            // stdout closed, process likely died
                            return SessionExit::ProcessDied(None);
                        }
                    }
                }
                _ = tokio::time::sleep(STALE_EVENT_TIMEOUT) => {
                    if last_event_time.elapsed() > STALE_EVENT_TIMEOUT {
                        // Process might be stale
                        if let Some(pid) = child_pid {
                            graceful_kill(pid as i32);
                        }
                        return SessionExit::Stale;
                    }
                }
            }
        }
    }

    /// Send SIGTERM to a process, wait 3 seconds, then SIGKILL if still alive.
    fn graceful_kill(pid: i32) {
        let nix_pid = Pid::from_raw(pid);
        if signal::kill(nix_pid, Signal::SIGTERM).is_ok() {
            debug!(pid, "sent SIGTERM to eslogger child");
            // Give it 3 seconds to exit gracefully
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(3));
                // If still alive, SIGKILL
                let _ = signal::kill(nix_pid, Signal::SIGKILL);
                debug!(pid = nix_pid.as_raw(), "sent SIGKILL to eslogger child");
            });
        }
    }

    /// Exponential backoff state.
    pub(crate) struct ExponentialBackoff {
        current: Duration,
        initial: Duration,
        max: Duration,
    }

    impl ExponentialBackoff {
        pub fn new(initial: Duration, max: Duration, _reset_after: Duration) -> Self {
            Self {
                current: initial,
                initial,
                max,
            }
        }

        pub fn next_delay(&mut self) -> Duration {
            let delay = self.current;
            self.current = (self.current * 2).min(self.max);
            delay
        }

        pub fn reset(&mut self) {
            self.current = self.initial;
        }
    }

    /// Parse a macOS version string and check it's >= 13.0.
    pub(crate) fn parse_and_check_version(version_str: &str) -> Result<()> {
        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.is_empty() {
            anyhow::bail!("could not parse macOS version: '{version_str}'");
        }
        let major: u32 = parts[0]
            .parse()
            .with_context(|| format!("invalid macOS major version: '{}'", parts[0]))?;
        if major < 13 {
            anyhow::bail!(
                "macOS {version_str} is not supported. eslogger requires macOS 13.0 (Ventura) or later."
            );
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_version_check_passes_13() {
            assert!(parse_and_check_version("13.0").is_ok());
            assert!(parse_and_check_version("13.5.1").is_ok());
            assert!(parse_and_check_version("14.0").is_ok());
            assert!(parse_and_check_version("15.2").is_ok());
        }

        #[test]
        fn test_version_check_rejects_old() {
            assert!(parse_and_check_version("12.7").is_err());
            assert!(parse_and_check_version("11.0").is_err());
            assert!(parse_and_check_version("10.15.7").is_err());
        }

        #[test]
        fn test_version_check_rejects_invalid() {
            assert!(parse_and_check_version("").is_err());
            assert!(parse_and_check_version("abc").is_err());
        }

        #[test]
        fn test_backoff_increases_exponentially() {
            let mut backoff = ExponentialBackoff::new(
                Duration::from_secs(2),
                Duration::from_secs(60),
                Duration::from_secs(300),
            );
            assert_eq!(backoff.next_delay(), Duration::from_secs(2));
            assert_eq!(backoff.next_delay(), Duration::from_secs(4));
            assert_eq!(backoff.next_delay(), Duration::from_secs(8));
            assert_eq!(backoff.next_delay(), Duration::from_secs(16));
            assert_eq!(backoff.next_delay(), Duration::from_secs(32));
            // Should cap at 60
            assert_eq!(backoff.next_delay(), Duration::from_secs(60));
            assert_eq!(backoff.next_delay(), Duration::from_secs(60));
        }

        #[test]
        fn test_backoff_resets() {
            let mut backoff = ExponentialBackoff::new(
                Duration::from_secs(2),
                Duration::from_secs(60),
                Duration::from_secs(300),
            );
            backoff.next_delay();
            backoff.next_delay();
            backoff.next_delay();
            backoff.reset();
            assert_eq!(backoff.next_delay(), Duration::from_secs(2));
        }

        #[test]
        fn test_backoff_caps_at_max() {
            let mut backoff = ExponentialBackoff::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(300),
            );
            assert_eq!(backoff.next_delay(), Duration::from_secs(30));
            assert_eq!(backoff.next_delay(), Duration::from_secs(60));
            assert_eq!(backoff.next_delay(), Duration::from_secs(60));
        }

        #[test]
        fn test_fda_instructions_not_empty() {
            let instructions = EsloggerManager::fda_instructions();
            assert!(instructions.contains("Full Disk Access"));
            assert!(instructions.contains("System Settings"));
        }

        #[test]
        fn test_fda_check_runs() {
            // This just ensures check_fda() doesn't panic; actual result
            // depends on the system's FDA state.
            let _ = EsloggerManager::check_fda();
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
        pub fn spawn(
            events: &[&str],
            _channel_capacity: Option<usize>,
            _ignore_processes: &[String],
            _ignore_paths: &[String],
        ) -> Result<(Self, tokio::sync::mpsc::Receiver<clawdefender_core::event::os::OsEvent>)> {
            let _ = events;
            anyhow::bail!("eslogger is only available on macOS with Endpoint Security entitlements")
        }

        /// Check whether the eslogger child process is still alive.
        pub fn is_shutting_down(&self) -> bool {
            false
        }

        /// Signal shutdown.
        pub fn shutdown(&self) {}

        /// Returns the event types this manager subscribes to.
        pub fn subscribed_events(&self) -> &[String] {
            &self.subscribed_events
        }

        pub fn check_fda() -> bool {
            false
        }

        pub fn fda_instructions() -> String {
            "eslogger is only available on macOS".to_string()
        }

        pub async fn check_macos_version() -> Result<()> {
            anyhow::bail!("eslogger is only available on macOS")
        }

        pub fn check_eslogger_binary() -> Result<()> {
            anyhow::bail!("eslogger is only available on macOS")
        }
    }
}

pub use platform::EsloggerManager;
