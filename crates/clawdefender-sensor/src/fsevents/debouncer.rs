//! Event debouncing, coalescing, and rate limiting for filesystem events.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::Utc;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

use super::{FsEvent, FsEventKind, SensitivityTier};

/// Priority for coalescing: higher = more significant.
fn event_priority(kind: &FsEventKind) -> u8 {
    match kind {
        FsEventKind::Created => 0,
        FsEventKind::Modified => 1,
        FsEventKind::Renamed => 2,
        FsEventKind::Removed => 3,
    }
}

/// Pending entry for a single path's debounce window.
struct PendingEvent {
    kind: FsEventKind,
    sensitivity: SensitivityTier,
    source_pid: Option<u32>,
    first_seen: Instant,
}

/// Debounces filesystem events within a configurable time window per path,
/// coalescing to the most significant event kind.
pub struct EventDebouncer {
    window: Duration,
    pending: HashMap<PathBuf, PendingEvent>,
}

impl EventDebouncer {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            pending: HashMap::new(),
        }
    }

    /// Ingest a new event. Returns nothing; call `flush` to get ready events.
    pub fn push(&mut self, event: &FsEvent) {
        let entry = self.pending.entry(event.path.clone());
        entry
            .and_modify(|p| {
                if event_priority(&event.kind) > event_priority(&p.kind) {
                    p.kind = event.kind.clone();
                }
                if let Some(pid) = event.source_pid {
                    p.source_pid = Some(pid);
                }
            })
            .or_insert_with(|| PendingEvent {
                kind: event.kind.clone(),
                sensitivity: event.sensitivity,
                source_pid: event.source_pid,
                first_seen: Instant::now(),
            });
    }

    /// Flush events whose debounce window has expired.
    pub fn flush(&mut self) -> Vec<FsEvent> {
        let now = Instant::now();
        let mut ready = Vec::new();
        let mut expired_keys = Vec::new();

        for (path, pending) in &self.pending {
            if now.duration_since(pending.first_seen) >= self.window {
                ready.push(FsEvent {
                    path: path.clone(),
                    kind: pending.kind.clone(),
                    timestamp: Utc::now(),
                    sensitivity: pending.sensitivity,
                    source_pid: pending.source_pid,
                });
                expired_keys.push(path.clone());
            }
        }

        for key in expired_keys {
            self.pending.remove(&key);
        }

        ready
    }

    /// Flush all remaining events regardless of window.
    pub fn flush_all(&mut self) -> Vec<FsEvent> {
        let events: Vec<FsEvent> = self
            .pending
            .drain()
            .map(|(path, pending)| FsEvent {
                path,
                kind: pending.kind,
                timestamp: Utc::now(),
                sensitivity: pending.sensitivity,
                source_pid: pending.source_pid,
            })
            .collect();
        events
    }
}

/// Global rate limiter that activates sampling when events exceed a threshold.
pub struct RateLimiter {
    /// Maximum events per second before sampling kicks in.
    threshold: u64,
    /// How many events to pass through per sampled batch (1-in-N).
    sample_ratio: u64,
    /// Counter for events in the current second.
    count_this_second: u64,
    /// When the current counting window started.
    window_start: Instant,
    /// Total events passed since sampling activated.
    pass_counter: u64,
    /// Whether sampling is currently active.
    pub sampling_active: bool,
}

impl RateLimiter {
    pub fn new(threshold: u64, sample_ratio: u64) -> Self {
        Self {
            threshold,
            sample_ratio,
            count_this_second: 0,
            window_start: Instant::now(),
            pass_counter: 0,
            sampling_active: false,
        }
    }

    /// Check whether an event should be passed through.
    /// Returns true if the event should be emitted, false if sampled out.
    pub fn should_pass(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start);

        // Reset window every second
        if elapsed >= Duration::from_secs(1) {
            let was_sampling = self.sampling_active;
            self.sampling_active = self.count_this_second > self.threshold;

            if self.sampling_active && !was_sampling {
                tracing::warn!(
                    events_per_sec = self.count_this_second,
                    "rate limiter: sampling activated (>{} events/sec)",
                    self.threshold
                );
            } else if !self.sampling_active && was_sampling {
                tracing::info!("rate limiter: sampling deactivated");
            }

            self.count_this_second = 0;
            self.window_start = now;
        }

        self.count_this_second += 1;

        if self.sampling_active {
            self.pass_counter += 1;
            self.pass_counter % self.sample_ratio == 0
        } else {
            true
        }
    }
}

/// Run the debounce + rate-limit pipeline as an async task.
/// Reads raw events from `input`, writes processed events to `output`.
pub async fn run_debounce_pipeline(
    mut input: mpsc::Receiver<FsEvent>,
    output: mpsc::Sender<FsEvent>,
    debounce_window: Duration,
    rate_threshold: u64,
    sample_ratio: u64,
) {
    let mut debouncer = EventDebouncer::new(debounce_window);
    let mut rate_limiter = RateLimiter::new(rate_threshold, sample_ratio);
    let tick_interval = debounce_window / 2; // Check at half the window interval

    let mut interval = tokio::time::interval(tick_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            event = input.recv() => {
                match event {
                    Some(ev) => debouncer.push(&ev),
                    None => {
                        // Input closed, flush remaining
                        for ev in debouncer.flush_all() {
                            let _ = output.send(ev).await;
                        }
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                for ev in debouncer.flush() {
                    if rate_limiter.should_pass() {
                        if output.send(ev).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_event(path: &str, kind: FsEventKind) -> FsEvent {
        FsEvent {
            path: PathBuf::from(path),
            kind,
            timestamp: Utc::now(),
            sensitivity: SensitivityTier::Low,
            source_pid: None,
        }
    }

    #[test]
    fn debounce_coalesces_to_most_significant() {
        let mut debouncer = EventDebouncer::new(Duration::from_millis(0));

        // Push Created then Removed for the same path
        debouncer.push(&make_event("/tmp/foo.txt", FsEventKind::Created));
        debouncer.push(&make_event("/tmp/foo.txt", FsEventKind::Removed));

        let events = debouncer.flush_all();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FsEventKind::Removed);
    }

    #[test]
    fn debounce_multiple_events_same_path() {
        let mut debouncer = EventDebouncer::new(Duration::from_millis(0));

        for _ in 0..20 {
            debouncer.push(&make_event("/tmp/bar.txt", FsEventKind::Modified));
        }

        let events = debouncer.flush_all();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FsEventKind::Modified);
    }

    #[test]
    fn rate_limiter_passes_under_threshold() {
        let mut limiter = RateLimiter::new(500, 10);
        let mut passed = 0;
        for _ in 0..100 {
            if limiter.should_pass() {
                passed += 1;
            }
        }
        assert_eq!(passed, 100);
        assert!(!limiter.sampling_active);
    }

    #[test]
    fn rate_limiter_samples_over_threshold() {
        let mut limiter = RateLimiter::new(500, 10);
        // Force sampling active
        limiter.sampling_active = true;
        limiter.pass_counter = 0;

        let mut passed = 0;
        for _ in 0..100 {
            if limiter.should_pass() {
                passed += 1;
            }
        }
        // Should pass roughly 1-in-10 = 10
        assert_eq!(passed, 10);
    }

    #[tokio::test]
    async fn debounce_pipeline_reduces_events() {
        let (raw_tx, raw_rx) = mpsc::channel(256);
        let (out_tx, mut out_rx) = mpsc::channel(256);

        tokio::spawn(run_debounce_pipeline(
            raw_rx,
            out_tx,
            Duration::from_millis(50),
            500,
            10,
        ));

        // Send 20 events for the same path rapidly
        for _ in 0..20 {
            raw_tx
                .send(make_event("/tmp/test.txt", FsEventKind::Modified))
                .await
                .unwrap();
        }

        // Drop sender to close the pipeline
        drop(raw_tx);

        // Collect output events
        let mut output_events = Vec::new();
        while let Some(ev) = out_rx.recv().await {
            output_events.push(ev);
        }

        // Should have far fewer than 20 events
        assert!(
            output_events.len() <= 2,
            "expected <=2 debounced events, got {}",
            output_events.len()
        );
    }
}
