//! Terminal UI for ClawAI interactive prompts and event monitoring.

pub mod prompt;

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Terminal;

use claw_core::ipc::protocol::UserDecision;

pub use crate::prompt::PendingPrompt;

// ── Constants ───────────────────────────────────────────────────

const MAX_EVENTS: usize = 200;
const RENDER_INTERVAL: Duration = Duration::from_millis(100); // ~10 FPS

// ── Shared state ────────────────────────────────────────────────

/// Focus mode for the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiMode {
    /// Normal mode — prompts focused if any exist.
    Normal,
    /// A specific prompt is focused for decision.
    PromptFocused,
    /// Scrolling through the event log.
    LogViewing,
}

/// Live statistics displayed in the status bar.
#[derive(Debug, Clone, Default)]
pub struct LiveStats {
    pub uptime: Duration,
    pub messages_total: u64,
    pub messages_blocked: u64,
    pub messages_prompted: u64,
    pub active_servers: Vec<String>,
}

/// A single event shown in the event log.
pub struct EventRecord {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub action: String,
    pub server_name: String,
    pub method: String,
    pub summary: String,
}

/// Main TUI state — not behind a lock, owned by the TUI task.
pub struct TuiState {
    pub pending_prompts: Vec<PendingPrompt>,
    pub recent_events: VecDeque<EventRecord>,
    pub stats: LiveStats,
    pub selected_prompt: usize,
    pub scroll_offset: usize,
    pub mode: UiMode,
    pub running: bool,
    /// Whether the user has manually scrolled the log (disables auto-scroll).
    user_scrolled: bool,
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            pending_prompts: Vec::new(),
            recent_events: VecDeque::new(),
            stats: LiveStats::default(),
            selected_prompt: 0,
            scroll_offset: 0,
            mode: UiMode::Normal,
            running: true,
            user_scrolled: false,
        }
    }
}

impl TuiState {
    /// Push a new event, keeping the buffer capped at [`MAX_EVENTS`].
    pub fn push_event(&mut self, event: EventRecord) {
        self.recent_events.push_back(event);
        while self.recent_events.len() > MAX_EVENTS {
            self.recent_events.pop_front();
        }
    }

    /// Add a pending prompt.
    pub fn add_prompt(&mut self, prompt: PendingPrompt) {
        self.pending_prompts.push(prompt);
        if self.mode == UiMode::Normal || self.mode == UiMode::LogViewing {
            self.mode = UiMode::PromptFocused;
        }
    }

    /// Navigate to the next prompt.
    pub fn select_next_prompt(&mut self) {
        if !self.pending_prompts.is_empty() {
            self.selected_prompt = (self.selected_prompt + 1) % self.pending_prompts.len();
        }
    }

    /// Navigate to the previous prompt.
    pub fn select_prev_prompt(&mut self) {
        if !self.pending_prompts.is_empty() {
            if self.selected_prompt == 0 {
                self.selected_prompt = self.pending_prompts.len() - 1;
            } else {
                self.selected_prompt -= 1;
            }
        }
    }

    /// Resolve the currently selected prompt with the given decision.
    /// Returns the prompt id if resolved, or None.
    pub fn resolve_selected(&mut self, decision: UserDecision) -> Option<String> {
        if self.pending_prompts.is_empty() {
            return None;
        }
        let idx = self.selected_prompt.min(self.pending_prompts.len() - 1);
        let mut prompt = self.pending_prompts.remove(idx);
        let id = prompt.id.clone();
        prompt.resolve(decision);

        // Fix selection index after removal.
        if self.pending_prompts.is_empty() {
            self.selected_prompt = 0;
            self.mode = UiMode::Normal;
        } else if self.selected_prompt >= self.pending_prompts.len() {
            self.selected_prompt = self.pending_prompts.len() - 1;
        }
        Some(id)
    }

    /// Expire timed-out prompts by auto-denying them.
    pub fn expire_prompts(&mut self) -> Vec<String> {
        let mut expired_ids = Vec::new();
        let mut i = 0;
        while i < self.pending_prompts.len() {
            if self.pending_prompts[i].is_expired() {
                let mut prompt = self.pending_prompts.remove(i);
                expired_ids.push(prompt.id.clone());
                prompt.resolve(UserDecision::DenyOnce);
            } else {
                i += 1;
            }
        }

        if !expired_ids.is_empty() {
            // Fix selection.
            if self.pending_prompts.is_empty() {
                self.selected_prompt = 0;
                self.mode = UiMode::Normal;
            } else if self.selected_prompt >= self.pending_prompts.len() {
                self.selected_prompt = self.pending_prompts.len() - 1;
            }
        }
        expired_ids
    }

    /// Scroll the event log down.
    pub fn scroll_down(&mut self) {
        let max = self.recent_events.len().saturating_sub(1);
        if self.scroll_offset < max {
            self.scroll_offset += 1;
            self.user_scrolled = true;
        }
    }

    /// Scroll the event log up.
    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
            self.user_scrolled = true;
        }
    }

    /// Toggle focus between prompts panel and event log.
    pub fn toggle_focus(&mut self) {
        self.mode = match self.mode {
            UiMode::Normal | UiMode::PromptFocused if !self.pending_prompts.is_empty() => {
                if self.mode == UiMode::PromptFocused {
                    UiMode::LogViewing
                } else {
                    UiMode::PromptFocused
                }
            }
            UiMode::LogViewing if !self.pending_prompts.is_empty() => UiMode::PromptFocused,
            _ => UiMode::Normal,
        };
    }

    /// Handle a key event. Returns `true` if the TUI should quit.
    pub fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> bool {
        // Ctrl+C always quits.
        if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            self.running = false;
            return true;
        }

        match code {
            KeyCode::Char('q') => {
                self.running = false;
                return true;
            }
            KeyCode::Tab => self.toggle_focus(),

            // Prompt navigation
            KeyCode::Up if self.mode == UiMode::PromptFocused => self.select_prev_prompt(),
            KeyCode::Down if self.mode == UiMode::PromptFocused => self.select_next_prompt(),

            // Prompt decisions (only in PromptFocused mode)
            KeyCode::Char('a') if self.mode == UiMode::PromptFocused => {
                self.resolve_selected(UserDecision::AllowOnce);
            }
            KeyCode::Char('s') if self.mode == UiMode::PromptFocused => {
                self.resolve_selected(UserDecision::AllowSession);
            }
            KeyCode::Char('p') if self.mode == UiMode::PromptFocused => {
                self.resolve_selected(UserDecision::AddPolicyRule);
            }
            KeyCode::Char('d') if self.mode == UiMode::PromptFocused => {
                self.resolve_selected(UserDecision::DenyOnce);
            }

            // Event log scrolling
            KeyCode::Char('j') | KeyCode::Down => self.scroll_down(),
            KeyCode::Char('k') | KeyCode::Up => self.scroll_up(),

            _ => {}
        }

        false
    }
}

// ── Public entry point (async) ──────────────────────────────────

/// Run the interactive TUI.
///
/// Receives new prompts and events through channels and renders the dashboard.
pub async fn run(
    mut prompt_rx: tokio::sync::mpsc::Receiver<PendingPrompt>,
    mut event_rx: tokio::sync::mpsc::Receiver<EventRecord>,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &mut prompt_rx, &mut event_rx).await;

    // Always restore terminal.
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    prompt_rx: &mut tokio::sync::mpsc::Receiver<PendingPrompt>,
    event_rx: &mut tokio::sync::mpsc::Receiver<EventRecord>,
) -> Result<()> {
    let mut state = TuiState::default();
    let mut tick_interval = tokio::time::interval(RENDER_INTERVAL);

    loop {
        if !state.running {
            break;
        }

        tokio::select! {
            _ = tick_interval.tick() => {
                // Expire timed-out prompts.
                let expired = state.expire_prompts();
                for id in &expired {
                    tracing::warn!(prompt_id = %id, "Prompt timed out — auto-denied");
                }

                // Poll keyboard (non-blocking).
                while event::poll(Duration::ZERO)? {
                    if let CrosstermEvent::Key(key) = event::read()? {
                        if state.handle_key(key.code, key.modifiers) {
                            return Ok(());
                        }
                    }
                }

                // Render.
                terminal.draw(|frame| draw_ui(frame, &state))?;
            }
            Some(prompt) = prompt_rx.recv() => {
                state.add_prompt(prompt);
            }
            Some(event) = event_rx.recv() => {
                state.push_event(event);
                // Auto-scroll if user hasn't scrolled manually.
                if !state.user_scrolled {
                    state.scroll_offset = state.recent_events.len().saturating_sub(1);
                }
            }
        }
    }

    Ok(())
}

// ── Headless mode ───────────────────────────────────────────────

/// Run in headless mode (no TTY). Auto-denies all prompted requests.
pub async fn run_headless(
    mut prompt_rx: tokio::sync::mpsc::Receiver<PendingPrompt>,
) -> Result<()> {
    tracing::warn!("No TTY available, auto-denying prompted requests");

    while let Some(mut prompt) = prompt_rx.recv().await {
        tracing::warn!(
            prompt_id = %prompt.id,
            server = %prompt.server_name,
            method = %prompt.method,
            "No TTY available, auto-denying prompted request"
        );
        prompt.resolve(UserDecision::DenyOnce);
    }

    Ok(())
}

// ── Drawing ─────────────────────────────────────────────────────

fn draw_ui(frame: &mut ratatui::Frame, state: &TuiState) {
    let area = frame.area();

    // Layout: header (1 line) + prompt panel + event log + footer (1 line).
    let prompt_height = if state.pending_prompts.is_empty() {
        0
    } else {
        // Each prompt takes ~5 lines, plus 2 for borders.
        let count = state.pending_prompts.len().min(3);
        (count as u16 * 5) + 2
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),              // status bar
            Constraint::Length(prompt_height),   // pending prompts
            Constraint::Min(5),                 // event log
            Constraint::Length(1),              // footer
        ])
        .split(area);

    draw_status_bar(frame, state, chunks[0]);
    if prompt_height > 0 {
        draw_prompts(frame, state, chunks[1]);
    }
    draw_event_log(frame, state, chunks[2]);
    draw_footer(frame, state, chunks[3]);
}

fn draw_status_bar(frame: &mut ratatui::Frame, state: &TuiState, area: Rect) {
    let uptime = format_uptime(state.stats.uptime.as_secs());
    let blocked = state.stats.messages_blocked;
    let total = state.stats.messages_total;
    let servers = state.stats.active_servers.len();

    let text = Line::from(vec![
        Span::styled(" ClawAI ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("| "),
        Span::styled("● Active", Style::default().fg(Color::Green)),
        Span::raw(format!(" | Up: {uptime} | {total} events, {blocked} blocked | {servers} server(s) ")),
    ]);

    frame.render_widget(Paragraph::new(text).style(Style::default().bg(Color::DarkGray)), area);
}

fn draw_prompts(frame: &mut ratatui::Frame, state: &TuiState, area: Rect) {
    let focused = state.mode == UiMode::PromptFocused;
    let border_style = if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let count = state.pending_prompts.len();
    let title = format!(" Pending Approvals ({count}) ");

    let mut lines: Vec<Line> = Vec::new();
    for (i, prompt) in state.pending_prompts.iter().enumerate().take(3) {
        let secs = prompt.seconds_remaining();
        let is_selected = i == state.selected_prompt;
        let marker = if is_selected { ">" } else { " " };

        let tool_display = prompt
            .tool_name
            .as_deref()
            .unwrap_or(&prompt.method);

        let header_style = if is_selected {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Yellow)
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!(" {marker} {server} -> {tool}", server = prompt.server_name, tool = tool_display),
                header_style,
            ),
            Span::styled(
                format!("  [{secs}s left]"),
                if secs <= 5 {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ),
        ]));

        // Summarize arguments (first 60 chars).
        let args_str = prompt.arguments.to_string();
        let args_display = if args_str.len() > 60 {
            format!("{}...", &args_str[..57])
        } else {
            args_str
        };
        lines.push(Line::from(format!("   Args: {args_display}")));

        lines.push(Line::from(vec![
            Span::raw(format!("   Rule: {}", prompt.policy_rule)),
            Span::styled(
                format!(" - \"{}\"", prompt.policy_message),
                Style::default().fg(Color::DarkGray),
            ),
        ]));

        if is_selected && focused {
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled("[A]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::raw("llow once  "),
                Span::styled("[S]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("ession  "),
                Span::styled("[P]", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                Span::raw("olicy  "),
                Span::styled("[D]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::raw("eny"),
            ]));
        } else {
            lines.push(Line::from(""));
        }
    }

    if count > 3 {
        lines.push(Line::from(Span::styled(
            format!("   ... and {} more", count - 3),
            Style::default().fg(Color::DarkGray),
        )));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(border_style);

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_event_log(frame: &mut ratatui::Frame, state: &TuiState, area: Rect) {
    let focused = state.mode == UiMode::LogViewing;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let inner_height = area.height.saturating_sub(2) as usize; // minus borders
    let total = state.recent_events.len();

    let lines: Vec<Line> = state
        .recent_events
        .iter()
        .skip(state.scroll_offset.saturating_sub(inner_height.saturating_sub(1)))
        .take(inner_height)
        .map(|e| {
            let time = e.timestamp.format("%H:%M:%S").to_string();
            let (icon, color) = action_style(&e.action);
            Line::from(vec![
                Span::styled(format!(" {time} "), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{icon} "), Style::default().fg(color)),
                Span::styled(
                    format!("{:<8} ", e.action.to_uppercase()),
                    Style::default().fg(color),
                ),
                Span::raw(format!("{} {} ", e.server_name, e.method)),
                Span::styled(
                    truncate_str(&e.summary, 40),
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        })
        .collect();

    let title = format!(" Event Log ({total}) ");
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(border_style);

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_footer(frame: &mut ratatui::Frame, state: &TuiState, area: Rect) {
    let help = match state.mode {
        UiMode::PromptFocused => "q:quit  ^C:quit  Up/Dn:select  a/s/p/d:decide  Tab:log",
        UiMode::LogViewing => "q:quit  ^C:quit  j/k:scroll  Tab:prompts",
        UiMode::Normal => "q:quit  ^C:quit  j/k:scroll  Tab:switch",
    };
    let line = Line::from(Span::styled(
        format!(" {help}"),
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(Paragraph::new(line), area);
}

// ── Helpers ─────────────────────────────────────────────────────

fn action_style(action: &str) -> (&str, Color) {
    match action.to_lowercase().as_str() {
        "allow" => ("✓", Color::Green),
        "block" => ("✗", Color::Red),
        "prompt" => ("?", Color::Yellow),
        _ => ("·", Color::DarkGray),
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h}h{m:02}m{s:02}s")
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_event(action: &str, server: &str, method: &str) -> EventRecord {
        EventRecord {
            timestamp: chrono::Utc::now(),
            action: action.to_string(),
            server_name: server.to_string(),
            method: method.to_string(),
            summary: format!("{server} {method}"),
        }
    }

    fn make_test_prompt(id: &str, timeout: Duration) -> (PendingPrompt, tokio::sync::oneshot::Receiver<UserDecision>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let prompt = PendingPrompt {
            id: id.to_string(),
            server_name: "test-server".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("run_command".to_string()),
            arguments: serde_json::json!({"cmd": "ls"}),
            policy_rule: "prompt_shell".to_string(),
            policy_message: "Shell execution".to_string(),
            received_at: std::time::Instant::now(),
            timeout,
            response_tx: Some(tx),
        };
        (prompt, rx)
    }

    #[test]
    fn test_tui_state_default() {
        let state = TuiState::default();
        assert!(state.pending_prompts.is_empty());
        assert!(state.recent_events.is_empty());
        assert_eq!(state.selected_prompt, 0);
        assert_eq!(state.mode, UiMode::Normal);
        assert!(state.running);
    }

    #[test]
    fn test_push_event_caps_at_max() {
        let mut state = TuiState::default();
        for i in 0..300 {
            state.push_event(make_event("allow", "srv", &format!("m{i}")));
        }
        assert_eq!(state.recent_events.len(), MAX_EVENTS);
        // Oldest events should be evicted; newest retained.
        assert_eq!(state.recent_events.back().unwrap().method, "m299");
        assert_eq!(state.recent_events.front().unwrap().method, "m100");
    }

    #[test]
    fn test_add_prompt_switches_mode() {
        let mut state = TuiState::default();
        assert_eq!(state.mode, UiMode::Normal);

        let (prompt, _rx) = make_test_prompt("p1", Duration::from_secs(30));
        state.add_prompt(prompt);

        assert_eq!(state.pending_prompts.len(), 1);
        assert_eq!(state.mode, UiMode::PromptFocused);
    }

    #[test]
    fn test_navigate_prompts() {
        let mut state = TuiState::default();
        for i in 0..3 {
            let (p, _rx) = make_test_prompt(&format!("p{i}"), Duration::from_secs(30));
            state.add_prompt(p);
        }

        assert_eq!(state.selected_prompt, 0);
        state.select_next_prompt();
        assert_eq!(state.selected_prompt, 1);
        state.select_next_prompt();
        assert_eq!(state.selected_prompt, 2);
        state.select_next_prompt();
        assert_eq!(state.selected_prompt, 0); // wraps
        state.select_prev_prompt();
        assert_eq!(state.selected_prompt, 2); // wraps back
    }

    #[test]
    fn test_resolve_selected_prompt() {
        let mut state = TuiState::default();
        let (p1, rx1) = make_test_prompt("p1", Duration::from_secs(30));
        let (p2, _rx2) = make_test_prompt("p2", Duration::from_secs(30));
        state.add_prompt(p1);
        state.add_prompt(p2);

        assert_eq!(state.pending_prompts.len(), 2);

        // Resolve the first (selected) prompt.
        let id = state.resolve_selected(UserDecision::AllowOnce);
        assert_eq!(id, Some("p1".to_string()));
        assert_eq!(state.pending_prompts.len(), 1);
        assert_eq!(state.pending_prompts[0].id, "p2");
        assert_eq!(rx1.blocking_recv().unwrap(), UserDecision::AllowOnce);
    }

    #[test]
    fn test_resolve_middle_prompt() {
        let mut state = TuiState::default();
        for i in 0..3 {
            let (p, _rx) = make_test_prompt(&format!("p{i}"), Duration::from_secs(30));
            state.add_prompt(p);
        }

        // Select the middle prompt.
        state.selected_prompt = 1;
        let id = state.resolve_selected(UserDecision::DenyOnce);
        assert_eq!(id, Some("p1".to_string()));
        assert_eq!(state.pending_prompts.len(), 2);
        assert_eq!(state.pending_prompts[0].id, "p0");
        assert_eq!(state.pending_prompts[1].id, "p2");
        // Selection should now point to p2 (index 1).
        assert_eq!(state.selected_prompt, 1);
    }

    #[test]
    fn test_resolve_last_prompt_resets_mode() {
        let mut state = TuiState::default();
        let (p, _rx) = make_test_prompt("p1", Duration::from_secs(30));
        state.add_prompt(p);
        assert_eq!(state.mode, UiMode::PromptFocused);

        state.resolve_selected(UserDecision::DenyOnce);
        assert!(state.pending_prompts.is_empty());
        assert_eq!(state.mode, UiMode::Normal);
        assert_eq!(state.selected_prompt, 0);
    }

    #[test]
    fn test_expire_prompts() {
        let mut state = TuiState::default();

        // One expired, one still valid.
        let (p1, rx1) = make_test_prompt("expired", Duration::from_millis(0));
        let (p2, _rx2) = make_test_prompt("valid", Duration::from_secs(30));
        state.add_prompt(p1);
        state.add_prompt(p2);

        std::thread::sleep(Duration::from_millis(5));

        let expired = state.expire_prompts();
        assert_eq!(expired, vec!["expired"]);
        assert_eq!(state.pending_prompts.len(), 1);
        assert_eq!(state.pending_prompts[0].id, "valid");
        // Expired prompt should have been auto-denied.
        assert_eq!(rx1.blocking_recv().unwrap(), UserDecision::DenyOnce);
    }

    #[test]
    fn test_timeout_auto_deny() {
        let mut state = TuiState::default();
        let (p, rx) = make_test_prompt("timeout-test", Duration::from_millis(1));
        state.add_prompt(p);

        std::thread::sleep(Duration::from_millis(5));

        let expired = state.expire_prompts();
        assert_eq!(expired.len(), 1);
        assert_eq!(rx.blocking_recv().unwrap(), UserDecision::DenyOnce);
    }

    #[test]
    fn test_scroll_event_log() {
        let mut state = TuiState::default();
        for i in 0..10 {
            state.push_event(make_event("allow", "srv", &format!("m{i}")));
        }

        assert_eq!(state.scroll_offset, 0);
        state.scroll_down();
        assert_eq!(state.scroll_offset, 1);
        assert!(state.user_scrolled);
        state.scroll_up();
        assert_eq!(state.scroll_offset, 0);
        // Cannot scroll below 0.
        state.scroll_up();
        assert_eq!(state.scroll_offset, 0);
    }

    #[test]
    fn test_handle_key_quit() {
        let mut state = TuiState::default();
        assert!(state.handle_key(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!state.running);
    }

    #[test]
    fn test_handle_key_ctrl_c() {
        let mut state = TuiState::default();
        assert!(state.handle_key(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(!state.running);
    }

    #[test]
    fn test_handle_key_prompt_decisions() {
        let mut state = TuiState::default();
        let (p, rx) = make_test_prompt("p1", Duration::from_secs(30));
        state.add_prompt(p);
        assert_eq!(state.mode, UiMode::PromptFocused);

        // Press 'a' to allow.
        assert!(!state.handle_key(KeyCode::Char('a'), KeyModifiers::NONE));
        assert!(state.pending_prompts.is_empty());
        assert_eq!(rx.blocking_recv().unwrap(), UserDecision::AllowOnce);
    }

    #[test]
    fn test_handle_key_session_allow() {
        let mut state = TuiState::default();
        let (p, rx) = make_test_prompt("p1", Duration::from_secs(30));
        state.add_prompt(p);

        assert!(!state.handle_key(KeyCode::Char('s'), KeyModifiers::NONE));
        assert_eq!(rx.blocking_recv().unwrap(), UserDecision::AllowSession);
    }

    #[test]
    fn test_handle_key_add_policy() {
        let mut state = TuiState::default();
        let (p, rx) = make_test_prompt("p1", Duration::from_secs(30));
        state.add_prompt(p);

        assert!(!state.handle_key(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(rx.blocking_recv().unwrap(), UserDecision::AddPolicyRule);
    }

    #[test]
    fn test_toggle_focus() {
        let mut state = TuiState::default();
        let (p, _rx) = make_test_prompt("p1", Duration::from_secs(30));
        state.add_prompt(p);
        assert_eq!(state.mode, UiMode::PromptFocused);

        state.toggle_focus();
        assert_eq!(state.mode, UiMode::LogViewing);

        state.toggle_focus();
        assert_eq!(state.mode, UiMode::PromptFocused);
    }

    #[test]
    fn test_stats_default() {
        let stats = LiveStats::default();
        assert_eq!(stats.uptime, Duration::ZERO);
        assert_eq!(stats.messages_total, 0);
        assert_eq!(stats.messages_blocked, 0);
        assert_eq!(stats.messages_prompted, 0);
        assert!(stats.active_servers.is_empty());
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(0), "0h00m00s");
        assert_eq!(format_uptime(61), "0h01m01s");
        assert_eq!(format_uptime(3661), "1h01m01s");
    }

    #[test]
    fn test_headless_auto_deny() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            let (prompt_tx, prompt_rx) = tokio::sync::oneshot::channel();

            let prompt = PendingPrompt {
                id: "headless-1".to_string(),
                server_name: "srv".to_string(),
                method: "tools/call".to_string(),
                tool_name: Some("cmd".to_string()),
                arguments: serde_json::Value::Null,
                policy_rule: "r".to_string(),
                policy_message: "m".to_string(),
                received_at: std::time::Instant::now(),
                timeout: Duration::from_secs(30),
                response_tx: Some(prompt_tx),
            };

            tx.send(prompt).await.unwrap();
            drop(tx); // Close channel so run_headless finishes.

            run_headless(rx).await.unwrap();

            let decision = prompt_rx.await.unwrap();
            assert_eq!(decision, UserDecision::DenyOnce);
        });
    }

    #[test]
    fn test_event_ordering_newest_at_back() {
        let mut state = TuiState::default();
        state.push_event(make_event("allow", "srv", "first"));
        state.push_event(make_event("block", "srv", "second"));

        assert_eq!(state.recent_events.front().unwrap().method, "first");
        assert_eq!(state.recent_events.back().unwrap().method, "second");
    }

    #[test]
    fn test_resolve_empty_prompts_returns_none() {
        let mut state = TuiState::default();
        assert_eq!(state.resolve_selected(UserDecision::DenyOnce), None);
    }
}
