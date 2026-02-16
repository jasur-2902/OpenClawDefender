//! Terminal UI for ClawAI interactive prompts and dashboards.

pub mod prompt;

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, RwLock};

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
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Tabs};
use ratatui::Terminal;

use claw_core::event::Severity;
use claw_core::ipc::protocol::UserDecision;

// ── Shared state types ──────────────────────────────────────────

/// Thread-safe shared state for the TUI.
pub type SharedState = Arc<RwLock<AppState>>;

/// Maximum number of events retained in memory.
const MAX_EVENTS: usize = 500;

/// Application state shared between the daemon and the TUI.
pub struct AppState {
    /// Recent events (newest first, capped at [`MAX_EVENTS`]).
    pub events: VecDeque<EventRecord>,
    /// Running statistics.
    pub stats: DashboardStats,
    /// Active prompt waiting for the user's decision.
    pub pending_prompt: Option<PromptRequest>,
    /// Resolved decision from the last prompt (consumed by the daemon).
    pub prompt_decision: Option<UserDecision>,
    /// Known AI agents.
    pub active_agents: Vec<AgentEntry>,
    /// Set to `false` when shutdown is requested.
    pub running: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            stats: DashboardStats::default(),
            pending_prompt: None,
            prompt_decision: None,
            active_agents: Vec::new(),
            running: true,
        }
    }
}

impl AppState {
    /// Push an event, evicting the oldest if at capacity.
    pub fn push_event(&mut self, event: EventRecord) {
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_back();
        }
        self.events.push_front(event);
    }
}

/// A single event record displayed in the TUI.
pub struct EventRecord {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub summary: String,
    pub action: String,
    pub severity: Severity,
    pub details: Option<String>,
}

/// Dashboard statistics.
#[derive(Default, Clone)]
pub struct DashboardStats {
    pub total_events: u64,
    pub blocked: u64,
    pub allowed: u64,
    pub prompted: u64,
    pub uptime_secs: u64,
    pub events_per_minute: f64,
}

/// A prompt request awaiting user decision.
pub struct PromptRequest {
    pub id: String,
    pub message: String,
    pub event_summary: String,
    pub rule_name: String,
    pub options: Vec<String>,
}

/// An entry for an active AI agent.
pub struct AgentEntry {
    pub pid: u32,
    pub name: String,
    pub client: String,
    pub events: u64,
}

// ── Tab enum ────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Events,
    Agents,
}

impl Tab {
    fn index(self) -> usize {
        match self {
            Self::Dashboard => 0,
            Self::Events => 1,
            Self::Agents => 2,
        }
    }

    fn titles() -> Vec<&'static str> {
        vec!["Dashboard", "Events", "Agents"]
    }
}

// ── TuiApp ──────────────────────────────────────────────────────

/// The main TUI application.
pub struct TuiApp {
    state: SharedState,
    current_tab: Tab,
    event_scroll: usize,
    _selected_event: Option<usize>,
}

impl TuiApp {
    pub fn new(state: SharedState) -> Self {
        Self {
            state,
            current_tab: Tab::Dashboard,
            event_scroll: 0,
            _selected_event: None,
        }
    }
}

// ── Public entry point ──────────────────────────────────────────

/// Run the TUI until the user quits.
///
/// This takes ownership of the terminal and restores it on exit.
pub fn run(state: SharedState) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, state);

    // Always restore the terminal, even on error.
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: SharedState,
) -> Result<()> {
    let mut app = TuiApp::new(state.clone());

    loop {
        // Check if we should stop.
        {
            let s = state.read().map_err(|e| anyhow::anyhow!("{e}"))?;
            if !s.running {
                break;
            }
        }

        // Draw.
        terminal.draw(|frame| draw_ui(frame, &app))?;

        // Poll for input (~10 FPS).
        if event::poll(std::time::Duration::from_millis(100))? {
            if let CrosstermEvent::Key(key) = event::read()? {
                match handle_key(&mut app, key.code, key.modifiers) {
                    KeyAction::Quit => break,
                    KeyAction::Continue => {}
                }
            }
        }
    }

    Ok(())
}

// ── Key handling ────────────────────────────────────────────────

enum KeyAction {
    Quit,
    Continue,
}

fn handle_key(app: &mut TuiApp, code: KeyCode, modifiers: KeyModifiers) -> KeyAction {
    // Ctrl+C always quits.
    if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
        return KeyAction::Quit;
    }

    // Check if a prompt is active.
    let has_prompt = app
        .state
        .read()
        .map(|s| s.pending_prompt.is_some())
        .unwrap_or(false);

    if has_prompt {
        match code {
            KeyCode::Char('a') => resolve_prompt(app, UserDecision::AllowOnce),
            KeyCode::Char('d') => resolve_prompt(app, UserDecision::DenyOnce),
            KeyCode::Char('A') => resolve_prompt(app, UserDecision::AllowSession),
            KeyCode::Char('D') => resolve_prompt(app, UserDecision::DenySession),
            KeyCode::Char('q') => return KeyAction::Quit,
            _ => {}
        }
        return KeyAction::Continue;
    }

    match code {
        KeyCode::Char('q') => return KeyAction::Quit,
        KeyCode::Tab => {
            app.current_tab = match app.current_tab {
                Tab::Dashboard => Tab::Events,
                Tab::Events => Tab::Agents,
                Tab::Agents => Tab::Dashboard,
            };
        }
        KeyCode::Char('1') => app.current_tab = Tab::Dashboard,
        KeyCode::Char('2') => app.current_tab = Tab::Events,
        KeyCode::Char('3') => app.current_tab = Tab::Agents,
        KeyCode::Up | KeyCode::Char('k') => {
            app.event_scroll = app.event_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let max = app
                .state
                .read()
                .map(|s| s.events.len().saturating_sub(1))
                .unwrap_or(0);
            if app.event_scroll < max {
                app.event_scroll += 1;
            }
        }
        _ => {}
    }

    KeyAction::Continue
}

fn resolve_prompt(app: &TuiApp, decision: UserDecision) {
    if let Ok(mut s) = app.state.write() {
        if s.pending_prompt.is_some() {
            s.pending_prompt = None;
            s.prompt_decision = Some(decision);
        }
    }
}

// ── Drawing ─────────────────────────────────────────────────────

fn draw_ui(frame: &mut ratatui::Frame, app: &TuiApp) {
    let size = frame.area();

    // Top bar (tabs) + main content.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(size);

    draw_tabs(frame, app, chunks[0]);

    let state = match app.state.read() {
        Ok(s) => s,
        Err(_) => return,
    };

    match app.current_tab {
        Tab::Dashboard => draw_dashboard(frame, &state, chunks[1]),
        Tab::Events => draw_events(frame, &state, app.event_scroll, chunks[1]),
        Tab::Agents => draw_agents(frame, &state, chunks[1]),
    }

    // Prompt overlay.
    if state.pending_prompt.is_some() {
        draw_prompt_modal(frame, &state, size);
    }
}

fn draw_tabs(frame: &mut ratatui::Frame, app: &TuiApp, area: Rect) {
    let titles: Vec<Line> = Tab::titles().into_iter().map(Line::from).collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" ClawAI Dashboard "),
        )
        .select(app.current_tab.index())
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, area);
}

fn draw_dashboard(frame: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // status bar
            Constraint::Length(9), // stats + agents
            Constraint::Min(0),   // recent events
        ])
        .split(area);

    // Status bar.
    let uptime = format_uptime(state.stats.uptime_secs);
    let status_text = format!("  Status: Running                    Uptime: {uptime}");
    let status = Paragraph::new(status_text).block(Block::default().borders(Borders::BOTTOM));
    frame.render_widget(status, chunks[0]);

    // Stats + Agents side by side.
    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    draw_stats_panel(frame, state, mid[0]);
    draw_agents_panel(frame, state, mid[1]);

    // Recent events.
    draw_recent_events(frame, state, chunks[2]);
}

fn draw_stats_panel(frame: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let stats = &state.stats;
    let text = vec![
        Line::from(format!(" Total Events:    {}", stats.total_events)),
        Line::from(vec![
            Span::styled(
                format!(" Blocked:         {}", stats.blocked),
                Style::default().fg(Color::Red),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!(" Allowed:         {}", stats.allowed),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!(" Prompted:        {}", stats.prompted),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(format!(" Events/min:      {:.1}", stats.events_per_minute)),
    ];

    let block = Block::default().borders(Borders::ALL).title(" Statistics ");
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

fn draw_agents_panel(frame: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let header = Row::new(vec!["PID", "Name", "Client", "Events"])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(0);

    let rows: Vec<Row> = state
        .active_agents
        .iter()
        .map(|a| {
            Row::new(vec![
                a.pid.to_string(),
                a.name.clone(),
                a.client.clone(),
                a.events.to_string(),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Active Agents "));

    frame.render_widget(table, area);
}

fn draw_recent_events(frame: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let header = Row::new(vec!["Time", "Source", "Action", "Summary"])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(0);

    let rows: Vec<Row> = state
        .events
        .iter()
        .take(20)
        .map(|e| {
            let action_style = action_color(&e.action);
            Row::new(vec![
                Cell::from(e.timestamp.format("%H:%M:%S").to_string()),
                Cell::from(e.source.clone()),
                Cell::from(e.action.clone()).style(action_style),
                Cell::from(e.summary.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Recent Events "),
    );

    frame.render_widget(table, area);
}

fn draw_events(
    frame: &mut ratatui::Frame,
    state: &AppState,
    scroll: usize,
    area: Rect,
) {
    let header = Row::new(vec!["Time", "Source", "Action", "Severity", "Summary"])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(0);

    let rows: Vec<Row> = state
        .events
        .iter()
        .skip(scroll)
        .map(|e| {
            let action_style = action_color(&e.action);
            let sev_style = severity_color(e.severity);
            Row::new(vec![
                Cell::from(e.timestamp.format("%H:%M:%S").to_string()),
                Cell::from(e.source.clone()),
                Cell::from(e.action.clone()).style(action_style),
                Cell::from(format!("{:?}", e.severity)).style(sev_style),
                Cell::from(e.summary.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Events (j/k to scroll) "),
    );

    frame.render_widget(table, area);
}

fn draw_agents(frame: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let header = Row::new(vec!["PID", "Name", "Client", "Events"])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(0);

    let rows: Vec<Row> = state
        .active_agents
        .iter()
        .map(|a| {
            Row::new(vec![
                a.pid.to_string(),
                a.name.clone(),
                a.client.clone(),
                a.events.to_string(),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Active Agents "),
    );

    frame.render_widget(table, area);
}

fn draw_prompt_modal(frame: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let prompt = match &state.pending_prompt {
        Some(p) => p,
        None => return,
    };

    // Center a box on screen.
    let modal = centered_rect(70, 50, area);
    frame.render_widget(Clear, modal);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", prompt.message),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("  Event: {}", prompt.event_summary)),
        Line::from(format!("  Rule:  {}", prompt.rule_name)),
        Line::from(""),
        Line::from(Span::styled(
            "  [a] Allow Once  [d] Deny Once  [A] Allow Session  [D] Deny All",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Security Prompt ")
        .border_style(Style::default().fg(Color::Yellow));

    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, modal);
}

// ── Helpers ─────────────────────────────────────────────────────

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn action_color(action: &str) -> Style {
    match action.to_lowercase().as_str() {
        "blocked" => Style::default().fg(Color::Red),
        "allowed" => Style::default().fg(Color::Green),
        "prompted" => Style::default().fg(Color::Yellow),
        "logged" => Style::default().fg(Color::DarkGray),
        _ => Style::default(),
    }
}

fn severity_color(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::High => Style::default().fg(Color::Red),
        Severity::Medium => Style::default().fg(Color::Yellow),
        Severity::Low => Style::default().fg(Color::Blue),
        Severity::Info => Style::default().fg(Color::DarkGray),
    }
}

fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h}h {m:02}m {s:02}s")
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(summary: &str, action: &str) -> EventRecord {
        EventRecord {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            summary: summary.to_string(),
            action: action.to_string(),
            severity: Severity::Medium,
            details: None,
        }
    }

    #[test]
    fn test_app_state_default() {
        let state = AppState::default();
        assert!(state.events.is_empty());
        assert!(state.pending_prompt.is_none());
        assert!(state.prompt_decision.is_none());
        assert!(state.active_agents.is_empty());
        assert!(state.running);
        assert_eq!(state.stats.total_events, 0);
        assert_eq!(state.stats.blocked, 0);
        assert_eq!(state.stats.allowed, 0);
        assert_eq!(state.stats.prompted, 0);
    }

    #[test]
    fn test_push_event() {
        let mut state = AppState::default();
        state.push_event(make_event("test event", "allowed"));
        assert_eq!(state.events.len(), 1);
        assert_eq!(state.events[0].summary, "test event");
    }

    #[test]
    fn test_event_capacity_eviction() {
        let mut state = AppState::default();
        for i in 0..600 {
            state.push_event(make_event(&format!("event-{i}"), "allowed"));
        }
        assert_eq!(state.events.len(), MAX_EVENTS);
        // Newest event should be at the front.
        assert_eq!(state.events[0].summary, "event-599");
        // Oldest retained event.
        assert_eq!(state.events[MAX_EVENTS - 1].summary, "event-100");
    }

    #[test]
    fn test_dashboard_stats_default() {
        let stats = DashboardStats::default();
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.blocked, 0);
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.prompted, 0);
        assert_eq!(stats.uptime_secs, 0);
        assert!((stats.events_per_minute - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_prompt_submit_and_resolve() {
        let state = Arc::new(RwLock::new(AppState::default()));

        // Submit a prompt.
        {
            let mut s = state.write().unwrap();
            s.pending_prompt = Some(PromptRequest {
                id: "test-1".to_string(),
                message: "Dangerous operation".to_string(),
                event_summary: "rm -rf /".to_string(),
                rule_name: "block_destructive".to_string(),
                options: vec![
                    "Allow Once".to_string(),
                    "Deny Once".to_string(),
                ],
            });
        }

        // Verify prompt is pending.
        {
            let s = state.read().unwrap();
            assert!(s.pending_prompt.is_some());
            assert_eq!(s.pending_prompt.as_ref().unwrap().id, "test-1");
        }

        // Resolve the prompt.
        {
            let mut s = state.write().unwrap();
            s.pending_prompt = None;
            s.prompt_decision = Some(UserDecision::DenyOnce);
        }

        // Verify it's cleared.
        {
            let s = state.read().unwrap();
            assert!(s.pending_prompt.is_none());
            assert_eq!(s.prompt_decision, Some(UserDecision::DenyOnce));
        }
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(0), "0h 00m 00s");
        assert_eq!(format_uptime(61), "0h 01m 01s");
        assert_eq!(format_uptime(3661), "1h 01m 01s");
        assert_eq!(format_uptime(8075), "2h 14m 35s");
    }

    #[test]
    fn test_tab_index() {
        assert_eq!(Tab::Dashboard.index(), 0);
        assert_eq!(Tab::Events.index(), 1);
        assert_eq!(Tab::Agents.index(), 2);
    }
}
