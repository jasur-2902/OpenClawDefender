use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{Event, EventStream, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::Terminal;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// AppState – shared TUI state
// ---------------------------------------------------------------------------

const MAX_EVENTS: usize = 100;
const MAX_VERDICTS: usize = 10;

#[derive(Clone)]
pub struct EventRecord {
    pub timestamp: Instant,
    pub event_type: EventType,
    pub pid: u32,
    pub description: String,
    pub blocked: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub enum EventType {
    Process,
    Network,
    Dns,
}

impl EventType {
    pub fn label(&self) -> &'static str {
        match self {
            EventType::Process => "PROCESS",
            EventType::Network => "NETWORK",
            EventType::Dns => "DNS",
        }
    }
}

#[derive(Clone)]
pub struct AiVerdictRecord {
    pub timestamp: Instant,
    pub event_description: String,
    pub verdict: Verdict,
    pub reasoning: String,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Verdict {
    Allow,
    Block,
}

pub struct AppState {
    pub events: VecDeque<EventRecord>,
    pub verdicts: VecDeque<AiVerdictRecord>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_EVENTS + 1),
            verdicts: VecDeque::with_capacity(MAX_VERDICTS + 1),
        }
    }

    pub fn push_event(&mut self, record: EventRecord) {
        self.events.push_back(record);
        if self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    pub fn push_verdict(&mut self, record: AiVerdictRecord) {
        self.verdicts.push_back(record);
        if self.verdicts.len() > MAX_VERDICTS {
            self.verdicts.pop_front();
        }
    }
}

pub type SharedState = Arc<RwLock<AppState>>;

pub fn new_shared_state() -> SharedState {
    Arc::new(RwLock::new(AppState::new()))
}

// ---------------------------------------------------------------------------
// Terminal setup / teardown
// ---------------------------------------------------------------------------

fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) {
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
}

// ---------------------------------------------------------------------------
// Elapsed time formatting
// ---------------------------------------------------------------------------

fn format_elapsed(instant: Instant) -> String {
    let elapsed = instant.elapsed();
    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m {}s ago", secs / 60, secs % 60)
    } else {
        format!("{}h {}m ago", secs / 3600, (secs % 3600) / 60)
    }
}

// ---------------------------------------------------------------------------
// TUI render loop
// ---------------------------------------------------------------------------

pub async fn run_tui(state: SharedState, shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to setup terminal: {e}");
            return;
        }
    };

    let mut event_stream = EventStream::new();
    let mut table_state = TableState::default();
    let mut scroll_offset: usize = 0;

    let tick_rate = Duration::from_millis(100); // ~10 FPS

    loop {
        // Check for shutdown signal
        if *shutdown.borrow() {
            break;
        }

        // Draw
        {
            let app = state.read().await;
            let _ = terminal.draw(|frame| {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                    .split(frame.area());

                // --- Left pane: syscall events table ---
                let header_cells = ["Time", "Type", "PID", "Details"]
                    .iter()
                    .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
                let header = Row::new(header_cells).height(1);

                let events: Vec<&EventRecord> = app.events.iter().rev().collect();
                let visible_events = events.iter().skip(scroll_offset);

                let rows = visible_events.map(|ev| {
                    let color = if ev.blocked { Color::Red } else { Color::Green };
                    let style = Style::default().fg(color);
                    Row::new(vec![
                        Cell::from(format_elapsed(ev.timestamp)),
                        Cell::from(ev.event_type.label()),
                        Cell::from(ev.pid.to_string()),
                        Cell::from(ev.description.clone()),
                    ])
                    .style(style)
                });

                let table = Table::new(
                    rows,
                    [
                        Constraint::Length(10),
                        Constraint::Length(9),
                        Constraint::Length(8),
                        Constraint::Fill(1),
                    ],
                )
                .header(header)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Intercepted Syscalls ")
                        .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                );

                frame.render_stateful_widget(table, chunks[0], &mut table_state);

                // --- Right pane: AI verdicts ---
                let verdict_lines: Vec<Line> = if app.verdicts.is_empty() {
                    vec![Line::from(Span::styled(
                        "No AI verdicts yet...",
                        Style::default().fg(Color::DarkGray),
                    ))]
                } else {
                    app.verdicts
                        .iter()
                        .rev()
                        .flat_map(|v| {
                            let (label, color) = match v.verdict {
                                Verdict::Allow => ("ALLOW", Color::Green),
                                Verdict::Block => ("BLOCK", Color::Red),
                            };
                            vec![
                                Line::from(vec![
                                    Span::styled(
                                        format!("[{}] ", format_elapsed(v.timestamp)),
                                        Style::default().fg(Color::DarkGray),
                                    ),
                                    Span::styled(
                                        format!("[{label}] "),
                                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                                    ),
                                    Span::raw(&v.event_description),
                                ]),
                                Line::from(Span::styled(
                                    format!("  {} ", v.reasoning),
                                    Style::default().fg(Color::Gray),
                                )),
                                Line::from(""),
                            ]
                        })
                        .collect()
                };

                let verdicts_widget = Paragraph::new(verdict_lines).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" AI Cold Path Analysis ")
                        .title_style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                );

                frame.render_widget(verdicts_widget, chunks[1]);
            });
        }

        // Handle input events with a timeout for the tick rate
        let deadline = tokio::time::sleep(tick_rate);
        tokio::pin!(deadline);

        tokio::select! {
            _ = &mut deadline => {}
            maybe_event = event_stream.next() => {
                if let Some(Ok(Event::Key(key))) = maybe_event {
                    match (key.code, key.modifiers) {
                        (KeyCode::Char('c'), KeyModifiers::CONTROL) | (KeyCode::Char('q'), _) => {
                            break;
                        }
                        (KeyCode::Up, _) => {
                            scroll_offset = scroll_offset.saturating_add(1);
                        }
                        (KeyCode::Down, _) => {
                            scroll_offset = scroll_offset.saturating_sub(1);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    restore_terminal(&mut terminal);
}
