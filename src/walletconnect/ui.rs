//! User interaction for the WalletConnect service: a plain line-based mode
//! (used when stdin/stdout are not terminals, and by the tests) and a
//! full-screen dashboard built on ratatui.
//!
//! Everything the user sees or answers goes through [`Ui`], so the protocol
//! code never prints directly.

use std::{
    collections::VecDeque,
    io::{BufRead, IsTerminal, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};

/// What the user asked for during an idle tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAction {
    Idle,
    /// Leave; saved sessions resume on the next run.
    Quit,
    /// Make the wallet at this index the selected session's active account.
    SwitchAccount(usize),
    /// Select the session (or pending pairing) at this index.
    SelectSession(usize),
    /// Pair with another dapp.
    NewConnection,
    /// End the selected session (or abandon the selected pairing).
    Disconnect,
    /// Add or remove wallets on the selected session.
    EditWallets,
    /// Generate a new wallet and store it in 1Password.
    NewWallet,
}

/// What the dashboard shows about one session, or about a pairing still
/// waiting for the dapp's proposal (`pending`).
#[derive(Debug, Clone, Default)]
pub struct SessionView {
    pub pending: bool,
    pub dapp_name: String,
    pub dapp_url: String,
    pub chains: Vec<String>,
    pub methods: Vec<String>,
    pub wallets: Vec<WalletRow>,
    /// Index into `wallets` of the account the dapp sees as selected.
    pub active: usize,
    /// Unix time the session expires (0 when unknown).
    pub expiry: u64,
    pub sign_ins: usize,
    pub requests_approved: usize,
    pub requests_rejected: usize,
}

/// A wallet shown on the dashboard.
#[derive(Debug, Clone)]
pub struct WalletRow {
    pub name: String,
    pub address: String,
}

/// Interaction surface used by the WalletConnect code.
pub trait Ui {
    /// Append a line to the activity log.
    fn log(&mut self, line: &str);
    /// Append a warning to the activity log.
    fn warn(&mut self, line: &str);
    /// One-line connection status ("Waiting for proposal", ...).
    fn status(&mut self, status: &str);
    /// Replace the session list and mark the selected entry.
    fn sessions(&mut self, sessions: Vec<SessionView>, selected: Option<usize>);
    /// Show `body` under `title` and ask for approval.
    fn confirm(&mut self, title: &str, body: &str) -> Result<bool>;
    /// Give the UI a chance to redraw and read keys.
    fn poll(&mut self) -> Result<UiAction>;
    /// Ask for a line of text; `None` when cancelled.
    fn input(&mut self, prompt: &str) -> Result<Option<String>>;
    /// Ask the user to tick any number of `items`, starting with
    /// `preselected` ticked; returns the ticked indices (empty when cancelled).
    fn select_many(
        &mut self,
        title: &str,
        items: &[String],
        preselected: &[usize],
    ) -> Result<Vec<usize>>;
    /// Show that blocking work is in progress (called repeatedly by [`run_busy`]).
    fn busy(&mut self, message: &str, elapsed: Duration);
    /// Remember a value the user may want to copy (transaction hash, ...).
    fn copyable(&mut self, label: &str, value: &str);
}

/// Run `work` on a worker thread while the UI keeps drawing a progress
/// indicator, so a slow 1Password unlock, relay handshake or RPC call never
/// looks like a frozen screen.
pub fn run_busy<T, F>(ui: &mut dyn Ui, message: &str, work: F) -> T
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    std::thread::scope(|scope| {
        let handle = scope.spawn(work);
        let started = Instant::now();
        loop {
            ui.busy(message, started.elapsed());
            if handle.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(80));
        }
        handle.join().unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    })
}

/// True when both stdin and stdout are terminals, i.e. the dashboard can run.
pub fn interactive_terminal() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn indent(text: &str) -> String {
    text.lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n")
}

/// Ctrl-C flag shared with the plain UI (raw-mode TUIs see Ctrl-C as a key).
pub fn install_ctrlc() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let _ = ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst));
    stop
}

// ---------------------------------------------------------------------------
// Plain (line based)
// ---------------------------------------------------------------------------

/// Prints to stdout and reads answers from stdin.
pub struct PlainUi {
    stop: Arc<AtomicBool>,
    busy_shown: Option<String>,
}

impl PlainUi {
    pub fn new(stop: Arc<AtomicBool>) -> Self {
        Self { stop, busy_shown: None }
    }

    fn read_line(&self) -> Result<Option<String>> {
        let mut line = String::new();
        let n = std::io::stdin().lock().read_line(&mut line)?;
        if n == 0 {
            println!();
            return Ok(None);
        }
        Ok(Some(line.trim().to_string()))
    }
}

impl Ui for PlainUi {
    fn copyable(&mut self, _label: &str, _value: &str) {
        // Plain output is already selectable text.
    }

    fn busy(&mut self, message: &str, _elapsed: Duration) {
        if self.busy_shown.as_deref() != Some(message) {
            println!("{message}...");
            self.busy_shown = Some(message.to_string());
        }
    }

    fn log(&mut self, line: &str) {
        println!("{line}");
    }

    fn warn(&mut self, line: &str) {
        eprintln!("warning: {line}");
    }

    fn status(&mut self, status: &str) {
        println!("{status}");
    }

    fn sessions(&mut self, _sessions: Vec<SessionView>, _selected: Option<usize>) {
        // Session changes are logged as they happen.
    }

    fn confirm(&mut self, title: &str, body: &str) -> Result<bool> {
        println!("\n  {title}\n{}\n", indent(body));
        print!("Approve? [y/N] ");
        std::io::stdout().flush()?;
        Ok(self
            .read_line()?
            .is_some_and(|l| matches!(l.to_ascii_lowercase().as_str(), "y" | "yes")))
    }

    fn poll(&mut self) -> Result<UiAction> {
        Ok(if self.stop.load(Ordering::SeqCst) { UiAction::Quit } else { UiAction::Idle })
    }

    fn input(&mut self, prompt: &str) -> Result<Option<String>> {
        print!("{prompt}: ");
        std::io::stdout().flush()?;
        Ok(self.read_line()?.filter(|l| !l.is_empty()))
    }

    fn select_many(
        &mut self,
        title: &str,
        items: &[String],
        preselected: &[usize],
    ) -> Result<Vec<usize>> {
        println!("{title}");
        for (i, item) in items.iter().enumerate() {
            let mark = if preselected.contains(&i) { "*" } else { " " };
            println!("{mark} {:>3}. {item}", i + 1);
        }
        if preselected.is_empty() {
            print!("Select by number (e.g. 1,3 or all): ");
        } else {
            print!("Select by number (e.g. 1,3 or all; empty keeps the * ones): ");
        }
        std::io::stdout().flush()?;
        let Some(line) = self.read_line()? else { return Ok(Vec::new()) };
        if line.is_empty() {
            return Ok(preselected.to_vec());
        }
        if line.eq_ignore_ascii_case("all") {
            return Ok((0..items.len()).collect());
        }
        let mut out = Vec::new();
        for part in line.split([',', ' ']).filter(|p| !p.is_empty()) {
            let n: usize = part.parse().with_context(|| format!("not a number: {part:?}"))?;
            if n == 0 || n > items.len() {
                bail!("{n} is out of range");
            }
            if !out.contains(&(n - 1)) {
                out.push(n - 1);
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Full screen dashboard
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Info,
    Warn,
}

/// Everything the dashboard renders. Kept separate from the terminal so it
/// can be drawn into a test backend.
#[derive(Default)]
pub struct Dashboard {
    pub relay: String,
    /// Sessions and pending pairings, in list order.
    pub sessions: Vec<SessionView>,
    pub selected: Option<usize>,
    /// Wallets of the selected session.
    pub wallets: Vec<WalletRow>,
    /// Active wallet of the selected session.
    pub active: usize,
    /// Recent values offered by the copy menu, newest first: (label, value).
    pub copyables: Vec<(String, String)>,
    pub mouse: bool,
    wallet_offset: usize,
    status: String,
    log: VecDeque<(Level, String, String)>,
    started: Option<Instant>,
    log_scroll: usize,
}

const LOG_CAPACITY: usize = 500;
/// Lines in the session details panel.
const DETAIL_ROWS: usize = 7;

/// "3d", "5h", "12m": how long until `expiry` (unix seconds).
fn remaining(expiry: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let left = expiry.saturating_sub(now);
    match left {
        0 => "expired".into(),
        s if s >= 86_400 => format!("{}d", (s + 43_200) / 86_400),
        s if s >= 3_600 => format!("{}h", s / 3_600),
        s => format!("{}m", s.div_ceil(60)),
    }
}

impl Dashboard {
    /// Replace the session list; the wallet panel follows the selection.
    pub fn set_sessions(&mut self, sessions: Vec<SessionView>, selected: Option<usize>) {
        self.selected = selected.filter(|&i| i < sessions.len());
        let current = self.selected.map(|i| &sessions[i]);
        self.wallets = current.map(|s| s.wallets.clone()).unwrap_or_default();
        self.active = current.map(|s| s.active).unwrap_or(0);
        self.sessions = sessions;
    }

    fn session(&self) -> Option<&SessionView> {
        self.selected.and_then(|i| self.sessions.get(i))
    }

    /// Everything the copy menu offers: recent values, then wallet addresses.
    fn copy_items(&self) -> Vec<(String, String)> {
        let mut items = self.copyables.clone();
        for w in &self.wallets {
            items.push((format!("address of {}", w.name), w.address.clone()));
        }
        items
    }

    fn remember(&mut self, label: &str, value: &str) {
        self.copyables.retain(|(_, v)| v != value);
        self.copyables.insert(0, (label.to_string(), value.to_string()));
        self.copyables.truncate(20);
    }

    fn stamp(&self) -> String {
        let secs = self.started.map(|s| s.elapsed().as_secs()).unwrap_or(0);
        format!("{:02}:{:02}", secs / 60, secs % 60)
    }

    fn push(&mut self, level: Level, line: &str) {
        let stamp = self.stamp();
        for l in line.lines() {
            self.log.push_back((level, stamp.clone(), l.to_string()));
        }
        while self.log.len() > LOG_CAPACITY {
            self.log.pop_front();
        }
        self.log_scroll = 0;
    }

    /// Width of the name column: the longest wallet name, never shortened.
    fn name_width(&self) -> usize {
        self.wallets.iter().map(|w| w.name.chars().count()).max().unwrap_or(0).max(4)
    }

    /// Terminal rows per wallet and the wallets panel width for a screen
    /// `width` wide: one row with name and full address side by side when
    /// they fit in 70% of the screen, otherwise the address moves to a
    /// second row. Nothing is ever truncated.
    fn geometry(&self, width: u16) -> (usize, u16) {
        const PREFIX: usize = 3; // marker, number, space
        const ADDRESS: usize = 42;
        let max_width = (width as usize * 70 / 100).max(20);
        let one_row = PREFIX + self.name_width() + 1 + ADDRESS + 2;
        if one_row <= max_width {
            (1, one_row as u16)
        } else {
            let needed = (PREFIX + self.name_width() + 2).max(PREFIX + ADDRESS + 2);
            (2, needed.min(max_width) as u16)
        }
    }

    /// Header, sessions, wallets, session details and log areas for a
    /// terminal of `area`.
    fn layout(&self, area: Rect) -> (Rect, Rect, Rect, Rect, Rect) {
        let (rows_per_wallet, panel_width) = self.geometry(area.width);
        // Both lists grow with their contents: sessions up to 25% of the
        // screen, wallets up to 45% (and at least the session details).
        let sessions_wanted = self.sessions.len().max(1) as u16 + 2;
        let sessions_cap = (area.height / 4).max(3);
        let wanted = (self.wallets.len() * rows_per_wallet).max(DETAIL_ROWS) as u16 + 2;
        let cap = (area.height * 45 / 100).max(7);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(sessions_wanted.min(sessions_cap)),
                Constraint::Length(wanted.min(cap)),
                Constraint::Min(5),
            ])
            .split(area);
        let panels = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(panel_width), Constraint::Min(20)])
            .split(rows[2]);
        (rows[0], rows[1], panels[0], panels[1], rows[3])
    }

    /// Visible wallet rows for a wallets panel of this size.
    fn wallet_window(&self, panel: Rect, rows_per_wallet: usize) -> (usize, usize) {
        let visible = panel.height.saturating_sub(2) as usize / rows_per_wallet.max(1);
        let mut offset = self.wallet_offset.min(self.wallets.len().saturating_sub(visible));
        if self.active < offset {
            offset = self.active;
        } else if visible > 0 && self.active >= offset + visible {
            offset = self.active + 1 - visible;
        }
        (offset, visible)
    }

    /// Visible session rows for a sessions panel of this size.
    fn session_window(&self, panel: Rect) -> (usize, usize) {
        let visible = panel.height.saturating_sub(2) as usize;
        let selected = self.selected.unwrap_or(0);
        let offset = if visible > 0 && selected >= visible { selected + 1 - visible } else { 0 };
        (offset, visible)
    }

    fn inside(panel: Rect, column: u16, row: u16) -> bool {
        column > panel.x
            && column < panel.x + panel.width.saturating_sub(1)
            && row > panel.y
            && row < panel.y + panel.height.saturating_sub(1)
    }

    /// Wallet index under a mouse click, if any.
    pub fn wallet_at(&self, area: Rect, column: u16, row: u16) -> Option<usize> {
        let (_, _, panel, _, _) = self.layout(area);
        if !Self::inside(panel, column, row) {
            return None;
        }
        let (rows_per_wallet, _) = self.geometry(area.width);
        let (offset, _) = self.wallet_window(panel, rows_per_wallet);
        let idx = offset + (row - panel.y - 1) as usize / rows_per_wallet;
        (idx < self.wallets.len()).then_some(idx)
    }

    /// Session index under a mouse click, if any.
    pub fn session_at(&self, area: Rect, column: u16, row: u16) -> Option<usize> {
        let (_, panel, _, _, _) = self.layout(area);
        if !Self::inside(panel, column, row) {
            return None;
        }
        let (offset, _) = self.session_window(panel);
        let idx = offset + (row - panel.y - 1) as usize;
        (idx < self.sessions.len()).then_some(idx)
    }

    /// Draw the dashboard (and no modal) into `frame`.
    pub fn render(&self, frame: &mut Frame) {
        let area = frame.area();
        let (header_area, sessions_area, wallets_area, session_area, log_area) = self.layout(area);

        let header = Paragraph::new(Line::from(vec![
            Span::styled(" opwallet ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("WalletConnect · "),
            Span::styled(self.status.clone(), Style::default().fg(Color::Cyan)),
        ]))
        .block(Block::default().borders(Borders::ALL).title(format!(" relay {} ", self.relay)));
        frame.render_widget(header, header_area);

        self.render_sessions(frame, sessions_area);
        self.render_wallets(frame, wallets_area);

        let session_lines: Vec<Line> = match self.session() {
            None => vec![
                Line::from("no session selected".dim()),
                Line::from(""),
                Line::from("press n to connect a dapp".dim()),
            ],
            Some(s) if s.pending => vec![
                Line::from(vec!["status:   ".dim(), Span::raw("waiting for the dapp's proposal")]),
                Line::from(vec![
                    "wallets:  ".dim(),
                    Span::raw(
                        s.wallets.iter().map(|w| w.name.as_str()).collect::<Vec<_>>().join(", "),
                    ),
                ]),
                Line::from(""),
                Line::from("d abandons this pairing".dim()),
            ],
            Some(s) => vec![
                Line::from(vec![
                    "account:  ".dim(),
                    Span::styled(
                        self.wallets
                            .get(self.active)
                            .map(|w| format!("{} {}", w.name, w.address))
                            .unwrap_or_default(),
                        Style::default().fg(Color::Yellow),
                    ),
                ]),
                Line::from(vec!["dapp:     ".dim(), Span::raw(s.dapp_name.clone()).bold()]),
                Line::from(vec!["url:      ".dim(), Span::raw(s.dapp_url.clone())]),
                Line::from(vec!["chains:   ".dim(), Span::raw(s.chains.join(", "))]),
                Line::from(vec!["methods:  ".dim(), Span::raw(s.methods.join(", "))]),
                Line::from(vec![
                    "activity: ".dim(),
                    Span::raw(format!(
                        "{} sign-in(s), {} approved, {} rejected",
                        s.sign_ins, s.requests_approved, s.requests_rejected
                    )),
                ]),
                Line::from(vec![
                    "expires:  ".dim(),
                    Span::raw(format!("in {}", remaining(s.expiry))),
                ]),
            ],
        };
        let session = Paragraph::new(session_lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Session ")
                .title_bottom(Line::from(" d disconnect · e wallets ").right_aligned()),
        );
        frame.render_widget(session, session_area);

        let visible = log_area.height.saturating_sub(2) as usize;
        let total = self.log.len();
        let end = total.saturating_sub(self.log_scroll);
        let start = end.saturating_sub(visible);
        let log_items: Vec<ListItem> = self
            .log
            .iter()
            .skip(start)
            .take(end - start)
            .map(|(level, stamp, text)| {
                let style = match level {
                    Level::Info => Style::default(),
                    Level::Warn => Style::default().fg(Color::Yellow),
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{stamp} "), Style::default().dim()),
                    Span::styled(text.clone(), style),
                ]))
            })
            .collect();
        let log = List::new(log_items).block(
            Block::default().borders(Borders::ALL).title(" Activity ").title_bottom(
                Line::from(format!(
                    " q quit · c copy · m mouse {} · ↑↓ scroll log ",
                    if self.mouse { "off" } else { "on" }
                ))
                .right_aligned(),
            ),
        );
        frame.render_widget(log, log_area);
    }

    fn render_sessions(&self, frame: &mut Frame, area: Rect) {
        let (offset, visible) = self.session_window(area);
        let items: Vec<ListItem> = if self.sessions.is_empty() {
            vec![ListItem::new(Line::from("no sessions yet · press n to connect a dapp".dim()))]
        } else {
            self.sessions
                .iter()
                .enumerate()
                .skip(offset)
                .take(visible)
                .map(|(i, s)| {
                    let chosen = Some(i) == self.selected;
                    let marker = if chosen { "▶ " } else { "  " };
                    let style = if chosen {
                        Style::default().bold().fg(Color::Yellow)
                    } else {
                        Style::default()
                    };
                    if s.pending {
                        return ListItem::new(Line::from(vec![
                            Span::styled(marker, style),
                            Span::styled("waiting for a proposal", style.italic()),
                            Span::raw(format!("  {} wallet(s)", s.wallets.len())).dim(),
                        ]));
                    }
                    ListItem::new(Line::from(vec![
                        Span::styled(marker, style),
                        Span::styled(s.dapp_name.clone(), style.bold()),
                        Span::raw("  "),
                        Span::raw(s.dapp_url.clone()).dim(),
                        Span::raw(format!(
                            "  {} wallet(s) · expires in {}",
                            s.wallets.len(),
                            remaining(s.expiry)
                        )),
                    ]))
                })
                .collect()
        };
        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Sessions ({}) ", self.sessions.len()))
                .title_bottom(
                    Line::from(" Tab / click select · n new · g new wallet ").right_aligned(),
                ),
        );
        frame.render_widget(list, area);
    }

    fn render_wallets(&self, frame: &mut Frame, wallets_area: Rect) {
        let (rows_per_wallet, _) = self.geometry(frame.area().width);
        let name_width = self.name_width();
        let (offset, visible) = self.wallet_window(wallets_area, rows_per_wallet);
        let wallet_items: Vec<ListItem> = self
            .wallets
            .iter()
            .enumerate()
            .skip(offset)
            .take(visible)
            .map(|(i, w)| {
                let marker = if i == self.active { "▶" } else { " " };
                let style = if i == self.active {
                    Style::default().bold().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                let key = match i {
                    0..=8 => format!("{}", i + 1),
                    9 => "0".to_string(),
                    _ => " ".to_string(),
                };
                let address = Span::styled(w.address.clone(), Style::default().fg(Color::Green));
                if rows_per_wallet == 1 {
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{marker}{key} "), style),
                        Span::styled(format!("{:<name_width$}", w.name), style.bold()),
                        Span::raw(" "),
                        address,
                    ]))
                } else {
                    ListItem::new(vec![
                        Line::from(vec![
                            Span::styled(format!("{marker}{key} "), style),
                            Span::styled(w.name.clone(), style.bold()),
                        ]),
                        Line::from(vec![Span::raw("   "), address]),
                    ])
                }
            })
            .collect();
        let more = self.wallets.len().saturating_sub(offset + visible);
        let title = if more > 0 || offset > 0 {
            format!(
                " Wallets ({}, showing {}-{}) ",
                self.wallets.len(),
                offset + 1,
                offset + visible.min(self.wallets.len() - offset)
            )
        } else {
            format!(" Wallets ({}) ", self.wallets.len())
        };
        let wallets = List::new(wallet_items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .title_bottom(Line::from(" click or 1-9, 0 to switch ").right_aligned()),
        );
        frame.render_widget(wallets, wallets_area);
    }
}

/// Centered rectangle covering the given percentages of `area`.
fn centered(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area)[1];
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(v)[1]
}

/// Draw a modal with a scrollable body over the dashboard.
pub fn render_modal(frame: &mut Frame, title: &str, body: &str, footer: &str, scroll: u16) {
    render_modal_sized(frame, title, body, footer, scroll, 84, 84);
}

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Small centered progress box.
pub fn render_busy(frame: &mut Frame, message: &str, elapsed: Duration) {
    let frame_idx = (elapsed.as_millis() / 100) as usize % SPINNER.len();
    let body = format!("{} {message} ({:.0}s)", SPINNER[frame_idx], elapsed.as_secs_f64());
    render_modal_sized(frame, "Working", &body, "please wait", 0, 60, 20);
}

pub fn render_modal_sized(
    frame: &mut Frame,
    title: &str,
    body: &str,
    footer: &str,
    scroll: u16,
    pct_x: u16,
    pct_y: u16,
) {
    let area = centered(frame.area(), pct_x, pct_y);
    frame.render_widget(Clear, area);
    let text =
        Paragraph::new(body.to_string()).wrap(Wrap { trim: false }).scroll((scroll, 0)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(format!(" {title} "))
                .title_bottom(Line::from(format!(" {footer} ")).right_aligned()),
        );
    frame.render_widget(text, area);
}

/// First line of `body` that is nothing but an http(s) URL.
fn find_link(body: &str) -> Option<&str> {
    body.lines().map(str::trim).find(|l| {
        (l.starts_with("https://") || l.starts_with("http://")) && !l.contains(char::is_whitespace)
    })
}

/// `body` as the dashboard shows it: bare URL lines, which would wrap into
/// an unclickable block, point at the link bar instead.
fn body_for_dashboard(body: &str) -> String {
    let link = find_link(body);
    body.lines()
        .map(|l| {
            if Some(l.trim()) == link {
                "  ↗ open it with the link at the bottom (click it or press o)"
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The approval modal inside `screen`: whole box and, when there is a
/// link, the one-row link bar at the bottom of its body.
fn confirm_layout(screen: Rect, link: bool) -> (Rect, Option<Rect>) {
    let area = centered(screen, 84, 84);
    if !link || area.height < 4 {
        return (area, None);
    }
    let inner = Block::default().borders(Borders::ALL).inner(area);
    let bar = Rect { y: inner.y + inner.height - 1, height: 1, ..inner };
    (area, Some(bar))
}

/// Approval modal: scrollable body plus a clickable link bar when the body
/// carries a URL.
pub fn render_confirm(
    frame: &mut Frame,
    title: &str,
    body: &str,
    footer: &str,
    scroll: u16,
    link: Option<&str>,
) {
    let (area, bar) = confirm_layout(frame.area(), link.is_some());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(format!(" {title} "))
        .title_bottom(Line::from(format!(" {footer} ")).right_aligned());
    let mut text_area = block.inner(area);
    frame.render_widget(block, area);
    if let (Some(bar), Some(url)) = (bar, link) {
        text_area.height -= 1;
        let prefix = "↗ open in browser: ";
        let room = (bar.width as usize).saturating_sub(prefix.chars().count());
        let shown: String = if url.chars().count() > room {
            url.chars().take(room.saturating_sub(1)).chain(['…']).collect()
        } else {
            url.to_string()
        };
        let line = Line::from(vec![
            Span::styled(prefix, Style::default().fg(Color::Cyan).bold()),
            Span::styled(shown, Style::default().fg(Color::Cyan).underlined()),
        ]);
        frame.render_widget(Paragraph::new(line), bar);
    }
    let text = Paragraph::new(body.to_string()).wrap(Wrap { trim: false }).scroll((scroll, 0));
    frame.render_widget(text, text_area);
}

/// Open an http(s) URL in the default browser.
pub fn open_in_browser(url: &str) -> Result<()> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        bail!("not a web link");
    }
    #[cfg(target_os = "macos")]
    let mut cmd = std::process::Command::new("open");
    #[cfg(windows)]
    let mut cmd = {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = std::process::Command::new("xdg-open");
    let mut child = cmd
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("could not start the browser opener")?;
    // Reap the opener without blocking the dashboard.
    std::thread::spawn(move || child.wait());
    Ok(())
}

/// Put `text` on the clipboard: the system clipboard first, then the
/// terminal's OSC 52 escape (works over SSH and in tmux with set-clipboard).
pub fn copy_to_clipboard(text: &str) -> Result<&'static str> {
    if let Ok(mut board) = arboard::Clipboard::new()
        && board.set_text(text.to_string()).is_ok()
    {
        return Ok("system clipboard");
    }
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut out = std::io::stdout();
    write!(out, "\x1b]52;c;{}\x07", STANDARD.encode(text))?;
    out.flush()?;
    Ok("terminal (OSC 52)")
}

/// Full-screen implementation of [`Ui`].
pub struct Tui {
    terminal: ratatui::DefaultTerminal,
    pub dashboard: Dashboard,
    quit: bool,
}

impl Tui {
    pub fn new(relay: &str) -> Result<Self> {
        let terminal = ratatui::init();
        let _ = crossterm::execute!(
            std::io::stdout(),
            event::EnableBracketedPaste,
            event::EnableMouseCapture
        );
        let mut dashboard =
            Dashboard { relay: relay.to_string(), mouse: true, ..Default::default() };
        dashboard.started = Some(Instant::now());
        dashboard.status = "starting".into();
        Ok(Self { terminal, dashboard, quit: false })
    }

    fn draw(&mut self) -> Result<()> {
        let dashboard = &self.dashboard;
        self.terminal.draw(|f| dashboard.render(f))?;
        Ok(())
    }

    fn draw_modal(&mut self, title: &str, body: &str, footer: &str, scroll: u16) -> Result<()> {
        let dashboard = &self.dashboard;
        self.terminal.draw(|f| {
            dashboard.render(f);
            render_modal(f, title, body, footer, scroll);
        })?;
        Ok(())
    }

    /// Wait for a key press (ignoring key releases).
    fn next_key(&mut self, timeout: Duration) -> Result<Option<Event>> {
        if !event::poll(timeout)? {
            return Ok(None);
        }
        match event::read()? {
            Event::Key(k) if k.kind == KeyEventKind::Release => Ok(None),
            e => Ok(Some(e)),
        }
    }

    fn set_mouse(&mut self, on: bool) {
        let mut out = std::io::stdout();
        let _ = if on {
            crossterm::execute!(out, event::EnableMouseCapture)
        } else {
            crossterm::execute!(out, event::DisableMouseCapture)
        };
        self.dashboard.mouse = on;
    }

    /// Pick one of the copyable values and put it on the clipboard.
    fn copy_menu(&mut self) -> Result<()> {
        let items = self.dashboard.copy_items();
        if items.is_empty() {
            self.dashboard.push(Level::Warn, "nothing to copy yet");
            return Ok(());
        }
        let mut cursor = 0usize;
        loop {
            let mut body = String::new();
            for (i, (label, value)) in items.iter().enumerate() {
                let pointer = if i == cursor { ">" } else { " " };
                let key = if i < 9 { format!("{}", i + 1) } else { " ".into() };
                body.push_str(&format!("{pointer}{key} {label}\n     {value}\n"));
            }
            self.draw_modal(
                "Copy to clipboard",
                &body,
                "Enter or 1-9 copy · ↑↓ move · Esc close",
                (cursor * 2).saturating_sub(6) as u16,
            )?;
            let Some(e) = self.next_key(Duration::from_millis(250))? else { continue };
            let Event::Key(k) = e else { continue };
            let chosen = match k.code {
                KeyCode::Esc | KeyCode::Char('c') | KeyCode::Char('q') => return Ok(()),
                KeyCode::Down | KeyCode::Char('j') => {
                    cursor = (cursor + 1).min(items.len() - 1);
                    continue;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    continue;
                }
                KeyCode::Enter => cursor,
                KeyCode::Char(c @ '1'..='9') => {
                    let i = c as usize - '1' as usize;
                    if i >= items.len() {
                        continue;
                    }
                    i
                }
                _ => continue,
            };
            let (label, value) = &items[chosen];
            match copy_to_clipboard(value) {
                Ok(how) => self.dashboard.push(Level::Info, &format!("copied {label} via {how}")),
                Err(e) => self.dashboard.push(Level::Warn, &format!("could not copy {label}: {e}")),
            }
            return Ok(());
        }
    }

    fn is_quit(e: &Event) -> bool {
        matches!(e, Event::Key(k)
            if (k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL))
                || k.code == KeyCode::Char('q'))
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = crossterm::execute!(
            std::io::stdout(),
            event::DisableMouseCapture,
            event::DisableBracketedPaste
        );
        ratatui::restore();
    }
}

impl Ui for Tui {
    fn copyable(&mut self, label: &str, value: &str) {
        self.dashboard.remember(label, value);
    }

    fn busy(&mut self, message: &str, elapsed: Duration) {
        let dashboard = &self.dashboard;
        let _ = self.terminal.draw(|f| {
            dashboard.render(f);
            render_busy(f, message, elapsed);
        });
        // Keys pressed while waiting are discarded, except Ctrl-C which is
        // honoured once the work finishes.
        while let Ok(Some(e)) = self.next_key(Duration::ZERO) {
            if Self::is_quit(&e)
                && matches!(e, Event::Key(k) if k.modifiers.contains(KeyModifiers::CONTROL))
            {
                self.quit = true;
            }
        }
    }

    fn log(&mut self, line: &str) {
        self.dashboard.push(Level::Info, line);
        let _ = self.draw();
    }

    fn warn(&mut self, line: &str) {
        self.dashboard.push(Level::Warn, line);
        let _ = self.draw();
    }

    fn status(&mut self, status: &str) {
        self.dashboard.status = status.to_string();
        self.dashboard.push(Level::Info, status);
        let _ = self.draw();
    }

    fn sessions(&mut self, sessions: Vec<SessionView>, selected: Option<usize>) {
        self.dashboard.set_sessions(sessions, selected);
        let _ = self.draw();
    }

    fn confirm(&mut self, title: &str, body: &str) -> Result<bool> {
        let out = self.confirm_inner(title, body);
        let _ = self.draw();
        out
    }

    fn input(&mut self, prompt: &str) -> Result<Option<String>> {
        let out = self.input_inner(prompt);
        let _ = self.draw();
        out
    }

    fn select_many(
        &mut self,
        title: &str,
        items: &[String],
        preselected: &[usize],
    ) -> Result<Vec<usize>> {
        let out = self.select_many_inner(title, items, preselected);
        let _ = self.draw();
        out
    }

    fn poll(&mut self) -> Result<UiAction> {
        if self.quit {
            return Ok(UiAction::Quit);
        }
        let mut redraw = false;
        let mut action = UiAction::Idle;
        while let Some(e) = self.next_key(Duration::ZERO)? {
            if Self::is_quit(&e) {
                self.quit = true;
                return Ok(UiAction::Quit);
            }
            match e {
                Event::Key(k) => match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.dashboard.log_scroll =
                            (self.dashboard.log_scroll + 1).min(self.dashboard.log.len());
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.dashboard.log_scroll = self.dashboard.log_scroll.saturating_sub(1);
                    }
                    KeyCode::Char('c') => {
                        self.copy_menu()?;
                    }
                    KeyCode::Char('m') => {
                        let on = !self.dashboard.mouse;
                        self.set_mouse(on);
                        self.dashboard.push(
                            Level::Info,
                            if on {
                                "mouse capture on: click wallets to switch"
                            } else {
                                "mouse capture off: select text with the terminal; press m to re-enable"
                            },
                        );
                    }
                    KeyCode::Char('n') => action = UiAction::NewConnection,
                    KeyCode::Char('d') => action = UiAction::Disconnect,
                    KeyCode::Char('e') => action = UiAction::EditWallets,
                    KeyCode::Char('g') => action = UiAction::NewWallet,
                    KeyCode::Tab | KeyCode::BackTab | KeyCode::Right | KeyCode::Left => {
                        let n = self.dashboard.sessions.len();
                        if n > 0 {
                            let current = self.dashboard.selected.unwrap_or(0);
                            let back = matches!(k.code, KeyCode::BackTab | KeyCode::Left);
                            let next = if back { (current + n - 1) % n } else { (current + 1) % n };
                            action = UiAction::SelectSession(next);
                        }
                    }
                    KeyCode::Char(c @ '0'..='9') => {
                        let idx = if c == '0' { 9 } else { c as usize - '1' as usize };
                        if idx < self.dashboard.wallets.len() {
                            action = UiAction::SwitchAccount(idx);
                        }
                    }
                    _ => {}
                },
                Event::Mouse(m) => match m.kind {
                    MouseEventKind::Down(MouseButton::Left) => {
                        let area = self.terminal.get_frame().area();
                        if let Some(idx) = self.dashboard.wallet_at(area, m.column, m.row) {
                            action = UiAction::SwitchAccount(idx);
                        } else if let Some(idx) = self.dashboard.session_at(area, m.column, m.row) {
                            action = UiAction::SelectSession(idx);
                        }
                    }
                    MouseEventKind::ScrollUp => {
                        self.dashboard.wallet_offset =
                            self.dashboard.wallet_offset.saturating_sub(1);
                    }
                    MouseEventKind::ScrollDown => {
                        self.dashboard.wallet_offset = (self.dashboard.wallet_offset + 1)
                            .min(self.dashboard.wallets.len().saturating_sub(1));
                    }
                    _ => {}
                },
                _ => {}
            }
            redraw = true;
            if action != UiAction::Idle {
                break;
            }
        }
        if redraw {
            self.draw()?;
        }
        Ok(action)
    }
}

impl Tui {
    fn open_link(&mut self, url: &str) {
        match open_in_browser(url) {
            Ok(()) => self.dashboard.push(Level::Info, "opened the link in your browser"),
            Err(e) => self.dashboard.push(
                Level::Warn,
                &format!("could not open the link ({e:#}); press c to copy it instead"),
            ),
        }
    }

    fn confirm_inner(&mut self, title: &str, body: &str) -> Result<bool> {
        let link = find_link(body).map(str::to_string);
        let shown = if link.is_some() { body_for_dashboard(body) } else { body.to_string() };
        let footer = if link.is_some() {
            "y approve · n / Esc reject · o open link · c copy · ↑↓ PgUp PgDn scroll"
        } else {
            "y approve · n / Esc reject · c copy · ↑↓ PgUp PgDn scroll"
        };
        let mut scroll: u16 = 0;
        loop {
            let dashboard = &self.dashboard;
            self.terminal.draw(|f| {
                dashboard.render(f);
                render_confirm(f, title, &shown, footer, scroll, link.as_deref());
            })?;
            let Some(e) = self.next_key(Duration::from_millis(250))? else { continue };
            if let Event::Mouse(m) = e {
                let screen = self.terminal.get_frame().area();
                match m.kind {
                    MouseEventKind::Down(MouseButton::Left) => {
                        let (_, bar) = confirm_layout(screen, link.is_some());
                        if let (Some(bar), Some(url)) = (bar, link.as_deref())
                            && bar.contains(ratatui::layout::Position::new(m.column, m.row))
                        {
                            self.open_link(url);
                        }
                    }
                    MouseEventKind::ScrollDown => scroll = scroll.saturating_add(1),
                    MouseEventKind::ScrollUp => scroll = scroll.saturating_sub(1),
                    _ => {}
                }
                continue;
            }
            if let Event::Key(k) = e {
                match k.code {
                    KeyCode::Char('o') => {
                        if let Some(url) = link.clone() {
                            self.open_link(&url);
                        }
                    }
                    KeyCode::Char('y') | KeyCode::Char('Y') => return Ok(true),
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => return Ok(false),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.quit = true;
                        return Ok(false);
                    }
                    KeyCode::Char('c') => self.copy_menu()?,
                    KeyCode::Down | KeyCode::Char('j') => scroll = scroll.saturating_add(1),
                    KeyCode::Up | KeyCode::Char('k') => scroll = scroll.saturating_sub(1),
                    KeyCode::PageDown => scroll = scroll.saturating_add(10),
                    KeyCode::PageUp => scroll = scroll.saturating_sub(10),
                    _ => {}
                }
            }
        }
    }

    fn input_inner(&mut self, prompt: &str) -> Result<Option<String>> {
        let mut value = String::new();
        loop {
            let body = format!("{value}▏");
            self.draw_modal(prompt, &body, "paste or type · Enter confirm · Esc cancel", 0)?;
            let Some(e) = self.next_key(Duration::from_millis(250))? else { continue };
            match e {
                Event::Paste(text) => value.push_str(text.trim()),
                Event::Key(k) => match k.code {
                    KeyCode::Enter => {
                        let v = value.trim().trim_matches(['"', '\'']).to_string();
                        if !v.is_empty() {
                            return Ok(Some(v));
                        }
                    }
                    KeyCode::Esc => return Ok(None),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.quit = true;
                        return Ok(None);
                    }
                    KeyCode::Backspace => {
                        value.pop();
                    }
                    KeyCode::Char(c) => value.push(c),
                    _ => {}
                },
                _ => {}
            }
        }
    }

    fn select_many_inner(
        &mut self,
        title: &str,
        items: &[String],
        preselected: &[usize],
    ) -> Result<Vec<usize>> {
        let mut selected = vec![false; items.len()];
        for &i in preselected {
            if let Some(s) = selected.get_mut(i) {
                *s = true;
            }
        }
        let mut cursor = 0usize;
        let mut filter = String::new();
        loop {
            let visible: Vec<usize> = items
                .iter()
                .enumerate()
                .filter(|(_, it)| {
                    filter.is_empty() || it.to_lowercase().contains(&filter.to_lowercase())
                })
                .map(|(i, _)| i)
                .collect();
            if cursor >= visible.len() {
                cursor = visible.len().saturating_sub(1);
            }
            let mut body = format!("filter: {filter}▏\n\n");
            for (row, &i) in visible.iter().enumerate() {
                let mark = if selected[i] { "[x]" } else { "[ ]" };
                let pointer = if row == cursor { ">" } else { " " };
                body.push_str(&format!("{pointer} {mark} {}\n", items[i]));
            }
            let chosen = selected.iter().filter(|s| **s).count();
            let footer = format!(
                "{chosen} selected · Space toggle · a all shown · type to filter · Enter confirm · Esc cancel"
            );
            self.draw_modal(title, &body, &footer, cursor.saturating_sub(10) as u16)?;
            let Some(e) = self.next_key(Duration::from_millis(250))? else { continue };
            let Event::Key(k) = e else { continue };
            match k.code {
                KeyCode::Enter => {
                    let out: Vec<usize> =
                        selected.iter().enumerate().filter(|(_, s)| **s).map(|(i, _)| i).collect();
                    if !out.is_empty() {
                        return Ok(out);
                    }
                }
                KeyCode::Esc => return Ok(Vec::new()),
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.quit = true;
                    return Ok(Vec::new());
                }
                KeyCode::Char(' ') => {
                    if let Some(&i) = visible.get(cursor) {
                        selected[i] = !selected[i];
                    }
                }
                KeyCode::Char('a') if filter.is_empty() => {
                    let all = visible.iter().all(|&i| selected[i]);
                    for &i in &visible {
                        selected[i] = !all;
                    }
                }
                KeyCode::Down => cursor = (cursor + 1).min(visible.len().saturating_sub(1)),
                KeyCode::Up => cursor = cursor.saturating_sub(1),
                KeyCode::Backspace => {
                    filter.pop();
                }
                KeyCode::Char(c) => filter.push(c),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn dashboard_renders_without_panicking() {
        let mut d = Dashboard { relay: "wss://relay.example".into(), ..Default::default() };
        d.status = "Waiting".into();
        let session = SessionView {
            dapp_name: "Dapp".into(),
            dapp_url: "https://dapp".into(),
            chains: vec!["eip155:1".into()],
            methods: vec!["personal_sign".into()],
            wallets: vec![WalletRow { name: "Main".into(), address: "0xabc".into() }],
            expiry: u64::MAX,
            sign_ins: 1,
            requests_approved: 2,
            ..Default::default()
        };
        let pending =
            SessionView { pending: true, wallets: session.wallets.clone(), ..Default::default() };
        d.set_sessions(vec![session, pending], Some(0));
        for i in 0..600 {
            d.push(Level::Info, &format!("line {i}"));
        }
        assert_eq!(d.log.len(), LOG_CAPACITY);
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| d.render(f)).unwrap();
        let text = format!("{}", terminal.backend());
        assert!(text.contains("Wallets (1)"), "{text}");
        assert!(text.contains("Sessions (2)"), "{text}");
        assert!(text.contains("Dapp"), "{text}");
        assert!(text.contains("waiting for a proposal"), "{text}");
        assert!(text.contains("line 599"), "{text}");
        terminal
            .draw(|f| {
                d.render(f);
                render_modal(f, "Sign?", "hello\nworld", "y/n", 0);
            })
            .unwrap();
        let text = format!("{}", terminal.backend());
        assert!(text.contains("Sign?") && text.contains("world"), "{text}");
        terminal
            .draw(|f| {
                d.render(f);
                render_busy(f, "Connecting", Duration::from_millis(1234));
            })
            .unwrap();
        let text = format!("{}", terminal.backend());
        assert!(text.contains("Connecting (1s)"), "{text}");
        // Tiny terminals must not panic either.
        let mut tiny = Terminal::new(TestBackend::new(10, 4)).unwrap();
        tiny.draw(|f| d.render(f)).unwrap();
    }

    #[test]
    fn approval_links_get_a_clickable_bar() {
        let url = format!(
            "https://dashboard.tenderly.co/simulator/new?network=1&rawFunctionInput=0x{}",
            "ab".repeat(400)
        );
        let body = format!("to:        0xdead\n\nsimulate this transaction in Tenderly:\n{url}");
        assert_eq!(find_link(&body), Some(url.as_str()));
        assert_eq!(find_link("no link here\nsee https://x.example for more"), None);
        let shown = body_for_dashboard(&body);
        assert!(!shown.contains(&url) && shown.contains("press o"), "{shown}");
        assert!(shown.starts_with("to:        0xdead\n\nsimulate this"), "{shown}");

        let screen = Rect::new(0, 0, 100, 30);
        let (area, bar) = confirm_layout(screen, true);
        let bar = bar.unwrap();
        assert_eq!(bar.y, area.y + area.height - 2, "last row inside the border");
        assert_eq!((bar.x, bar.width), (area.x + 1, area.width - 2));
        assert_eq!(confirm_layout(screen, false).1, None);

        let d = Dashboard::default();
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal
            .draw(|f| {
                d.render(f);
                render_confirm(f, "Send?", &shown, "y/n", 0, Some(&url));
            })
            .unwrap();
        let text = format!("{}", terminal.backend());
        let bar_row: String = text.lines().nth(bar.y as usize).unwrap().to_string();
        assert!(
            bar_row.contains("↗ open in browser: https://dashboard.tenderly.co/simulator/new?"),
            "{text}"
        );
        assert!(bar_row.contains('…'), "long links are shortened to one row: {bar_row}");
        assert!(text.contains("simulate this transaction in Tenderly:"), "{text}");
        assert!(open_in_browser("file:///etc/passwd").is_err());
    }

    #[test]
    fn run_busy_returns_the_work_result_and_ticks() {
        struct Counting(usize);
        impl Ui for Counting {
            fn log(&mut self, _: &str) {}
            fn warn(&mut self, _: &str) {}
            fn status(&mut self, _: &str) {}
            fn sessions(&mut self, _: Vec<SessionView>, _: Option<usize>) {}
            fn confirm(&mut self, _: &str, _: &str) -> Result<bool> {
                Ok(false)
            }
            fn poll(&mut self) -> Result<UiAction> {
                Ok(UiAction::Idle)
            }
            fn copyable(&mut self, _: &str, _: &str) {}
            fn input(&mut self, _: &str) -> Result<Option<String>> {
                Ok(None)
            }
            fn select_many(&mut self, _: &str, _: &[String], _: &[usize]) -> Result<Vec<usize>> {
                Ok(vec![])
            }
            fn busy(&mut self, _: &str, _: Duration) {
                self.0 += 1;
            }
        }
        let mut ui = Counting(0);
        let value = run_busy(&mut ui, "work", || {
            std::thread::sleep(Duration::from_millis(250));
            42
        });
        assert_eq!(value, 42);
        assert!(ui.0 >= 2, "ticked {} times", ui.0);
    }

    #[test]
    fn wallet_panel_grows_scrolls_and_hit_tests() {
        let mut d = Dashboard {
            wallets: (0..12)
                .map(|i| WalletRow { name: format!("w{i}"), address: format!("0x{i:040x}") })
                .collect(),
            ..Default::default()
        };
        let area = Rect::new(0, 0, 100, 40);
        let (_, _, panel, _, _) = d.layout(area);
        assert_eq!(panel.height, 14, "12 wallets + borders fit under the 45% cap");
        // First row of the panel body is wallet 0.
        assert_eq!(d.wallet_at(area, panel.x + 2, panel.y + 1), Some(0));
        assert_eq!(d.wallet_at(area, panel.x + 2, panel.y + 12), Some(11));
        assert_eq!(d.wallet_at(area, panel.x + 2, panel.y), None, "border is not a row");
        assert_eq!(d.wallet_at(area, 0, 0), None);

        // A short terminal scrolls the list so the active wallet stays visible.
        let short = Rect::new(0, 0, 100, 20);
        let (_, _, panel, _, _) = d.layout(short);
        assert_eq!(panel.height, 9);
        d.active = 11;
        let (offset, visible) = d.wallet_window(panel, 1);
        assert_eq!(visible, 7);
        assert_eq!(offset, 5);
        assert_eq!(d.wallet_at(short, panel.x + 1, panel.y + 7), Some(11));
        let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
        terminal.draw(|f| d.render(f)).unwrap();
        let text = format!("{}", terminal.backend());
        assert!(text.contains("showing 6-12"), "{text}");
        assert!(text.contains("▶") && text.contains("w11"), "{text}");
    }

    #[test]
    fn sessions_panel_hit_tests_and_follows_selection() {
        let view = |name: &str, wallets: usize| SessionView {
            dapp_name: name.into(),
            wallets: (0..wallets)
                .map(|i| WalletRow { name: format!("{name}{i}"), address: format!("0x{i:040x}") })
                .collect(),
            active: wallets - 1,
            ..Default::default()
        };
        let mut d = Dashboard::default();
        d.set_sessions(vec![view("a", 1), view("b", 3), view("c", 2)], Some(1));
        assert_eq!(d.wallets.len(), 3, "wallet panel shows the selected session");
        assert_eq!(d.active, 2);
        let area = Rect::new(0, 0, 120, 40);
        let (_, sessions, _, _, _) = d.layout(area);
        assert_eq!(sessions.height, 5, "three sessions plus borders");
        assert_eq!(d.session_at(area, sessions.x + 2, sessions.y + 1), Some(0));
        assert_eq!(d.session_at(area, sessions.x + 2, sessions.y + 3), Some(2));
        assert_eq!(d.session_at(area, sessions.x + 2, sessions.y), None);
        d.set_sessions(vec![view("a", 1)], Some(5));
        assert_eq!(d.selected, None, "out of range selection is dropped");
        assert!(d.wallets.is_empty());
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        d.set_sessions(Vec::new(), None);
        terminal.draw(|f| d.render(f)).unwrap();
        let text = format!("{}", terminal.backend());
        assert!(text.contains("press n to connect a dapp"), "{text}");
    }

    #[test]
    fn copy_items_prefer_recent_values_then_addresses() {
        let mut d = Dashboard {
            wallets: vec![WalletRow { name: "Main".into(), address: "0xabc".into() }],
            ..Default::default()
        };
        assert_eq!(d.copy_items(), vec![("address of Main".to_string(), "0xabc".to_string())]);
        d.remember("tx hash on eip155:1", "0x1");
        d.remember("tx hash on eip155:10", "0x2");
        d.remember("tx hash on eip155:1", "0x1"); // re-noting moves it to the front, no duplicate
        let items = d.copy_items();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].1, "0x1");
        assert_eq!(items[1].1, "0x2");
        assert_eq!(items[2].0, "address of Main");
    }

    #[test]
    fn long_names_and_addresses_are_never_truncated() {
        let long = "Long-Term Treasury Reserve for Operations Account".to_string();
        let addr = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string();
        let d = Dashboard {
            wallets: vec![
                WalletRow { name: long.clone(), address: addr.clone() },
                WalletRow { name: "short".into(), address: addr.clone() },
            ],
            ..Default::default()
        };
        // Wide terminal: one row per wallet, panel sized to fit name + address.
        let (rows, width) = d.geometry(160);
        assert_eq!(rows, 1);
        assert_eq!(width as usize, 3 + long.chars().count() + 1 + 42 + 2);
        let mut terminal = Terminal::new(TestBackend::new(160, 20)).unwrap();
        terminal.draw(|f| d.render(f)).unwrap();
        let text = format!("{}", terminal.backend());
        assert!(text.contains(&long) && text.contains(&addr), "{text}");
        assert!(!text.contains('…'), "{text}");

        // Narrow terminal: the address moves to a second row, still complete.
        let (rows, _) = d.geometry(90);
        assert_eq!(rows, 2);
        let area = Rect::new(0, 0, 90, 30);
        let (_, _, panel, _, _) = d.layout(area);
        assert_eq!(panel.height, 9, "at least the session details plus borders");
        assert_eq!(d.wallet_at(area, panel.x + 1, panel.y + 1), Some(0));
        assert_eq!(d.wallet_at(area, panel.x + 1, panel.y + 2), Some(0));
        assert_eq!(d.wallet_at(area, panel.x + 1, panel.y + 3), Some(1));
        let mut terminal = Terminal::new(TestBackend::new(90, 30)).unwrap();
        terminal.draw(|f| d.render(f)).unwrap();
        let text = format!("{}", terminal.backend());
        assert!(text.contains(&long) && text.contains(&addr), "{text}");
        assert!(!text.contains('…'), "{text}");
    }
}
