use chrono::{DateTime, Local};
use clap::{Parser, Subcommand};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use libc::{self, ESRCH, SIGTERM};
use ratatui::{
    Frame,
    prelude::*,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;
use std::time::{Duration, Instant, SystemTime};

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const LSOF_CHUNK_SIZE: usize = 40;
const IGNORE_PREFIXES: &[&str] = &["/Applications/", "/System/"];
const SUPPRESS_COMMANDS: &[&str] = &["zsh", "bash", "sh", "fish", "pwsh", "powershell"];

#[derive(Parser, Debug)]
#[command(
    name = "baywatch",
    about = "Group running processes by working directory."
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print a single snapshot of the grouped processes.
    Snapshot,
    /// Write a snapshot to the given JSON file.
    Export {
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize)]
struct ProcessInfo {
    pid: u32,
    user: String,
    command_line: String,
    cwd: Option<String>,
}

type GroupedProcesses = BTreeMap<String, Vec<ProcessInfo>>;

#[derive(Debug, Clone)]
struct GroupEntry {
    name: String,
    processes: Vec<ProcessInfo>,
    selected_process: Option<usize>,
}

impl GroupEntry {
    fn new(name: String, processes: Vec<ProcessInfo>, preferred_pid: Option<u32>) -> Self {
        let selected_process = preferred_pid
            .and_then(|pid| processes.iter().position(|proc| proc.pid == pid))
            .or_else(|| if !processes.is_empty() { Some(0) } else { None });
        Self {
            name,
            processes,
            selected_process,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Focus {
    Groups,
    Processes,
}

#[derive(Copy, Clone, Debug)]
enum StatusKind {
    Info,
    Success,
    Warning,
    Error,
}

impl StatusKind {
    fn style(self) -> Style {
        match self {
            StatusKind::Info => Style::default().fg(Color::Gray),
            StatusKind::Success => Style::default().fg(Color::LightGreen),
            StatusKind::Warning => Style::default().fg(Color::Yellow),
            StatusKind::Error => Style::default().fg(Color::LightRed),
        }
    }
}

#[derive(Clone, Debug)]
struct StatusMessage {
    text: String,
    kind: StatusKind,
}

impl StatusMessage {
    fn new(kind: StatusKind, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind,
        }
    }
}

struct App {
    groups: Vec<GroupEntry>,
    last_updated: SystemTime,
    status: Option<StatusMessage>,
    focus: Focus,
    selected_group: usize,
}

impl App {
    fn new() -> io::Result<Self> {
        let mut app = Self {
            groups: Vec::new(),
            last_updated: SystemTime::now(),
            status: None,
            focus: Focus::Groups,
            selected_group: 0,
        };

        let initial_groups = gather_groups()?;
        app.replace_groups(initial_groups);
        if app.groups.is_empty() {
            app.status = Some(StatusMessage::new(
                StatusKind::Info,
                "no matching processes",
            ));
        }
        Ok(app)
    }

    fn refresh(&mut self) -> io::Result<()> {
        match gather_groups() {
            Ok(groups) => {
                self.last_updated = SystemTime::now();
                if groups.is_empty() {
                    if self.groups.is_empty() {
                        self.set_status(StatusKind::Info, "no matching processes");
                    } else {
                        self.set_status(
                            StatusKind::Warning,
                            "no matching processes right now; showing previous snapshot",
                        );
                    }
                    return Ok(());
                }

                self.replace_groups(groups);
                self.clear_warning();
                Ok(())
            }
            Err(err) => {
                self.set_status(StatusKind::Error, format!("refresh failed: {err}"));
                Err(err)
            }
        }
    }

    fn replace_groups(&mut self, map: GroupedProcesses) {
        let preferred: HashMap<String, Option<u32>> = self
            .groups
            .iter()
            .map(|group| {
                let pid = group
                    .selected_process
                    .and_then(|idx| group.processes.get(idx))
                    .map(|proc| proc.pid);
                (group.name.clone(), pid)
            })
            .collect();

        let previous_selection = self.selected_group_name().map(|name| name.to_string());

        let mut new_groups = Vec::new();
        for (name, processes) in map.into_iter() {
            let preferred_pid = preferred.get(&name).copied().flatten();
            new_groups.push(GroupEntry::new(name, processes, preferred_pid));
        }

        if new_groups.is_empty() {
            self.selected_group = 0;
        } else if let Some(name) = previous_selection {
            if let Some(index) = new_groups.iter().position(|g| g.name == name) {
                self.selected_group = index;
            } else {
                self.selected_group = self.selected_group.min(new_groups.len() - 1);
            }
        } else {
            self.selected_group = self.selected_group.min(new_groups.len() - 1);
        }

        self.groups = new_groups;
        self.ensure_focus_valid();
    }

    fn ensure_focus_valid(&mut self) {
        if self.groups.is_empty() {
            self.focus = Focus::Groups;
            self.selected_group = 0;
            return;
        }

        if self.selected_group >= self.groups.len() {
            self.selected_group = self.groups.len() - 1;
        }

        if matches!(self.focus, Focus::Processes)
            && self.groups[self.selected_group].selected_process.is_none()
        {
            self.focus = Focus::Groups;
        }
    }

    fn selected_group_name(&self) -> Option<&str> {
        self.groups
            .get(self.selected_group)
            .map(|group| group.name.as_str())
    }

    fn move_focus(&mut self, delta: isize) {
        match self.focus {
            Focus::Groups => self.move_group(delta),
            Focus::Processes => self.move_process(delta),
        }
    }

    fn move_group(&mut self, delta: isize) {
        if self.groups.is_empty() {
            return;
        }
        let len = self.groups.len() as isize;
        let mut index = self.selected_group as isize + delta;
        index = index.clamp(0, len - 1);
        self.selected_group = index as usize;
        if let Some(group) = self.groups.get_mut(self.selected_group) {
            if group.selected_process.is_none() && !group.processes.is_empty() {
                group.selected_process = Some(0);
            }
        }
    }

    fn move_process(&mut self, delta: isize) {
        if let Some(group) = self.groups.get_mut(self.selected_group) {
            if group.processes.is_empty() {
                return;
            }
            let len = group.processes.len() as isize;
            let current = group.selected_process.unwrap_or(0) as isize;
            let mut index = current + delta;
            index = index.clamp(0, len - 1);
            group.selected_process = Some(index as usize);
        }
    }

    fn focus_groups(&mut self) {
        self.focus = Focus::Groups;
    }

    fn focus_processes(&mut self) {
        if self.groups.is_empty() {
            self.set_status(StatusKind::Info, "no projects to focus on");
            return;
        }
        if self.groups[self.selected_group].processes.is_empty() {
            let name = self.groups[self.selected_group].name.clone();
            self.set_status(StatusKind::Info, format!("{name} has no visible processes"));
            return;
        }
        if let Some(group) = self.groups.get_mut(self.selected_group) {
            if group.selected_process.is_none() {
                group.selected_process = Some(0);
            }
        }
        self.focus = Focus::Processes;
    }

    fn toggle_focus(&mut self) {
        match self.focus {
            Focus::Groups => self.focus_processes(),
            Focus::Processes => self.focus_groups(),
        }
    }

    fn to_group_map(&self) -> GroupedProcesses {
        let mut map = BTreeMap::new();
        for group in &self.groups {
            map.insert(group.name.clone(), group.processes.clone());
        }
        map
    }

    fn selected_process_details(&self) -> Option<(String, ProcessInfo)> {
        let group = self.groups.get(self.selected_group)?;
        let index = group.selected_process?;
        group
            .processes
            .get(index)
            .cloned()
            .map(|process| (group.name.clone(), process))
    }

    fn kill_selected_process(&mut self) {
        if !matches!(self.focus, Focus::Processes) {
            self.set_status(
                StatusKind::Info,
                "focus the process pane (Tab) to terminate a process",
            );
            return;
        }

        let Some((directory, process)) = self.selected_process_details() else {
            self.set_status(StatusKind::Info, "no process selected");
            return;
        };

        match terminate_process(process.pid) {
            Ok(()) => {
                self.set_status(
                    StatusKind::Success,
                    format!("sent SIGTERM to {} ({})", process.pid, process.command_line),
                );
                let _ = self.refresh();
            }
            Err(err) => {
                self.set_status(
                    StatusKind::Error,
                    format!("failed to kill {} in {}: {err}", process.pid, directory),
                );
            }
        }
    }

    fn kill_selected_group(&mut self) {
        if self.groups.is_empty() {
            self.set_status(StatusKind::Info, "no projects to terminate");
            return;
        }
        let group_name = self.groups[self.selected_group].name.clone();
        let processes = self.groups[self.selected_group].processes.clone();

        if processes.is_empty() {
            self.set_status(
                StatusKind::Info,
                format!("{group_name} has no visible processes"),
            );
            return;
        }

        let mut successes = 0usize;
        let mut failures: Vec<(u32, io::Error)> = Vec::new();

        for process in &processes {
            match terminate_process(process.pid) {
                Ok(()) => successes += 1,
                Err(err) => failures.push((process.pid, err)),
            }
        }

        if failures.is_empty() {
            self.set_status(
                StatusKind::Success,
                format!(
                    "terminated {} process{} in {}",
                    successes,
                    if successes == 1 { "" } else { "es" },
                    group_name
                ),
            );
            let _ = self.refresh();
        } else {
            let (pid, err) = &failures[0];
            self.set_status(
                StatusKind::Error,
                format!(
                    "partial kill: {} failure(s), first failure on {}: {err}",
                    failures.len(),
                    pid
                ),
            );
        }
    }

    fn write_snapshot_file(&self) -> io::Result<PathBuf> {
        let map = self.to_group_map();
        let path = timestamped_path("baywatch", "txt");
        let mut file = File::create(&path)?;
        render_snapshot(&mut file, &map)?;
        file.flush()?;
        Ok(path)
    }

    fn write_export_file(&self) -> io::Result<PathBuf> {
        let map = self.to_group_map();
        let path = timestamped_path("baywatch", "json");
        export_json(&map, &path)?;
        Ok(path)
    }

    fn set_status(&mut self, kind: StatusKind, text: impl Into<String>) {
        self.status = Some(StatusMessage::new(kind, text));
    }

    fn clear_warning(&mut self) {
        if matches!(
            self.status.as_ref().map(|status| status.kind),
            Some(StatusKind::Warning)
        ) {
            self.status = None;
        }
    }
}

fn main() {
    let args = Args::parse();

    if let Err(err) = run(args) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> io::Result<()> {
    match args.command {
        Some(Command::Snapshot) => {
            let groups = gather_groups()?;
            let mut stdout = io::stdout();
            render_snapshot(&mut stdout, &groups)?;
            stdout.flush()
        }
        Some(Command::Export { path }) => {
            let groups = gather_groups()?;
            export_json(&groups, &path)?;
            println!("snapshot written to {}", path.display());
            Ok(())
        }
        None => run_tui(),
    }
}

fn run_tui() -> io::Result<()> {
    let mut app = App::new()?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut last_tick = Instant::now();

    let result: io::Result<()> = loop {
        terminal.draw(|frame| draw(frame, &app))?;

        let timeout = REFRESH_INTERVAL
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_millis(0));

        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    let ctrl_c = key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL);
                    if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) || ctrl_c {
                        break Ok(());
                    }

                    match key.code {
                        KeyCode::Tab => app.toggle_focus(),
                        KeyCode::Left | KeyCode::Char('h') => app.focus_groups(),
                        KeyCode::Right | KeyCode::Char('l') => app.focus_processes(),
                        KeyCode::Up | KeyCode::Char('k') => app.move_focus(-1),
                        KeyCode::Down | KeyCode::Char('j') => app.move_focus(1),
                        KeyCode::Char('s') => match app.write_snapshot_file() {
                            Ok(path) => app.set_status(
                                StatusKind::Success,
                                format!("snapshot saved to {}", path.display()),
                            ),
                            Err(err) => {
                                app.set_status(StatusKind::Error, format!("snapshot failed: {err}"))
                            }
                        },
                        KeyCode::Char('e') => match app.write_export_file() {
                            Ok(path) => app.set_status(
                                StatusKind::Success,
                                format!("exported JSON to {}", path.display()),
                            ),
                            Err(err) => {
                                app.set_status(StatusKind::Error, format!("export failed: {err}"))
                            }
                        },
                        KeyCode::Char('x') => app.kill_selected_process(),
                        KeyCode::Char('X') => app.kill_selected_group(),
                        KeyCode::Char('r') => {
                            let _ = app.refresh();
                            app.set_status(StatusKind::Info, "manual refresh requested");
                        }
                        _ => {}
                    }
                }
                Event::Resize(_, _) => {
                    terminal.draw(|frame| draw(frame, &app))?;
                }
                _ => {}
            }
        }

        if last_tick.elapsed() >= REFRESH_INTERVAL {
            let _ = app.refresh();
            last_tick = Instant::now();
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, cursor::Show)?;
    terminal.show_cursor()?;

    result
}

fn draw(frame: &mut Frame, app: &App) {
    let size = frame.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(size);

    let workspace_count = app.groups.len();
    let overview_line = Line::from(vec![
        Span::styled(
            "baywatch ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "• {} workspace{}",
            workspace_count,
            if workspace_count == 1 { "" } else { "s" }
        )),
        Span::raw(" • last refresh "),
        Span::styled(
            format_timestamp(app.last_updated),
            Style::default().fg(Color::LightGreen),
        ),
    ]);

    let header = Paragraph::new(overview_line)
        .alignment(Alignment::Left)
        .block(Block::default().title("Overview").borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    if app.groups.is_empty() {
        let placeholder = Paragraph::new("No processes found for current user.")
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .title("Active directories")
                    .borders(Borders::ALL),
            );
        frame.render_widget(placeholder, chunks[1]);
    } else {
        let body_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(chunks[1]);

        let directory_items = build_directory_items(app);
        let mut directory_state = ListState::default();
        directory_state.select(Some(app.selected_group));

        let directory_block = Block::default()
            .title("Projects")
            .borders(Borders::ALL)
            .border_style(if matches!(app.focus, Focus::Groups) {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            });

        let directory_list = List::new(directory_items)
            .block(directory_block)
            .highlight_style({
                if matches!(app.focus, Focus::Groups) {
                    Style::default()
                        .bg(Color::Yellow)
                        .fg(Color::Black)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                        .fg(Color::LightYellow)
                        .add_modifier(Modifier::BOLD)
                }
            })
            .highlight_symbol("» ");

        frame.render_stateful_widget(directory_list, body_chunks[0], &mut directory_state);

        if let Some(group) = app.groups.get(app.selected_group) {
            if group.processes.is_empty() {
                let empty = Paragraph::new("No visible processes in this project.")
                    .alignment(Alignment::Center)
                    .block(
                        Block::default()
                            .title(format!("Processes in {}", group.name))
                            .borders(Borders::ALL),
                    );
                frame.render_widget(empty, body_chunks[1]);
            } else {
                let process_items = build_process_items(group);
                let mut process_state = ListState::default();
                process_state.select(group.selected_process);

                let process_block = Block::default()
                    .title(format!("Processes in {}", group.name))
                    .borders(Borders::ALL)
                    .border_style(if matches!(app.focus, Focus::Processes) {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    });

                let process_list = List::new(process_items)
                    .block(process_block)
                    .highlight_style(if matches!(app.focus, Focus::Processes) {
                        Style::default()
                            .bg(Color::LightBlue)
                            .fg(Color::Black)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    })
                    .highlight_symbol("› ");

                frame.render_stateful_widget(process_list, body_chunks[1], &mut process_state);
            }
        }
    }

    let status = build_status_bar(app);
    frame.render_widget(status, chunks[2]);
}

fn build_directory_items(app: &App) -> Vec<ListItem<'static>> {
    app.groups
        .iter()
        .map(|group| {
            let mut spans = Vec::new();
            spans.push(Span::styled(
                group.name.clone(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                format!("({})", group.processes.len()),
                Style::default().fg(Color::Gray),
            ));
            ListItem::new(Line::from(spans))
        })
        .collect()
}

fn build_process_items(group: &GroupEntry) -> Vec<ListItem<'static>> {
    group
        .processes
        .iter()
        .map(|process| {
            let line = Line::from(vec![
                Span::styled(
                    format!("[{}]", process.pid),
                    Style::default().fg(Color::LightBlue),
                ),
                Span::raw(" "),
                Span::styled(process.user.clone(), Style::default().fg(Color::Green)),
                Span::raw(" - "),
                Span::raw(process.command_line.clone()),
            ]);
            ListItem::new(line)
        })
        .collect()
}

fn build_status_bar(app: &App) -> Paragraph<'static> {
    let instructions: [(&str, &str, Color); 8] = [
        ("q", "quit", Color::LightRed),
        ("Tab", "focus", Color::Yellow),
        ("←/→", "pane", Color::Yellow),
        ("↑/↓", "move", Color::Yellow),
        ("s", "snapshot txt", Color::LightBlue),
        ("e", "export json", Color::LightBlue),
        ("x", "kill process", Color::LightRed),
        ("X", "kill project", Color::Red),
    ];

    let mut spans: Vec<Span> = Vec::new();
    for (idx, (key, label, color)) in instructions.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            *key,
            Style::default().fg(*color).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {}", label),
            Style::default().fg(Color::Gray),
        ));
    }

    spans.push(Span::raw("  • focus "));
    let focus_span = match app.focus {
        Focus::Groups => Span::styled("projects", Style::default().fg(Color::Yellow)),
        Focus::Processes => Span::styled("processes", Style::default().fg(Color::LightBlue)),
    };
    spans.push(focus_span.add_modifier(Modifier::BOLD));

    if let Some(status) = &app.status {
        spans.push(Span::raw("  • "));
        spans.push(Span::styled(status.text.clone(), status.kind.style()));
    }

    Paragraph::new(Line::from(spans))
        .alignment(Alignment::Left)
        .block(Block::default().title("Status").borders(Borders::ALL))
}

fn format_timestamp(time: SystemTime) -> String {
    let date_time: DateTime<Local> = time.into();
    let absolute = date_time.format("%Y-%m-%d %H:%M:%S").to_string();
    let relative = format_relative(time);
    format!("{absolute} ({relative})")
}

fn format_relative(time: SystemTime) -> String {
    match SystemTime::now().duration_since(time) {
        Ok(duration) => {
            if duration < Duration::from_secs(1) {
                "just now".to_string()
            } else if duration < Duration::from_secs(60) {
                format!("{}s ago", duration.as_secs())
            } else if duration < Duration::from_secs(3600) {
                let minutes = duration.as_secs() / 60;
                format!("{minutes}m ago")
            } else if duration < Duration::from_secs(86_400) {
                let hours = duration.as_secs() / 3600;
                let minutes = (duration.as_secs() % 3600) / 60;
                if minutes == 0 {
                    format!("{hours}h ago")
                } else {
                    format!("{hours}h {minutes}m ago")
                }
            } else {
                let days = duration.as_secs() / 86_400;
                format!("{days}d ago")
            }
        }
        Err(_) => "in the future".to_string(),
    }
}

fn gather_groups() -> io::Result<BTreeMap<String, Vec<ProcessInfo>>> {
    let processes = collect_processes()?;
    let cwd_map = resolve_cwds(&processes)?;
    Ok(group_by_directory(processes, cwd_map))
}

fn collect_processes() -> io::Result<Vec<ProcessInfo>> {
    let output = ProcCommand::new("ps")
        .arg("-axo")
        .arg("pid=,user=,comm=,args=")
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "ps exited with status {}",
                output.status.code().unwrap_or_default()
            ),
        ));
    }

    let home_user = env::var("USER").unwrap_or_default();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }

        let mut fields = trimmed.split_whitespace();
        let pid_str = match fields.next() {
            Some(pid) => pid,
            None => continue,
        };
        let pid = match pid_str.parse::<u32>() {
            Ok(value) => value,
            Err(_) => continue,
        };

        let user = match fields.next() {
            Some(user) => user.to_string(),
            None => continue,
        };

        // Default to the command name when args are unavailable.
        let comm = fields.next().unwrap_or("").to_string();
        let mut args = fields.collect::<Vec<_>>().join(" ");

        if args.is_empty() {
            args = comm.clone();
        }

        // Trim redundant spaces that can appear when ps truncates columns.
        let full_command = args.trim().to_string();

        let mut command_words = full_command.split_whitespace();
        let first_word = command_words.next().unwrap_or("");
        let rest = command_words.collect::<Vec<_>>().join(" ");
        let base = first_word.rsplit('/').next().unwrap_or(first_word);
        let command_line = if rest.is_empty() {
            base.to_string()
        } else {
            format!("{base} {rest}")
        };

        // Focus on processes owned by the current user to avoid permission noise.
        if !home_user.is_empty() && user != home_user {
            continue;
        }

        processes.push(ProcessInfo {
            pid,
            user,
            command_line,
            cwd: None,
        });
    }

    Ok(processes)
}

fn resolve_cwds(processes: &[ProcessInfo]) -> io::Result<HashMap<u32, String>> {
    let mut cwd_map = HashMap::new();
    let pids: Vec<u32> = processes.iter().map(|p| p.pid).collect();

    for chunk in pids.chunks(LSOF_CHUNK_SIZE) {
        if chunk.is_empty() {
            continue;
        }

        let pid_list = chunk
            .iter()
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let output = ProcCommand::new("lsof")
            .args(["-Fn", "-a", "-d", "cwd", "-p", &pid_list])
            .output()?;

        if !output.status.success() {
            // Keep going even if we cannot inspect some processes.
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_pid: Option<u32> = None;

        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix('p') {
                if let Ok(pid) = rest.trim().parse::<u32>() {
                    current_pid = Some(pid);
                }
            } else if let Some(path) = line.strip_prefix('n') {
                if let Some(pid) = current_pid {
                    cwd_map.insert(pid, path.trim().to_string());
                }
            }
        }
    }

    Ok(cwd_map)
}

fn group_by_directory(
    mut processes: Vec<ProcessInfo>,
    cwd_map: HashMap<u32, String>,
) -> BTreeMap<String, Vec<ProcessInfo>> {
    for process in &mut processes {
        if let Some(path) = cwd_map.get(&process.pid) {
            process.cwd = Some(path.clone());
        }
    }

    let home_dir = env::var("HOME").ok();
    let mut groups: BTreeMap<String, Vec<ProcessInfo>> = BTreeMap::new();

    for process in processes {
        if should_suppress_command(&process.command_line) {
            continue;
        }

        let key = match &process.cwd {
            Some(path) if should_ignore(path, home_dir.as_deref()) => continue,
            Some(path) => shorten_path(path, home_dir.as_deref()),
            None => continue,
        };
        if key == "~" {
            continue;
        }
        groups.entry(key).or_default().push(process);
    }

    groups
}

fn shorten_path(path: &str, home_dir: Option<&str>) -> String {
    if let Some(home) = home_dir {
        if path.starts_with(home) {
            let mut shortened = String::from("~");
            if home.len() < path.len() {
                shortened.push_str(&path[home.len()..]);
            }
            return shortened;
        }
    }
    path.to_string()
}

fn should_ignore(path: &str, home_dir: Option<&str>) -> bool {
    let ignores_static = IGNORE_PREFIXES
        .iter()
        .any(|prefix| path == prefix.trim_end_matches('/') || path.starts_with(prefix));

    if ignores_static {
        return true;
    }

    if let Some(home) = home_dir {
        if !path.starts_with(home) {
            return true;
        }

        let suffix = &path[home.len()..];
        if suffix.is_empty() {
            return false;
        }

        if suffix == "/Library" || suffix.starts_with("/Library/") {
            return true;
        }
    }

    false
}

fn should_suppress_command(command_line: &str) -> bool {
    let base = command_line.split_whitespace().next().unwrap_or("");
    SUPPRESS_COMMANDS
        .iter()
        .any(|candidate| base.eq_ignore_ascii_case(candidate))
}

fn export_json(groups: &BTreeMap<String, Vec<ProcessInfo>>, path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, groups)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    file.flush()
}

fn render_snapshot<W: Write>(
    writer: &mut W,
    groups: &BTreeMap<String, Vec<ProcessInfo>>,
) -> io::Result<()> {
    let timestamp = format_timestamp(SystemTime::now());

    writeln!(
        writer,
        "baywatch snapshot — grouping processes by working directory"
    )?;
    writeln!(writer, "snapshot captured {timestamp}")?;
    writeln!(writer)?;

    if groups.is_empty() {
        writeln!(writer, "no processes found for current user.")?;
        writer.flush()?;
        return Ok(());
    }

    for (directory, processes) in groups {
        writeln!(writer, "{directory}")?;
        for process in processes {
            writeln!(
                writer,
                "    [{pid}] {user}: {cmd}",
                pid = process.pid,
                user = process.user,
                cmd = process.command_line
            )?;
        }
        writeln!(writer)?;
    }

    writer.flush()
}

fn timestamped_path(prefix: &str, extension: &str) -> PathBuf {
    let stamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
    PathBuf::from(format!("{prefix}-{stamp}.{extension}"))
}

fn terminate_process(pid: u32) -> io::Result<()> {
    let pid_t = pid as libc::pid_t;
    let result = unsafe { libc::kill(pid_t, SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ESRCH) {
            Ok(())
        } else {
            Err(err)
        }
    }
}
