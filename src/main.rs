use chrono::{DateTime, Local};
use clap::{Parser, Subcommand};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame,
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
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

struct App {
    groups: GroupedProcesses,
    last_updated: SystemTime,
    message: Option<String>,
}

impl App {
    fn new() -> io::Result<Self> {
        let groups = gather_groups()?;
        Ok(Self {
            groups,
            last_updated: SystemTime::now(),
            message: None,
        })
    }

    fn refresh(&mut self) -> io::Result<()> {
        let groups = gather_groups()?;
        self.groups = groups;
        self.last_updated = SystemTime::now();
        self.message = None;
        Ok(())
    }

    fn set_error(&mut self, err: io::Error) {
        self.message = Some(format!("refresh failed: {err}"));
    }

    fn status_line(&self) -> String {
        self.message.clone().unwrap_or_else(|| {
            "Press q to quit • snapshot: baywatch snapshot • export: baywatch export <file>"
                .to_string()
        })
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
            render_snapshot(&groups)?;
        }
        Some(Command::Export { path }) => {
            let groups = gather_groups()?;
            export_json(&groups, &path)?;
            println!("snapshot written to {}", path.display());
        }
        None => run_tui()?,
    }

    Ok(())
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
                    let is_ctrl_c = key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL);
                    if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) || is_ctrl_c {
                        break Ok(());
                    }
                }
                Event::Resize(_, _) => {
                    // trigger redraw immediately on resize
                    terminal.draw(|frame| draw(frame, &app))?;
                }
                _ => {}
            }
        }

        if last_tick.elapsed() >= REFRESH_INTERVAL {
            match app.refresh() {
                Ok(_) => {}
                Err(err) => app.set_error(err),
            }
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
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(size);

    let header_lines = vec![
        Line::from(Span::styled(
            "baywatch",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "tracking {} workspace{}",
            app.groups.len(),
            if app.groups.len() == 1 { "" } else { "s" }
        )),
        Line::from(format!(
            "last refresh {}",
            format_timestamp(app.last_updated)
        )),
    ];

    let header = Paragraph::new(header_lines)
        .alignment(Alignment::Left)
        .block(Block::default().title("Overview").borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let items = build_process_items(&app.groups);
    let list_block = Block::default()
        .title("Active directories")
        .borders(Borders::ALL);

    if items.is_empty() {
        let empty = Paragraph::new("No processes found for current user.")
            .alignment(Alignment::Center)
            .block(list_block);
        frame.render_widget(empty, chunks[1]);
    } else {
        let list = List::new(items).block(list_block);
        frame.render_widget(list, chunks[1]);
    }

    let status_line = app.status_line();
    let status = Paragraph::new(status_line)
        .alignment(Alignment::Left)
        .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(status, chunks[2]);
}

fn build_process_items(groups: &GroupedProcesses) -> Vec<ListItem<'static>> {
    let mut items = Vec::new();
    let mut first_group = true;

    for (directory, processes) in groups {
        if !first_group {
            items.push(ListItem::new(Line::from("")));
        }
        first_group = false;

        items.push(ListItem::new(Line::from(vec![Span::styled(
            directory.clone(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )])));

        for process in processes {
            let pid_span = Span::styled(
                format!("[{}]", process.pid),
                Style::default().fg(Color::LightBlue),
            );
            let user_span = Span::styled(process.user.clone(), Style::default().fg(Color::Green));
            let command_span = Span::raw(process.command_line.clone());

            let line = Line::from(vec![
                Span::raw("  "),
                pid_span,
                Span::raw(" "),
                user_span,
                Span::raw(": "),
                command_span,
            ]);
            items.push(ListItem::new(line));
        }
    }

    items
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
        let key = match &process.cwd {
            Some(path) if should_ignore(path, home_dir.as_deref()) => continue,
            Some(path) => shorten_path(path, home_dir.as_deref()),
            None => continue,
        };
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
        // Match exact ~/Library or any nested path like ~/Library/Containers/...
        if suffix.is_empty() {
            return false;
        }

        if suffix == "/Library" || suffix.starts_with("/Library/") {
            return true;
        }
    }

    false
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

fn render_snapshot(groups: &BTreeMap<String, Vec<ProcessInfo>>) -> io::Result<()> {
    let mut stdout = io::stdout();
    let timestamp = format_timestamp(SystemTime::now());

    writeln!(
        stdout,
        "baywatch snapshot — grouping processes by working directory"
    )?;
    writeln!(stdout, "snapshot captured {timestamp}")?;
    writeln!(stdout)?;

    if groups.is_empty() {
        writeln!(stdout, "no processes found for current user.")?;
        stdout.flush()?;
        return Ok(());
    }

    for (directory, processes) in groups {
        writeln!(stdout, "{directory}")?;
        for process in processes {
            writeln!(
                stdout,
                "    [{pid}] {user}: {cmd}",
                pid = process.pid,
                user = process.user,
                cmd = process.command_line
            )?;
        }
        writeln!(stdout)?;
    }

    stdout.flush()
}
