use clap::{Parser, Subcommand};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;
use std::thread;
use std::time::{Duration, SystemTime};

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

#[derive(Copy, Clone)]
enum ViewMode {
    Live,
    Snapshot,
}

#[derive(Debug, Clone, Serialize)]
struct ProcessInfo {
    pid: u32,
    user: String,
    command_line: String,
    cwd: Option<String>,
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
            render(&groups, ViewMode::Snapshot)?;
        }
        Some(Command::Export { path }) => {
            let groups = gather_groups()?;
            export_json(&groups, &path)?;
            println!("snapshot written to {}", path.display());
        }
        None => run_live()?,
    }

    Ok(())
}

fn run_live() -> io::Result<()> {
    loop {
        let groups = gather_groups()?;
        render(&groups, ViewMode::Live)?;
        thread::sleep(REFRESH_INTERVAL);
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

fn render(groups: &BTreeMap<String, Vec<ProcessInfo>>, mode: ViewMode) -> io::Result<()> {
    let mut stdout = io::stdout();
    if matches!(mode, ViewMode::Live) {
        // Clear screen and move cursor to top-left.
        write!(stdout, "\u{001b}[2J\u{001b}[H")?;
    }

    let now = SystemTime::now();
    let timestamp = match now.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            format!("{secs}")
        }
        Err(_) => String::from("unknown"),
    };

    writeln!(stdout, "baywatch — grouping processes by working directory")?;
    match mode {
        ViewMode::Live => writeln!(stdout, "updated at {timestamp}; press Ctrl+C to exit")?,
        ViewMode::Snapshot => writeln!(stdout, "snapshot at {timestamp}")?,
    }
    writeln!(stdout)?;

    if groups.is_empty() {
        writeln!(stdout, "no processes found for current user")?;
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
