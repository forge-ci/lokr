use crate::{catalog_json, object, scan, to_json, Entry};
use kernal_api::json::{parse, Value};
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SCAN_INTERVAL: Duration = Duration::from_secs(60);
/// The daemon exits when no MCP server has touched the heartbeat for this long.
const IDLE_EXIT: Duration = Duration::from_secs(600);

fn state_dir() -> std::io::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| std::io::Error::other("no home directory"))?;
    let dir = PathBuf::from(home).join(".lokr");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

pub fn catalog_path() -> std::io::Result<PathBuf> {
    Ok(state_dir()?.join("catalog.json"))
}

fn write_private(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let temp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&temp)?.write_all(bytes)?;
    std::fs::rename(&temp, path)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn write_catalog(entries: &[Entry]) -> std::io::Result<()> {
    let document = object([("scanned_at", Value::Unsigned(now())), ("secrets", catalog_json(entries))]);
    write_private(&catalog_path()?, to_json(&document).as_bytes())
}

/// The stored catalog, or `None` before the first scan has finished.
pub fn load_catalog() -> Option<Value> {
    parse(&std::fs::read(catalog_path().ok()?).ok()?).ok()
}

/// Marks an MCP server as alive, so the daemon keeps scanning.
pub(crate) fn touch_heartbeat() {
    if let Ok(dir) = state_dir() {
        let _ = write_private(&dir.join("heartbeat"), b"");
    }
}

fn pid_alive(pid: &str) -> bool {
    !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) && {
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/proc").join(pid).exists()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

/// Starts the scanner unless one is running. `command` is program plus args.
pub fn ensure_daemon(command: &[OsString]) -> std::io::Result<()> {
    let pid = std::fs::read_to_string(state_dir()?.join("daemon.pid")).unwrap_or_default();
    if pid_alive(pid.trim()) {
        return Ok(());
    }
    let (program, args) = command
        .split_first()
        .ok_or_else(|| std::io::Error::other("empty daemon command"))?;
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(drop)
}

/// Scans on a background thread until no MCP server has been alive for a while.
pub fn run_daemon() -> std::io::Result<()> {
    let dir = state_dir()?;
    let pid_file = dir.join("daemon.pid");
    let existing = std::fs::read_to_string(&pid_file).unwrap_or_default();
    if pid_alive(existing.trim()) {
        return Ok(());
    }
    write_private(&pid_file, std::process::id().to_string().as_bytes())?;
    touch_heartbeat();
    std::thread::spawn(|| loop {
        let _ = write_catalog(&scan());
        std::thread::sleep(SCAN_INTERVAL);
    });
    let heartbeat = dir.join("heartbeat");
    loop {
        std::thread::sleep(Duration::from_secs(30));
        let idle = std::fs::metadata(&heartbeat)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|time| time.elapsed().ok())
            .unwrap_or(IDLE_EXIT);
        if idle >= IDLE_EXIT {
            let _ = std::fs::remove_file(&pid_file);
            return Ok(());
        }
    }
}
