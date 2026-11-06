use crate::Entry;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SUFFIXES: [&str; 7] = [
    "_API_KEY", "_APIKEY", "_TOKEN", "_SECRET", "_SECRET_KEY", "_ACCESS_KEY", "_PASSWORD",
];
const KEYRING_TIMEOUT: Duration = Duration::from_secs(5);

/// (name, path under home) of files whose existence means a tool is logged in.
const CREDENTIAL_FILES: [(&str, &str); 5] = [
    ("CARGO_REGISTRY_TOKEN", ".cargo/credentials.toml"),
    ("PYPI_TOKEN", ".pypirc"),
    ("GITHUB_TOKEN", ".config/gh/hosts.yml"),
    ("AWS_SECRET_ACCESS_KEY", ".aws/credentials"),
    ("NPM_TOKEN", ".npmrc"),
];

/// (name, keyring service, keyring user).
const KEYRING_ENTRIES: [(&str, &str, &str); 1] =
    [("PYPI_TOKEN", "https://upload.pypi.org/legacy/", "__token__")];

/// Does this environment variable name look like a credential?
pub fn is_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && SUFFIXES.iter().any(|suffix| name.ends_with(suffix) && name.len() > suffix.len())
}

/// Names of non-empty secrets in `KEY=value` lines. Values are not kept.
pub fn parse_env_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (name, value) = line.split_once('=')?;
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
            (!value.is_empty() && is_secret_name(name.trim())).then(|| name.trim().to_string())
        })
        .collect()
}

/// Every secret this user's account can see, without keeping any value.
pub fn scan() -> Vec<Entry> {
    let mut found = BTreeSet::new();
    let mut add = |name: String, kind: &'static str, location: String| {
        found.insert((name, kind, location));
    };
    for (name, value) in std::env::vars_os() {
        if let Some(name) = name.to_str() {
            if !value.is_empty() && is_secret_name(name) {
                add(name.to_string(), "env", "this session".to_string());
            }
        }
    }
    scan_processes(&mut add);
    if let Some(home) = home() {
        for path in dotenv_files(&home) {
            if let Ok(text) = std::fs::read_to_string(&path) {
                for name in parse_env_names(&text) {
                    add(name, "dotenv", path.display().to_string());
                }
            }
        }
        // Secrets the user entered through `request_secret`.
        for path in children(&home.join(".lokr/store")) {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                add(name.to_string(), "store", path.display().to_string());
            }
        }
        for (name, relative) in CREDENTIAL_FILES {
            let path = home.join(relative);
            if path.metadata().is_ok_and(|meta| meta.len() > 0) {
                add(name.to_string(), "credential_file", path.display().to_string());
            }
        }
    }
    for (name, service, user) in KEYRING_ENTRIES {
        if keyring_has(service, user) {
            add(name.to_string(), "keyring", format!("{service} / {user}"));
        }
    }
    found
        .into_iter()
        .map(|(name, kind, location)| Entry { name, kind, location })
        .collect()
}

#[cfg(target_os = "linux")]
fn scan_processes(add: &mut impl FnMut(String, &'static str, String)) {
    let Ok(dir) = std::fs::read_dir("/proc") else { return };
    let me = std::process::id().to_string();
    for entry in dir.flatten() {
        let pid = entry.file_name();
        let Some(pid) = pid.to_str().filter(|p| p.bytes().all(|b| b.is_ascii_digit())) else {
            continue;
        };
        if pid == me {
            continue;
        }
        // Readable only for processes of this same user.
        let Ok(environ) = std::fs::read(entry.path().join("environ")) else { continue };
        let names: Vec<String> = environ
            .split(|byte| *byte == 0)
            .filter_map(|pair| {
                let pair = String::from_utf8_lossy(pair);
                let (name, value) = pair.split_once('=')?;
                (!value.is_empty() && is_secret_name(name)).then(|| name.to_string())
            })
            .collect();
        if names.is_empty() {
            continue;
        }
        let program = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        let program = program.trim();
        for name in names {
            add(name, "process", format!("program {program}"));
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn scan_processes(_add: &mut impl FnMut(String, &'static str, String)) {}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// `~/.env`, `~/.<tool>/.env` and `~/.config/<tool>/{.env,*.env}`.
fn dotenv_files(home: &Path) -> Vec<PathBuf> {
    let mut files = vec![home.join(".env")];
    for entry in children(home) {
        if entry.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.')) {
            files.push(entry.join(".env"));
        }
    }
    for tool in children(&home.join(".config")) {
        for file in children(&tool) {
            if file.file_name().is_some_and(|n| n.to_string_lossy().ends_with(".env")) {
                files.push(file);
            }
        }
    }
    files
}

fn children(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default()
}

/// Asks the `keyring` CLI, discarding the value. A hang counts as absent.
fn keyring_has(service: &str, user: &str) -> bool {
    let mut candidates = vec![PathBuf::from("keyring")];
    if let Some(home) = home() {
        candidates.push(home.join(".venv/bin/keyring"));
    }
    candidates.into_iter().any(|program| {
        // Exit status alone proves presence; stdout goes nowhere.
        let child = Command::new(program)
            .args(["get", service, user])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else { return false };
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) if start.elapsed() < KEYRING_TIMEOUT => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }
        }
    })
}
