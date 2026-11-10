//! Credential collection and delivery. No public operation returns a credential.
use regex::Regex;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// Fail closed in unit tests, integration-test binaries, and explicitly headless checks.
/// The executable check also protects a plain `soldr cargo test` without environment flags.
pub fn interaction_disabled() -> bool {
    cfg!(test)
        || std::env::var_os("LOKR_TEST_MODE").is_some()
        || std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.ends_with("deps")))
            .unwrap_or(false)
}

/// Deliberately carries no input or backend diagnostics that could expose a value.
#[derive(Debug, Clone, Copy)]
pub struct RequestError;
impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("credential request failed")
    }
}
impl std::error::Error for RequestError {}

pub const WARNING: &str = "This is NOT your computer or login password.";
pub const FORMAT_ERROR: &str = "Format error: the value must fully match the expected format. Try again (three attempts maximum).";

#[derive(Clone)]
pub enum Sink {
    File(PathBuf),
    Keyring(String, String),
    Command(Vec<String>),
}

#[derive(Clone)]
pub struct Request {
    pub title: String,
    pub message: String,
    pub hint: Option<String>,
    pub pattern: Option<String>,
    pub multiline: bool,
    pub sink: Sink,
    pub requester: String,
}

fn meaningful(value: &str) -> bool {
    let words: Vec<String> = value
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        .collect();
    let generic = [
        "password",
        "secret",
        "credential",
        "credentials",
        "enter",
        "the",
        "requested",
        "please",
        "your",
        "a",
        "an",
        "value",
        "input",
        "provide",
        "needed",
        "required",
        "token",
        "key",
        "api",
        "here",
        "it",
        "for",
        "authentication",
        "auth",
        "login",
        "now",
        "below",
        "above",
        "this",
        "that",
        "some",
        "to",
        "continue",
        "access",
        "system",
        "computer",
        "account",
        "and",
        "or",
        "prompt",
        "request",
        "string",
        "text",
        "is",
        "be",
        "me",
        "us",
        "you",
    ];
    words.len() >= 3
        && words.iter().any(|w| !generic.contains(&w.as_str()))
        && value.len() <= 4096
        && !value.chars().any(|c| c.is_control() && c != '\n')
}

impl Request {
    pub fn validate(&self) -> Result<(), RequestError> {
        if !meaningful(&self.title) || !meaningful(&self.message) {
            return Err(RequestError);
        }
        Validation::new(self.pattern.as_deref())?;
        match &self.sink {
            Sink::File(p) if p.as_os_str().is_empty() => Err(RequestError),
            Sink::Keyring(s, u) if s.trim().is_empty() || u.trim().is_empty() => Err(RequestError),
            Sink::Command(c) if c.is_empty() || c[0].is_empty() => Err(RequestError),
            _ => Ok(()),
        }
    }

    pub fn parse(args: Vec<String>) -> Result<Self, RequestError> {
        let mut title = None;
        let mut message = None;
        let mut hint = None;
        let mut pattern = None;
        let mut multiline = false;
        let mut sink = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--title" if title.is_none() => title = Some(args.next().ok_or(RequestError)?),
                "--message" if message.is_none() => {
                    message = Some(args.next().ok_or(RequestError)?)
                }
                "--hint" if hint.is_none() => hint = Some(args.next().ok_or(RequestError)?),
                "--pattern" if pattern.is_none() => {
                    pattern = Some(args.next().ok_or(RequestError)?)
                }
                "--multiline" if !multiline => multiline = true,
                "--to-file" if sink.is_none() => {
                    sink = Some(Sink::File(args.next().ok_or(RequestError)?.into()))
                }
                "--to-keyring" if sink.is_none() => {
                    sink = Some(Sink::Keyring(
                        args.next().ok_or(RequestError)?,
                        args.next().ok_or(RequestError)?,
                    ))
                }
                "--to-command" if sink.is_none() => {
                    sink = Some(Sink::Command(args.collect()));
                    break;
                }
                _ => return Err(RequestError),
            }
        }
        let request = Self {
            title: title.ok_or(RequestError)?,
            message: message.ok_or(RequestError)?,
            hint,
            pattern,
            multiline,
            sink: sink.ok_or(RequestError)?,
            requester: requester(),
        };
        request.validate()?;
        Ok(request)
    }
}

fn requester() -> String {
    #[cfg(target_os = "linux")]
    {
        let mut pid = std::process::id().to_string();
        let mut chain = Vec::new();
        for _ in 0..4 {
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                break;
            };
            let Some(parent) = stat
                .rsplit_once(')')
                .and_then(|(_, s)| s.split_whitespace().nth(1))
            else {
                break;
            };
            if parent == "0" {
                break;
            }
            let Ok(name) = std::fs::read_to_string(format!("/proc/{parent}/comm")) else {
                break;
            };
            chain.push(format!("{} (PID {parent})", name.trim()));
            pid = parent.into();
        }
        if !chain.is_empty() {
            return chain.join(" ← ");
        }
    }
    // Native OS APIs are queried through noninteractive system utilities. No
    // credential, request text or caller-provided script enters these commands.
    #[cfg(target_os = "macos")]
    {
        let parent = Command::new("/bin/ps")
            .args(["-o", "ppid=", "-p", &std::process::id().to_string()])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        if let Ok(parent) = parent {
            let pid = String::from_utf8_lossy(&parent.stdout);
            let pid = pid.trim();
            if !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(output) = Command::new("/bin/ps")
                    .args(["-o", "comm=", "-p", pid])
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .output()
                {
                    let name = String::from_utf8_lossy(&output.stdout);
                    if output.status.success() && !name.trim().is_empty() {
                        return format!("{} (PID {pid})", name.trim());
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        let script = "$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$env:LOKR_REQUEST_PID); $parent=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ParentProcessId); Write-Output ($parent.Name+' (PID '+$parent.ProcessId+')')";
        if let Ok(output) = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("LOKR_REQUEST_PID", std::process::id().to_string())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            let name = String::from_utf8_lossy(&output.stdout);
            if output.status.success() && !name.trim().is_empty() {
                return name.trim().into();
            }
        }
    }
    format!(
        "lokr request (PID {}; parent process unavailable)",
        std::process::id()
    )
}

pub struct Validation {
    regex: Option<Regex>,
    failures: usize,
}
impl Validation {
    pub fn new(pattern: Option<&str>) -> Result<Self, RequestError> {
        let regex = pattern
            .map(|p| {
                if p.len() > 4096 {
                    return Err(RequestError);
                }
                Regex::new(&format!(r"\A(?:{p})\z")).map_err(|_| RequestError)
            })
            .transpose()?;
        Ok(Self { regex, failures: 0 })
    }
    pub fn accept(&mut self, value: &str) -> bool {
        if self.exhausted() {
            return false;
        }
        let valid = !value.is_empty() && self.regex.as_ref().is_none_or(|r| r.is_match(value));
        if !valid {
            self.failures += 1;
        }
        valid
    }
    pub fn exhausted(&self) -> bool {
        self.failures >= 3
    }
}

/// Implementations own the masked input and use the shared three-attempt validator.
/// A successful input is erased when its Zeroizing buffer is dropped.
pub trait Prompt {
    fn collect(
        &mut self,
        request: &Request,
        validation: &mut Validation,
    ) -> Result<Option<Zeroizing<String>>, RequestError>;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Status {
    Stored,
    Cancelled,
    Failed,
}
impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
    pub fn code(self) -> i32 {
        match self {
            Self::Stored => 0,
            Self::Cancelled => 3,
            Self::Failed => 1,
        }
    }
}

pub fn execute(request: &Request, prompt: &mut dyn Prompt) -> Status {
    if request.validate().is_err() {
        return Status::Failed;
    }
    let Ok(mut validation) = Validation::new(request.pattern.as_deref()) else {
        return Status::Failed;
    };
    match prompt.collect(request, &mut validation) {
        Ok(Some(value)) => {
            // Validate independently of the UI implementation before touching a sink.
            let Ok(mut check) = Validation::new(request.pattern.as_deref()) else {
                return Status::Failed;
            };
            if !check.accept(&value) || request.sink.deliver(&value).is_err() {
                return Status::Failed;
            }
            drop(value);
            if record(request).is_err() {
                Status::Failed
            } else {
                Status::Stored
            }
        }
        Ok(None) => Status::Cancelled,
        Err(RequestError) => Status::Failed,
    }
}

pub fn atomic_private(path: &Path, bytes: &[u8]) -> Result<(), RequestError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|_| RequestError)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| RequestError)?;
    }
    #[cfg(windows)]
    {
        // Lock the empty temporary file to the current identity before writing any bytes.
        let script = "$ErrorActionPreference='Stop'; $p=$env:LOKR_PRIVATE_PATH; $id=[System.Security.Principal.WindowsIdentity]::GetCurrent(); $acl=New-Object System.Security.AccessControl.FileSecurity; $acl.SetOwner($id.User); $acl.SetAccessRuleProtection($true,$false); $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($id.User,'FullControl','Allow'); $acl.AddAccessRule($rule); Set-Acl -LiteralPath $p -AclObject $acl -ErrorAction Stop";
        if !Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("LOKR_PRIVATE_PATH", file.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| RequestError)?
            .success()
        {
            return Err(RequestError);
        }
    }
    file.write_all(bytes).map_err(|_| RequestError)?;
    file.as_file().sync_all().map_err(|_| RequestError)?;
    file.persist(path).map_err(|_| RequestError)?;
    Ok(())
}

impl Sink {
    pub fn deliver(&self, value: &str) -> Result<(), RequestError> {
        match self {
            Self::File(path) => atomic_private(path, value.as_bytes()),
            Self::Keyring(service, user) => {
                if interaction_disabled() {
                    return Err(RequestError);
                }
                keyring::Entry::new(service, user)
                    .map_err(|_| RequestError)?
                    .set_password(value)
                    .map_err(|_| RequestError)
            }
            Self::Command(args) => {
                let (program, args) = args.split_first().ok_or(RequestError)?;
                let mut child = Command::new(program)
                    .args(args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|_| RequestError)?;
                let written = child
                    .stdin
                    .take()
                    .ok_or(RequestError)?
                    .write_all(value.as_bytes());
                let status = child.wait().map_err(|_| RequestError)?;
                if written.is_ok() && status.success() {
                    Ok(())
                } else {
                    Err(RequestError)
                }
            }
        }
    }
    fn location(&self) -> String {
        match self {
            Self::File(p) => format!(
                "file:{}",
                std::path::absolute(p)
                    .unwrap_or_else(|_| p.clone())
                    .display()
            ),
            Self::Keyring(s, u) => format!("keyring:{s}/{u}"),
            Self::Command(c) => format!(
                "command:{} (delivered via stdin)",
                c.first().map(String::as_str).unwrap_or("")
            ),
        }
    }
}

fn records_dir() -> Result<PathBuf, RequestError> {
    Ok(crate::catalog_path()
        .map_err(|_| RequestError)?
        .parent()
        .ok_or(RequestError)?
        .join("requests"))
}
fn record(request: &Request) -> Result<(), RequestError> {
    let dir = records_dir()?;
    std::fs::create_dir_all(&dir).map_err(|_| RequestError)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| RequestError)?;
    }
    let data = crate::object([
        ("name", crate::text(&request.title)),
        ("location", crate::text(request.sink.location())),
    ]);
    // Unique files avoid lost updates between concurrent requests and daemon scans.
    let marker = tempfile::NamedTempFile::new_in(&dir).map_err(|_| RequestError)?;
    atomic_private(marker.path(), crate::to_json(&data).as_bytes())?;
    marker.keep().map_err(|_| RequestError)?;
    Ok(())
}
pub(crate) fn recorded() -> Vec<crate::Entry> {
    let Ok(dir) = records_dir() else {
        return Vec::new();
    };
    let Ok(files) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    files
        .flatten()
        .filter_map(|f| {
            let bytes = std::fs::read(f.path()).ok()?;
            let kernal_api::json::Value::Object(mut data) = kernal_api::json::parse(&bytes).ok()?
            else {
                return None;
            };
            let kernal_api::json::Value::String(name) = data.remove("name")? else {
                return None;
            };
            let kernal_api::json::Value::String(location) = data.remove("location")? else {
                return None;
            };
            Some(crate::Entry {
                name,
                location,
                kind: "store",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        attempts: usize,
    }
    impl Prompt for Fake {
        fn collect(
            &mut self,
            _: &Request,
            validation: &mut Validation,
        ) -> Result<Option<Zeroizing<String>>, RequestError> {
            for input in ["wrong", "also wrong", "1234"] {
                self.attempts += 1;
                if validation.accept(input) {
                    return Ok(Some(Zeroizing::new(input.into())));
                }
            }
            Err(RequestError)
        }
    }
    #[test]
    fn fake_retry_stores_and_catalog_contains_metadata_only() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        std::env::set_var("USERPROFILE", dir.path());
        let path = dir.path().join("credential");
        let request = Request {
            title: "GitHub OAuth Client ID".into(),
            message: "Needed for GitHub OAuth; find it in developer settings".into(),
            hint: Some("four digits".into()),
            pattern: Some("[0-9]{4}".into()),
            multiline: false,
            sink: Sink::File(path.clone()),
            requester: "fake-test-agent".into(),
        };
        let mut fake = Fake { attempts: 0 };
        assert_eq!(execute(&request, &mut fake), Status::Stored);
        assert_eq!(fake.attempts, 3);
        assert!(std::fs::read(path).unwrap() == b"1234");
        let records = recorded();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, request.title);
        let json = crate::to_json(&crate::catalog_json(&records));
        assert!(!json.contains("1234"));
        assert!(json.contains("credential"));
    }
}
