use crate::daemon::{ensure_daemon, load_catalog, touch_heartbeat};
use crate::{catalog_json, object, scan, text, to_json};
use kernal_api::json::{parse, Value};
use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

/// How the host wires lokr in.
#[derive(Clone, Debug, Default)]
pub struct ServerOptions {
    /// Program and arguments that run the background scanner.
    pub daemon_command: Vec<OsString>,
    /// Program and arguments of a masked prompt that delivers to its own sink
    /// and prints `stored`, `failed` or `cancelled`. `{name}` is replaced in
    /// each argument. Empty disables `request_secret`.
    pub ask_command: Vec<OsString>,
}

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map.get(key),
        _ => None,
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match field(value, key) {
        Some(Value::String(found)) => Some(found),
        _ => None,
    }
}

fn input_schema<const N: usize>(properties: [&str; N], required: bool) -> Value {
    let string_type = || object([("type", text("string"))]);
    let names: Vec<(&str, Value)> = properties.iter().map(|p| (*p, string_type())).collect();
    let mut schema = vec![
        ("type".to_string(), text("object")),
        (
            "properties".to_string(),
            Value::Object(names.into_iter().map(|(k, v)| (k.to_string(), v)).collect()),
        ),
    ];
    if required {
        schema.push((
            "required".to_string(),
            Value::Array(properties.iter().map(|p| text(*p)).collect()),
        ));
    }
    Value::Object(schema.into_iter().collect())
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    object([
        ("name", text(name)),
        ("description", text(description)),
        ("inputSchema", schema),
    ])
}

fn tools(options: &ServerOptions) -> Value {
    let mut list = vec![
        tool(
            "list_secrets",
            "List credentials found on this machine: names and locations, never values. `query` filters by name, for example `openrouter`.",
            input_schema(["query"], false),
        ),
        tool(
            "secret_status",
            "Check whether a named credential is available and where. Never returns the value.",
            input_schema(["name"], true),
        ),
    ];
    if !options.ask_command.is_empty() {
        list.push(tool(
            "request_secret",
            "Ask the user for a missing credential in a masked prompt outside the chat. Returns only stored, failed or cancelled.",
            input_schema(["name"], true),
        ));
    }
    Value::Array(list)
}

fn catalog() -> (Vec<Value>, Value) {
    let as_list = |value: Option<&Value>| match value {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    match load_catalog() {
        Some(document) => (
            as_list(field(&document, "secrets")),
            field(&document, "scanned_at").cloned().unwrap_or(Value::Null),
        ),
        // First call beat the daemon's first scan.
        None => (as_list(Some(&catalog_json(&scan()))), Value::Null),
    }
}

fn matching(secrets: Vec<Value>, query: &str) -> Vec<Value> {
    let squash = |input: &str| -> String {
        input
            .chars()
            .filter(|c| !matches!(c, '-' | '_'))
            .flat_map(char::to_lowercase)
            .collect()
    };
    let wanted = squash(query);
    secrets
        .into_iter()
        .filter(|secret| squash(string(secret, "name").unwrap_or("")).contains(&wanted))
        .collect()
}

/// Letters, digits, `_` and `-` only: the name reaches a prompt's arguments.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn ask(options: &ServerOptions, name: &str) -> Result<Value, String> {
    if !valid_name(name) {
        return Err("`name` may contain only letters, digits, `_` and `-`".to_string());
    }
    let (program, args) = options
        .ask_command
        .split_first()
        .ok_or("no secret prompt is configured")?;
    let args = args
        .iter()
        .map(|arg| arg.to_string_lossy().replace("{name}", name));
    // Status comes from the exit code; the prompt's output never reaches us.
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "could not start the secret prompt".to_string())?;
    let outcome = match status.code() {
        Some(0) => "stored",
        Some(3) => "cancelled",
        _ => "failed",
    };
    Ok(object([("name", text(name)), ("status", text(outcome))]))
}

fn call_tool(options: &ServerOptions, name: &str, arguments: &Value) -> Result<Value, String> {
    let required = || {
        string(arguments, "name")
            .filter(|found| !found.is_empty())
            .ok_or("`name` is required".to_string())
    };
    match name {
        "list_secrets" => {
            let (secrets, scanned_at) = catalog();
            let query = string(arguments, "query").unwrap_or("");
            Ok(object([
                ("scanned_at", scanned_at),
                ("secrets", Value::Array(matching(secrets, query))),
            ]))
        }
        "secret_status" => {
            let query = required()?;
            let (secrets, scanned_at) = catalog();
            let found = matching(secrets, query);
            Ok(object([
                ("name", text(query)),
                ("available", Value::Bool(!found.is_empty())),
                ("scanned_at", scanned_at),
                ("found", Value::Array(found)),
            ]))
        }
        "request_secret" if !options.ask_command.is_empty() => ask(options, required()?),
        other => Err(format!("unknown tool: {other}")),
    }
}

/// The JSON-RPC response to one message, or `None` for a notification.
pub fn handle_message(options: &ServerOptions, message: &Value) -> Option<Value> {
    let id = field(message, "id")?.clone();
    let method = string(message, "method").unwrap_or("");
    let null = Value::Null;
    let params = field(message, "params").unwrap_or(&null);
    let result = match method {
        "initialize" => object([
            (
                "protocolVersion",
                text(string(params, "protocolVersion").unwrap_or("2025-06-18")),
            ),
            ("capabilities", object([("tools", object([]))])),
            (
                "serverInfo",
                object([("name", text("lokr")), ("version", text(env!("CARGO_PKG_VERSION")))]),
            ),
        ]),
        "ping" => object([]),
        "tools/list" => object([("tools", tools(options))]),
        "tools/call" => {
            let arguments = field(params, "arguments").unwrap_or(&null);
            let outcome = call_tool(options, string(params, "name").unwrap_or(""), arguments);
            let (body, is_error) = match outcome {
                Ok(value) => (to_json(&value), false),
                Err(error) => (error, true),
            };
            object([
                (
                    "content",
                    Value::Array(vec![object([("type", text("text")), ("text", text(body))])]),
                ),
                ("isError", Value::Bool(is_error)),
            ])
        }
        _ => {
            return Some(object([
                ("jsonrpc", text("2.0")),
                ("id", id),
                (
                    "error",
                    object([("code", Value::Signed(-32601)), ("message", text("method not found"))]),
                ),
            ]))
        }
    };
    Some(object([("jsonrpc", text("2.0")), ("id", id), ("result", result)]))
}

/// Serves MCP on stdin/stdout and starts the background scanner.
pub fn serve_stdio(options: &ServerOptions) -> std::io::Result<()> {
    let _ = ensure_daemon(&options.daemon_command);
    std::thread::spawn(|| loop {
        touch_heartbeat();
        std::thread::sleep(Duration::from_secs(60));
    });
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        let Ok(message) = parse(line.as_bytes()) else { continue };
        if let Some(response) = handle_message(options, &message) {
            writeln!(stdout, "{}", to_json(&response))?;
            stdout.flush()?;
        }
    }
    Ok(())
}
