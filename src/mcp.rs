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
    /// and prints `stored`, `failed` or `cancelled`. Validated request flags are
    /// appended to this command. Empty disables `request_secret`.
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
            request_schema(),
        ));
    }
    Value::Array(list)
}

fn catalog() -> (Vec<Value>, Value) {
    let as_list = |value: Option<&Value>| match value {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    let (mut secrets, scanned_at) = match load_catalog() {
        Some(document) => (
            as_list(field(&document, "secrets")),
            field(&document, "scanned_at")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        // First call beat the daemon's first scan.
        None => (as_list(Some(&catalog_json(&scan()))), Value::Null),
    };
    // New requests must be visible before the daemon's next periodic scan.
    if let Value::Array(records) = catalog_json(&crate::request::recorded()) {
        for record in records {
            if !secrets.contains(&record) {
                secrets.push(record);
            }
        }
    }
    (secrets, scanned_at)
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

fn request_args(arguments: &Value) -> Result<Vec<String>, String> {
    let required = |key| {
        string(arguments, key)
            .map(str::to_owned)
            .ok_or_else(|| format!("`{key}` is required"))
    };
    let mut args = vec![
        "--title".into(),
        required("title")?,
        "--message".into(),
        required("message")?,
    ];
    for (key, flag) in [("hint", "--hint"), ("pattern", "--pattern")] {
        if let Some(value) = field(arguments, key) {
            let Value::String(value) = value else {
                return Err(format!("`{key}` must be a string"));
            };
            args.extend([flag.into(), value.clone()]);
        }
    }
    let sink = field(arguments, "sink").ok_or("`sink` is required")?;
    let Value::Object(sink_fields) = sink else {
        return Err("sink must be an object".into());
    };
    let allowed: &[&str] = match string(sink, "type") {
        Some("file") => &["type", "path"],
        Some("keyring") => &["type", "service", "user"],
        Some("command") => &["type", "argv"],
        _ => return Err("sink type must be file, keyring or command".into()),
    };
    if sink_fields
        .keys()
        .any(|key| !allowed.contains(&key.as_str()))
    {
        return Err("exactly one sink variant is required".into());
    }
    let prop = |key| {
        string(sink, key)
            .map(str::to_owned)
            .ok_or_else(|| format!("sink `{key}` is required"))
    };
    match string(sink, "type") {
        Some("file") => args.extend(["--to-file".into(), prop("path")?]),
        Some("keyring") => args.extend(["--to-keyring".into(), prop("service")?, prop("user")?]),
        Some("command") => {
            let Some(Value::Array(argv)) = field(sink, "argv") else {
                return Err("sink `argv` must be an array".into());
            };
            args.push("--to-command".into());
            for arg in argv {
                let Value::String(arg) = arg else {
                    return Err("command arguments must be strings".into());
                };
                args.push(arg.clone());
            }
        }
        _ => return Err("sink type must be file, keyring or command".into()),
    }
    crate::request::Request::parse(args.clone()).map_err(|_| {
        "A specific title, explanatory message, valid pattern and exactly one sink are required"
            .to_string()
    })?;
    Ok(args)
}

fn ask(options: &ServerOptions, arguments: &Value) -> Result<Value, String> {
    let args = request_args(arguments)?;
    if crate::request::interaction_disabled() {
        return Ok(text("failed"));
    }
    let (program, prefix) = options
        .ask_command
        .split_first()
        .ok_or("no secret prompt is configured")?;
    // The child owns input, delivery, erasure and catalog registration. Never capture output.
    let status = Command::new(program)
        .args(prefix)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "could not start the secret prompt".to_string())?;
    Ok(text(match status.code() {
        Some(0) => "stored",
        Some(3) => "cancelled",
        _ => "failed",
    }))
}

fn request_schema() -> Value {
    let str_prop = || object([("type", text("string"))]);
    let variant = |kind: &str, extra: Vec<(&str, Value)>| {
        let mut fields = vec![("type", object([("const", text(kind))]))];
        fields.extend(extra);
        let required = Value::Array(fields.iter().map(|(key, _)| text(*key)).collect());
        object([
            ("type", text("object")),
            (
                "properties",
                Value::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect()),
            ),
            ("required", required),
            ("additionalProperties", Value::Bool(false)),
        ])
    };
    object([
        ("type", text("object")),
        (
            "properties",
            object([
                ("title", str_prop()),
                ("message", str_prop()),
                ("hint", str_prop()),
                ("pattern", str_prop()),
                (
                    "sink",
                    object([(
                        "oneOf",
                        Value::Array(vec![
                            variant("file", vec![("path", str_prop())]),
                            variant(
                                "keyring",
                                vec![("service", str_prop()), ("user", str_prop())],
                            ),
                            variant(
                                "command",
                                vec![(
                                    "argv",
                                    object([
                                        ("type", text("array")),
                                        ("items", str_prop()),
                                        ("minItems", Value::Unsigned(1)),
                                    ]),
                                )],
                            ),
                        ]),
                    )]),
                ),
            ]),
        ),
        (
            "required",
            Value::Array(["title", "message", "sink"].into_iter().map(text).collect()),
        ),
        ("additionalProperties", Value::Bool(false)),
    ])
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
        "request_secret" if !options.ask_command.is_empty() => ask(options, arguments),
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
                object([
                    ("name", text("lokr")),
                    ("version", text(env!("CARGO_PKG_VERSION"))),
                ]),
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
                    object([
                        ("code", Value::Signed(-32601)),
                        ("message", text("method not found")),
                    ]),
                ),
            ]))
        }
    };
    Some(object([
        ("jsonrpc", text("2.0")),
        ("id", id),
        ("result", result),
    ]))
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
        let Ok(message) = parse(line.as_bytes()) else {
            continue;
        };
        if let Some(response) = handle_message(options, &message) {
            writeln!(stdout, "{}", to_json(&response))?;
            stdout.flush()?;
        }
    }
    Ok(())
}
