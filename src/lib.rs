//! Local secrets catalog for AI agents. Names and locations only: nothing in
//! this crate returns, logs or stores a secret's value.

mod daemon;
mod mcp;
mod scan;

pub use daemon::{catalog_path, ensure_daemon, load_catalog, run_daemon};
pub use mcp::{handle_message, serve_stdio, ServerOptions};
pub use scan::{is_secret_name, parse_env_names, scan};

use kernal_api::json::{encode, Layout, Value};
use std::collections::BTreeMap;

/// One place a named secret was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// `env`, `process`, `dotenv`, `store`, `credential_file` or `keyring`.
    pub kind: &'static str,
    pub location: String,
}

/// Entries whose name contains `query`, ignoring case and `-`/`_`.
pub fn filter<'a>(entries: &'a [Entry], query: Option<&str>) -> Vec<&'a Entry> {
    let wanted = query.map(normalize).unwrap_or_default();
    entries
        .iter()
        .filter(|entry| normalize(&entry.name).contains(&wanted))
        .collect()
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// How a caller can use a secret found in `kind` without exposing it.
pub fn usage_hint(kind: &str) -> &'static str {
    match kind {
        "env" => "Already in this session's environment. Pass it to one command; never print it.",
        "process" => "Held by another program. Ask the user before reusing it, and pipe it over stdin; never print it.",
        "dotenv" => "In an env file. Ask the user before reusing it, and load it for one command; never print it.",
        "credential_file" => "Used automatically by the owning tool. Prefer running that tool.",
        "store" => "Entered by the user through lokr. Load it for one command through a pipe; never print it.",
        "keyring" => "In the OS keyring. Fetch it for one command through a pipe; never print it.",
        _ => "Ask the user before using it.",
    }
}

/// A JSON string.
pub(crate) fn text(value: impl Into<String>) -> Value {
    Value::String(value.into())
}

/// A JSON object from key/value pairs.
pub(crate) fn object<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect::<BTreeMap<_, _>>())
}

/// Compact JSON text.
pub fn to_json(value: &Value) -> String {
    encode(value, Layout::Compact)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_else(|_| "null".to_string())
}

/// The catalog as JSON. There is no value field to leak.
pub fn catalog_json(entries: &[Entry]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                object([
                    ("name", text(entry.name.clone())),
                    ("kind", text(entry.kind)),
                    ("location", text(entry.location.clone())),
                    ("how_to_use", text(usage_hint(entry.kind))),
                ])
            })
            .collect(),
    )
}
