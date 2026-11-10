use kernal_api::json::parse;
use lokr::{handle_message, is_secret_name, parse_env_names, to_json, ServerOptions};

const CANARY: &str = "sk-or-v1-canary-must-never-appear";

fn send(options: &ServerOptions, message: &str) -> String {
    to_json(&handle_message(options, &parse(message.as_bytes()).unwrap()).unwrap())
}

#[test]
fn recognises_credential_names() {
    assert!(is_secret_name("OPENROUTER_API_KEY"));
    assert!(is_secret_name("GITHUB_TOKEN"));
    assert!(!is_secret_name("PATH"));
    assert!(!is_secret_name("_TOKEN"));
    assert!(!is_secret_name("lower_token"));
}

#[test]
fn env_parsing_skips_empty_values_and_keeps_only_names() {
    let text = format!("export A_API_KEY={CANARY}\nB_TOKEN=\nC_TOKEN=\"\"\nHOME=/x\n# D_TOKEN=y");
    assert_eq!(parse_env_names(&text), ["A_API_KEY"]);
}

#[test]
fn scan_finds_key_without_leaking_it_and_no_value_route_exists() {
    std::env::set_var("LOKRTEST_API_KEY", CANARY);
    let options = ServerOptions::default();
    let entries = lokr::scan();
    assert!(entries
        .iter()
        .any(|e| e.name == "LOKRTEST_API_KEY" && e.kind == "env"));
    assert!(!to_json(&lokr::catalog_json(&entries)).contains(CANARY));
    let status = send(
        &options,
        r#"{"id":1,"method":"tools/call","params":{"name":"secret_status","arguments":{"name":"no-such-key-xyz"}}}"#,
    );
    assert!(status.contains(r#"\"available\":false"#), "{status}");
    let listed = send(&options, r#"{"id":2,"method":"tools/list"}"#);
    assert!(listed.contains("list_secrets") && listed.contains("secret_status"));
    assert!(!listed.contains("get_secret"));
    assert!(!listed.contains("request_secret"), "no prompt configured");
}

#[test]
fn request_secret_reports_only_status_and_rejects_generic_context() {
    let options = ServerOptions {
        daemon_command: Vec::new(),
        ask_command: vec!["must-never-spawn-a-real-prompt".into()],
    };
    let call = |title: &str| {
        send(
            &options,
            &format!(
                r#"{{"id":3,"method":"tools/call","params":{{"name":"request_secret","arguments":{{"title":"{title}","message":"Needed for OAuth; find it in GitHub developer settings","sink":{{"type":"file","path":"unused"}}}}}}}}"#
            ),
        )
    };
    let cancelled = call("GitHub OAuth Client ID");
    assert!(
        cancelled.contains("failed") && !cancelled.contains(CANARY),
        "{cancelled}"
    );
    assert!(call("password").contains("specific title"));
}

#[test]
fn notifications_get_no_response() {
    let message = parse(br#"{"method":"notifications/initialized"}"#).unwrap();
    assert!(handle_message(&ServerOptions::default(), &message).is_none());
}

#[test]
fn request_schema_requires_context_and_sink() {
    let options = ServerOptions {
        daemon_command: vec![],
        ask_command: vec!["lokr".into(), "request".into()],
    };
    let listed = send(&options, r#"{"id":1,"method":"tools/list"}"#);
    assert!(
        listed.contains("request_secret")
            && listed.contains("title")
            && listed.contains("message")
            && listed.contains("sink")
    );
    let missing = send(
        &options,
        r#"{"id":2,"method":"tools/call","params":{"name":"request_secret","arguments":{"name":"TOKEN"}}}"#,
    );
    assert!(missing.contains("isError") && missing.contains("title"));
}
