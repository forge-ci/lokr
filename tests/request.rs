use lokr::request::{Request, RequestError, Sink, Validation};

#[test]
fn context_and_exactly_one_sink_are_required() {
    for args in [
        vec![],
        vec![
            "--title",
            "password",
            "--message",
            "secret",
            "--to-file",
            "x",
        ],
        vec![
            "--title",
            "GitHub OAuth Client ID",
            "--message",
            "enter the requested credential",
            "--to-file",
            "x",
        ],
        vec![
            "--title",
            "GitHub OAuth Client ID",
            "--message",
            "Needed for OAuth; find it in GitHub developer settings",
        ],
    ] {
        assert!(Request::parse(args.into_iter().map(String::from).collect()).is_err());
    }
}

#[test]
fn full_match_and_three_attempt_limit() {
    let mut v = Validation::new(Some("[0-9]{4}")).unwrap();
    assert!(!v.accept("x1234"));
    assert!(!v.accept("1234x"));
    assert!(!v.exhausted());
    assert!(!v.accept("bad"));
    assert!(v.exhausted());
    assert!(!v.accept("1234"));
    let mut v = Validation::new(Some("[0-9]{4}")).unwrap();
    assert!(v.accept("1234"));
}

#[test]
fn file_sink_is_private_and_replaces_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credential");
    std::fs::write(&path, "old").unwrap();
    Sink::File(path.clone()).deliver("test-only-value").unwrap();
    assert!(std::fs::read(&path).unwrap() == b"test-only-value");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn command_gets_stdin_and_failure_is_reported() {
    Sink::Command(vec![
        "sh".into(),
        "-c".into(),
        "test \"$(cat)\" = test-only-value".into(),
    ])
    .deliver("test-only-value")
    .unwrap();
    assert!(
        Sink::Command(vec!["sh".into(), "-c".into(), "exit 1".into()])
            .deliver("test-only-value")
            .is_err()
    );
}

#[test]
fn polite_generic_requests_are_rejected() {
    for generic in [
        "Please enter your password now",
        "Enter the requested credential below",
        "Please provide a secret value",
        "Please enter your password again",
        "Enter the requested credential securely",
        "Please enter your password again again",
    ] {
        assert!(Request::parse(vec![
            "--title".into(),
            generic.into(),
            "--message".into(),
            "Needed for GitHub OAuth setup in developer settings".into(),
            "--to-file".into(),
            "unused".into()
        ])
        .is_err());
    }
}

#[test]
fn real_interaction_is_disabled_in_integration_tests() {
    use lokr::request::Prompt;
    assert!(lokr::request::interaction_disabled());
    let request = Request::parse(vec![
        "--title".into(),
        "GitHub OAuth Client ID".into(),
        "--message".into(),
        "Needed for GitHub OAuth; find it in developer settings".into(),
        "--to-file".into(),
        "unused".into(),
    ])
    .unwrap();
    let mut validation = Validation::new(None).unwrap();
    assert!(lokr::request_ui::SystemPrompt
        .collect(&request, &mut validation)
        .is_err());
    assert!(lokr::request_ui::TtyPrompt
        .collect(&request, &mut validation)
        .is_err());
    assert!(Sink::Keyring("test".into(), "test".into())
        .deliver("test-only-value")
        .is_err());
}

struct FakePrompt {
    inputs: Vec<Option<&'static str>>,
    attempts: usize,
}
impl lokr::request::Prompt for FakePrompt {
    fn collect(
        &mut self,
        _: &Request,
        validation: &mut Validation,
    ) -> Result<Option<zeroize::Zeroizing<String>>, RequestError> {
        for input in &self.inputs {
            self.attempts += 1;
            let Some(input) = input else {
                return Ok(None);
            };
            if validation.accept(input) {
                return Ok(Some(zeroize::Zeroizing::new((*input).into())));
            }
            if validation.exhausted() {
                return Err(RequestError);
            }
        }
        Err(RequestError)
    }
}

#[test]
fn fake_ui_cancellation_and_exhaustion_never_touch_sink() {
    use lokr::request::{execute, Status};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("never-written");
    let request = Request::parse(vec![
        "--title".into(),
        "GitHub OAuth Client ID".into(),
        "--message".into(),
        "Needed for GitHub OAuth; find it in developer settings".into(),
        "--pattern".into(),
        "[0-9]{4}".into(),
        "--to-file".into(),
        path.to_str().unwrap().into(),
    ])
    .unwrap();
    let mut fake = FakePrompt {
        inputs: vec![None],
        attempts: 0,
    };
    assert_eq!(execute(&request, &mut fake), Status::Cancelled);
    assert!(!path.exists());
    let mut fake = FakePrompt {
        inputs: vec![Some("bad"), Some("bad"), Some("bad"), Some("1234")],
        attempts: 0,
    };
    assert_eq!(execute(&request, &mut fake), Status::Failed);
    assert_eq!(fake.attempts, 3);
    assert!(!path.exists());
}

#[test]
fn parser_rejects_multiple_sinks_invalid_regex_and_missing_context() {
    let base = [
        "--title",
        "GitHub OAuth Client ID",
        "--message",
        "Needed for GitHub OAuth; find it in developer settings",
    ];
    for extra in [
        vec!["--to-file", "x", "--to-keyring", "s", "u"],
        vec!["--to-file", "x", "--pattern", "["],
        vec!["--to-command"],
        vec!["--to-file", ""],
    ] {
        assert!(Request::parse(
            base.iter()
                .chain(extra.iter())
                .map(|s| (*s).into())
                .collect()
        )
        .is_err());
    }
    for title in ["", " ", "secret", "credential", "password"] {
        assert!(Request::parse(vec![
            "--title".into(),
            title.into(),
            "--message".into(),
            base[3].into(),
            "--to-file".into(),
            "x".into()
        ])
        .is_err());
    }
}

#[test]
fn statuses_have_the_documented_exit_codes() {
    use lokr::request::Status;
    for (status, text, code) in [
        (Status::Stored, "stored", 0),
        (Status::Cancelled, "cancelled", 3),
        (Status::Failed, "failed", 1),
    ] {
        assert_eq!(status.as_str(), text);
        assert_eq!(status.code(), code);
    }
}

#[test]
fn missing_message_or_generic_message_is_rejected_before_ui() {
    for message in [
        None,
        Some(""),
        Some("   "),
        Some("password"),
        Some("enter the requested credential"),
        Some("Please enter your password now"),
    ] {
        let mut args = vec![
            "--title".into(),
            "GitHub OAuth Client ID".into(),
            "--to-file".into(),
            "unused".into(),
        ];
        if let Some(message) = message {
            args.extend(["--message".into(), message.into()]);
        }
        assert!(Request::parse(args).is_err());
    }
}

#[cfg(unix)]
#[test]
fn file_sink_replaces_a_symlink_without_writing_its_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let link = dir.path().join("link");
    std::fs::write(&target, b"original").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    Sink::File(link.clone()).deliver("test-only-value").unwrap();
    assert!(!std::fs::symlink_metadata(link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(std::fs::read(target).unwrap() == b"original");
}

#[test]
fn lowercase_service_title_is_specific_with_an_explanatory_message() {
    assert!(Request::parse(vec![
        "--title".into(),
        "github api key".into(),
        "--message".into(),
        "Needed for GitHub OAuth; find it in developer settings".into(),
        "--to-file".into(),
        "unused".into()
    ])
    .is_ok());
}
