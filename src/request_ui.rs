//! Native masked window and controlling-terminal fallback.
use crate::request::{Prompt, Request, RequestError, Validation, FORMAT_ERROR, WARNING};
use kernal_api::gfx::{self, App, Event, Frame, Key, WindowOptions};
use std::io::Write;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

type Answer = Result<Option<Zeroizing<String>>, RequestError>;
pub struct SystemPrompt;
impl Prompt for SystemPrompt {
    fn collect(&mut self, request: &Request, validation: &mut Validation) -> Answer {
        if crate::request::interaction_disabled() {
            return Err(RequestError);
        }
        #[cfg(target_os = "linux")]
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return TtyPrompt.collect(request, validation);
        }
        let output = Arc::new(Mutex::new(Ok(None)));
        let shared = output.clone();
        let fallback_request = request.clone();
        let request = request.clone();
        let validation = Validation::new(request.pattern.as_deref())?;
        let options = WindowOptions::new("lokr — credential request")
            .size(660.0, 540.0)
            .resizable(true);
        let result = gfx::run(
            options,
            Window {
                request,
                validation,
                value: Zeroizing::new(String::with_capacity(65536)),
                error: false,
                output: shared,
            },
        );
        if result.is_err() {
            let mut validation = Validation::new(fallback_request.pattern.as_deref())?;
            return TtyPrompt.collect(&fallback_request, &mut validation);
        }
        let answer = output.lock().map_err(|_| RequestError)?.take();
        answer
    }
}

// Take the answer without ever cloning a credential.
trait TakeAnswer {
    fn take(&mut self) -> Answer;
}
impl TakeAnswer for Answer {
    fn take(&mut self) -> Answer {
        std::mem::replace(self, Ok(None))
    }
}
struct Window {
    request: Request,
    validation: Validation,
    value: Zeroizing<String>,
    error: bool,
    output: Arc<Mutex<Answer>>,
}
impl App for Window {
    fn frame(&mut self, frame: &mut Frame<'_>) {
        // Keep the fixed warning visible even with unusually long request context.
        frame.heading(WARNING);
        frame.heading(&self.request.title);
        frame.scroll(120.0, |frame| frame.label(&self.request.message));
        if let Some(hint) = &self.request.hint {
            frame.label(&format!("Expected format: {hint}"));
        }
        if let Some(pattern) = &self.request.pattern {
            frame.label(&format!("Must fully match: {pattern}"));
        }
        frame.label(&format!("Requesting process: {}", self.request.requester));
        frame.separator();
        frame.secret_field(&mut self.value, self.request.multiline);
        frame.label(
            "Type or paste here. Backspace deletes; no reveal, copy or undo. Escape cancels.",
        );
        if frame.events().iter().any(|event| {
            matches!(
                event,
                Event::Key {
                    key: Key::Escape,
                    pressed: true,
                    ..
                }
            )
        }) {
            self.value.zeroize();
            frame.close();
            return;
        }
        if self.error {
            frame.label(FORMAT_ERROR);
        }
        if frame.button("Store credential") {
            if self.submit() {
                frame.close();
            } else {
                frame.clear_keyboard_focus();
                frame.request_repaint();
            }
        }
        if frame.button("Cancel") {
            self.value.zeroize();
            frame.close();
        }
        frame.separator();
        frame.label(WARNING);
    }
}

impl Window {
    // Return true only when the request has a final result.
    fn submit(&mut self) -> bool {
        if self.validation.accept(&self.value) {
            if let Ok(mut output) = self.output.lock() {
                *output = Ok(Some(std::mem::replace(
                    &mut self.value,
                    Zeroizing::new(String::with_capacity(65536)),
                )));
            }
            true
        } else {
            self.value.zeroize();
            self.error = true;
            if self.validation.exhausted() {
                if let Ok(mut output) = self.output.lock() {
                    *output = Err(RequestError);
                }
                true
            } else {
                false
            }
        }
    }
}

pub struct TtyPrompt;
impl Prompt for TtyPrompt {
    fn collect(&mut self, request: &Request, validation: &mut Validation) -> Answer {
        if crate::request::interaction_disabled() {
            return Err(RequestError);
        }
        // Never read MCP stdin or write prompts to the agent's stdout/stderr.
        #[cfg(unix)]
        let tty_name = "/dev/tty";
        #[cfg(windows)]
        let tty_name = "CONOUT$";
        let mut tty = std::fs::OpenOptions::new()
            .write(true)
            .open(tty_name)
            .map_err(|_| RequestError)?;
        writeln!(
            tty,
            "\n{}\n{}\nRequesting process: {}\n{}",
            request.title, request.message, request.requester, WARNING
        )
        .map_err(|_| RequestError)?;
        if let Some(hint) = &request.hint {
            writeln!(tty, "Expected format: {hint}").map_err(|_| RequestError)?;
        }
        if let Some(pattern) = &request.pattern {
            writeln!(tty, "Must fully match: {pattern}").map_err(|_| RequestError)?;
        }
        writeln!(tty, "Submit an empty input to cancel.").map_err(|_| RequestError)?;
        while !validation.exhausted() {
            let mut value = Zeroizing::new(String::with_capacity(65536));
            if request.multiline {
                writeln!(tty, "Enter masked lines; an empty line finishes.")
                    .map_err(|_| RequestError)?;
            }
            loop {
                let mut line = Zeroizing::new(
                    rpassword::prompt_password("Credential: ").map_err(|_| RequestError)?,
                );
                if line.is_empty() {
                    break;
                }
                if !value.is_empty() {
                    value.push('\n');
                }
                value.push_str(&line);
                line.zeroize();
                if !request.multiline {
                    break;
                }
            }
            if value.is_empty() {
                return Ok(None);
            }
            if validation.accept(&value) {
                return Ok(Some(value));
            }
            value.zeroize();
            writeln!(tty, "{FORMAT_ERROR}").map_err(|_| RequestError)?;
        }
        Err(RequestError)
    }
}
