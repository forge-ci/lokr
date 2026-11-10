//! Native masked window and controlling-terminal fallback.
use crate::request::{Prompt, Request, RequestError, Validation, FORMAT_ERROR, WARNING};
use eframe::egui;
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
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("lokr — credential request")
                .with_inner_size([660.0, 440.0])
                .with_min_inner_size([600.0, 400.0]),
            ..Default::default()
        };
        let result = eframe::run_native(
            "lokr",
            options,
            Box::new(move |_| {
                Ok(Box::new(Window {
                    request,
                    validation,
                    value: Zeroizing::new(String::with_capacity(65536)),
                    error: false,
                    output: shared,
                }))
            }),
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
impl eframe::App for Window {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        egui::TopBottomPanel::bottom("permanent-warning").show(ctx, |ui| {
            ui.colored_label(
                egui::Color32::from_rgb(210, 65, 35),
                egui::RichText::new(WARNING).strong(),
            );
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading(egui::RichText::new(&self.request.title).size(28.0));
            egui::ScrollArea::vertical()
                .max_height(120.0)
                .show(ui, |ui| {
                    ui.label(&self.request.message);
                });
            if let Some(hint) = &self.request.hint {
                ui.label(format!("Expected format: {hint}"));
            }
            if let Some(pattern) = &self.request.pattern {
                ui.label(format!("Must fully match: {pattern}"));
            }
            ui.label(format!("Requesting process: {}", self.request.requester));
            ui.separator();
            ui.colored_label(
                egui::Color32::from_rgb(210, 65, 35),
                egui::RichText::new(WARNING).strong(),
            );
            ui.separator();
            // The ordinary egui TextEdit stores plaintext undo snapshots even in
            // password mode. Keep only bullets in widgets; edit the zeroizing buffer
            // directly, with no undo, copy, accessibility text or reveal control.
            let masked: String = self
                .value
                .chars()
                .map(|c| if c == '\n' { '\n' } else { '•' })
                .collect();
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_min_size(egui::vec2(
                    ui.available_width(),
                    if self.request.multiline { 90.0 } else { 28.0 },
                ));
                ui.label(egui::RichText::new(masked).monospace());
            });
            ui.small(
                "Type or paste here. Backspace deletes; no reveal, copy or undo. Escape cancels.",
            );
            ctx.input_mut(|input| {
                for event in &mut input.events {
                    match event {
                        egui::Event::Text(text)
                        | egui::Event::Paste(text)
                        | egui::Event::Ime(egui::ImeEvent::Commit(text)) => {
                            if self.value.len() + text.len() <= 65536 {
                                for c in text.chars() {
                                    if !c.is_control() || (c == '\n' && self.request.multiline) {
                                        self.value.push(c);
                                    }
                                }
                            }
                            text.zeroize();
                        }
                        egui::Event::Key {
                            key: egui::Key::Backspace,
                            pressed: true,
                            ..
                        } => {
                            // Erase removed bytes as well as shortening the string.
                            if let Some((index, _)) = self.value.char_indices().last() {
                                let mut bytes = Zeroizing::new(self.value.as_bytes().to_vec());
                                bytes[index..].zeroize();
                                self.value.zeroize();
                                self.value
                                    .push_str(std::str::from_utf8(&bytes[..index]).unwrap_or(""));
                            }
                        }
                        egui::Event::Key {
                            key: egui::Key::Enter,
                            pressed: true,
                            ..
                        } if self.request.multiline && self.value.len() < 65536 => {
                            self.value.push('\n')
                        }
                        egui::Event::Key {
                            key: egui::Key::Escape,
                            pressed: true,
                            ..
                        } => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                        _ => {}
                    }
                }
                for event in &mut input.raw.events {
                    if let egui::Event::Text(text)
                    | egui::Event::Paste(text)
                    | egui::Event::Ime(egui::ImeEvent::Commit(text)) = event
                    {
                        text.zeroize();
                    }
                }
            });
            if self.error {
                ui.colored_label(egui::Color32::RED, FORMAT_ERROR);
            }
            ui.horizontal(|ui| {
                if ui.button("Store credential").clicked() {
                    if self.validation.accept(&self.value) {
                        if let Ok(mut output) = self.output.lock() {
                            *output = Ok(Some(std::mem::replace(
                                &mut self.value,
                                Zeroizing::new(String::with_capacity(65536)),
                            )));
                        }
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    } else {
                        self.value.zeroize();
                        self.error = true;
                        if self.validation.exhausted() {
                            if let Ok(mut output) = self.output.lock() {
                                *output = Err(RequestError);
                            }
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
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
