use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as _base64, Engine};
use bytes::BytesMut;
use config::Config;
use smtp_codec::{
    parse::{command::command, utils::single_line},
    types::{Command, Response},
};
use tracing::{error, info};

use crate::{utils::escape, Cert, ConsolidatedStream, Splitter};

pub mod config;

pub struct SmtpServer {
    config: Config,
    stream: ConsolidatedStream,
    buffer: BytesMut,
    command_counter: usize,
}

impl SmtpServer {
    pub fn new(stream: ConsolidatedStream, config: Config) -> Self {
        Self {
            config,
            stream,
            buffer: BytesMut::new(),
            command_counter: 0,
        }
    }

    async fn send(&mut self, response: Response) {
        let mut out = Vec::new();
        response.serialize(&mut out).unwrap();
        self.send_raw(&out).await;
    }
}

#[async_trait]
impl Splitter for SmtpServer {
    async fn run(mut self) {
        if self.config.implicit_tls {
            self.stream
                .accept_tls(&self.config.cert.crt_path, &self.config.cert.key_path)
                .await;
        }

        let greeting = self.config.greeting.clone();
        self.send_raw(greeting.as_bytes()).await;

        loop {
            let command = match self.recv(command).await {
                Ok(cmd) => cmd,
                Err(rem) if rem.is_empty() => break,
                Err(_rem) => {
                    continue;
                }
            };

            if self.command_counter >= 50 {
                println!("Too many commands");
                break;
            }

            // Got command, iterate
            self.command_counter += 1;

            if self.stream.is_tls() {
                if self
                    .config
                    .ignore_commands_tls
                    .iter()
                    .any(|item| item.to_lowercase() == command.name().to_lowercase())
                {
                    continue;
                }
            } else {
                // not used yet
            }

            // Pretend that command is not supported...
            if self
                .config
                .hide_commands
                .iter()
                .any(|item| item.to_lowercase() == command.name().to_lowercase())
            {
                self.send(Response::other(502, "command not recognized"))
                    .await;
                continue;
            }

            // Use override...
            let mut answered = false;
            for (key, value) in self.config.override_response.clone() {
                if key.to_lowercase() == command.name().to_lowercase() {
                    self.send_raw(value.as_bytes()).await;
                    answered = true;
                    continue;
                }
            }
            if answered {
                continue;
            }

            match command {
                Command::Ehlo { .. } => {
                    let capabilities = if self.stream.is_tls() {
                        self.config.capabilities_tls.clone()
                    } else {
                        self.config.capabilities.clone()
                    };

                    self.send(Response::ehlo("example.org", Some("..."), capabilities))
                        .await;
                }
                Command::Helo { .. } => {
                    self.send(Response::other(250, "...")).await;
                }
                Command::Mail { .. } => {
                    self.send(Response::other(250, "...")).await;
                }
                Command::Rcpt { .. } => {
                    self.send(Response::other(250, "...")).await;
                }
                Command::Data => {
                    self.send(Response::other(354, "...")).await;

                    let mut mail = String::new();

                    loop {
                        let line = self.recv(single_line).await.unwrap();

                        if line == "." {
                            break;
                        }

                        mail.push_str(&line);
                        mail.push('\n');
                    }

                    info!(%mail, "You've Got Mail!");

                    self.send(Response::other(250, "...")).await;
                }
                Command::Rset => {
                    self.send(Response::other(250, "...")).await;
                }
                Command::Vrfy { .. } => {
                    unimplemented!()
                }
                Command::Expn { .. } => {
                    unimplemented!()
                }
                Command::Help { .. } => {
                    unimplemented!()
                }
                Command::Noop { .. } => {
                    self.send(Response::other(250, "...")).await;
                }
                Command::Quit => {
                    self.send(Response::other(221, "...")).await;
                    break;
                }
                Command::StartTLS => {
                    self.send_raw(self.config.stls_response.clone().as_bytes())
                        .await;

                    if self.config.stls_make_transition {
                        self.accept_tls().await;
                    }
                }
                Command::AuthLogin(initial_response) => {
                    let username_b64 = match initial_response {
                        Some(username_b64) => username_b64,
                        None => {
                            self.send(Response::other(334, "VXNlcm5hbWU6")).await;
                            self.recv(single_line).await.unwrap()
                        }
                    };

                    if let Ok(username) = _base64.decode(username_b64.trim()) {
                        info!(
                            username=%escape(&username),
                            "base64-decoded and escaped",
                        );
                    } else {
                        error!(data=%username_b64.trim(), "username is not valid base64");
                    }

                    let password_b64 = {
                        self.send(Response::other(334, "UGFzc3dvcmQ6")).await;
                        self.recv(single_line).await.unwrap()
                    };

                    if let Ok(password) = _base64.decode(password_b64.trim()) {
                        info!(
                            password=%escape(&password),
                            "base64-decoded and escaped",
                        );
                    } else {
                        error!(data=%password_b64.trim(), "password is not valid base64");
                    }

                    self.send(Response::other(235, "...")).await;
                }
                Command::AuthPlain(initial_response) => {
                    let credentials_b64 = match initial_response {
                        Some(credentials_b64) => credentials_b64,
                        None => {
                            // Trojita does not work with "334\r\n" only.
                            self.send(Response::other(334, "...")).await;
                            self.recv(single_line).await.unwrap()
                        }
                    };

                    if let Ok(credentials) = _base64.decode(credentials_b64.trim()) {
                        info!(
                            credentials=%escape(&credentials),
                            "base64-decoded and escaped",
                        );
                    } else {
                        error!(data=%credentials_b64.trim(), "credentials are not valid base64");
                    }

                    self.send(Response::other(235, "...")).await;
                }
            }
        }
    }

    fn buffer(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }

    fn stream(&mut self) -> &mut ConsolidatedStream {
        &mut self.stream
    }

    fn cert(&self) -> Cert {
        self.config.cert.clone()
    }

    fn recv_timeout(&self) -> Duration {
        let t = self.config.recv_timeout.unwrap_or(0);
        Duration::from_secs(t)
    }
}
