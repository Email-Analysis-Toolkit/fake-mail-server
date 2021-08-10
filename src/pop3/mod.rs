use std::str::from_utf8;

use async_trait::async_trait;
use bytes::BytesMut;
use config::Config;
use nom::{
    character::streaming::{line_ending, not_line_ending},
    combinator::map_res,
    sequence::terminated,
    IResult,
};
use pop3_codec::{
    parse::command,
    types::{Command, State},
};
use tracing::{debug, error, info};

use crate::{utils::escape, ConsolidatedStream, Splitter, PKCS12};

pub mod config;

fn single_line_owned(input: &[u8]) -> IResult<&[u8], String> {
    let (rem, out) = map_res(terminated(not_line_ending, line_ending), from_utf8)(input)?;
    Ok((rem, out.to_owned()))
}

pub struct Pop3Server {
    state: State,
    config: Config,
    stream: ConsolidatedStream,
    buffer: BytesMut,
    command_counter: usize,
}

impl Pop3Server {
    pub fn new(stream: ConsolidatedStream, config: Config) -> Self {
        Self {
            state: State::Authorization,
            config,
            stream,
            buffer: BytesMut::new(),
            command_counter: 0,
        }
    }
}

#[async_trait]
impl Splitter for Pop3Server {
    async fn run(mut self) {
        if self.config.implicit_tls {
            self.stream
                .accept_tls(&self.config.pkcs12.file, &self.config.pkcs12.password)
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

            // Ignore certain commands
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
                self.send_raw(b"-ERR bad command\r\n").await;
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

            match self.state.clone() {
                State::Authorization => match command {
                    Command::User(user) => {
                        info!(%user, kind="user", "command");
                        self.send_raw(b"+OK user ok\r\n").await;
                    }
                    Command::Pass(pass) => {
                        info!(%pass, kind="pass", "command");
                        self.send_raw(b"+OK pass ok\r\n").await;

                        self.state = State::Transaction;
                    }
                    Command::Capa => {
                        let caps = if self.stream.is_tls() {
                            self.config.capa_tls.clone()
                        } else {
                            self.config.capa.clone()
                        };

                        let capa_response = "+OK list of capabilities\r\n".to_string()
                            + &caps.join("\r\n")
                            + "\r\n.\r\n";
                        self.send_raw(capa_response.as_bytes()).await;
                    }
                    Command::Stls => {
                        let response = self.config.stls_response.clone();
                        self.send_raw(response.as_bytes()).await;

                        if self.config.stls_make_transition {
                            self.accept_tls().await;
                        }
                    }
                    Command::Auth {
                        mechanism,
                        initial_response,
                    } => {
                        match mechanism.to_lowercase().as_ref() {
                            "plain" => {
                                let credentials_b64 = match initial_response {
                                    Some(credentials_b64) => credentials_b64,
                                    None => {
                                        self.send_raw(b"+ \r\n").await;
                                        self.recv(single_line_owned).await.unwrap()
                                    }
                                };

                                if let Ok(credentials) = base64::decode(credentials_b64.trim()) {
                                    info!(
                                        credentials=%escape(&credentials),
                                        "base64-decoded and escaped",
                                    );
                                } else {
                                    error!(
                                        data = credentials_b64.trim(),
                                        "credentials are not valid base64"
                                    );
                                }
                            }
                            "login" => {
                                let username_b64 = match initial_response {
                                    Some(username_b64) => username_b64,
                                    None => {
                                        self.send_raw(b"+ VXNlcm5hbWU6\r\n").await;
                                        self.recv(single_line_owned).await.unwrap()
                                    }
                                };

                                if let Ok(username) = base64::decode(username_b64.trim()) {
                                    info!(
                                        username=%escape(&username),
                                        "base64-decoded and escaped",
                                    );
                                } else {
                                    error!(
                                        data = username_b64.trim(),
                                        "username is not valid base64"
                                    );
                                }

                                let password_b64 = {
                                    self.send_raw(b"+ UGFzc3dvcmQ6\r\n").await;
                                    self.recv(single_line_owned).await.unwrap()
                                };

                                if let Ok(password) = base64::decode(password_b64.trim()) {
                                    info!(
                                        password=%escape(&password),
                                        "base64-decoded and escaped",
                                    );
                                } else {
                                    error!(
                                        data = password_b64.trim(),
                                        "password is not valid base64"
                                    );
                                }
                            }
                            mechanism => {
                                error!(%mechanism, "not supported");
                                self.send_raw(b"-ERR not supported.\r\n").await;

                                return;
                            }
                        }

                        self.send_raw(b"+OK Fake maildrop locked and ready.\r\n")
                            .await;
                        self.state = State::Transaction;
                    }
                    Command::AuthAll => {
                        self.send_raw(b"+OK\r\nPLAIN\r\nLOGIN\r\n.\r\n").await;
                    }
                    Command::Quit => {
                        self.send_raw(b"+OK Fake logging out.\r\n").await;
                        debug!("Quit in Authorization Phase");
                        return;
                    }
                    _ => unimplemented!(),
                },
                State::Transaction => match command {
                    Command::Stat => {
                        self.send_raw(b"+OK 2 92\r\n").await;
                    }
                    Command::ListAll => {
                        self.send_raw(b"+OK 2 messages (92 octets)\r\n1 46\r\n2 46\r\n.\r\n")
                            .await;
                    }
                    Command::List { msg } => match msg {
                        1 => {
                            self.send_raw(b"+OK 1 46\r\n").await;
                        }
                        2 => {
                            self.send_raw(b"+OK 2 46\r\n").await;
                        }
                        _ => {
                            self.send_raw(b"-ERR no such message, only 2 messages in maildrop\r\n")
                                .await;
                        }
                    },
                    Command::Retr { msg } => match msg {
                        1 => {
                            self.send_raw(b"+OK 46 octets\r\n").await;
                            self.send_raw(b"From: A\r\nTo: B\r\nSubject: 1\r\n\r\nHello, World 1!")
                                .await;
                            self.send_raw(b"\r\n.\r\n").await;
                        }
                        2 => {
                            self.send_raw(b"+OK 46 octets\r\n").await;
                            self.send_raw(b"From: A\r\nTo: B\r\nSubject: 2\r\n\r\nHello, World 2!")
                                .await;
                            self.send_raw(b"\r\n.\r\n").await;
                        }
                        _ => {
                            self.send_raw(b"-ERR no such message\r\n").await;
                        }
                    },
                    Command::Dele { msg } => match msg {
                        1 | 2 => {
                            self.send_raw(b"+OK message deleted\r\n").await;
                        }
                        _ => {
                            self.send_raw(b"-ERR no such message\r\n").await;
                        }
                    },
                    Command::Noop => {
                        self.send_raw(b"+OK\r\n").await;
                    }
                    Command::Rset => {
                        self.send_raw(b"+OK maildrop has 2 messages (92 octets)\r\n")
                            .await;
                    }
                    Command::Top { msg, n: _ } => match msg {
                        1 => {
                            self.send_raw(b"+OK\r\n").await;
                            self.send_raw(b"From: A\r\nTo: B\r\nSubject: 1\r\n\r\nHello, World 1!")
                                .await;
                            self.send_raw(b"\r\n.\r\n").await;
                        }
                        2 => {
                            self.send_raw(b"+OK\r\n").await;
                            self.send_raw(b"From: A\r\nTo: B\r\nSubject: 2\r\n\r\nHello, World 2!")
                                .await;
                            self.send_raw(b"\r\n.\r\n").await;
                        }
                        _ => {
                            self.send_raw(b"-ERR no such message\r\n").await;
                        }
                    },
                    Command::UidlAll => {
                        self.send_raw(b"+OK\r\n1 AAAAAAAA\r\n2 BBBBBBBB\r\n.\r\n")
                            .await;
                    }
                    Command::Uidl { msg } => match msg {
                        1 => {
                            self.send_raw(b"+OK 1 AAAAAAAA\r\n").await;
                        }
                        2 => {
                            self.send_raw(b"+OK 2 BBBBBBBB\r\n").await;
                        }
                        _ => {
                            self.send_raw(b"-ERR no such message, only 2 messages in maildrop\r\n")
                                .await;
                        }
                    },
                    Command::Quit => {
                        self.send_raw(b"+OK Fake logging out.\r\n").await;
                        debug!("Quit in Transaction Phase");
                        self.state = State::Update;
                    }

                    Command::Capa => {
                        let caps = if self.stream.is_tls() {
                            self.config.capa_tls_auth.clone()
                        } else {
                            self.config.capa_auth.clone()
                        };

                        self.send_raw((caps.join("\r\n") + "\r\n.\r\n").as_bytes())
                            .await;
                    }
                    _ => unimplemented!(),
                },
                State::Update => match command {
                    Command::Quit => {
                        self.send_raw(b"+OK Fake logging out.\r\n").await;
                        debug!("Quit in Update Phase");
                        return;
                    }
                    _ => unimplemented!(),
                },
            }
        }
    }

    fn buffer(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }

    fn stream(&mut self) -> &mut ConsolidatedStream {
        &mut self.stream
    }

    fn pkcs12(&self) -> PKCS12 {
        self.config.pkcs12.clone()
    }
}
