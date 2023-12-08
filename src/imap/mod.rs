use std::{
    convert::{TryFrom, TryInto},
    time::Duration,
};

use async_trait::async_trait;
use bytes::BytesMut;
use config::Config;
use imap_codec::{
    codec::{Decode, DecodeError, Encode},
    command::{
        fetch::{FetchAttribute, MacroOrFetchAttributes},
        idle::IdleDone,
        search::SearchKey,
        status::StatusAttribute,
        AuthenticateData, Command, CommandBody, Strategy,
    },
    imap_types::bounded_static::IntoBoundedStatic,
    message::{AuthMechanism, Mailbox, Tag},
    response::{
        data::{Capability, StatusAttributeValue},
        Code, Continue, Data, Status,
    },
    security::Secret,
    state::State,
};
use nom::{IResult, Needed};
use tracing::{debug, error, info};

use crate::{imap::account::Account, utils::escape, ConsolidatedStream, Splitter, PKCS12};

pub mod account;
pub mod config;
pub mod responses;

pub struct ImapServer<'a> {
    account: Account,
    buffer: BytesMut,
    config: Config<'a>,
    state: State<'a>,
    stream: ConsolidatedStream,
}

impl<'a> ImapServer<'a> {
    pub fn new(stream: ConsolidatedStream, account: Account, config: Config<'a>) -> Self {
        Self {
            account,
            buffer: BytesMut::new(),
            config,
            state: State::NotAuthenticated,
            stream,
        }
    }

    pub async fn send<T: Encode>(&mut self, msg: T) {
        let mut out = Vec::with_capacity(512);
        msg.encode(&mut out).unwrap();
        self.send_raw(&out).await;
    }

    /// "Statemachine"
    ///
    /// Testing can be done here.
    async fn transition(&mut self, command: Command<'a>) -> bool {
        let mut ignored = if self.stream.is_tls() {
            self.config.ignore_commands_tls.iter()
        } else {
            self.config.ignore_commands.iter()
        };

        if ignored.any(|item| item.to_lowercase() == command.name().to_lowercase()) {
            return true;
        }

        // Pretend that command is not supported...
        if self
            .config
            .hide_commands
            .iter()
            .any(|item| item.to_lowercase() == command.name().to_lowercase())
        {
            self.send(Status::bad(Some(command.tag), None, "unknown command.").unwrap())
                .await;
            return true;
        }

        match self.state.clone() {
            State::Greeting => {
                // Unused.
            }
            State::NotAuthenticated => match command.body {
                CommandBody::Append { .. } => {
                    self.send(Status::bad(Some(command.tag), None, "Append not allowed.").unwrap())
                        .await;
                }
                CommandBody::Capability => {
                    if self.stream.is_tls() {
                        self.send(Data::capability(self.config.caps_tls.clone()).unwrap())
                            .await;
                    } else {
                        self.send(Data::capability(self.config.caps.clone()).unwrap())
                            .await;
                    }
                    self.send(Status::ok(Some(command.tag), None, "capability done.").unwrap())
                        .await;
                }
                CommandBody::Noop => {
                    self.send(Status::ok(Some(command.tag), None, "noop done.").unwrap())
                        .await;
                }
                CommandBody::Logout => {
                    self.send(Status::bye(None, "bye done.").unwrap()).await;
                    self.send(Status::ok(Some(command.tag), None, "logout done.").unwrap())
                        .await;
                    self.state = State::Logout;
                }

                CommandBody::StartTLS => {
                    match self.config.starttls_response.clone() {
                        Some(response) => {
                            //self.state = State::Authenticated;
                            self.send_raw(
                                response.replace("<tag>", command.tag.inner()).as_bytes(),
                            )
                            .await;
                        }
                        None => {
                            self.send(
                                Status::ok(Some(command.tag), None, "begin TLS now.").unwrap(),
                            )
                            .await;
                        }
                    }

                    if self.config.starttls_transition {
                        self.accept_tls().await;
                    }

                    if let Some(response) = self.config.response_after_tls.clone() {
                        self.send_raw(response.as_bytes()).await;
                    }
                }
                CommandBody::Authenticate {
                    mechanism,
                    initial_response,
                } => {
                    match mechanism {
                        AuthMechanism::Plain => {
                            let credentials = match initial_response {
                                Some(credentials) => AuthenticateData(Secret::new(
                                    credentials.expose_secret().to_vec(),
                                )),
                                None => {
                                    // TODO: this is not standard-conform, because `text` is `1*TEXT-CHAR`.
                                    //       Was this changed due to Mutt?
                                    self.send_raw(b"+ \r\n").await;
                                    self.recv(authenticate_data).await.unwrap()
                                }
                            };

                            info!(
                                credentials=%escape(credentials.0.expose_secret()),
                                "base64-decoded and escaped"
                            );
                        }
                        AuthMechanism::Login => {
                            let username = match initial_response {
                                Some(username) => {
                                    AuthenticateData(Secret::new(username.expose_secret().to_vec()))
                                }
                                None => {
                                    self.send_raw(b"+ VXNlcm5hbWU6\r\n").await;
                                    self.recv(authenticate_data).await.unwrap()
                                }
                            };

                            info!(
                                username=%escape(&username.0.expose_secret()),
                                "base64-decoded and escaped"
                            );

                            let password = {
                                self.send_raw(b"+ UGFzc3dvcmQ6\r\n").await;
                                self.recv(authenticate_data).await.unwrap()
                            };

                            info!(
                                password=%escape(&password.0.expose_secret()),
                                "base64-decoded and escaped"
                            );
                        }
                        AuthMechanism::Other(mechanism) => {
                            error!(?mechanism, "auth mechanism not supported");

                            self.send(
                                Status::no(Some(command.tag), None, "not supported.").unwrap(),
                            )
                            .await;

                            return true;
                        }
                    }

                    if let Some(mut status) = self.config.override_authenticate.clone() {
                        match status {
                            Status::Ok { ref mut tag, .. }
                            | Status::No { ref mut tag, .. }
                            | Status::Bad { ref mut tag, .. } => {
                                if *tag == Some(Tag::try_from("<tag>").unwrap()) {
                                    *tag = Some(command.tag);
                                }
                            }
                            _ => {}
                        }

                        self.send(status.clone()).await;
                        if let Status::Ok { .. } = status {
                            self.state = State::Authenticated;
                        }

                        return true;
                    }

                    self.send(Status::ok(Some(command.tag), None, "authenticate done.").unwrap())
                        .await;
                    self.state = State::Authenticated;
                }
                CommandBody::Login { username, password } => {
                    info!(?username, ?password, "login");

                    if let Some(mut status) = self.config.override_login.clone() {
                        match status {
                            Status::Ok { ref mut tag, .. }
                            | Status::No { ref mut tag, .. }
                            | Status::Bad { ref mut tag, .. } => {
                                if *tag == Some(Tag::try_from("<tag>").unwrap()) {
                                    *tag = Some(command.tag);
                                }
                            }
                            _ => {}
                        }

                        self.send(status.clone()).await;
                        if let Status::Ok { .. } = status {
                            self.state = State::Authenticated;
                        }

                        return true;
                    }

                    self.send(Status::ok(Some(command.tag), None, "login done.").unwrap())
                        .await;
                    self.state = State::Authenticated;
                }

                bad_command => {
                    self.send(
                        Status::bad(
                            Some(command.tag),
                            None,
                            format!("{} not allowed.", bad_command.name()),
                        )
                        .unwrap(),
                    )
                    .await;
                }
            },
            State::Authenticated => {
                match command.body {
                    CommandBody::Capability => {
                        if self.stream.is_tls() {
                            self.send(Data::capability(self.config.caps_tls_auth.clone()).unwrap())
                                .await;
                        } else {
                            self.send(Data::capability(self.config.caps_auth.clone()).unwrap())
                                .await;
                        }
                        self.send(Status::ok(Some(command.tag), None, "capability done.").unwrap())
                            .await;
                    }
                    CommandBody::StartTLS => {
                        self.send(
                            Status::no(
                                Some(command.tag),
                                Some(
                                    Code::capability(vec![
                                        Capability::Imap4Rev1,
                                        Capability::Auth(AuthMechanism::Login),
                                    ])
                                    .unwrap(),
                                ),
                                "not allowed due to RFC.",
                            )
                            .unwrap(),
                        )
                        .await;
                    }
                    CommandBody::Noop => {
                        self.send(Status::ok(Some(command.tag), None, "noop done.").unwrap())
                            .await;
                    }
                    CommandBody::Logout => {
                        self.send(Status::bye(None, "bye done.").unwrap()).await;
                        self.send(Status::ok(Some(command.tag), None, "logout done.").unwrap())
                            .await;
                        self.state = State::Logout;
                    }

                    CommandBody::Select { mailbox } | CommandBody::Examine { mailbox } => {
                        debug!(?mailbox, account=?self.account, "select");

                        if let Some(mut status) = self.config.override_select.clone() {
                            match status {
                                Status::Ok { ref mut tag, .. }
                                | Status::No { ref mut tag, .. }
                                | Status::Bad { ref mut tag, .. } => {
                                    if *tag == Some(Tag::try_from("<tag>").unwrap()) {
                                        *tag = Some(command.tag);
                                    }
                                }
                                _ => {}
                            }

                            self.send(status.clone()).await;
                            if let Status::Ok { .. } = status {
                                self.state = State::Selected(mailbox);
                            }
                            return true;
                        }

                        match self.account.get_folder_by_name(&mailbox) {
                            Some(folder) => {
                                responses::ret_select_data(self, &folder).await;
                                self.send(
                                    Status::ok(
                                        Some(command.tag),
                                        Some(Code::ReadWrite),
                                        "select/examine done.",
                                    )
                                    .unwrap(),
                                )
                                .await;
                                self.state = State::Selected(mailbox);
                            }
                            None => {
                                self.send(
                                    Status::no(Some(command.tag), None, "no such folder.").unwrap(),
                                )
                                .await;
                                debug!(?mailbox, "folder not found");
                            }
                        }
                    }
                    CommandBody::Create { .. } => {
                        self.send(Status::ok(Some(command.tag), None, "create done.").unwrap())
                            .await;
                    }
                    CommandBody::Delete { .. } => unimplemented!(),
                    CommandBody::Rename { .. } => unimplemented!(),
                    CommandBody::Subscribe { .. } => {
                        self.send(Status::ok(Some(command.tag), None, "subscribe done.").unwrap())
                            .await;
                    }
                    CommandBody::Unsubscribe { .. } => {
                        self.send(
                            Status::ok(Some(command.tag), None, "unsubscribe done.").unwrap(),
                        )
                        .await;
                    }
                    CommandBody::List {
                        reference,
                        mailbox_wildcard,
                    } => {
                        responses::ret_list_data(self, &reference, &mailbox_wildcard).await;
                        self.send(Status::ok(Some(command.tag), None, "list done.").unwrap())
                            .await;
                    }
                    CommandBody::Lsub {
                        reference,
                        mailbox_wildcard,
                    } => {
                        responses::ret_lsub_data(self, &reference, &mailbox_wildcard).await;
                        self.send(Status::ok(Some(command.tag), None, "lsub done.").unwrap())
                            .await;
                    }
                    CommandBody::Status {
                        mailbox,
                        attributes,
                    } => {
                        match self.account.get_folder_by_name(&mailbox) {
                            Some(folder) => {
                                responses::ret_status_data(self, &folder, &attributes).await;
                            }
                            None => {
                                // Pretend to be mailbox with 0 mails.
                                let attributes = attributes
                                    .iter()
                                    .map(|attribute| match attribute {
                                        StatusAttribute::Messages => {
                                            StatusAttributeValue::Messages(0)
                                        }
                                        StatusAttribute::Unseen => StatusAttributeValue::Unseen(0),
                                        StatusAttribute::UidValidity => {
                                            StatusAttributeValue::UidValidity(
                                                123_456.try_into().unwrap(),
                                            )
                                        }
                                        StatusAttribute::UidNext => {
                                            StatusAttributeValue::UidNext(1.try_into().unwrap())
                                        }
                                        StatusAttribute::Recent => StatusAttributeValue::Recent(0),
                                    })
                                    .collect();

                                self.send(Data::Status {
                                    mailbox,
                                    attributes,
                                })
                                .await;
                            }
                        }
                        self.send(Status::ok(Some(command.tag), None, "status done.").unwrap())
                            .await;
                    }
                    CommandBody::Append { .. } => {
                        self.send(Status::ok(Some(command.tag), None, "append done.").unwrap())
                            .await;
                    }

                    CommandBody::Enable { capabilities } => {
                        self.send(Data::Enabled {
                            capabilities: capabilities.as_ref().to_vec(),
                        })
                        .await;
                        self.send(Status::ok(Some(command.tag), None, "enable done.").unwrap())
                            .await;
                    }

                    CommandBody::Idle => {
                        self.send(Continue::basic(None, "idle from auth.").unwrap())
                            .await;
                        self.send(Data::Exists(4)).await;

                        self.recv(idle_done).await.unwrap();
                        self.send(Status::ok(Some(command.tag), None, "idle done.").unwrap())
                            .await;
                    }

                    CommandBody::Compress { .. } => {
                        self.send(
                            Status::ok(Some(command.tag), None, "starting DEFLATE compression")
                                .unwrap(),
                        )
                        .await;
                        self.accept_compression().await;
                    }

                    bad_command => {
                        self.send(
                            Status::bad(
                                Some(command.tag),
                                None,
                                format!("{} not allowed.", bad_command.name()),
                            )
                            .unwrap(),
                        )
                        .await;
                    }
                }
            }
            State::Selected(ref selected) => match command.body {
                CommandBody::Capability => {
                    if self.stream.is_tls() {
                        self.send(Data::capability(self.config.caps_tls_auth.clone()).unwrap())
                            .await;
                    } else {
                        self.send(Data::capability(self.config.caps_auth.clone()).unwrap())
                            .await;
                    }
                    self.send(Status::ok(Some(command.tag), None, "capability done.").unwrap())
                        .await;
                }
                CommandBody::Noop => {
                    self.send(Status::ok(Some(command.tag), None, "noop done.").unwrap())
                        .await;
                }
                CommandBody::Logout => {
                    self.send(Status::bye(None, "bye done.").unwrap()).await;
                    self.send(Status::ok(Some(command.tag), None, "logout done.").unwrap())
                        .await;
                    self.state = State::Logout;
                }

                CommandBody::Select { mailbox } | CommandBody::Examine { mailbox } => {
                    debug!(?mailbox, account=?self.account, "select");

                    match self.account.get_folder_by_name(&mailbox) {
                        Some(folder) => {
                            responses::ret_select_data(self, &folder).await;
                            self.send(
                                Status::ok(
                                    Some(command.tag),
                                    Some(Code::ReadWrite),
                                    "select/examine done.",
                                )
                                .unwrap(),
                            )
                            .await;
                            self.state = State::Selected(mailbox);
                        }
                        None => {
                            self.send(
                                Status::no(Some(command.tag), None, "no such folder.").unwrap(),
                            )
                            .await;
                            debug!(?mailbox, "No such folder.");
                        }
                    }
                }
                CommandBody::Create { .. } => {
                    self.send(Status::ok(Some(command.tag), None, "create done.").unwrap())
                        .await;
                }
                CommandBody::Delete { .. } => unimplemented!(),
                CommandBody::Rename { .. } => unimplemented!(),
                CommandBody::Subscribe { .. } => {
                    self.send(Status::ok(Some(command.tag), None, "subscribe done.").unwrap())
                        .await;
                }
                CommandBody::Unsubscribe { .. } => {
                    self.send(Status::ok(Some(command.tag), None, "unsubscribe done.").unwrap())
                        .await;
                }
                CommandBody::List {
                    reference,
                    mailbox_wildcard,
                } => {
                    responses::ret_list_data(self, &reference, &mailbox_wildcard).await;
                    self.send(Status::ok(Some(command.tag), None, "list done.").unwrap())
                        .await;
                }
                CommandBody::Lsub {
                    reference,
                    mailbox_wildcard,
                } => {
                    responses::ret_lsub_data(self, &reference, &mailbox_wildcard).await;
                    self.send(Status::ok(Some(command.tag), None, "lsub done.").unwrap())
                        .await;
                }
                CommandBody::Status {
                    mailbox,
                    attributes,
                } => match self.account.get_folder_by_name(&mailbox) {
                    Some(folder) => {
                        responses::ret_status_data(self, &folder, &attributes).await;
                        self.send(Status::ok(Some(command.tag), None, "status done.").unwrap())
                            .await;
                    }
                    None => {
                        self.send(Status::no(Some(command.tag), None, "no such folder.").unwrap())
                            .await;
                    }
                },
                CommandBody::Append { .. } => {
                    self.send(Status::ok(Some(command.tag), None, "append done.").unwrap())
                        .await;
                }

                CommandBody::Check => {
                    self.send(Status::ok(Some(command.tag), None, "check done.").unwrap())
                        .await;
                }
                CommandBody::Close => {
                    self.send(Status::ok(Some(command.tag), None, "close done.").unwrap())
                        .await;
                    self.state = State::Authenticated;
                }
                CommandBody::Expunge => {
                    self.send(Status::ok(Some(command.tag), None, "expunge done.").unwrap())
                        .await;
                }
                CommandBody::Search { criteria, uid, .. } => {
                    if uid {
                        match criteria {
                            SearchKey::Header(..) => {
                                self.send(Data::Search(vec![])).await;
                                self.send(
                                    Status::ok(Some(command.tag), None, "search done.").unwrap(),
                                )
                                .await;
                            }
                            _ => {
                                match selected {
                                    Mailbox::Inbox => {
                                        self.send(Data::Search(vec![
                                            1.try_into().unwrap(),
                                            2.try_into().unwrap(),
                                            3.try_into().unwrap(),
                                        ]))
                                        .await;
                                    }
                                    Mailbox::Other(_) => {
                                        self.send(Data::Search(vec![])).await;
                                    }
                                }
                                self.send(
                                    Status::ok(Some(command.tag), None, "search done.").unwrap(),
                                )
                                .await;
                            }
                        }
                    } else {
                        self.send(Data::Search(vec![])).await;
                        self.send(Status::ok(Some(command.tag), None, "search done.").unwrap())
                            .await;
                    }
                }
                CommandBody::Fetch {
                    ref sequence_set,
                    ref attributes,
                    uid,
                } => {
                    let selected = self.account.get_folder_by_name(selected).unwrap();

                    if selected.mails.is_empty() {
                        self.send(
                            Status::ok(Some(command.tag), None, "mailbox is empty.").unwrap(),
                        )
                        .await;
                        return true;
                    }

                    let sequence_set = sequence_set.clone();

                    let mut fetch_attrs = match attributes {
                        MacroOrFetchAttributes::Macro(macro_) => macro_.expand(),
                        MacroOrFetchAttributes::FetchAttributes(items) => items.to_vec(),
                    };

                    if uid {
                        if !fetch_attrs.contains(&FetchAttribute::Uid) {
                            fetch_attrs.insert(0, FetchAttribute::Uid)
                        }

                        // Safe unwrap: this code is not reachable with an empty mailbox
                        let largest = selected.mails.iter().map(|mail| mail.uid).max().unwrap();
                        let iterator = sequence_set.iter(Strategy::Naive { largest });

                        for uid in iterator.take(500) {
                            if let Some((seq, mail)) = selected
                                .mails
                                .iter()
                                .enumerate()
                                .find(|(_, mail)| mail.uid == uid)
                            {
                                let res = responses::attr_to_data(mail, &fetch_attrs);
                                let resp = format!("* {} FETCH ({})\r\n", seq + 1, res);
                                self.send_raw(resp.as_bytes()).await;
                            } else {
                                debug!(uid, "No such mail. Sending no mail.");
                            }
                        }
                    } else {
                        let largest = (selected.mails.len() as u32).try_into().unwrap();
                        let iterator = sequence_set.iter(Strategy::Naive { largest });

                        for seq in iterator.take(500) {
                            // Safe subtraction: this code is not reachable with seq == 0
                            if let Some(mail) = selected.mails.get(seq.get() as usize - 1) {
                                let res = responses::attr_to_data(mail, &fetch_attrs);
                                let resp = format!("* {} FETCH ({})\r\n", seq, res);
                                self.send_raw(resp.as_bytes()).await;
                            } else {
                                debug!(uid, "No such mail. Sending no mail.");
                            }
                        }
                    }

                    self.send(Status::ok(Some(command.tag), None, "fetch done.").unwrap())
                        .await;
                }
                CommandBody::Store { .. } => {
                    self.send(Status::ok(Some(command.tag), None, "store done.").unwrap())
                        .await;
                }
                CommandBody::Copy { .. } => {
                    self.send(Status::ok(Some(command.tag), None, "copy done.").unwrap())
                        .await;
                }
                CommandBody::Idle => {
                    self.send(Continue::basic(None, "idle from selected.").unwrap())
                        .await;
                    self.send(Data::Exists(4)).await;

                    self.recv(idle_done).await.unwrap();
                    self.send(Status::ok(Some(command.tag), None, "idle done.").unwrap())
                        .await;
                }

                bad_command => {
                    self.send(
                        Status::bad(
                            Some(command.tag),
                            None,
                            format!("{} not allowed.", bad_command.name()),
                        )
                        .unwrap(),
                    )
                    .await;
                }
            },
            State::Logout => {
                info!("Logout.",);
            }
            State::IdleAuthenticated(_tag) => {
                // Can't receive command here.
            }
            State::IdleSelected(_tag, _folder) => {
                // Can't receive command here.
            }
        }

        true
    }
}

pub fn command(input: &[u8]) -> IResult<&[u8], Command<'static>> {
    match Command::decode(input) {
        Ok((rem, out)) => Ok((rem, out.into_static())),
        Err(error) => match error {
            DecodeError::LiteralAckRequired => Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fix,
            ))),
            DecodeError::Incomplete => Err(nom::Err::Incomplete(Needed::Unknown)),
            DecodeError::Failed => Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fail,
            ))),
        },
    }
}

pub fn authenticate_data(input: &[u8]) -> IResult<&[u8], AuthenticateData> {
    match AuthenticateData::decode(input) {
        Ok((rem, out)) => Ok((rem, out.into_static())),
        Err(error) => match error {
            DecodeError::LiteralAckRequired => Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fix,
            ))),
            DecodeError::Incomplete => Err(nom::Err::Incomplete(Needed::Unknown)),
            DecodeError::Failed => Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fail,
            ))),
        },
    }
}

pub fn idle_done(input: &[u8]) -> IResult<&[u8], IdleDone> {
    match IdleDone::decode(input) {
        Ok((rem, out)) => Ok((rem, out.into_static())),
        Err(error) => match error {
            DecodeError::LiteralAckRequired => Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fix,
            ))),
            DecodeError::Incomplete => Err(nom::Err::Incomplete(Needed::Unknown)),
            DecodeError::Failed => Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fail,
            ))),
        },
    }
}

#[async_trait]
impl<'a> Splitter for ImapServer<'a> {
    async fn run(mut self) {
        if self.config.implicit_tls {
            self.accept_tls().await;
        }

        // Send Greeting...
        if let Some(greeting) = self.config.override_response.get("greeting").cloned() {
            self.send_raw(greeting.as_bytes()).await;
        } else {
            self.send(self.config.greeting.clone()).await;
        }

        self.state = self.config.state.clone();

        if let Some(data) = self.config.response_after_greeting.clone() {
            self.send_raw(data.as_bytes()).await;
        }

        loop {
            match self.recv(command).await {
                Ok(cmd) => {
                    // Use override...
                    let mut answered = false;
                    for (key, value) in self.config.override_response.clone() {
                        if key.to_lowercase() == cmd.name().to_lowercase() {
                            let resp = value.replace("<tag>", cmd.tag.inner());
                            self.send_raw(resp.as_bytes()).await;
                            answered = true;
                            continue;
                        }
                    }
                    if answered {
                        continue;
                    }
                    if !self.transition(cmd).await {
                        return;
                    }
                }
                Err(rem) if rem.is_empty() => break,
                Err(rem) => {
                    //self.send(Status::bad(None, None, "error in IMAP command")).await;
                    if let Ok(cmd) = String::from_utf8(rem) {
                        if let Some(could_be_tag) = cmd.split_whitespace().next() {
                            self.send_raw(
                                format!("{} OK keep going.\r\n", could_be_tag).as_bytes(),
                            )
                            .await;
                        }
                    }
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

    fn pkcs12(&self) -> PKCS12 {
        self.config.pkcs12.clone()
    }

    fn recv_timeout(&self) -> Duration {
        let t = self.config.recv_timeout.unwrap_or(0);
        Duration::from_secs(t)
    }

    async fn incomplete(&mut self) {
        if let Ok(msg) = String::from_utf8(self.buffer().to_vec()) {
            if msg.ends_with("}\r\n") || msg.ends_with("}\n") {
                debug!(
                    "Found incomplete data, which ends with `}}\\r\\n`. Sending a continuation."
                );
                self.send(Continue::basic(None, "continue, please").unwrap())
                    .await;
            }
        }
    }
}
