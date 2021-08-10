use std::{convert::TryFrom, thread::sleep, time::Duration};

use async_trait::async_trait;
use bytes::BytesMut;
use config::Config;
use imap_codec::{
    codec::Encode,
    parse::command::{authenticate_data, command, idle_done},
    state::State,
    types::{
        command::{Command, CommandBody, SearchKey::Header, StatusItem},
        core::Tag,
        data_items::{DataItem, MacroOrDataItems},
        mailbox::Mailbox,
        response::{Capability, Code, Continuation, Data, Status, StatusItemResponse},
        sequence::{SequenceSet, Strategy},
        AuthMechanism,
    },
};
use tracing::{debug, error, info};

use crate::{imap::account::Account, utils::escape, ConsolidatedStream, Splitter, PKCS12};

pub mod account;
pub mod config;
pub mod responses;

pub struct ImapServer {
    account: Account,
    buffer: BytesMut,
    config: Config,
    state: State,
    stream: ConsolidatedStream,
}

impl ImapServer {
    pub fn new(stream: ConsolidatedStream, account: Account, config: Config) -> Self {
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
    async fn transition(&mut self, command: Command) -> bool {
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
            State::NotAuthenticated => match command.body {
                CommandBody::Append { .. } => {
                    self.send(Status::bad(Some(command.tag), None, "Append not allowed.").unwrap())
                        .await;
                }
                CommandBody::Capability => {
                    if self.stream.is_tls() {
                        self.send(Data::Capability(self.config.caps_tls.clone()))
                            .await;
                    } else {
                        self.send(Data::Capability(self.config.caps.clone())).await;
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
                                response
                                    .replace("<tag>", &command.tag.to_string())
                                    .as_bytes(),
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
                            let credentials_b64 = match initial_response {
                                Some(credentials) => credentials,
                                None => {
                                    // TODO: this is not standard-conform, because `text` is `1*TEXT-CHAR`.
                                    //       Was this changed due to Mutt?
                                    self.send_raw(b"+ \r\n").await;
                                    self.recv(authenticate_data).await.unwrap()
                                }
                            };

                            if let Ok(credentials) = base64::decode(credentials_b64.trim()) {
                                info!(
                                    credentials=%escape(&credentials),
                                    "base64-decoded and escaped"
                                );
                            } else {
                                error!(data=%credentials_b64.trim(), "credentials are not valid base64");
                            }
                        }
                        AuthMechanism::Login => {
                            let username_b64 = match initial_response {
                                Some(username) => username,
                                None => {
                                    self.send_raw(b"+ VXNlcm5hbWU6\r\n").await;
                                    self.recv(authenticate_data).await.unwrap()
                                }
                            };

                            if let Ok(username) = base64::decode(username_b64.trim()) {
                                info!(
                                    username=%escape(&username),
                                    "base64-decoded and escaped"
                                );
                            } else {
                                error!(data=%username_b64.trim(), "username is not valid base64");
                            }

                            let password_b64 = {
                                self.send_raw(b"+ UGFzc3dvcmQ6\r\n").await;
                                self.recv(authenticate_data).await.unwrap()
                            };

                            if let Ok(password) = base64::decode(password_b64.trim()) {
                                info!(
                                    password=%escape(&password),
                                    "base64-decoded and escaped"
                                );
                            } else {
                                error!(data=%password_b64.trim(), "password is not valid base64");
                            }
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
                            &format!("{} not allowed.", bad_command.name()),
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
                            self.send(Data::Capability(self.config.caps_tls_auth.clone()))
                                .await;
                        } else {
                            self.send(Data::Capability(self.config.caps_auth.clone()))
                                .await;
                        }
                        self.send(Status::ok(Some(command.tag), None, "capability done.").unwrap())
                            .await;
                    }
                    CommandBody::StartTLS => {
                        self.send(
                            Status::no(
                                Some(command.tag),
                                Some(Code::Capability(vec![
                                    Capability::Imap4Rev1,
                                    Capability::Auth(AuthMechanism::Login),
                                ])),
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
                    CommandBody::Status { mailbox, items } => {
                        match self.account.get_folder_by_name(&mailbox) {
                            Some(folder) => {
                                responses::ret_status_data(self, &folder, &items).await;
                            }
                            None => {
                                // Pretend to be mailbox with 0 mails.
                                let items = items
                                    .iter()
                                    .map(|items| match items {
                                        StatusItem::Messages => StatusItemResponse::Messages(0),
                                        StatusItem::Unseen => StatusItemResponse::Unseen(0),
                                        StatusItem::UidValidity => {
                                            StatusItemResponse::UidValidity(123_456)
                                        }
                                        StatusItem::UidNext => StatusItemResponse::UidNext(1),
                                        StatusItem::Recent => StatusItemResponse::Recent(0),
                                    })
                                    .collect();

                                self.send(Data::Status { mailbox, items }).await;
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
                        self.send(Data::Enabled { capabilities }).await;
                        self.send(Status::ok(Some(command.tag), None, "enable done.").unwrap())
                            .await;
                    }

                    CommandBody::Idle => {
                        self.send(Continuation::basic(None, "idle from auth.").unwrap())
                            .await;
                        self.state = State::IdleAuthenticated(command.tag.to_string());
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
                                &format!("{} not allowed.", bad_command.name()),
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
                        self.send(Data::Capability(self.config.caps_tls_auth.clone()))
                            .await;
                    } else {
                        self.send(Data::Capability(self.config.caps_auth.clone()))
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
                CommandBody::Status { mailbox, items } => {
                    match self.account.get_folder_by_name(&mailbox) {
                        Some(folder) => {
                            responses::ret_status_data(self, &folder, &items).await;
                            self.send(Status::ok(Some(command.tag), None, "status done.").unwrap())
                                .await;
                        }
                        None => {
                            self.send(
                                Status::no(Some(command.tag), None, "no such folder.").unwrap(),
                            )
                            .await;
                        }
                    }
                }
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
                            Header(..) => {
                                self.send(Data::Search(vec![])).await;
                                self.send(
                                    Status::ok(Some(command.tag), None, "search done.").unwrap(),
                                )
                                .await;
                            }
                            _ => {
                                match selected {
                                    Mailbox::Inbox => {
                                        self.send(Data::Search(vec![1, 2, 3])).await;
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
                    ref items,
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

                    let sequence_set = SequenceSet(sequence_set.clone());

                    let mut fetch_attrs = match items {
                        MacroOrDataItems::Macro(macro_) => macro_.expand(),
                        MacroOrDataItems::DataItems(items) => items.to_vec(),
                    };

                    if uid {
                        if !fetch_attrs.contains(&DataItem::Uid) {
                            fetch_attrs.insert(0, DataItem::Uid)
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
                                let res = responses::attr_to_data(&mail, &fetch_attrs);
                                let resp = format!("* {} FETCH ({})\r\n", seq + 1, res);
                                self.send_raw(resp.as_bytes()).await;
                            } else {
                                debug!(uid, "No such mail. Sending no mail.");
                            }
                        }
                    } else {
                        let largest = selected.mails.len() as u32;
                        let iterator = sequence_set.iter(Strategy::Naive { largest });

                        for seq in iterator.take(500) {
                            // Safe subtraction: this code is not reachable with seq == 0
                            if let Some(mail) = selected.mails.get(seq as usize - 1) {
                                let res = responses::attr_to_data(&mail, &fetch_attrs);
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
                    self.send(Continuation::basic(None, "idle from selected.").unwrap())
                        .await;
                    self.state = State::IdleSelected(command.tag.to_string(), selected.clone());
                }

                bad_command => {
                    self.send(
                        Status::bad(
                            Some(command.tag),
                            None,
                            &format!("{} not allowed.", bad_command.name()),
                        )
                        .unwrap(),
                    )
                    .await;
                }
            },
            State::Logout => {
                info!("Logout.",);
            }
            State::IdleAuthenticated(tag) => {
                self.send(Data::Exists(4)).await;
                sleep(Duration::from_secs(1));

                self.recv(idle_done).await.unwrap();
                self.send(
                    Status::ok(Some(Tag::try_from(tag).unwrap()), None, "idle done.").unwrap(),
                )
                .await;

                self.state = State::Authenticated;
            }
            State::IdleSelected(tag, folder) => {
                self.send(Data::Exists(4)).await;
                sleep(Duration::from_secs(3));

                self.recv(idle_done).await.unwrap();
                self.send(
                    Status::ok(Some(Tag::try_from(tag).unwrap()), None, "idle done.").unwrap(),
                )
                .await;

                self.state = State::Selected(folder);
            }
        }

        return true;
    }
}

#[async_trait]
impl Splitter for ImapServer {
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
                            let resp = value.replace("<tag>", cmd.tag.to_string().as_str());
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

    async fn incomplete(&mut self) {
        if let Ok(msg) = String::from_utf8(self.buffer().to_vec()) {
            if msg.ends_with("}\r\n") || msg.ends_with("}\n") {
                debug!(
                    "Found incomplete data, which ends with `}}\\r\\n`. Sending a continuation."
                );
                self.send(Continuation::basic(None, "continue, please").unwrap())
                    .await;
            }
        }
    }
}
