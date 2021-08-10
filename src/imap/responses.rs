use std::convert::TryFrom;

use imap_codec::{
    codec::Encode,
    types::{
        command::StatusItem,
        data_items::{DataItem, Section},
        flag::Flag,
        mailbox::{ListMailbox, Mailbox},
        response::{Code, Data, Status, StatusItemResponse},
    },
};
use tracing::error;

use crate::imap::{
    account::{Folder, Mail},
    ImapServer,
};

enum Interpretation {
    /// An empty ("" string) mailbox name argument is a special request to
    /// return the hierarchy delimiter and the root name of the name given
    /// in the reference.
    HierarchyRequest,
    /// If a server implementation has no concept of break out
    /// characters, the canonical form is normally the reference
    /// name appended with the mailbox name.
    Canonical(String),
}

fn canonical_form(
    reference: &Mailbox,
    mailbox: &ListMailbox,
) -> Result<Interpretation, std::string::FromUtf8Error> {
    let reference = String::try_from(reference.clone())?;
    let mailbox = String::try_from(mailbox.clone())?;

    if mailbox.is_empty() {
        Ok(Interpretation::HierarchyRequest)
    } else {
        Ok(Interpretation::Canonical(reference + mailbox.as_str()))
    }
}

pub fn attr_to_data(mail: &Mail, fetch_attrs: &[DataItem]) -> String {
    fetch_attrs.iter().map(|fetch_attr| {
        match fetch_attr {
            DataItem::Body => unimplemented!(),

            DataItem::BodyExt{section, partial, peek: _} => {
                match section {
                    Some(ref section) => {
                        match *partial {
                            Some((first, maximum)) => {
                                if first != 0 {
                                    unimplemented!()
                                }
                                let ret = std::cmp::min(mail.body().len() as u32, maximum);
                                // FIXME: Do not ignore section.
                                format!("BODY[1]<{}> {{{}}}\r\n{}", ret, ret, &mail.body()[..ret as usize]) // YOLO! (will panic if on UTF-8 boundary... ignore section
                            }
                            None => {
                                match section {
                                    Section::Part(_part) => unimplemented!(),
                                    Section::Header(Some(_part)) => unimplemented!(),
                                    Section::Header(None) => {
                                        format!("BODY[HEADER] {{{}}}\r\n{}", mail.header().len(), mail.header())
                                    },
                                    Section::HeaderFields(_maybe_part, fields) => format!(
                                        "BODY[HEADER.FIELDS ({})] {{{}}}\r\n{}",
                                        fields
                                            .iter()
                                            .map(|s| {
                                                let mut out = Vec::with_capacity(64);
                                                s.encode(&mut out).unwrap();
                                                String::from_utf8(out).unwrap()
                                            })
                                            .collect::<Vec<String>>()
                                            .join(" "),
                                        mail.header().len(),
                                        mail.header()
                                    ),
                                    Section::HeaderFieldsNot(_maybe_part, _fields) => unimplemented!(),
                                    Section::Text(_maybe_part) => format!(
                                        "BODY[TEXT] {{{}}}\r\n{}",
                                        mail.body().len(),
                                        mail.body()
                                    ),
                                    Section::Mime(_maybe_part) => unimplemented!(),
                                }
                            }
                        }
                    }
                    None => {
                        match *partial {
                            Some((first, maximum)) => {
                                if first != 0 {
                                    unimplemented!()
                                }
                                let ret = std::cmp::min(mail.body().len() as u32, maximum);
                                format!("BODY[]<{}> {{{}}}\r\n{}", ret, ret, &mail.body()[..ret as usize]) // YOLO! (will panic if on UTF-8 boundary...
                            }
                            None => {
                                format!("BODY[] {{{}}}\r\n{}", mail.body().len(), mail.body())
                            }
                        }
                    }
                }
            },

            DataItem::BodyStructure => format!("BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" {} {})", mail.body().len(), mail.body().lines().count()),

            DataItem::Envelope => "ENVELOPE \"\"".to_string(), // FIXME
            DataItem::Flags => format!("FLAGS {}", "(\\Recent)"),
            DataItem::InternalDate => format!("INTERNALDATE \"{}\"", "01-Oct-2019 12:34:56 +0000"),
            DataItem::Rfc822 => unimplemented!(),
            DataItem::Rfc822Header => format!("RFC822.HEADER {{{}}}\r\n{}", mail.header().len(), mail.header()),
            DataItem::Rfc822Size => format!("RFC822.SIZE {}", mail.body().len()),
            DataItem::Rfc822Text => unimplemented!(),
            DataItem::Uid => format!("UID {}", mail.uid),
        }
    }).collect::<Vec<String>>().join(" ")
}

pub async fn ret_select_data(client: &mut ImapServer, folder: &Folder) {
    client
        .send(Data::Flags(vec![
            Flag::Answered,
            Flag::Flagged,
            Flag::Deleted,
            Flag::Seen,
            Flag::Draft,
        ]))
        .await;
    client.send(Data::Exists(folder.mails.len() as u32)).await;
    client.send(Data::Recent(folder.mails.len() as u32)).await;
    client
        .send(
            Status::ok(
                None,
                Some(Code::Unseen(1)),
                "first message without the \\Seen flag set.",
            )
            .unwrap(),
        )
        .await;
    client
        .send(
            Status::ok(
                None,
                Some(Code::PermanentFlags(vec![
                    Flag::Answered,
                    Flag::Flagged,
                    Flag::Deleted,
                    Flag::Seen,
                    Flag::Draft,
                ])),
                "flags the client can change permanently.",
            )
            .unwrap(),
        )
        .await;
    client
        .send(
            Status::ok(
                None,
                Some(Code::UidNext(folder.uidnext)),
                "the next unique identifier value.",
            )
            .unwrap(),
        )
        .await;
    client
        .send(
            Status::ok(
                None,
                Some(Code::UidValidity(folder.uidvalidity)),
                "the unique identifier validity value.",
            )
            .unwrap(),
        )
        .await;
}

pub async fn ret_list_data(client: &mut ImapServer, reference: &Mailbox, mailbox: &ListMailbox) {
    match canonical_form(reference, mailbox) {
        Ok(Interpretation::HierarchyRequest) => {
            client
                .send(Data::List {
                    items: vec![],
                    delimiter: Some('/'),
                    mailbox: Mailbox::from(""),
                })
                .await;
        }
        Ok(Interpretation::Canonical(canonical)) => {
            if canonical == "*" || canonical == "%" {
                for mailbox in client.config.folders.clone().into_iter() {
                    client
                        .send(Data::List {
                            items: vec![],
                            delimiter: Some('/'),
                            mailbox: Mailbox::from(mailbox),
                        })
                        .await;
                }
            } else if client.config.folders.contains(&canonical) {
                client
                    .send(Data::List {
                        items: vec![],
                        delimiter: Some('/'),
                        mailbox: Mailbox::from(canonical),
                    })
                    .await;
            } else if Mailbox::from(canonical) == Mailbox::Inbox {
                client
                    .send(Data::List {
                        items: vec![],
                        delimiter: Some('/'),
                        mailbox: Mailbox::Inbox,
                    })
                    .await;
            }
        }
        Err(error) => error!(%error, "can not compute canonical form"),
    }
}

pub async fn ret_lsub_data(client: &mut ImapServer, reference: &Mailbox, mailbox: &ListMailbox) {
    match canonical_form(reference, mailbox) {
        Ok(Interpretation::HierarchyRequest) => {
            client
                .send(Data::List {
                    items: vec![],
                    delimiter: Some('/'),
                    mailbox: Mailbox::from(""),
                })
                .await;
        }
        Ok(Interpretation::Canonical(canonical)) => {
            if canonical == "*" || canonical == "%" {
                for mailbox in client.config.folders.clone().into_iter() {
                    client
                        .send(Data::List {
                            items: vec![],
                            delimiter: Some('/'),
                            mailbox: Mailbox::from(mailbox),
                        })
                        .await;
                }
            } else if client.config.folders.contains(&canonical) {
                client
                    .send(Data::List {
                        items: vec![],
                        delimiter: Some('/'),
                        mailbox: Mailbox::from(canonical),
                    })
                    .await;
            } else if Mailbox::from(canonical) == Mailbox::Inbox {
                client
                    .send(Data::List {
                        items: vec![],
                        delimiter: Some('/'),
                        mailbox: Mailbox::Inbox,
                    })
                    .await;
            }
        }
        Err(error) => error!(%error, "can not compute canonical form"),
    }
}

pub async fn ret_status_data(client: &mut ImapServer, folder: &Folder, items: &[StatusItem]) {
    let items = items
        .iter()
        .map(|items| match items {
            StatusItem::Messages => StatusItemResponse::Messages(folder.mails.len() as u32),
            StatusItem::Unseen => StatusItemResponse::Unseen(folder.mails.len() as u32),
            StatusItem::UidValidity => StatusItemResponse::UidValidity(folder.uidvalidity),
            StatusItem::UidNext => StatusItemResponse::UidNext(folder.uidnext),
            StatusItem::Recent => StatusItemResponse::Recent(folder.mails.len() as u32),
        })
        .collect();

    client
        .send(Data::Status {
            mailbox: Mailbox::try_from(folder.name.clone()).unwrap(),
            items,
        })
        .await;
}
