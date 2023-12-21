use std::{
    convert::{AsRef, TryFrom, TryInto},
    num::NonZeroU32,
    path::Path,
    sync::Once,
};

use imap_codec::{
    codec::Encode,
    command::{fetch::FetchAttribute, status::StatusAttribute, ListMailbox},
    core::{AString, IString, NString},
    message::{Flag, FlagPerm, Mailbox, Section},
    response::{
        data::{Address, Envelope, QuotedChar, StatusAttributeValue},
        Code, Data, Status,
    },
};
use mailparse::{
    body::Body, parse_mail, DispositionType, MailHeaderMap, ParsedContentDisposition, ParsedMail,
};
use rand::{thread_rng, Rng, RngCore};
use regex::Regex;
use tracing::error;

use crate::imap::{
    account::{Folder, Mail},
    ImapServer,
};

#[path = "../oracles/mod.rs"]
mod oracles;

static RNGINIT: Once = Once::new();
static mut UIDVALIDITY: u32 = 0;

#[derive(Clone, Debug)]
pub struct Account {
    pub folders: Vec<Folder>,
}

impl Account {
    pub fn get_folder_by_name(&self, mailbox: &Mailbox) -> Option<Folder> {
        let mailbox = match mailbox {
            Mailbox::Inbox => "INBOX".to_string(),
            Mailbox::Other(other) => std::str::from_utf8(other.as_ref()).unwrap().to_string(),
        };

        self.folders
            .iter()
            .find(|folder| folder.name == *mailbox)
            .cloned()
    }

    pub fn from_dir<P: AsRef<Path>>(path: P, folders_p: &[String]) -> std::io::Result<Account> {
        let files = {
            let mut files = Vec::new();

            let directory = std::fs::read_dir(&path).unwrap_or_else(|_| {
                panic!("Could not read mails directory: \"{:?}\"", path.as_ref())
            });

            for entry in directory {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    files.push(entry.path());
                }
            }

            files
        };

        let mut rng = thread_rng();
        let uid: u32 = rng.gen();
        let amt: u32 = files.len() as u32;

        let mut folders = Vec::new();

        for name in folders_p {
            let folder = unsafe {
                RNGINIT.call_once(|| {
                    UIDVALIDITY = thread_rng().next_u32();
                });
                let mut folder = Folder::new(
                    &[String::from("\\Subscribed")],
                    ".",
                    name,
                    NonZeroU32::try_from(UIDVALIDITY).unwrap(),
                    NonZeroU32::try_from(uid + amt + 1).unwrap(),
                );

                if *name == "INBOX" {
                    for (i, path) in files.iter().enumerate() {
                        folder.push_mail(Mail::from_file(
                            path,
                            NonZeroU32::try_from(i as u32 + 1).unwrap(),
                        )?);
                    }
                }

                folder
            };

            folders.push(folder);
        }

        Ok(Account { folders })
    }
}

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
    let reference = {
        let mut out = Vec::new();
        reference.encode(&mut out).unwrap();
        String::from_utf8(out)?
    };
    let mailbox = {
        let mut out = Vec::new();
        mailbox.encode(&mut out).unwrap();
        String::from_utf8(out)?
    };

    if mailbox.is_empty() {
        Ok(Interpretation::HierarchyRequest)
    } else {
        Ok(Interpretation::Canonical(reference + mailbox.as_str()))
    }
}

pub fn attr_to_data(mail: &Mail, fetch_attrs: &[FetchAttribute]) -> String {
    fetch_attrs
        .iter()
        .map(|fetch_attr| {
            let parsed_mail = parse_mail(&mail.data.as_bytes()).unwrap();
            match fetch_attr {
                FetchAttribute::Body => unimplemented!(),

                FetchAttribute::BodyExt {
                    section,
                    partial,
                    peek: _,
                } => {
                    let mut headers = String::new();
                    match section {
                        Some(ref section) => {
                            let section_part: Option<String> = match section {
                                // FIXME: Works for single part requests
                                Section::Part(_part) => {
                                    let mut part_str = String::new();
                                    for subpart in _part.0.as_ref() {
                                        if part_str.len() > 0 {
                                            part_str.push('.')
                                        }
                                        part_str.push_str(&format!("{}", subpart));
                                    }
                                    Some(part_str)
                                }
                                Section::Text(..) => Some(String::new()),
                                Section::Header(_part) => {
                                    let mut header_vals = String::new();
                                    for header in parsed_mail.get_headers() {
                                        header_vals.push_str(
                                            format!(
                                                "{}: {}\r\n",
                                                header.get_key(),
                                                header.get_value()
                                            )
                                            .as_str(),
                                        );
                                    }
                                    headers = format!(
                                        "BODY[HEADER] {{{}}}\r\n{}",
                                        header_vals.len(),
                                        header_vals
                                    );
                                    None
                                }
                                Section::HeaderFields(_part, fields) => {
                                    let mut found_header_fields = String::new();
                                    let mut header_vals = String::new();
                                    headers.push_str("BODY[HEADER.FIELDS (");
                                    for field in fields.as_ref() {
                                        let key = match field {
                                            AString::Atom(atom) => atom.as_ref().to_string(),
                                            AString::String(s) => match s {
                                                IString::Literal(lit) => {
                                                    String::from_utf8(lit.as_ref().to_owned())
                                                        .unwrap_or("".to_string())
                                                }
                                                IString::Quoted(quoted) => {
                                                    quoted.as_ref().to_string()
                                                }
                                            },
                                        };

                                        found_header_fields
                                            .push_str(key.to_ascii_uppercase().as_str());
                                        found_header_fields.push(' ');
                                        match parsed_mail.headers.get_first_header(key.as_str()) {
                                            Some(header) => {
                                                header_vals.push_str(
                                                    format!(
                                                        "{}: {}\r\n",
                                                        header.get_key(),
                                                        header.get_value()
                                                    )
                                                    .as_str(),
                                                );
                                            }
                                            None => {}
                                        }
                                    }
                                    found_header_fields.pop();
                                    headers.push_str(found_header_fields.as_str());
                                    headers.push_str(")] {");
                                    headers.push_str(
                                        format!("{}}}\r\n", header_vals.len() + 2).as_str(),
                                    );
                                    headers.push_str(header_vals.as_str());
                                    headers.push_str("\r\n");
                                    None
                                }
                                _ => Some(String::new()),
                            };
                            if let Some(part) = section_part {
                                match *partial {
                                    Some((first, maximum)) => {
                                        if first != 0 {
                                            unimplemented!()
                                        }
                                        let data;
                                        match part.len() {
                                            0 => data = (&mail.data).to_string(),
                                            _ => {
                                                let mut current_part = &parsed_mail;
                                                for part_str in part.split(".") {
                                                    let part_num: usize =
                                                        part_str.parse().unwrap_or(1);
                                                    match current_part.subparts.len() {
                                                        0 => {}
                                                        _ => {
                                                            current_part =
                                                                &current_part.subparts[part_num - 1]
                                                        }
                                                    }
                                                    break;
                                                }
                                                data = match current_part.get_body_encoded() {
                                                    Body::Base64(body) => String::from_utf8(
                                                        body.get_raw().iter().cloned().collect(),
                                                    )
                                                    .unwrap(),
                                                    _ => current_part.get_body().unwrap(),
                                                }
                                            }
                                        };
                                        let ret = std::cmp::min(data.len() as u32, maximum.into());
                                        format!(
                                            "BODY[{}]<{}> {{{}}}\r\n{}",
                                            part,
                                            first,
                                            ret,
                                            &data[..ret as usize]
                                        ) // YOLO! (will panic if on UTF-8 boundary... ignore section
                                    }
                                    None => {
                                        let data;
                                        match section {
                                            Section::Part(_part) => {
                                                match part.len() {
                                                    0 => {
                                                        data = (&mail.data).to_string();
                                                    }
                                                    _ => {
                                                        let mut current_part = &parsed_mail;
                                                        for part_str in part.split(".") {
                                                            let part_num: usize =
                                                                part_str.parse().unwrap_or(1);
                                                            match current_part.subparts.len() {
                                                                0 => {}
                                                                _ => {
                                                                    current_part = &current_part
                                                                        .subparts[part_num - 1]
                                                                }
                                                            }
                                                            break;
                                                        }
                                                        data = match current_part.get_body_encoded()
                                                        {
                                                            Body::Base64(body) => {
                                                                String::from_utf8(
                                                                    body.get_raw()
                                                                        .iter()
                                                                        .cloned()
                                                                        .collect(),
                                                                )
                                                                .unwrap()
                                                            }
                                                            _ => current_part.get_body().unwrap(),
                                                        }
                                                    }
                                                };
                                                format!(
                                                    "BODY[{}] {{{}}}\r\n{}",
                                                    part,
                                                    data.len(),
                                                    &data
                                                ) // YOLO! (will panic if on UTF-8 boundary... ignorae section
                                            }
                                            Section::Header(Some(_part)) => unimplemented!(),
                                            Section::Header(None) => {
                                                format!(
                                                    "BODY[HEADER] {{{}}}\r\n{}",
                                                    parsed_mail.get_headers().get_raw_bytes().len(),
                                                    std::str::from_utf8(
                                                        parsed_mail.get_headers().get_raw_bytes()
                                                    )
                                                    .unwrap()
                                                )
                                            }
                                            Section::HeaderFields(_maybe_part, fields) => format!(
                                                "BODY[HEADER.FIELDS ({})] {{{}}}\r\n{}",
                                                fields
                                                    .as_ref()
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
                                            Section::HeaderFieldsNot(_maybe_part, _fields) => {
                                                unimplemented!()
                                            }
                                            Section::Text(_maybe_part) => {
                                                let data = get_full_body(parsed_mail, false, "");
                                                format!("BODY[TEXT] {{{}}}\r\n{}", data.len(), data)
                                            }
                                            Section::Mime(section_part) => {
                                                let mut section_str = String::new();
                                                let mut current_part = &parsed_mail;
                                                for part in section_part.0.as_ref() {
                                                    section_str.push_str(&part.to_string());
                                                    match current_part.subparts.len() {
                                                        0 => {}
                                                        _ => {
                                                            current_part = &current_part.subparts
                                                                [usize::try_from(u32::from(*part))
                                                                    .unwrap_or(1)
                                                                    - 1]
                                                        }
                                                    }
                                                    break;
                                                }
                                                let part_headers = String::from_utf8(
                                                    current_part
                                                        .get_headers()
                                                        .get_raw_bytes()
                                                        .to_vec(),
                                                )
                                                .unwrap();
                                                format!(
                                                    "BODY[{}.MIME] {{{}}}\r\n{}",
                                                    section_str,
                                                    part_headers.len(),
                                                    part_headers
                                                )
                                            }
                                        }
                                    }
                                }
                            } else {
                                headers
                            }
                        }
                        None => {
                            match *partial {
                                Some((first, maximum)) => {
                                    if first != 0 {
                                        unimplemented!()
                                    }
                                    let ret = std::cmp::min(mail.data.len() as u32, maximum.into());
                                    format!(
                                        "BODY[]<{}> {{{}}}\r\n{}",
                                        first,
                                        ret,
                                        &mail.data[..ret as usize]
                                    ) // YOLO! (will panic if on UTF-8 boundary...
                                }
                                None => {
                                    format!("BODY[] {{{}}}\r\n{}", mail.data.len(), mail.data)
                                }
                            }
                        }
                    }
                }

                FetchAttribute::BodyStructure => {
                    let bodystructure = build_bodystructure(parsed_mail);
                    format!("BODYSTRUCTURE {}", bodystructure)
                }
                FetchAttribute::Envelope => {
                    let subject = match parsed_mail.get_headers().get_first_header("Subject") {
                        Some(header) => header.get_value(),
                        _ => "No subject".to_string(),
                    };

                    let mut from = vec![];
                    for from_addr in parsed_mail.get_headers().get_all_headers("From") {
                        let re = Regex::new(r"(.*)( <.*>)?").unwrap();
                        let name: &str;
                        let mailbox: &str;
                        let host: &str;
                        let addr_val = from_addr.get_value();
                        match re.captures(&addr_val) {
                            Some(caps) => {
                                name = caps.get(1).map_or("No Name", |m| m.as_str().into());
                                match caps.get(2) {
                                    Some(addr) => {
                                        let re = Regex::new("<(.*)@(.*>)").unwrap();
                                        match re.captures(addr.as_str()) {
                                            Some(caps) => {
                                                mailbox = caps.get(1).unwrap().as_str();
                                                host = caps.get(2).unwrap().as_str();
                                            }
                                            None => {
                                                mailbox = "None";
                                                host = "None";
                                            }
                                        }
                                    }
                                    None => {
                                        mailbox = "None";
                                        host = "None";
                                    }
                                }
                            }
                            None => {
                                name = "No Name";
                                mailbox = "None";
                                host = "None";
                            }
                        };

                        let addr = Address {
                            name: NString(Some(IString::try_from(name.to_owned()).unwrap())),
                            adl: NString(None),
                            mailbox: NString(Some(mailbox.to_owned().try_into().unwrap())),
                            host: NString(Some(host.to_owned().try_into().unwrap())),
                        };
                        from.push(addr);
                    }
                    let envelope = Envelope {
                        date: NString(Some("01-Oct-2021 12:34:56 +0000".try_into().unwrap())),
                        subject: NString(Some(subject.try_into().unwrap())),
                        from: from,
                        sender: vec![],
                        reply_to: vec![],
                        to: vec![],
                        cc: vec![],
                        bcc: vec![],
                        in_reply_to: NString(None),
                        message_id: NString(None),
                    };
                    let mut buffer = Vec::new();
                    envelope.encode(&mut buffer).unwrap();
                    format!("ENVELOPE {}", String::from_utf8(buffer).unwrap())
                    //"ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)".to_string()
                } // unimplemented!(), // FIXME
                FetchAttribute::Flags => {
                    format!("FLAGS {}", "(\\Recent)")
                }
                FetchAttribute::InternalDate => {
                    format!("INTERNALDATE \"{}\"", "01-Oct-2021 12:34:56 +0000")
                } // FIXME
                FetchAttribute::Rfc822 => unimplemented!(),
                FetchAttribute::Rfc822Header => format!(
                    "RFC822.HEADER {{{}}}\r\n{}",
                    mail.header().len(),
                    mail.header()
                ),
                FetchAttribute::Rfc822Size => format!("RFC822.SIZE {}", mail.data.len()),
                FetchAttribute::Rfc822Text => unimplemented!(),
                FetchAttribute::Uid => format!("UID {}", mail.uid),
            }
        })
        .collect::<Vec<String>>()
        .join(" ")
}

pub fn attr_to_data_oracles(uid: u32, fetch_attrs: &[FetchAttribute]) -> String {
    fetch_attrs
        .iter()
        .map(|fetch_attr| {
            let headers = oracles::get_headers(uid);
            match fetch_attr {
                FetchAttribute::Body => unimplemented!(),

                FetchAttribute::BodyExt {
                    section,
                    partial,
                    peek: _,
                } => {
                    let parsed_mail = parse_mail(headers.as_bytes()).unwrap();
                    let mut parsed_headers = String::new();
                    match section {
                        Some(ref section) => {
                            let section_part: Option<String> = match section {
                                // FIXME: Works for single part requests
                                Section::Part(_part) => {
                                    let mut part_str = String::new();
                                    for subpart in _part.0.as_ref() {
                                        if part_str.len() > 0 {
                                            part_str.push('.')
                                        }
                                        part_str.push_str(&format!("{}", subpart));
                                    }
                                    Some(part_str)
                                }
                                Section::Text(..) => Some(String::new()),
                                Section::Header(_part) => {
                                    parsed_headers = format!(
                                        "BODY[HEADER] {{{}}}\r\n{}",
                                        headers.len(),
                                        headers
                                    );
                                    None
                                }
                                Section::HeaderFields(_part, fields) => {
                                    let mut found_header_fields = String::new();
                                    let mut header_vals = String::new();
                                    parsed_headers.push_str("BODY[HEADER.FIELDS (");
                                    for field in fields.as_ref() {
                                        let key = match field {
                                            AString::Atom(atom) => atom.as_ref().to_string(),
                                            AString::String(s) => match s {
                                                IString::Literal(lit) => {
                                                    String::from_utf8(lit.as_ref().to_owned())
                                                        .unwrap_or("".to_string())
                                                }
                                                IString::Quoted(quoted) => {
                                                    quoted.as_ref().to_string()
                                                }
                                            },
                                        };

                                        found_header_fields
                                            .push_str(key.to_ascii_uppercase().as_str());
                                        found_header_fields.push(' ');
                                        match parsed_mail.headers.get_first_header(key.as_str()) {
                                            Some(header) => {
                                                header_vals.push_str(
                                                    format!(
                                                        "{}: {}\r\n",
                                                        header.get_key(),
                                                        header.get_value()
                                                    )
                                                    .as_str(),
                                                );
                                            }
                                            None => {}
                                        }
                                    }
                                    found_header_fields.pop();
                                    parsed_headers.push_str(found_header_fields.as_str());
                                    parsed_headers.push_str(")] {");
                                    parsed_headers.push_str(
                                        format!("{}}}\r\n", header_vals.len() + 2).as_str(),
                                    );
                                    parsed_headers.push_str(header_vals.as_str());
                                    parsed_headers.push_str("\r\n");
                                    None
                                }
                                _ => Some(String::new()),
                            };
                            if let Some(part) = section_part {
                                match *partial {
                                    Some((first, maximum)) => {
                                        if first != 0 {
                                            unimplemented!()
                                        }
                                        let data;
                                        match part.len() {
                                            0 => data = oracles::get_body(uid),
                                            _ => {
                                                data = oracles::get_part(uid, &part);
                                            }
                                        };
                                        let ret = std::cmp::min(data.len() as u32, maximum.into());
                                        format!(
                                            "BODY[{}]<{}> {{{}}}\r\n{}",
                                            part,
                                            first,
                                            ret,
                                            &data[..ret as usize]
                                        ) // YOLO! (will panic if on UTF-8 boundary... ignore section
                                    }
                                    None => {
                                        let data;
                                        match section {
                                            Section::Part(_part) => {
                                                match part.len() {
                                                    0 => {
                                                        data = oracles::get_body(uid);
                                                    }
                                                    _ => {
                                                        data = oracles::get_part(uid, &part);
                                                    }
                                                };
                                                format!(
                                                    "BODY[{}] {{{}}}\r\n{}",
                                                    part,
                                                    data.len(),
                                                    &data
                                                ) // YOLO! (will panic if on UTF-8 boundary... ignore section
                                            }
                                            Section::Header(Some(_part)) => unimplemented!(),
                                            Section::Header(None) => format!(
                                                "BODY[HEADER] {{{}}}\r\n{}",
                                                parsed_mail.get_headers().get_raw_bytes().len(),
                                                std::str::from_utf8(
                                                    parsed_mail.get_headers().get_raw_bytes()
                                                )
                                                .unwrap()
                                            ),
                                            Section::HeaderFields(_maybe_part, fields) => format!(
                                                "BODY[HEADER.FIELDS ({})] {{{}}}\r\n{}",
                                                fields
                                                    .as_ref()
                                                    .iter()
                                                    .map(|s| {
                                                        let mut out = Vec::with_capacity(64);
                                                        s.encode(&mut out).unwrap();
                                                        String::from_utf8(out).unwrap()
                                                    })
                                                    .collect::<Vec<String>>()
                                                    .join(" "),
                                                parsed_headers.len(),
                                                parsed_headers
                                            ),
                                            Section::HeaderFieldsNot(_maybe_part, _fields) => {
                                                unimplemented!()
                                            }
                                            Section::Text(_maybe_part) => {
                                                let data = oracles::get_body(uid);
                                                format!("BODY[TEXT] {{{}}}\r\n{}", data.len(), data)
                                            }
                                            Section::Mime(_maybe_part) => {
                                                let mut buffer = Vec::new();
                                                _maybe_part.encode(&mut buffer).unwrap();
                                                let part_str = String::from_utf8(buffer).unwrap();
                                                data = oracles::get_part_headers(
                                                    uid,
                                                    part_str.as_str(),
                                                );
                                                format!(
                                                    "BODY[{}.MIME] {{{}}}\r\n{}",
                                                    part_str,
                                                    data.len(),
                                                    &data
                                                )
                                            }
                                        }
                                    }
                                }
                            } else {
                                parsed_headers
                            }
                        }
                        None => match *partial {
                            Some((_first, _maximum)) => {
                                unimplemented!()
                            }
                            None => {
                                let mail = oracles::get_body(uid);
                                format!("BODY[] {{{}}}\r\n{}", mail.len(), mail)
                            }
                        },
                    }
                }
                FetchAttribute::BodyStructure => {
                    let bodystructure = oracles::get_bodystructure(uid); //build_bodystructure(parsed_mail);
                    format!("BODYSTRUCTURE {}", bodystructure)
                }
                FetchAttribute::Envelope => {
                    let parsed_mail = parse_mail(headers.as_bytes()).unwrap();
                    let subject = match parsed_mail.get_headers().get_first_header("Subject") {
                        Some(header) => header.get_value(),
                        _ => "No subject".to_string(),
                    };

                    let mut from = vec![];
                    for from_addr in parsed_mail.get_headers().get_all_headers("From") {
                        let re = Regex::new(r"(.*)( <.*>)?").unwrap();
                        let name: &str;
                        let mailbox: &str;
                        let host: &str;
                        let addr_val = from_addr.get_value();
                        match re.captures(addr_val.as_str()) {
                            Some(caps) => {
                                name = caps.get(1).map_or("No Name", |m| m.as_str().into());
                                match caps.get(2) {
                                    Some(addr) => {
                                        let re = Regex::new("<(.*)@(.*>)").unwrap();
                                        match re.captures(addr.as_str()) {
                                            Some(caps) => {
                                                mailbox = caps.get(1).unwrap().as_str();
                                                host = caps.get(2).unwrap().as_str();
                                            }
                                            None => {
                                                mailbox = "None";
                                                host = "None";
                                            }
                                        }
                                    }
                                    None => {
                                        mailbox = "None";
                                        host = "None";
                                    }
                                }
                            }
                            None => {
                                name = "No Name";
                                mailbox = "None";
                                host = "None";
                            }
                        };
                        let addr = Address {
                            name: NString(Some(name.to_string().try_into().unwrap())),
                            adl: NString(None),
                            mailbox: NString(Some(mailbox.to_string().try_into().unwrap())),
                            host: NString(Some(host.to_string().try_into().unwrap())),
                        };
                        from.push(addr);
                    }
                    let envelope = Envelope {
                        date: NString(Some("01-Oct-2021 12:34:56 +0000".try_into().unwrap())),
                        subject: NString(Some(subject.try_into().unwrap())),
                        from: from,
                        sender: vec![],
                        reply_to: vec![],
                        to: vec![],
                        cc: vec![],
                        bcc: vec![],
                        in_reply_to: NString(None),
                        message_id: NString(None),
                    };
                    let mut buffer = Vec::new();
                    envelope.encode(&mut buffer).unwrap();
                    format!("ENVELOPE {}", String::from_utf8(buffer).unwrap())
                    //"ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)".to_string()
                } // unimplemented!(), // FIXME
                FetchAttribute::Flags => {
                    format!("FLAGS {}", "(\\Recent)")
                }
                FetchAttribute::InternalDate => {
                    format!("INTERNALDATE \"{}\"", "01-Oct-2021 12:34:56 +0000")
                }
                FetchAttribute::Rfc822 => unimplemented!(),
                FetchAttribute::Rfc822Header => format!(
                    "RFC822.HEADER {{{}}}\r\n{}",
                    oracles::get_headers(uid).len(),
                    oracles::get_headers(uid)
                ),
                FetchAttribute::Rfc822Size => format!("RFC822.SIZE {}", oracles::get_size(uid)),
                FetchAttribute::Rfc822Text => unimplemented!(),
                FetchAttribute::Uid => format!("UID {}", uid),
            }
        })
        .collect::<Vec<String>>()
        .join(" ")
}

pub async fn ret_select_data(client: &mut ImapServer<'_>, folder: &Folder) {
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
                Some(Code::Unseen(1.try_into().unwrap())),
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
                    FlagPerm::Flag(Flag::Answered),
                    FlagPerm::Flag(Flag::Flagged),
                    FlagPerm::Flag(Flag::Deleted),
                    FlagPerm::Flag(Flag::Seen),
                    FlagPerm::Flag(Flag::Draft),
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

pub async fn ret_list_data(
    client: &mut ImapServer<'_>,
    reference: &Mailbox<'_>,
    mailbox: &ListMailbox<'_>,
) {
    let qc = QuotedChar::try_from('/').unwrap();

    match canonical_form(reference, mailbox) {
        Ok(Interpretation::HierarchyRequest) => {
            client
                .send(Data::List {
                    items: vec![],
                    delimiter: Some(qc),
                    mailbox: Mailbox::try_from("").unwrap(),
                })
                .await;
        }
        Ok(Interpretation::Canonical(canonical)) => {
            if canonical == "*" || canonical == "%" {
                for mailbox in client.config.folders.clone().into_iter() {
                    client
                        .send(Data::List {
                            items: vec![],
                            delimiter: Some(qc),
                            mailbox: Mailbox::try_from(mailbox).unwrap(),
                        })
                        .await;
                }
            } else if client.config.folders.contains(&canonical) {
                client
                    .send(Data::List {
                        items: vec![],
                        delimiter: Some(qc),
                        mailbox: Mailbox::try_from(canonical).unwrap(),
                    })
                    .await;
            } else if Mailbox::try_from(canonical).unwrap() == Mailbox::Inbox {
                client
                    .send(Data::List {
                        items: vec![],
                        delimiter: Some(qc),
                        mailbox: Mailbox::Inbox,
                    })
                    .await;
            }
        }
        Err(error) => error!(%error, "can not compute canonical form"),
    }
}

pub async fn ret_lsub_data(
    client: &mut ImapServer<'_>,
    reference: &Mailbox<'_>,
    mailbox: &ListMailbox<'_>,
) {
    let qc = QuotedChar::try_from('/').unwrap();

    match canonical_form(reference, mailbox) {
        Ok(Interpretation::HierarchyRequest) => {
            client
                .send(Data::List {
                    items: vec![],
                    delimiter: Some(qc),
                    mailbox: Mailbox::try_from("").unwrap(),
                })
                .await;
        }
        Ok(Interpretation::Canonical(canonical)) => {
            if canonical == "*" || canonical == "%" {
                for mailbox in client.config.folders.clone().into_iter() {
                    client
                        .send(Data::List {
                            items: vec![],
                            delimiter: Some(qc),
                            mailbox: Mailbox::try_from(mailbox).unwrap(),
                        })
                        .await;
                }
            } else if client.config.folders.contains(&canonical) {
                client
                    .send(Data::List {
                        items: vec![],
                        delimiter: Some(qc),
                        mailbox: Mailbox::try_from(canonical).unwrap(),
                    })
                    .await;
            } else if Mailbox::try_from(canonical).unwrap() == Mailbox::Inbox {
                client
                    .send(Data::List {
                        items: vec![],
                        delimiter: Some(qc),
                        mailbox: Mailbox::Inbox,
                    })
                    .await;
            }
        }
        Err(error) => error!(%error, "can not compute canonical form"),
    }
}

pub async fn ret_status_data(
    client: &mut ImapServer<'_>,
    folder: &Folder,
    attributes: &[StatusAttribute],
) {
    let attributes = attributes
        .iter()
        .map(|items| match items {
            StatusAttribute::Messages => StatusAttributeValue::Messages(folder.mails.len() as u32),
            StatusAttribute::Unseen => StatusAttributeValue::Unseen(folder.mails.len() as u32),
            StatusAttribute::UidValidity => StatusAttributeValue::UidValidity(folder.uidvalidity),
            StatusAttribute::UidNext => StatusAttributeValue::UidNext(folder.uidnext),
            StatusAttribute::Recent => StatusAttributeValue::Recent(folder.mails.len() as u32),
        })
        .collect();

    client
        .send(Data::Status {
            mailbox: Mailbox::try_from(folder.name.clone()).unwrap(),
            attributes,
        })
        .await;
}

pub fn build_bodystructure(mail_part: ParsedMail) -> String {
    let mut sub_parts = String::new();
    let mut attributes = String::new();
    match mail_part.ctype.params.len() {
        0 => attributes.push_str("NIL"),
        _ => {
            attributes.push('(');
            for x in &mail_part.ctype.params {
                attributes.push_str(format!("\"{}\" \"{}\" ", x.0, x.1).as_str())
            }
            attributes.pop(); // Remove trailing space
            attributes.push(')');
        }
    }
    let mut disposition = String::new();
    match mail_part.get_content_disposition() {
        ParsedContentDisposition {
            disposition: DispositionType::Attachment,
            params,
        } => {
            disposition.push_str(" (\"ATTACHMENT\" (");
            for x in &params {
                disposition.push_str(format!("\"{}\" \"{}\" ", x.0, x.1).as_str())
            }
            disposition.pop(); // Remove trailing space
            disposition.push_str(")) NIL NIL");
        }
        ParsedContentDisposition { .. } => {}
    }

    if mail_part
        .ctype
        .mimetype
        .to_ascii_lowercase()
        .starts_with("multipart/")
    {
        let subtype = mail_part.ctype.mimetype.split("/").nth(1).unwrap();
        for part in mail_part.subparts {
            sub_parts.push_str(build_bodystructure(part).as_str());
        }
        format!("({} \"{}\" {} NIL NIL NIL)", sub_parts, subtype, attributes)
    } else {
        let data = match mail_part.get_body_encoded() {
            Body::Base64(body) => {
                String::from_utf8(body.get_raw().iter().cloned().collect()).unwrap()
            }
            _ => mail_part.get_body().unwrap(),
        };
        let line_count = "NIL"; //data.lines().count();
        let data_len = data.len();
        let mut comp_type = mail_part.ctype.mimetype.split("/");
        let (mimetype, subtype) = (comp_type.next().unwrap(), comp_type.next().unwrap());
        let encoding = match mail_part
            .headers
            .get_first_header("Content-Transfer-Encoding")
        {
            Some(header) => header.get_value(),
            _ => "7BIT".to_string(),
        };
        format!(
            "(\"{}\" \"{}\" {} NIL NIL \"{}\" {} {}{})",
            mimetype, subtype, attributes, encoding, data_len, line_count, disposition
        )
    }
}

pub fn get_full_body(parsed_mail: ParsedMail, nested: bool, boundary: &str) -> String {
    let mut data = String::new();
    if nested {
        data.push_str(format!("\r\n--{}\r\n", boundary).as_str());
        for header in parsed_mail.get_headers() {
            let header_str = format!("{}: {}\r\n", header.get_key(), header.get_value());
            data.push_str(header_str.as_str());
        }
    }
    data.push_str("\r\n");
    return if parsed_mail.ctype.mimetype.starts_with("multipart") {
        let replacement_boundary = "".to_string();
        let boundary = parsed_mail
            .ctype
            .params
            .get("boundary")
            .unwrap_or(&replacement_boundary);
        for part in parsed_mail.subparts {
            let part_data = get_full_body(part, true, boundary);
            data.push_str(part_data.as_str());
        }
        data.push_str(format!("\r\n\r\n--{}--\r\n", boundary).as_str());
        data
    } else {
        let body = match parsed_mail.get_body_encoded() {
            Body::Base64(body) => {
                String::from_utf8(body.get_raw().iter().cloned().collect()).unwrap()
            }
            _ => parsed_mail.get_body().unwrap(),
        };
        data.push_str(body.as_str());
        data
    };
}
