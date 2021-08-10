use std::convert::TryFrom;

use fake_mail_server::utils::escape;
use imap_codec::{
    codec::Encode,
    types::{
        core::{IString, NString},
        flag::Flag,
        mailbox::Mailbox,
        response::{Capability, Data, DataItemResponse, StatusItemResponse},
    },
};

fn gen_nonce() -> String {
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    String::from_utf8(thread_rng().sample_iter(&Alphanumeric).take(8).collect()).unwrap()
}

#[test]
fn generate_response() {
    let some_things = &[
        Data::Capability(vec![Capability::Idle]),
        Data::List {
            mailbox: Mailbox::try_from(gen_nonce()).unwrap(),
            delimiter: Some('/'),
            items: vec![],
        },
        Data::Lsub {
            mailbox: Mailbox::try_from(gen_nonce()).unwrap(),
            delimiter: Some('/'),
            items: vec![],
        },
        Data::Status {
            mailbox: Mailbox::try_from(gen_nonce()).unwrap(),
            items: vec![
                StatusItemResponse::Messages(529_001),
                StatusItemResponse::Recent(529_002),
                StatusItemResponse::UidNext(529_003),
                StatusItemResponse::Unseen(529_004),
                StatusItemResponse::UidValidity(529_005),
            ],
        },
        Data::Status {
            mailbox: Mailbox::Inbox,
            items: vec![
                StatusItemResponse::Messages(718_001),
                StatusItemResponse::Recent(718_002),
                StatusItemResponse::UidNext(718_003),
                StatusItemResponse::Unseen(718_004),
                StatusItemResponse::UidValidity(718_005),
            ],
        },
        Data::Search((1..=20).into_iter().collect::<Vec<_>>()),
        Data::Flags(vec![Flag::Flagged]),
        Data::Exists(54321),
        Data::Recent(12345),
        Data::Expunge(1),
        Data::Fetch {
            seq_or_uid: 1,
            items: vec![DataItemResponse::BodyExt {
                data: NString(Some(IString::Quoted(
                    "From: Injected\r\n\r\nInjected\r\n".into(),
                ))),
                origin: None,
                section: None,
            }],
        },
        // ----- ENABLE Extension (RFC 5161) -----
        Data::Enabled {
            capabilities: vec![Capability::Idle],
        },
    ];

    for some_thing in some_things {
        let mut out = Vec::new();
        some_thing.encode(&mut out).unwrap();
        println!("{}", escape(&out));
    }
}
