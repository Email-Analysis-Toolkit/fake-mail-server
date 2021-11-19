use std::{
    convert::{TryFrom, TryInto},
    num::NonZeroU32,
};

use fake_mail_server::utils::escape;
use imap_codec::{
    codec::Encode,
    types::{
        core::{IString, NString, Quoted},
        flag::Flag,
        mailbox::Mailbox,
        response::{Capability, Data, MessageAttribute, StatusAttributeValue},
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
            attributes: vec![
                StatusAttributeValue::Messages(529_001),
                StatusAttributeValue::Recent(529_002),
                StatusAttributeValue::UidNext(529_003.try_into().unwrap()),
                StatusAttributeValue::Unseen(529_004),
                StatusAttributeValue::UidValidity(529_005.try_into().unwrap()),
            ],
        },
        Data::Status {
            mailbox: Mailbox::Inbox,
            attributes: vec![
                StatusAttributeValue::Messages(718_001),
                StatusAttributeValue::Recent(718_002),
                StatusAttributeValue::UidNext(718_003.try_into().unwrap()),
                StatusAttributeValue::Unseen(718_004),
                StatusAttributeValue::UidValidity(718_005.try_into().unwrap()),
            ],
        },
        Data::Search(
            (1..=20)
                .into_iter()
                .map(|num| NonZeroU32::try_from(num).unwrap())
                .collect::<Vec<_>>(),
        ),
        Data::Flags(vec![Flag::Flagged]),
        Data::Exists(54321),
        Data::Recent(12345),
        Data::Expunge(1.try_into().unwrap()),
        Data::Fetch {
            seq_or_uid: 1.try_into().unwrap(),
            attributes: vec![MessageAttribute::BodyExt {
                data: NString(Some(IString::Quoted(
                    // Good and bad: Can't create invalid Quoted anymore!
                    // Quoted::try_from(
                    //     "From: Injected\r\n\r\nInjected\r\n"
                    // ).unwrap(),
                    Quoted::try_from("Huch ...").unwrap(),
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
