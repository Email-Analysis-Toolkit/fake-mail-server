use std::{
    collections::HashMap,
    convert::TryFrom,
    fs::{create_dir_all, File},
    io::Write,
};

use fake_mail_server::{imap::config as ImapConfig, PKCS12};
use imap_codec::types::{
    codec::Encode,
    core::{NonEmptyVec, Tag},
    response::{Capability, Code, Status},
    state::State,
    AuthMechanism,
};
use itertools::Itertools;
use ron::ser::{to_string_pretty, PrettyConfig};

enum GroupedCaps {
    Capability(Capability<'static>),
    AuthGroup,
}

fn combos<'a, T>(vector: &'a Vec<T>) -> impl Iterator<Item = Vec<&T>> + 'a {
    let length = vector.len();
    (1..=length).flat_map(move |len| vector.iter().combinations(len))
}

fn encode_stuff<T: Encode>(obj: T) -> String {
    let mut out = Vec::with_capacity(256);
    obj.encode(&mut out).expect("Could not encode!");
    String::from_utf8(out).unwrap()
}

fn generate_responses() -> HashMap<String, String> {
    let mut responses = HashMap::new();
    responses.insert(
        "OK".to_string(),
        encode_stuff(Status::ok(Some(Tag::try_from("<tag>").unwrap()), None, "Proceed!").unwrap()),
    );
    responses.insert(
        "NO".to_string(),
        encode_stuff(
            Status::no(
                Some(Tag::try_from("<tag>").unwrap()),
                None,
                "Don't proceed!",
            )
            .unwrap(),
        ),
    );
    responses.insert(
        "BAD".to_string(),
        encode_stuff(
            Status::bad(
                Some(Tag::try_from("<tag>").unwrap()),
                None,
                "Don't proceed now!",
            )
            .unwrap(),
        ),
    );
    responses
}

fn ok_greeting_caps() {
    let caps: Vec<GroupedCaps> = vec![
        GroupedCaps::Capability(Capability::Imap4Rev1),
        GroupedCaps::AuthGroup,
        GroupedCaps::Capability(Capability::StartTls),
        GroupedCaps::Capability(Capability::LoginDisabled),
        /*Capability::SaslIr,
        Capability::LoginReferrals,
        Capability::MailboxReferrals,
        Capability::Enable,
        Capability::Idle, //Authenticated/Selected only
        */
    ];
    // bundle auth + saslir
    //
    for cap_combo in combos(&caps) {
        let mut cap_str = String::new();
        let mut cap_vec: Vec<&Capability> = Vec::new();
        for cap in &cap_combo {
            match cap {
                GroupedCaps::Capability(cap) => {
                    cap_str.push_str("_");
                    let tmp = {
                        let mut out = Vec::new();
                        cap.encode(&mut out).unwrap();
                        String::from_utf8(out).unwrap()
                    };
                    cap_str.push_str(&tmp);
                    cap_vec.push(cap);
                }
                GroupedCaps::AuthGroup => {
                    cap_vec.push(&Capability::Auth(AuthMechanism::Plain));
                    cap_vec.push(&Capability::Auth(AuthMechanism::Login));
                    cap_str.push_str("_AUTH");
                }
            }
        }
        let greeting = Status::ok(None, None, "Fake IMAP server ready").unwrap();
        let mut overrides = HashMap::new();
        overrides.insert("create".to_string(), "<tag> OK created\r\n".to_string());

        overrides.insert(
            "select".to_string(),
            format!(
                "* FLAGS (\\Seen \\Draft)\r\n* 0 EXISTS\r\n* 0 RECENT\r\n<tag> OK selected\r\n"
            ),
        );
        let config = ImapConfig::Config {
            state: State::NotAuthenticated,
            greeting,
            response_after_greeting: None,
            caps: cap_vec.into_iter().map(|f| f.to_owned()).collect(),
            caps_auth: vec![],
            caps_tls: vec![],
            caps_tls_auth: vec![],
            starttls_response: None,
            starttls_transition: false,
            ignore_commands: vec![],
            ignore_commands_tls: vec![],
            hide_commands: vec![],
            response_after_tls: None,
            workaround: vec![],
            override_select: None,
            override_login: None,
            override_authenticate: None,
            folders: vec![],
            override_response: overrides,
            pkcs12: PKCS12 {
                file: "certs/example.org.p12".to_string(),
                password: "changeit".to_string(),
            },
            implicit_tls: false,
        };
        let path = format!(
            "generated_tests/imap/capability/greeting_ok_capability_{}.ron",
            cap_str
        );
        write_config(config, path);
    }
}

fn greetings() {
    let mut greetings: HashMap<&str, Status> = HashMap::new();
    greetings.insert(
        "ok",
        Status::ok(None, None, "Fake IMAP server ready").unwrap(),
    );
    greetings.insert("bad", Status::bad(None, None, "This is bad").unwrap());
    greetings.insert(
        "no",
        Status::no(None, None, "Fake IMAP server not ready").unwrap(),
    );
    greetings.insert(
        "preauth",
        Status::preauth(None, "Welcome pre-authed user").unwrap(),
    );
    greetings.insert("bye", Status::bye(None, "Please leave").unwrap());
    for (name, greeting) in greetings {
        let config = ImapConfig::Config {
            state: State::NotAuthenticated,
            greeting,
            response_after_greeting: None,
            caps: vec![
                Capability::Imap4Rev1,
                Capability::StartTls,
                Capability::Auth(AuthMechanism::Login),
                Capability::Auth(AuthMechanism::Plain),
            ],
            caps_auth: vec![],
            caps_tls: vec![],
            caps_tls_auth: vec![],
            starttls_response: None,
            starttls_transition: false,
            ignore_commands: vec![],
            ignore_commands_tls: vec![],
            hide_commands: vec![],
            response_after_tls: None,
            workaround: vec![],
            override_select: None,
            override_login: None,
            override_authenticate: None,
            folders: vec![],
            override_response: Default::default(),
            pkcs12: PKCS12 {
                file: "certs/example.org.p12".to_string(),
                password: "changeit".to_string(),
            },
            implicit_tls: false,
        };
        let path = format!("generated_tests/imap/greeting/{}.ron", name);
        write_config(config, path);
    }
}

fn ok_greeting_codes() {
    let mut codes = HashMap::new();
    codes.insert("ALERT".to_string(), Code::Alert);
    let caps: Vec<GroupedCaps> = vec![
        GroupedCaps::Capability(Capability::Imap4Rev1),
        GroupedCaps::AuthGroup,
        GroupedCaps::Capability(Capability::StartTls),
        GroupedCaps::Capability(Capability::LoginDisabled),
    ];
    for cap_combo in combos(&caps) {
        let mut cap_str = String::new();
        cap_str.push_str("CAPABILITY");
        let mut cap_vec: Vec<Capability> = Vec::new();
        for cap in &cap_combo {
            match cap {
                GroupedCaps::Capability(cap) => {
                    cap_str.push_str("_");
                    let tmp = {
                        let mut out = Vec::new();
                        cap.encode(&mut out).unwrap();
                        String::from_utf8(out).unwrap()
                    };
                    cap_str.push_str(&tmp);
                    cap_vec.push(cap.clone());
                }
                GroupedCaps::AuthGroup => {
                    cap_vec.push(Capability::Auth(AuthMechanism::Plain));
                    cap_vec.push(Capability::Auth(AuthMechanism::Login));
                    cap_str.push_str("_AUTH");
                }
            }
        }

        let cap_vec = NonEmptyVec::try_from(cap_vec).unwrap();

        codes.insert(cap_str.to_string(), Code::Capability(cap_vec));
    }
    codes.insert(
        "CAPABILITY_STARTTLS".to_string(),
        Code::capability(vec![Capability::Imap4Rev1, Capability::StartTls]).unwrap(),
    );
    for (name, code) in codes {
        let greeting = Status::ok(None, Some(code), "Fake Mail server ready").unwrap();
        let mut overrides = HashMap::new();
        overrides.insert("create".to_string(), "<tag> OK created\r\n".to_string());
        overrides.insert(
            "select".to_string(),
            format!(
                "* FLAGS (\\Seen \\Draft)\r\n* 0 EXISTS\r\n* 0 RECENT\r\n<tag> OK selected\r\n"
            ),
        );
        let config = ImapConfig::Config {
            state: State::NotAuthenticated,
            greeting,
            response_after_greeting: None,
            caps: vec![
                Capability::Imap4Rev1,
                Capability::Auth(AuthMechanism::Login),
                Capability::Auth(AuthMechanism::Plain),
            ],
            caps_auth: vec![],
            caps_tls: vec![],
            caps_tls_auth: vec![],
            starttls_response: None,
            starttls_transition: false,
            ignore_commands: vec![],
            ignore_commands_tls: vec![],
            hide_commands: vec![],
            response_after_tls: None,
            workaround: vec![],
            override_select: None,
            override_login: None,
            override_authenticate: None,
            folders: vec![],
            override_response: overrides,
            pkcs12: PKCS12 {
                file: "certs/example.org.p12".to_string(),
                password: "changeit".to_string(),
            },
            implicit_tls: false,
        };
        let path = format!("generated_tests/imap/greeting/ok_{}.ron", name);
        write_config(config, path);
    }
}

fn starttls() {
    let responses = generate_responses();
    for (name, response) in responses {
        let mut overrides = HashMap::new();
        overrides.insert("starttls".to_string(), response);
        let config = ImapConfig::Config {
            state: State::NotAuthenticated,
            greeting: Status::ok(None, None, "Fake mail server ready!").unwrap(),
            response_after_greeting: None,
            caps: vec![
                Capability::Imap4Rev1,
                Capability::StartTls,
                Capability::Auth(AuthMechanism::Login),
                Capability::Auth(AuthMechanism::Plain),
            ],
            caps_auth: vec![],
            caps_tls: vec![],
            caps_tls_auth: vec![],
            starttls_response: None,
            starttls_transition: false,
            ignore_commands: vec![],
            ignore_commands_tls: vec![],
            hide_commands: vec![],
            response_after_tls: None,
            workaround: vec![],
            override_select: None,
            override_login: None,
            override_authenticate: None,
            folders: vec![],
            override_response: overrides,
            pkcs12: PKCS12 {
                file: "certs/example.org.p12".to_string(),
                password: "changeit".to_string(),
            },
            implicit_tls: false,
        };
        let path = format!("generated_tests/imap/starttls/{}.ron", name);
        write_config(config, path);
    }
}

#[test]
fn create() {
    create_dir_all("generated_tests/imap/greeting").expect("Error creating directory!");
    greetings();
    ok_greeting_codes();
    create_dir_all("generated_tests/imap/capability").expect("Error creating directory!");
    ok_greeting_caps();
    create_dir_all("generated_tests/imap/starttls").expect("Error creating directory!");
    starttls();
}

fn write_config(config: ImapConfig::Config, file_path: String) {
    let pretty = PrettyConfig::new();
    let s = to_string_pretty(&config, pretty).expect("Serialization failed!");
    let mut pos = 0;
    let mut buffer = File::create(file_path).unwrap();
    while pos < s.len() {
        let bytes_written = buffer.write(&s.as_bytes()[pos..]).unwrap();
        pos += bytes_written;
    }
}
