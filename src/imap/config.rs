use std::collections::HashMap;

use imap_codec::{
    state::State,
    types::response::{Capability, Status},
};
use serde::{Deserialize, Serialize};

use crate::PKCS12;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub state: State,
    #[serde(default = "default_greeting")]
    pub greeting: Status,
    #[serde(default = "default_response_after_greeting")]
    pub response_after_greeting: Option<String>,
    pub caps: Vec<Capability>,
    pub caps_auth: Vec<Capability>,
    pub caps_tls: Vec<Capability>,
    pub caps_tls_auth: Vec<Capability>,
    #[serde(default = "default_starttls_response")]
    pub starttls_response: Option<String>,
    #[serde(default = "default_starttls_transition")]
    pub starttls_transition: bool,
    #[serde(default = "default_ignore_commands")]
    pub ignore_commands: Vec<String>,
    #[serde(default = "default_ignore_commands_tls")]
    pub ignore_commands_tls: Vec<String>,
    #[serde(default = "default_hide_commands")]
    pub hide_commands: Vec<String>,
    #[serde(default = "default_response_after_tls")]
    pub response_after_tls: Option<String>,
    #[serde(default = "default_workaround")]
    pub workaround: Vec<String>,
    #[serde(default = "default_override_select")]
    pub override_select: Option<Status>,
    #[serde(default = "default_override_login")]
    pub override_login: Option<Status>,
    #[serde(default = "default_override_authenticate")]
    pub override_authenticate: Option<Status>,
    #[serde(default = "default_folders")]
    pub folders: Vec<String>,
    #[serde(default = "default_override_response")]
    pub override_response: HashMap<String, String>,
    pub pkcs12: PKCS12,
    pub implicit_tls: bool,
}

fn default_greeting() -> Status {
    Status::ok(None, None, "Fake IMAP server ready.").unwrap()
}

fn default_response_after_greeting() -> Option<String> {
    None
}

fn default_starttls_response() -> Option<String> {
    None
}

fn default_starttls_transition() -> bool {
    true
}

fn default_ignore_commands() -> Vec<String> {
    vec![]
}

fn default_ignore_commands_tls() -> Vec<String> {
    vec![]
}

fn default_hide_commands() -> Vec<String> {
    vec![]
}

fn default_response_after_tls() -> Option<String> {
    None
}

fn default_workaround() -> Vec<String> {
    vec![]
}

fn default_override_select() -> Option<Status> {
    None
}

fn default_override_login() -> Option<Status> {
    None
}

fn default_override_authenticate() -> Option<Status> {
    None
}

fn default_folders() -> Vec<String> {
    ["INBOX", "Sent", "sent", "Trash", "Drafts"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn default_override_response() -> HashMap<String, String> {
    HashMap::new()
}
