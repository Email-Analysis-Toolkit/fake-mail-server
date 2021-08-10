use std::collections::HashMap;

use serde::Deserialize;
use smtp_codec::types::Capability;

use crate::PKCS12;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_greeting")]
    pub greeting: String,
    pub capabilities: Vec<Capability>,
    pub capabilities_tls: Vec<Capability>,
    #[serde(default = "default_stls_response")]
    pub stls_response: String,
    #[serde(default = "default_stls_make_transition")]
    pub stls_make_transition: bool,
    #[serde(default = "default_ignore_commands_tls")]
    pub ignore_commands_tls: Vec<String>,
    #[serde(default = "default_hide_commands")]
    pub hide_commands: Vec<String>,
    pub implicit_tls: bool,
    pub pkcs12: PKCS12,
    #[serde(default = "default_override_response")]
    pub override_response: HashMap<String, String>,
}

fn default_stls_response() -> String {
    String::from("220 Ready to start TLS\r\n")
}

fn default_greeting() -> String {
    String::from("220 smtp.example.com ESMTP fake\r\n")
}

fn default_stls_make_transition() -> bool {
    true
}

fn default_ignore_commands_tls() -> Vec<String> {
    vec![]
}

fn default_hide_commands() -> Vec<String> {
    vec![]
}

fn default_override_response() -> HashMap<String, String> {
    HashMap::new()
}
