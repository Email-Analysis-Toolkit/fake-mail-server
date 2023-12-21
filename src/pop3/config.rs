use std::collections::HashMap;

use serde::Deserialize;

use crate::Cert;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub greeting: String,
    pub capa: Vec<String>,
    pub capa_auth: Vec<String>,
    pub capa_tls: Vec<String>,
    pub capa_tls_auth: Vec<String>,
    #[serde(default = "default_stls_response")]
    pub stls_response: String,
    #[serde(default = "default_stls_make_transition")]
    pub stls_make_transition: bool,
    #[serde(default = "default_hide_commands")]
    pub hide_commands: Vec<String>,
    #[serde(default = "default_ignore_commands_tls")]
    pub ignore_commands_tls: Vec<String>,
    pub implicit_tls: bool,
    pub cert: Cert,
    #[serde(default = "default_override_response")]
    pub override_response: HashMap<String, String>,
    pub recv_timeout: Option<u64>,
}

fn default_stls_response() -> String {
    String::from("+OK Begin fake TLS negotiation now.\r\n")
}

fn default_stls_make_transition() -> bool {
    true
}

fn default_hide_commands() -> Vec<String> {
    vec![]
}

fn default_ignore_commands_tls() -> Vec<String> {
    vec![]
}

fn default_override_response() -> HashMap<String, String> {
    HashMap::new()
}
