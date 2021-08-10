use std::path::Path;

use anyhow::Context;
use ron::from_str;
use serde::Deserialize;

use crate::Filter;

pub fn read_ron_config<P: AsRef<Path>, T>(path: P) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let data = std::fs::read_to_string(path)?;
    let config = from_str(&data).context("Error parsing file")?;
    Ok(config)
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub smtp: String,
    pub pop3: String,
    pub imap: String,
    #[serde(default = "default_filter")]
    pub filter: Filter,
    #[serde(default = "default_script")]
    pub script: Option<String>,
}

fn default_filter() -> Filter {
    Filter::Reject(vec![])
}

fn default_script() -> Option<String> {
    None
}
