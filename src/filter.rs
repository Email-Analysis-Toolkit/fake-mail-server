use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub enum Filter {
    Accept(Vec<String>),
    Reject(Vec<String>),
}

impl Filter {
    pub fn accepts(&self, peer: &str) -> bool {
        match self {
            Filter::Accept(ref ips) => ips.iter().any(|item| peer.contains(item)),
            Filter::Reject(ref ips) => ips.iter().all(|item| !peer.contains(item)),
        }
    }

    pub fn rejects(&self, peer: &str) -> bool {
        !self.accepts(peer)
    }
}
