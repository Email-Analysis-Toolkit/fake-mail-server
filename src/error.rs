use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

#[derive(Debug)]
pub struct StringError {
    inner: String,
}

impl StringError {
    pub fn new<S: Into<String>>(msg: S) -> StringError {
        StringError { inner: msg.into() }
    }
}

impl Display for StringError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.inner)
    }
}

impl Error for StringError {}
