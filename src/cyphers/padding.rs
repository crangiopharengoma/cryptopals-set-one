use std::error::Error;
use std::fmt::{Display, Formatter};

pub mod pkcs7;

#[derive(Debug, PartialEq)]
enum PaddingError {
    InvalidPadding(String),
}

impl Display for PaddingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Error for PaddingError {}
