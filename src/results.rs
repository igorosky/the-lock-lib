use core::fmt;
use std::error::{self};


#[derive(Debug, Clone)]
pub struct JustError {
    error_msg: String,
}

impl fmt::Display for JustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.error_msg)
    }
}

impl error::Error for JustError { }

impl JustError {
    pub fn new(msg: String) -> Self {
        Self { error_msg: msg }
    }
}

pub type SResult<T> = Result<T, Box<dyn error::Error>>;