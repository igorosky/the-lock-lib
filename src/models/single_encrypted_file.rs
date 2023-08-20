use serde::{Serialize, Deserialize};

use super::signable::Signable;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleEncryptedFile {
    name: String,
    is_signed: bool,
}

impl Signable for SingleEncryptedFile {
    fn is_signed(&self) -> bool {
        self.is_signed
    }

    fn signed(&mut self) -> &mut bool {
        &mut self.is_signed
    }
}

impl SingleEncryptedFile {
    pub fn new(name: &str) -> Self {
        Self { name: name.to_owned(), is_signed: false }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }
}
