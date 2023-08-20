use serde::{Serialize, Deserialize};

use super::{signable::Signable, single_encrypted_file::SingleEncryptedFile};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    name: String,
    is_signed: bool,
    encrypted_files: Vec<SingleEncryptedFile>,
}

impl Signable for Manifest {
    fn signed(&mut self) -> &mut bool {
        &mut self.is_signed
    }
    
    fn is_signed(&self) -> bool {
        self.is_signed
    }
}

impl Manifest {
    pub fn new(name: &str) -> Self {
        Self { name: name.to_string(), is_signed: false, encrypted_files: Vec::new() }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_encrypted_files(&self) -> &Vec<SingleEncryptedFile> {
        &self.encrypted_files
    }

    pub fn get_encrypted_files_mut(&mut self) -> &mut Vec<SingleEncryptedFile> {
        &mut self.encrypted_files
    }
}
