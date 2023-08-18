extern crate serde;

use std::{path::Path, ffi::{OsString, OsStr}};
use serde::{Serialize, Deserialize};

pub trait Signable {
    fn is_signed(&self) -> bool;
    fn signed<P: AsRef<Path>>(&mut self, signature: P);
    fn get_signature_path(&self) -> Option<&Path>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    name: String,
    is_manifest_signed: bool,
    manifest_signature_file: Option<Box<Path>>,
    encrypted_files: Vec<SingleEncryptedFile>,
}

impl Signable for Manifest {
    fn signed<P: AsRef<Path>>(&mut self, signature: P) {
        self.is_manifest_signed = true;
        self.manifest_signature_file = Some(Box::from(signature.as_ref().to_owned()));
    }
    
    fn is_signed(&self) -> bool {
        self.is_manifest_signed
    }
    
    fn get_signature_path(&self) -> Option<&Path> {
        self.manifest_signature_file.as_deref()
    }
}

impl Manifest {
    pub fn new(name: &str) -> Self {
        Self { name: name.to_string(), is_manifest_signed: false, manifest_signature_file: None, encrypted_files: Vec::new() }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_manifest_signature_file(&self) -> Option<&Box<Path>> {
        self.manifest_signature_file.as_ref()
    }

    pub fn get_encrypted_files(&self) -> &Vec<SingleEncryptedFile> {
        &self.encrypted_files
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleEncryptedFile {
    name: OsString,
    file_pieces: Vec<SingleEncryptedFilePiece>,
}

impl SingleEncryptedFile {
    pub fn new(name: OsString, file_pieces: Vec<SingleEncryptedFilePiece>) -> Self {
        Self { name: name, file_pieces: file_pieces }
    }

    pub fn get_name(&self) -> &OsStr {
        &self.name
    }

    pub fn get_file_pieces(&self) -> &Vec<SingleEncryptedFilePiece> {
        &self.file_pieces
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleEncryptedFilePiece {
    path: Box<Path>,
    signed: bool,
    signature: Option<Box<Path>>,
}

impl Signable for SingleEncryptedFilePiece {
    fn signed<P: AsRef<Path>>(&mut self, signature: P) {
        self.signed = true;
        self.signature = Some(Box::from(signature.as_ref().to_owned()));
    }

    fn is_signed(&self) -> bool {
        self.signed
    }

    fn get_signature_path(&self) -> Option<&Path> {
        self.signature.as_deref()
    }
}

impl SingleEncryptedFilePiece {
    pub fn new(path: Box<Path>) -> Self {
        Self { path: path, signed: false, signature: None }
    }

    pub fn get_path(&self) -> &Box<Path> {
        &self.path
    }
}
