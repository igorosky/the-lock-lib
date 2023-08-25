// extern crate serde_json;
// extern crate libaes;
// extern crate rsa;
// extern crate chacha20poly1305;
// extern crate sha2;
// extern crate rand;
// extern crate argon2;

use std::borrow::BorrowMut;
use std::{fs::File, fmt::Display};
use std::io::Read;
use std::io::prelude::Write;
use std::path::Path;
use rsa::{RsaPublicKey, Oaep, RsaPrivateKey, Pss};
use sha2::Sha512;
use signers_list::SignersList;
use zip::{ZipArchive, ZipWriter, write::FileOptions};
use rand::rngs::OsRng;

mod symmertic_cipher;
mod directory_content;
mod signers_list;
pub mod rsa_private_key_serializer;

use directory_content::DirectoryContent;
use symmertic_cipher::{SymmetricCipher, SymmetricKey};

const FILE_CONETENT_NAME: &str = "file";
const FILE_KEY_NAME: &str = "key";
const FILE_SIGNATURE_NAME: &str = "signature";

type SResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum EncryptedFileError {
    FileAlreadyExists,
    InvalidSignatureFile,
    FileDoesNotExist,
    FileIsNotSigned,
    FileKeyIsMissing,
    FileContentIsMissing,
}

impl Display for EncryptedFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            EncryptedFileError::FileAlreadyExists => "FileAlreadyExists",
            EncryptedFileError::InvalidSignatureFile => "InvalidSignatureFile",
            EncryptedFileError::FileDoesNotExist => "FileDoesNotExist",
            EncryptedFileError::FileIsNotSigned => "FileIsNotSigned",
            EncryptedFileError::FileKeyIsMissing => "FileKeyIsMissing",
            EncryptedFileError::FileContentIsMissing => "FileContentIsMissing",
        })
    }
}

impl std::error::Error for EncryptedFileError { }

pub struct EncryptedFile {
    file: File,
    directory_content: Option<DirectoryContent>,
    symmetric_cipher: SymmetricCipher,
}

impl EncryptedFile {
    pub fn new<P: AsRef<Path>>(path: P) -> SResult<Self> {
        let path = path.as_ref();
        if !path.exists() {
            let file = File::create(path)?;
            ZipWriter::new(file);
        }
        Ok(Self { file: File::options().read(true).write(true).open(path)?, directory_content: None, symmetric_cipher: SymmetricCipher::default() })
    }

    pub fn change_buffor_size(&mut self, buffor_size: usize) {
        self.symmetric_cipher.change_buffor_size(buffor_size);
    }

    pub fn buffor_size(&self) -> usize {
        self.symmetric_cipher.buffor_size()
    }

    pub fn get_directory_content_soft(&self) -> Option<&DirectoryContent> {
        self.directory_content.as_ref()
    }

    pub fn get_directory_content(&mut self) -> SResult<&DirectoryContent> {
        match self.directory_content.is_some() {
            true => Ok(self.get_directory_content_soft().unwrap()),
            false => self.get_directory_content_hard(),
        }
    }

    #[inline]
    fn without_suffix<'a>(str: &'a str, suffix: &str) -> Option<&'a str> {
        if str.len() < suffix.len() {
            return None;
        }
        match str.get((str.len() - suffix.len())..).unwrap() == suffix {
            true => str.get(..(str.len() - suffix.len())),
            false => None,
        }
    }

    pub fn get_directory_content_hard(&mut self) -> SResult<&DirectoryContent> {
        let archive = ZipArchive::new(&self.file)?;
        let mut ans = DirectoryContent::new();
        for name in archive.file_names() {
            if let Some(rest) = Self::without_suffix(name, FILE_CONETENT_NAME) {
                ans.get_or_create_file_mut(rest)?.content(true);
            }
            else if let Some(rest) = Self::without_suffix(name, FILE_KEY_NAME) {
                ans.get_or_create_file_mut(rest)?.key(true);
            }
            else if let Some(rest) = Self::without_suffix(name, FILE_SIGNATURE_NAME) {
                ans.get_or_create_file_mut(rest)?.signed(true);
            }
        }
        self.directory_content = Some(ans);
        Ok(self.directory_content.as_ref().unwrap())
    }

    fn sign_file(&self, dst_path: &str, file_hash: &[u8; 64], private_key: &RsaPrivateKey) -> SResult<()> {
        let mut zip = ZipWriter::new_append(&self.file)?;
        zip.start_file(format!("content/{}/{}", dst_path, FILE_SIGNATURE_NAME), FileOptions::default())?;
        zip.write(&private_key.sign_with_rng(&mut OsRng, Pss::new::<Sha512>(), file_hash)?)?;
        Ok(())
    }

    fn verify_signature(&self, src_path: &str, file_hash: &[u8; 64], public_key: &RsaPublicKey) -> SResult<()> {
        let mut zip = ZipArchive::new(&self.file)?;
        let mut buf = Vec::new();
        // todo!("Check size");
        zip.by_name(&format!("{}/{}", src_path, FILE_SIGNATURE_NAME))?.read_to_end(&mut buf)?;
        if buf.len() != 64 {
            return Err(EncryptedFileError::InvalidSignatureFile.into());
        }
        public_key.verify(Pss::new::<Sha512>(), file_hash, &buf)?;
        Ok(())
    }

    fn add_file_digest<I: Read>(&self, src: I, dst_path: &str, public_key: &RsaPublicKey) -> SResult<Box<[u8; 64]>> {
        let dst = format!("content/{}", dst_path);
        let key = SymmetricKey::new();
        let mut zip = ZipWriter::new_append(&self.file)?;
        zip.start_file(format!("{}/{}", dst, FILE_CONETENT_NAME), FileOptions::default())?;
        let dig = self.symmetric_cipher.encrypt_file(&key, b"uno dos", src, &mut zip)?;
        let key_bytes: [u8; 51] = key.into();
        let encrypted_key = public_key.encrypt(&mut OsRng, Oaep::new::<sha2::Sha256>(), &key_bytes)?;
        zip.start_file(format!("{}/{}", dst, FILE_KEY_NAME), FileOptions::default())?;
        zip.write_all(&encrypted_key)?;
        Ok(dig)
    }

    fn decrypt_file_digest<O: Write>(&self, src: &str, mut dst: O, private_key: &RsaPrivateKey) -> SResult<Box<[u8; 64]>> {
        let mut zip = ZipArchive::new(&self.file)?;
        let key = {
            let mut zipfile = zip.by_name(format!("content/{}/{}", src, FILE_KEY_NAME).as_str())?;
            let mut buf: Vec<u8> = Vec::new();
            // todo!("Check size");
            zipfile.read_to_end(&mut buf)?;
            SymmetricKey::try_from(private_key.decrypt(Oaep::new::<sha2::Sha256>(), &buf)?)?
        };
        let ans = self.symmetric_cipher.decrypt_file(&key, b"uno dos", &mut zip.by_name(format!("content/{}/{}", src, FILE_CONETENT_NAME).as_str())?, &mut dst)?;
        Ok(ans)
    }

    pub fn add_file<I: Read>(&mut self, src: I, dst_path: &str, public_key: &RsaPublicKey) -> SResult<()> {
        if self.get_directory_content().unwrap().get_file(dst_path).is_some() {
            return Err(EncryptedFileError::FileAlreadyExists.into());
        }
        self.add_file_digest(src, dst_path, public_key)?;
        self.directory_content.as_mut().unwrap().borrow_mut().add_file_with_path(dst_path)?.content(true).key(true);
        Ok(())
    }
    
    pub fn add_file_and_sign<I: Read>(&mut self, src: I, dst_path: &str, public_key: &RsaPublicKey, private_key: &RsaPrivateKey) -> SResult<()> {
        if self.get_directory_content().unwrap().get_file(dst_path).is_some() {
            return Err(EncryptedFileError::FileAlreadyExists.into());
        }
        self.sign_file(dst_path, self.add_file_digest(src, dst_path, public_key)?.as_ref(), private_key)?;
        self.directory_content.as_mut().unwrap().borrow_mut().add_file_with_path(dst_path)?.content(true).key(true).signed(true);
        Ok(())
    }

    pub fn decrypt_file<O: Write>(&mut self, src: &str, dst: O, private_key: &RsaPrivateKey) -> SResult<()> {
        let file = self.get_directory_content()?.get_file(src).ok_or(EncryptedFileError::FileDoesNotExist)?;
        if !file.has_content() {
            Err(EncryptedFileError::FileContentIsMissing.into())
        }
        else if !file.has_key() {
            Err(EncryptedFileError::FileKeyIsMissing.into())
        }
        else {
            self.decrypt_file_digest(src, dst, private_key)?;
            Ok(())
        }
    }

    pub fn decrypt_file_and_verify<O: Write>(&mut self, src: &str, dst: O, private_key: &RsaPrivateKey, public_key: &RsaPublicKey) -> SResult<()> {
        let file = self.get_directory_content()?.get_file(src).ok_or(EncryptedFileError::FileDoesNotExist)?;
        if !file.has_content() {
            Err(EncryptedFileError::FileContentIsMissing.into())
        }
        else if !file.has_key() {
            Err(EncryptedFileError::FileKeyIsMissing.into())
        }
        else if !file.is_signed() {
            Err(EncryptedFileError::FileIsNotSigned.into())
        }
        else {
            self.verify_signature(src, self.decrypt_file_digest(src, dst, private_key)?.as_ref(), public_key)?;
            Ok(())
        }
    }

    pub fn decrypt_file_and_find_signer<O: Write>(&mut self, src: &str, dst: O, private_key: &RsaPrivateKey, signers_list: &SignersList) -> SResult<Option<String>> {
        let file = self.get_directory_content()?.get_file(src).ok_or(EncryptedFileError::FileDoesNotExist)?;
        if !file.has_content() {
            Err(EncryptedFileError::FileContentIsMissing.into())
        }
        else if !file.has_key() {
            Err(EncryptedFileError::FileKeyIsMissing.into())
        }
        else if !file.is_signed() {
            Err(EncryptedFileError::FileIsNotSigned.into())
        }
        else {
            let digest = self.decrypt_file_digest(src, dst, private_key)?;
            for (signer, key) in signers_list {
                if self.verify_signature(src, &digest, &key).is_ok() {
                    return Ok(Some(signer.to_owned()));
                }
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adding_file() {
        let mut ef = EncryptedFile::new(Path::new("testing/test2.zip")).expect("Creating new EncryptedFile");
        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        ef.add_file(File::open(Path::new("testing/testfile.txt")).unwrap(), "test/testfile.txt", &key.to_public_key()).unwrap();
    }

    #[test]
    fn adding_file_and_decrypting() {
        let mut ef = EncryptedFile::new(Path::new("testing/test4.zip")).expect("Creating new EncryptedFile");
        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        ef.add_file(File::open(Path::new("testing/testfile.txt")).unwrap(), "test/testfile.txt", &key.to_public_key()).unwrap();
        ef.decrypt_file("test/testfile.txt", File::create(Path::new("testing/decrypted.txt")).unwrap(), &key).unwrap();
    }

    #[test]
    fn get_directory_content() {
        let mut ef = EncryptedFile::new(Path::new("testing/test4.zip")).expect("Creating new EncryptedFile");
        println!("{:?}", ef.get_directory_content().unwrap());
    }
}
