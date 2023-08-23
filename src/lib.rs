// extern crate tempdir;
extern crate serde_json;
extern crate libaes;
extern crate rsa;
extern crate chacha20poly1305;
extern crate sha2;
extern crate rand;
extern crate argon2;

use std::fs::File;
use std::io::Read;
use std::io::prelude::Write;
use std::path::Path;
use models::{symmetric_key::SymmetricKey, directory_content::DirectoryContent};
use rsa::{RsaPublicKey, Oaep, RsaPrivateKey};
use symmertic_cipher::SymmetricCipher;
// use tempdir::TempDir;
use zip::{ZipArchive, ZipWriter, write::FileOptions};
use rand::rngs::OsRng;

mod manifest_models;
mod symmertic_cipher;
mod results;
mod models;
pub mod rsa_private_key_serializer;

use results::{SResult, JustError};

const FILE_CONETENT_NAME: &str = "file";
const FILE_KEY_NAME: &str = "key";
const FILE_SIGNATURE_NAME: &str = "signature";

pub struct EncryptedFile {
    file: File,
    directory_content: Option<DirectoryContent>,
    // tmp_dir: TempDir,
    // manifest: Option<Box<Manifest>>,
}

impl EncryptedFile {
    pub fn new<P: AsRef<Path>>(path: P) -> SResult<Self> {
        let path = path.as_ref();
        // let mut manifest_opt = None;
        if !path.exists() {
            let file = File::create(path)?;
            ZipWriter::new(file);
            // let mut zip = ZipWriter::new(file);
            // zip.add_directory("content", FileOptions::default())?;
            // let manifest = Box::new(Manifest::new(path.file_name().unwrap().to_str().unwrap()));
            // zip.start_file("manifest", FileOptions::default())?;
            // zip.write(serde_json::to_string(&manifest)?.as_bytes())?;
            // manifest_opt = Some(manifest);
        }
        // let tmp_dir = TempDir::new("theLock")?;
        Ok(Self { file: File::options().read(true).write(true).open(path)?, directory_content: None, /*tmp_dir, manifest: manifest_opt*/ })
    }

    pub fn get_directory_content_soft(&self) -> Option<&DirectoryContent> {
        self.directory_content.as_ref()
    }

    pub fn get_directory_content(&mut self) -> SResult<&DirectoryContent> {
        match self.directory_content.is_some() {
            true => self.get_directory_content_soft().ok_or(Box::new(JustError::new("msg".to_owned()))),
            false => self.get_directory_content_hard(),
        }
    }

    #[inline]
    fn without_suffix<'a>(str: &'a str, suffix: &str) -> Option<&'a str> {
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
        self.directory_content.as_ref().ok_or(Box::new(JustError::new("msg".to_owned())))
    }

    /*fn push_manifest(&self) -> SResult<()> {
        let mut zip = ZipWriter::new_append(&self.file)?;
        // zip.start_file("manifest", FileOptions::default())?;
        zip.start_file_aligned("manifest", FileOptions::default(), 0)?;
        zip.write(&serde_json::to_vec(self.manifest.as_ref().unwrap())?)?;
        Ok(())
    }

    pub fn get_cached_manifest(&self) -> Option<&Box<Manifest>> {
        if let Some(ans) = self.manifest.as_ref() {
            return Some(ans);
        }
        None
    }

    pub fn get_manifest(&mut self) -> SResult<&Box<Manifest>> {
        match self.manifest.is_some() {
            true => Ok(self.manifest.as_ref().unwrap()),
            false => self.get_manifest_force()
        }
    }

    pub fn get_manifest_force(&mut self) -> SResult<&Box<Manifest>> {
        let mut zip = ZipArchive::new(&self.file)?;
        let mut manifest_zip_file = zip.by_name("manifest")?;
        if manifest_zip_file.is_dir() {
            return Err(Box::new(JustError::new("Not a file".to_owned())));
        }
        let mut buffor = Vec::new();
        // todo!("check manifest size to not blow up app");
        manifest_zip_file.read_to_end(&mut buffor)?;
        let s: String = buffor.into_iter().map(|b| b as char).collect();
        self.manifest = Some(Box::new(serde_json::from_str(&s[..]).unwrap()));
        Ok(self.manifest.as_ref().unwrap())
    }*/

    pub fn add_file<I: Read>(&mut self, src: I, dst_path: &str, public_key: &RsaPublicKey) -> SResult<()> {
        let dst = format!("content/{}", dst_path);
        let symmertic_cipher = SymmetricCipher::new();
        let key = SymmetricKey::new();
        {
            let mut zip = ZipWriter::new_append(&self.file)?;
            zip.start_file(format!("{}/{}", dst, FILE_CONETENT_NAME), FileOptions::default())?;
            symmertic_cipher.encrypt_file(&key, b"uno dos", src, &mut zip)?;
            let key_bytes: [u8; 51] = key.into();
            let encrypted_key = public_key.encrypt(&mut OsRng, Oaep::new::<sha2::Sha256>(), &key_bytes)?;
            zip.start_file(format!("{}/{}", dst, FILE_KEY_NAME), FileOptions::default())?;
            zip.write_all(&encrypted_key)?;
        }
        // self.get_manifest()?;
        // self.manifest.as_mut().unwrap().get_encrypted_files_mut().push(SingleEncryptedFile::new(&dst));
        // self.push_manifest()?;
        Ok(())
    }

    pub fn decrypt_file<O: Write>(&mut self, src: &str, mut dst: O, private_key: &RsaPrivateKey) -> SResult<()> {
        let mut zip = ZipArchive::new(&self.file)?;
        let key = {
            let mut zipfile = zip.by_name(format!("content/{}/{}", src, FILE_KEY_NAME).as_str())?;
            let mut buf: Vec<u8> = Vec::new();
            zipfile.read_to_end(&mut buf)?;
            SymmetricKey::from(private_key.decrypt(Oaep::new::<sha2::Sha256>(), &buf)?)
        };
        let symmertic_cipher = SymmetricCipher::new();
        symmertic_cipher.decrypt_file(&key, b"uno dos", &mut zip.by_name(format!("content/{}/{}", src, FILE_CONETENT_NAME).as_str())?, &mut dst)?;
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adding_file() {
        let mut ef = EncryptedFile::new(Path::new("testing/test2.zip")).expect("Creating new EncryptedFile");
        // println!("{:?}", ef.get_manifest().unwrap());
        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        ef.add_file(File::open(Path::new("testing/testfile.txt")).unwrap(), "test/testfile.txt", &key.to_public_key()).unwrap();
    }

    #[test]
    fn adding_file_and_decrypting() {
        let mut ef = EncryptedFile::new(Path::new("testing/test4.zip")).expect("Creating new EncryptedFile");
        // println!("{:?}", ef.get_manifest().unwrap());
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
