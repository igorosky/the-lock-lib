#[cfg(any(feature = "serde", feature = "signers-list"))]
extern crate serde;
pub extern crate rsa;
extern crate chacha20poly1305;
extern crate sha2;
extern crate rand;

use std::borrow::BorrowMut;
use std::fs::File;
use std::io::{Read, Write, Seek};
use std::path::Path;

use asymetric_key::{PublicKey, PrivateKey};
use rsa::{RsaPublicKey, RsaPrivateKey, Pss};
use sha2::Sha512;
#[cfg(feature = "signers-list")]
use signers_list::SignersList;
use trie_rs::TrieBuilder;
use zip::{ZipArchive, ZipWriter};
use rand::rngs::OsRng;

pub use zip::write::FileOptions;

mod symmertic_cipher;
pub mod directory_content;
#[cfg(feature = "signers-list")]
pub mod signers_list;
pub mod error;
pub mod asymetric_key;

use directory_content::DirectoryContent;
use symmertic_cipher::{SymmetricCipher, SymmetricKey};
use error::{EncryptedFileError, EncryptedFileResult};

const FILE_CONETENT_DIR: &str = "content";
const FILE_CONTENT_NAME: &str = "file";
const FILE_KEY_NAME: &str = "key";
const FILE_SIGNATURE_NAME: &str = "signature";
const FILE_DIGEST_NAME: &str = "digest";

/**
 * TODO
 * checking file sizes
 */

pub struct EncryptedFile {
    file: File,
    directory_content: Option<DirectoryContent>,
    symmetric_cipher: SymmetricCipher,
    associated_data: Vec<u8>,
    file_options: FileOptions,
}

type DecyptFileResult = EncryptedFileResult<bool>;
type DecryptFileAndVerifyResult = EncryptedFileResult<(bool, EncryptedFileResult<()>)>;
#[cfg(feature = "signers-list")]
type DecryptFileAndFindSignerResult = EncryptedFileResult<(bool, Option<String>)>;

impl EncryptedFile {
    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            let file = File::create(path)?;
            ZipWriter::new(file);
        }
        Ok(Self {
            file: File::options().read(true).write(true).open(path)?,
            directory_content: None,
            symmetric_cipher: SymmetricCipher::default(),
            associated_data: b"@s3ue9lWmFBMthC%NQnes1@2!SK@drScEQV6GPr^s$v@US&N6lI$uCirVwr8@6HkqStAS%%9T#Fn5Axom%C2#3&Ss0wQQL8J&1w*QKb64Mlt!cH4DaV0v^ZFh8^oCh@Y".to_vec(),
            file_options: FileOptions::default(),
        })
    }

    pub fn zip_file_options(&self) -> &FileOptions {
        &self.file_options
    }

    pub fn set_zip_file_options(&mut self, file_options: FileOptions) {
        self.file_options = file_options
    }

    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }

    pub fn change_associated_data(&mut self, associated_data: Vec<u8>) {
        self.associated_data = associated_data;
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

    pub fn get_directory_content(&mut self) -> EncryptedFileResult<&DirectoryContent> {
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

    pub fn get_directory_content_hard(&mut self) -> EncryptedFileResult<&DirectoryContent> {
        let archive = ZipArchive::new(&self.file)?;
        let mut ans = DirectoryContent::new();
        for mut name in archive.file_names() {
            if name.len() < FILE_CONETENT_DIR.len() {
                continue;
            }
            name = name.get(FILE_CONETENT_DIR.len()..).unwrap();
            if let Some(rest) = Self::without_suffix(name, FILE_CONTENT_NAME) {
                ans.get_or_create_file_mut(rest)?.content(true);
            }
            else if let Some(rest) = Self::without_suffix(name, FILE_KEY_NAME) {
                ans.get_or_create_file_mut(rest)?.key(true);
            }
            else if let Some(rest) = Self::without_suffix(name, FILE_SIGNATURE_NAME) {
                ans.get_or_create_file_mut(rest)?.signed(true);
            }
            else if let Some(rest) = Self::without_suffix(name, FILE_DIGEST_NAME) {
                ans.get_or_create_file_mut(rest)?.digest(true);
            }
        }
        self.directory_content = Some(ans);
        Ok(self.directory_content.as_ref().unwrap())
    }

    fn sign_file(&self, dst_path: &str, file_hash: &[u8; 64], private_key: &RsaPrivateKey) -> EncryptedFileResult<()> {
        let mut zip = ZipWriter::new_append(&self.file)?;
        zip.start_file(format!("{FILE_CONETENT_DIR}/{dst_path}/{FILE_SIGNATURE_NAME}"), self.file_options)?;
        zip.write(&private_key.sign_with_rng(&mut OsRng, Pss::new::<Sha512>(), file_hash)?)?;
        Ok(())
    }

    fn verify_signature(&self, src_path: &str, file_hash: &[u8; 64], public_key: &RsaPublicKey) -> EncryptedFileResult<()> {
        let mut zip = ZipArchive::new(&self.file)?;
        let mut buf = Vec::new();
        // todo!("Check size");
        zip.by_name(&format!("{FILE_CONETENT_DIR}/{src_path}/{FILE_SIGNATURE_NAME}"))?.read_to_end(&mut buf)?;
        public_key.verify(Pss::new::<Sha512>(), file_hash, &buf)?;
        Ok(())
    }

    fn add_file_digest<I: Read>(&self, src: I, dst_path: &str, public_key: &PublicKey) -> EncryptedFileResult<Box<[u8; 64]>> {
        let dst = format!("{FILE_CONETENT_DIR}/{dst_path}");
        let key = SymmetricKey::new();
        let mut zip = ZipWriter::new_append(&self.file)?;
        zip.start_file(format!("{}/{}", dst, FILE_CONTENT_NAME), self.file_options)?;
        let dig = self.symmetric_cipher.encrypt_file(&key, self.associated_data(), src, &mut zip)?;
        let key_bytes: [u8; 51] = key.into();
        let encrypted_key = public_key.encrypt_symmetric_key(&key_bytes)?;
        zip.start_file(format!("{}/{}", dst, FILE_KEY_NAME), self.file_options)?;
        zip.write_all(&encrypted_key)?;
        zip.start_file(format!("{}/{}", dst, FILE_DIGEST_NAME), self.file_options)?;
        zip.write_all(dig.as_ref())?;
        Ok(dig)
    }

    fn decrypt_file_digest<O: Write>(&self, src: &str, mut dst: O, private_key: &PrivateKey) -> EncryptedFileResult<(Box<[u8; 64]>, bool)> {
        let mut zip = ZipArchive::new(&self.file)?;
        let key = {
            let mut zipfile = zip.by_name(format!("{FILE_CONETENT_DIR}/{src}/{FILE_KEY_NAME}").as_str())?;
            let mut buf: Vec<u8> = Vec::new();
            // todo!("Check size");
            zipfile.read_to_end(&mut buf)?;
            SymmetricKey::try_from(private_key.decrypt_symmetric_key(&buf)?)?
        };
        let ans = self.symmetric_cipher.decrypt_file(&key, self.associated_data(), &mut zip.by_name(format!("{FILE_CONETENT_DIR}/{src}/{FILE_CONTENT_NAME}").as_str())?, &mut dst)?;
        let is_digest_correct = *ans == {
            let mut zipfile = zip.by_name(format!("{FILE_CONETENT_DIR}/{src}/{FILE_DIGEST_NAME}").as_str())?;
            let mut buf = [0; 64];
            zipfile.read_exact(&mut buf)?;
            buf
        };
        Ok((
            ans,
            is_digest_correct
        ))
    }

    pub fn add_file<I: Read>(&mut self, src: I, dst_path: &str, public_key: &PublicKey) -> EncryptedFileResult<()> {
        if self.get_directory_content().unwrap().get_file(dst_path).is_some() {
            return Err(EncryptedFileError::FileAlreadyExists.into());
        }
        self.add_file_digest(src, dst_path, public_key)?;
        self.directory_content.as_mut().unwrap().borrow_mut().add_file_with_path(dst_path)?.content(true).key(true).digest(true);
        Ok(())
    }
    
    pub fn add_file_and_sign<I: Read>(&mut self, src: I, dst_path: &str, public_key: &PublicKey, private_key: &RsaPrivateKey) -> EncryptedFileResult<()> {
        if self.get_directory_content().unwrap().get_file(dst_path).is_some() {
            return Err(EncryptedFileError::FileAlreadyExists.into());
        }
        self.sign_file(dst_path, self.add_file_digest(src, dst_path, public_key)?.as_ref(), private_key)?;
        self.directory_content.as_mut().unwrap().borrow_mut().add_file_with_path(dst_path)?.content(true).key(true).signed(true).digest(true);
        Ok(())
    }

    pub fn decrypt_file<O: Write>(&self, src: &str, dst: O, private_key: &PrivateKey) -> DecyptFileResult {
        if self.get_directory_content_soft().is_none() {
            return Err(EncryptedFileError::ContentIsUnknown.into());
        }
        let file = self.get_directory_content_soft().unwrap().get_file(src).ok_or(EncryptedFileError::FileDoesNotExist)?;
        if !file.has_content() {
            Err(EncryptedFileError::FileContentIsMissing.into())
        }
        else if !file.has_key() {
            Err(EncryptedFileError::FileKeyIsMissing.into())
        }
        else {
            Ok(self.decrypt_file_digest(src, dst, private_key)?.1)
        }
    }


    pub fn decrypt_file_and_verify<O: Write>(&self, src: &str, dst: O, private_key: &PrivateKey, public_key: &RsaPublicKey) -> DecryptFileAndVerifyResult {
        if self.get_directory_content_soft().is_none() {
            return Err(EncryptedFileError::ContentIsUnknown.into());
        }
        let file = self.get_directory_content_soft().unwrap().get_file(src).ok_or(EncryptedFileError::FileDoesNotExist)?;
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
            let (dig, ans) = self.decrypt_file_digest(src, dst, private_key)?;
            let signature_verification = self.verify_signature(src, dig.as_ref(), public_key);
            Ok((ans, signature_verification))
        }
    }

    #[cfg(feature = "signers-list")]
    pub fn decrypt_file_and_find_signer<O: Write>(&self, src: &str, dst: O, private_key: &PrivateKey, signers_list: &SignersList) -> DecryptFileAndFindSignerResult {
        if self.get_directory_content_soft().is_none() {
            return Err(EncryptedFileError::ContentIsUnknown.into());
        }
        let file = self.get_directory_content_soft().unwrap().get_file(src).ok_or(EncryptedFileError::FileDoesNotExist)?;
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
            let (digest, is_valid) = self.decrypt_file_digest(src, dst, private_key)?;
            for (signer, key) in signers_list {
                if self.verify_signature(src, &digest, &key).is_ok() {
                    return Ok((is_valid, Some(signer.to_owned())));
                }
            }
            Ok((is_valid, None))
        }
    }

    pub fn add_directory<P: AsRef<Path>>(&mut self, src: P, dst: &str, public_key: &PublicKey) -> EncryptedFileResult<Vec<(Box<Path>, EncryptedFileResult<()>)>> {
        if !src.as_ref().is_dir() {
            return Err(EncryptedFileError::ThisIsNotADirectory.into());
        }
        let dst = format!("{}/{}", dst, src.as_ref().file_name().ok_or(EncryptedFileError::InvalidPath)?.to_str().ok_or(EncryptedFileError::InvalidPath)?);
        let mut ans = Vec::new();
        for path in src.as_ref().read_dir()?.filter(|path| path.is_ok()).map(|path| path.unwrap()) {
            if path.path().is_file() {
                if path.file_name().to_str().is_some() {
                    ans.push((Box::from(path.path()), self.add_file(File::open(path.path())?, &format!("{}/{}", dst, path.file_name().to_str().unwrap()), public_key)));
                }
            }
            else {
                let res = self.add_directory(path.path(), &dst, public_key);
                if let Ok(mut res) = res {
                    ans.append(&mut res);
                }
                else {
                    ans.push((Box::from(path.path()), Err(res.unwrap_err())));
                }
            }
        }
        Ok(ans)
    }

    // Directory is not signed, but only every file it contains
    pub fn add_directory_and_sign<P: AsRef<Path>>(&mut self, src: P, dst: &str, public_key: &PublicKey, private_key: &RsaPrivateKey) -> EncryptedFileResult<Vec<(Box<Path>, EncryptedFileResult<()>)>> {
        if !src.as_ref().is_dir() {
            return Err(EncryptedFileError::ThisIsNotADirectory.into());
        }
        let dst = format!("{}/{}", dst, src.as_ref().file_name().ok_or(EncryptedFileError::InvalidPath)?.to_str().ok_or(EncryptedFileError::InvalidPath)?);
        let mut ans = Vec::new();
        for path in src.as_ref().read_dir()?.filter(|path| path.is_ok()).map(|path| path.unwrap()) {
            if path.path().is_file() {
                if path.file_name().to_str().is_some() {
                    ans.push((Box::from(path.path()), self.add_file_and_sign(File::open(path.path())?, &format!("{}/{}", dst, path.file_name().to_str().unwrap()), public_key, private_key)));
                }
            }
            else {
                let res = self.add_directory_and_sign(path.path(), &dst, public_key, private_key);
                if let Ok(mut res) = res {
                    ans.append(&mut res);
                }
                else {
                    ans.push((Box::from(path.path()), Err(res.unwrap_err())));
                }
            }
        }
        Ok(ans)
    }

    fn str_path_last_element(path: &str) -> &str {
        let mut p;
        {
            let path = path.as_bytes();
            p = path.len();
            while p > 0 && path[p - 1] != '/' as u8 && path[p - 1] != '\\' as u8 {
                p -= 1;
            }
        }
        path.get(p..).unwrap()
    }

    pub fn decrypt_directory<P: AsRef<Path>>(&self, src: &str, dst: P, private_key: &PrivateKey) -> EncryptedFileResult<Vec<(String, DecyptFileResult)>> {
        if self.get_directory_content_soft().is_none() {
            return Err(EncryptedFileError::ContentIsUnknown.into());
        }
        if self.get_directory_content_soft().unwrap().get_dir(src).is_none() {
            return Err(EncryptedFileError::DirectoryDoesNotExist.into());
        }
        if !dst.as_ref().is_dir() {
            return Err(EncryptedFileError::ThisIsNotADirectory.into());
        }
        let dst: Box<Path> = Box::from(dst.as_ref().join(Self::str_path_last_element(src)).as_path());
        std::fs::create_dir_all(dst.as_ref())?;
        let mut ans = Vec::new();
        let directory_content = self.directory_content.as_ref().unwrap().get_dir(src).ok_or(EncryptedFileError::DirectoryDoesNotExist)?;
        for (name, _) in directory_content.get_files_iter() {
            let output_file = File::create(dst.join(name));
            if let Ok(output_file) = output_file {
                ans.push((name.to_owned(), self.decrypt_file(&format!("{src}/{name}"), output_file, private_key)));
            }
            else {
                ans.push((name.to_owned(), Err(output_file.unwrap_err().into())));
            }
        }
        for (name, _) in directory_content.get_dir_iter() {
            ans.append(&mut self.decrypt_directory(&format!("{}/{}", src, name), dst.as_ref(), private_key)?);
        }
        Ok(ans)
    }

    pub fn decrypt_directory_and_verify<P: AsRef<Path>>(&self, src: &str, dst: P, private_key: &PrivateKey, public_key: &RsaPublicKey) -> EncryptedFileResult<Vec<(String, DecryptFileAndVerifyResult)>> {
        if self.get_directory_content_soft().is_none() {
            return Err(EncryptedFileError::ContentIsUnknown.into());
        }
        if self.get_directory_content_soft().unwrap().get_dir(src).is_none() {
            return Err(EncryptedFileError::DirectoryDoesNotExist.into());
        }
        if !dst.as_ref().is_dir() {
            return Err(EncryptedFileError::ThisIsNotADirectory.into());
        }
        let dst: Box<Path> = Box::from(dst.as_ref().join(Self::str_path_last_element(src)).as_path());
        let mut ans = Vec::new();
        let directory_content = self.directory_content.as_ref().unwrap().get_dir(src).ok_or(EncryptedFileError::DirectoryDoesNotExist)?;
        for (name, _) in self.directory_content.as_ref().unwrap().get_files_iter() {
            let output_file = File::create(dst.join(name));
            if let Ok(output_file) = output_file {
                ans.push((name.to_owned(), self.decrypt_file_and_verify(&format!("{src}/{name}"), output_file, private_key, public_key)));
            }
            else {
                ans.push((name.to_owned(), Err(output_file.unwrap_err().into())));
            }
        }
        for (name, _) in directory_content.get_dir_iter() {
            ans.append(&mut self.decrypt_directory_and_verify(&format!("{}/{}", src, name), dst.as_ref(), private_key, public_key)?);
        }
        Ok(ans)
    }

    #[cfg(feature = "signers-list")]
    pub fn decrypt_directory_and_find_signer<P: AsRef<Path>>(&self, src: &str, dst: P, private_key: &PrivateKey, signers_list: &SignersList) -> EncryptedFileResult<Vec<(String, DecryptFileAndFindSignerResult)>> {
        if self.get_directory_content_soft().is_none() {
            return Err(EncryptedFileError::ContentIsUnknown.into());
        }
        if self.get_directory_content_soft().unwrap().get_dir(src).is_none() {
            return Err(EncryptedFileError::DirectoryDoesNotExist.into());
        }
        if !dst.as_ref().is_dir() {
            return Err(EncryptedFileError::ThisIsNotADirectory.into());
        }
        let dst: Box<Path> = Box::from(dst.as_ref().join(Self::str_path_last_element(src)).as_path());
        let mut ans = Vec::new();
        let directory_content = self.directory_content.as_ref().unwrap().get_dir(src).ok_or(EncryptedFileError::DirectoryDoesNotExist)?;
        for (name, _) in self.directory_content.as_ref().unwrap().get_files_iter() {
            let output_file = File::create(dst.join(name));
            if let Ok(output_file) = output_file {
                ans.push((name.to_owned(), self.decrypt_file_and_find_signer(&format!("{src}/{name}"), output_file, private_key, signers_list)));
            }
            else {
                ans.push((name.to_owned(), Err(output_file.unwrap_err().into())));
            }
        }
        for (name, _) in directory_content.get_dir_iter() {
            ans.append(&mut self.decrypt_directory_and_find_signer(&format!("{}/{}", src, name), dst.as_ref(), private_key, signers_list)?);
        }
        Ok(ans)
    }

    // Impossible with current ways
    // pub fn add_empty_directory(&mut self, path: &str) -> SResult<()> {
    //     self.get_directory_content()?;
    //     let result = self.directory_content.as_mut().unwrap().add_directory(path);
    //     if let Err(err) = result {
    //         Err(err.into())
    //     }
    //     else {
    //         if let Err(err) = ZipWriter::new_append(&self.file)?.add_directory(format!("{FILE_CONETENT_DIR}/{path}"), self.file_options) {
    //             Err(err.into())
    //         }
    //         else {
    //             Ok(())
    //         }
    //     }
    // }

    pub fn delete_path<O: Write + Seek>(&self, output: O, to_delete: &Vec<String>) -> EncryptedFileResult<()> {
        let mut output = ZipWriter::new(output);
        let mut zip = ZipArchive::new(&self.file)?;
        let trie = {
            let mut trie_builder = TrieBuilder::new();
            for path in to_delete {
                trie_builder.push(DirectoryContent::get_path_as_vec(path));
            }
            trie_builder.build()
        };
        for file_name in zip.file_names().map(|s| s.to_owned()).collect::<Vec<String>>() {
            if trie.common_prefix_search(DirectoryContent::get_path_as_vec(&file_name).into_iter().skip(1).rev().skip(1).rev().collect::<Vec<&str>>()).is_empty() {
                output.raw_copy_file(zip.by_name(&file_name)?)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
