// extern crate tempdir;
extern crate serde_json;
// extern crate libaes;
extern crate rsa;
extern crate chacha20poly1305;
extern crate sha2;

use std::fs::File;
use std::io::prelude::{Write, Seek};
use std::path::Path;
use models::{manifest::Manifest, symmetric_key::SymmetricKey};
use symmertic_cipher::SymmetricCipher;
// use tempdir::TempDir;
use zip::{ZipArchive, ZipWriter, write::FileOptions};

mod manifest_models;
mod symmertic_cipher;
mod results;
mod models;

use results::{JustError, SResult};


pub struct EncryptedFile {
    file_path: Box<Path>,
    // tmp_dir: TempDir,
    manifest: Option<Box<Manifest>>,
}

impl EncryptedFile {
    pub fn new<P: AsRef<Path>>(path: P) -> SResult<Self> {
        let path = path.as_ref();
        let mut manifest_opt = None;
        if !path.exists() {
            let file = File::create(path)?;
            let mut zip = ZipWriter::new(file);
            zip.add_directory("content", FileOptions::default())?;
            let manifest = Box::new(Manifest::new(path.file_name().unwrap().to_str().unwrap()));
            zip.start_file("manifest", FileOptions::default())?;
            zip.write(serde_json::to_string(&manifest)?.as_bytes())?;
            manifest_opt = Some(manifest);
        }
        // let tmp_dir = TempDir::new("theLock")?;
        Ok(Self { file_path: Box::from(path), /*tmp_dir, */manifest: manifest_opt })
    }

    fn push_manifest<W: Write + Seek>(file: W, manifest: &Manifest) -> SResult<()> {
        let mut zip = ZipWriter::new(file);
        zip.start_file("manifest", FileOptions::default())?;
        zip.write(serde_json::to_string(manifest)?.as_bytes())?;
        Ok(())
    }

    pub fn get_cached_manifest(&self) -> Option<Box<Manifest>> {
        if let Some(ans) = self.manifest.clone() {
            return Some(ans);
        }
        None
    }

    pub fn get_manifest(&mut self) -> SResult<Box<Manifest>> {
        if let Some(ans) = self.get_cached_manifest() {
            return Ok(ans);
        }
        self.get_manifest_force()
    }

    pub fn get_manifest_force(&mut self) -> SResult<Box<Manifest>> {
        let file = File::open(self.file_path.clone()).unwrap();
        let mut zip = ZipArchive::new(file)?;
        let mut manifest_zip_file = zip.by_name("manifest")?;
        if manifest_zip_file.is_dir() {
            return Err(Box::new(JustError::new("Not a file".to_owned())));
        }
        let mut buffor = Vec::new();
        // todo!("check manifest size to not blow up app");
        std::io::copy(&mut manifest_zip_file, &mut buffor)?;
        let s: String = buffor.into_iter().map(|b| b as char).collect();
        Ok(Box::new(serde_json::from_str(&s[..]).unwrap()))
    }

    pub fn add_file<P: AsRef<Path>>(&mut self, src: P, dst_path: P) -> SResult<()> {
        let src = src.as_ref();
        if !src.exists() {
            return Err(Box::new(JustError::new(format!("File {} does not exist", src.as_os_str().to_str().unwrap().to_owned()))));
        }
        let dst = format!("content/{}", dst_path.as_ref().to_str().unwrap());
        let symmertic_cipher = SymmetricCipher::new();
        let key = SymmetricKey::new();
        let mut zip = ZipWriter::new_append(File::options().read(true).write(true).open(self.file_path.as_ref())?)?;
        println!("{}", dst);
        zip.start_file(dst, FileOptions::default())?;
        symmertic_cipher.encrypt_file(&key, b"uno dos", &mut File::open(src)?, &mut zip)?;
        
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let mut ef = EncryptedFile::new(Path::new("test2.zip")).expect("Creating new EncryptedFile");
        println!("{:?}", ef.get_manifest().expect("No manifest"));
        ef.add_file(Path::new("testfile.txt"), Path::new("test/testfile.txt")).unwrap();
    }
}
