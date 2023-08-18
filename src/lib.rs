extern crate tempdir;
extern crate serde_json;
extern crate libaes;
extern crate rsa;

use std::fs::File;
use std::path::Path;
use rsa::pkcs8::der::Writer;
use symmertic_cipher::SymmetricCipher;
use tempdir::TempDir;
use zip::{ZipArchive, ZipWriter, write::FileOptions};

mod manifest_models;
use manifest_models::Manifest;

mod symmertic_cipher;

mod results;
use results::{JustError, SResult};


pub struct EncryptedFile {
    file_path: Box<Path>,
    tmp_dir: TempDir,
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
        let tmp_dir = TempDir::new("theLock")?;
        Ok(Self { file_path: Box::from(path), tmp_dir, manifest: manifest_opt })
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
        let content = {
            let file = File::open(self.file_path.clone()).unwrap();
            let mut zip = ZipArchive::new(file)?;
            let mut manifest_zip_file = zip.by_name("manifest")?;
            if manifest_zip_file.is_dir() {
                return Err(Box::new(JustError::new("Not a file".to_owned())));
            }
            let mut buffor = Vec::new();
            // todo!("check manifest size to not blow up app");
            std::io::copy(&mut manifest_zip_file, &mut buffor)?;
            buffor
        };
        let s: String = content.into_iter().map(|b| b as char).collect();
        Ok(Box::new(serde_json::from_str(&s[..]).unwrap()))
    }

    pub fn add_file<P: AsRef<Path>>(&mut self, src: P/*, dst_path: P*/) -> SResult<()> {
        let src = src.as_ref();
        if !src.exists() {
            return Err(Box::new(JustError::new(format!("File {} does not exist", src.as_os_str().to_str().unwrap().to_owned()))));
        }
        let symmertic_cipher = SymmetricCipher::new(SymmetricCipher::get_256_key()?, b"lalalalalalajfhd".to_vec());
        symmertic_cipher.encrypt_file(src, self.tmp_dir.path(), None)?;
        // let mut zip = ZipWriter::new(File::options().append(true).open(self.file_path.as_ref())?);
        
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use std::path::Path;
    use super::*;

    #[test]
    fn it_works() {
        let mut ef = EncryptedFile::new(Path::new("test2.zip")).expect("Creating new EncryptedFile");
        println!("{:?}", ef.get_manifest().expect("No manifest"));
    }
}
