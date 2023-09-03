use std::{collections::{HashMap, HashSet}, path::Path, fs::{File, remove_file}, io::{Write, Read}};

use rsa::RsaPublicKey;
use uuid::Uuid;

use crate::error::{SignersListError, SignersListResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignersList {
    path: Box<Path>,
    signers: HashMap<String, String>,
    used_uuid: HashSet<String>,
}

impl SignersList {
    pub fn new<P: AsRef<Path>>(path: P) -> SignersListResult<Self> {
        if !path.as_ref().exists() {
            return Err(SignersListError::DirectoryDoesNotExit.into());
        }
        else if path.as_ref().is_file() {
            return Err(SignersListError::ItIsNotAnDirectory.into());
        }
        else {
            Ok(Self { path: Box::from(path.as_ref()), signers: HashMap::new(), used_uuid: HashSet::new() })   
        }
    }

    const MANIFEST: &str = "manifest";

    pub fn open<P: AsRef<Path>>(path: P) -> SignersListResult<Self> {
        let mut ans = Self::new(path.as_ref())?;
        let mut manifest = File::open(path.as_ref().join(Self::MANIFEST))?;
        let mut buf = String::new();
        manifest.read_to_string(&mut buf)?;
        ans.signers = serde_json::from_str(&buf)?;
        for (_, uuid) in &ans.signers {
            if !ans.used_uuid.insert(uuid.to_owned()) {
                return Err(SignersListError::MoreThanOneSignerHasSameKeyFile.into());
            }
        }
        Ok(ans)
    }
    
    pub fn add_signer(&mut self, name: &str, rsa_public_key: &RsaPublicKey) -> SignersListResult<()> {
        let uuid = {
            let mut uuid = Uuid::new_v4().to_string();
            while self.used_uuid.contains(&uuid) {
                uuid = Uuid::new_v4().to_string();
            }
            uuid
        };
        self.signers.insert(name.to_owned(), uuid.clone());
        File::create(self.path.join(uuid))?.write(&serde_json::to_vec(rsa_public_key)?)?;
        File::create(self.path.join(Self::MANIFEST))?.write(&serde_json::to_vec(&self.signers)?)?;
        Ok(())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.signers.contains_key(name)
    }

    pub fn is_valid(&self, name: &str) -> SignersListResult<()> {
        if self.path.join(self.signers.get(name).ok_or(SignersListError::SignerDoesNotExist)?).is_file() {
            Ok(())
        }
        else {
            Err(SignersListError::SignerIsNotValid.into())
        }
    }

    pub fn delete_signer(&mut self, name: &str) -> SignersListResult<()> {
        if let Some(uuid) = self.signers.remove(name) {
            remove_file(self.path.join(uuid))?;
            File::create(self.path.join(Self::MANIFEST))?.write(&serde_json::to_vec(&self.signers)?)?;
            Ok(())
        }
        else {
            Err(SignersListError::SignerDoesNotExist)
        }
    }

    pub fn rename(&mut self, name: &str, new_name: &str) -> SignersListResult<()> {
        let v = self.signers.remove(name).ok_or(SignersListError::SignerDoesNotExist)?;
        self.signers.insert(new_name.to_owned(), v);
        Ok(())
    }
}

pub struct SignersListIterator<'a> {
    path: &'a Path,
    signers_list_iter: std::collections::hash_map::Iter<'a, std::string::String, std::string::String>,
}

impl<'a> Iterator for SignersListIterator<'a> {
    type Item = (&'a str, RsaPublicKey);
    
    fn next(&mut self) -> Option<Self::Item> {
        if let Some((name, uuid)) = self.signers_list_iter.next() {
            let path = self.path.join(uuid);
            let mut buf = String::new();
            if path.is_file() && File::open(path).unwrap().read_to_string(&mut buf).is_ok() {
                if let Ok(rsa) = serde_json::from_str(&buf) {
                    return Some((&name, rsa));
                }
            }
            self.next()
        }
        else {
            None
        }
    }
}

impl<'a> IntoIterator for &'a SignersList {
    type Item = (&'a str, RsaPublicKey);
    type IntoIter = SignersListIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SignersListIterator { path: &self.path, signers_list_iter: self.signers.iter() }
    }
}
