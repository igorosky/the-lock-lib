use std::collections::{BTreeMap, btree_map::Iter};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use crate::error::{ContentError, DirectoryContentResult};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SingleEncryptedFile {
    has_content: bool,
    has_key: bool,
    is_signed: bool,
    has_digest: bool,
}

impl Default for SingleEncryptedFile {
    #[inline]
    fn default() -> Self {
        Self { has_content: false, has_key: false, is_signed: false, has_digest: false }
    }
}

impl SingleEncryptedFile {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn new_with_val(has_content: bool, has_key: bool, is_signed: bool, has_digest: bool) -> Self {
        Self { has_content, has_key, is_signed, has_digest }
    }

    #[inline]
    pub fn content(&mut self, content: bool) -> &mut Self {
        self.has_content = content;
        self
    }

    #[inline]
    pub fn has_content(&self) -> bool {
        self.has_content
    }

    #[inline]
    pub fn key(&mut self, key: bool) -> &mut Self {
        self.has_key = key;
        self
    }

    #[inline]
    pub fn has_key(&self) -> bool {
        self.has_key
    }

    #[inline]
    pub fn signed(&mut self, v: bool) -> &mut Self {
        self.is_signed = v;
        self
    }

    #[inline]
    pub fn is_signed(&self) -> bool {
        self.is_signed
    }

    #[inline]
    pub fn digest(&mut self, v: bool) -> &mut Self {
        self.has_digest = v;
        self
    }

    #[inline]
    pub fn has_digest(&self) -> bool {
        self.has_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DirectoryContent {
    files: BTreeMap<String, SingleEncryptedFile>,
    directories: BTreeMap<String, DirectoryContent>,
}

impl Default for DirectoryContent {
    #[inline]
    fn default() -> Self {
        Self { files: BTreeMap::new(), directories: BTreeMap::new() }
    }
}

impl DirectoryContent {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    fn trim_path(mut str: &str) -> &str {
        let mut p = 0;
        for c in str.chars() {
            if c != '\\' && c != '/' {
                break;
            }
            p += 1;
        }
        str = str.get(p..).unwrap();
        p = str.len();
        for c in str.chars().rev() {
            if c != '\\' && c != '/' {
                break;
            }
            p -= 1;
        }
        str = str.get(..p).unwrap();
        str
    }

    fn get_next_and_rest(mut path: &str) -> (&str, &str) {
        path = Self::trim_path(path);
        let mut q = 0;
        for c in path.chars() {
            if c == '/' || c == '\\' {
                break;
            }
            q += 1;
        }
        let mut p = q;
        for c in path.chars().skip(q) {
            if c != '/' && c != '\\' {
                break;
            }
            p += 1;
        }
        (path.get(..q).unwrap(), path.get(p..).unwrap())
    }

    pub fn get_path_as_vec(path: &str) -> Vec<&str> {
        let mut ans = Vec::new();
        let (mut next, mut rest) = Self::get_next_and_rest(path);
        ans.push(next);
        while !rest.is_empty() {
            (next, rest) = Self::get_next_and_rest(rest);
            ans.push(next);
        }
        ans
    }

    pub fn get_dir(&self, path: &str) -> Option<&DirectoryContent> {
        let (next_part, rest) = Self::get_next_and_rest(path);
        if next_part.is_empty() {
            return Some(self);
        }
        match (rest.is_empty(), self.directories.get(next_part)) {
            (true, Some(dir)) => Some(dir),
            (false, Some(dir)) => dir.get_dir(rest),
            (_, None) => None,
        }
    }

    pub fn get_dir_mut(&mut self, path: &str) -> Option<&mut DirectoryContent> {
        let (next_part, rest) = Self::get_next_and_rest(path);
        if next_part.is_empty() {
            return Some(self);
        }
        match (rest.is_empty(), self.directories.get_mut(next_part)) {
            (true, Some(dir)) => Some(dir),
            (false, Some(dir)) => dir.get_dir_mut(rest),
            (_, None) => None,
        }
    }

    pub fn get_file(&self, path: &str) -> Option<&SingleEncryptedFile> {
        let (next_part, rest) = Self::get_next_and_rest(path);
        match (rest.is_empty(), self.files.get(next_part), self.directories.get(next_part)) {
            (true, Some(file), _) => Some(file),
            (false, _, Some(dir)) => dir.get_file(rest),
            _ => None,
        }
    }

    pub(crate) fn get_file_mut(&mut self, path: &str) -> Option<&mut SingleEncryptedFile> {
        let (next_part, rest) = Self::get_next_and_rest(path);
        match (rest.is_empty(), self.files.get_mut(next_part), self.directories.get_mut(next_part)) {
            (true, Some(file), _) => Some(file),
            (false, _, Some(dir)) => dir.get_file_mut(rest),
            _ => None,
        }
    }

    pub(crate) fn add_directory(&mut self, path: &str) -> DirectoryContentResult<&mut DirectoryContent> {
        let (next_part, rest) = Self::get_next_and_rest(path);
        if next_part.is_empty() {
            return Ok(self);
        }
        match (self.files.contains_key(next_part), self.directories.contains_key(next_part)) {
            (_, true) => self.directories.get_mut(next_part).unwrap().add_directory(rest),
            (false, false) => {
                self.directories.insert(next_part.to_owned(), DirectoryContent::new());
                self.directories.get_mut(next_part).unwrap().add_directory(rest)
            },
            (true, false) => Err(ContentError::FileAlreadyExists),
        }
    }

    // Dead code
    #[cfg(test)]
    pub(crate) fn add_file(&mut self, path: &str) -> DirectoryContentResult<&mut SingleEncryptedFile> {
        let (next_part, rest) = Self::get_next_and_rest(path);
        if next_part.is_empty() {
            return Err(ContentError::NameCanNotBeEmpty);
        }
        match (rest.is_empty(), self.files.contains_key(next_part), self.directories.contains_key(next_part)) {
            (true, false, false) => {
                self.files.insert(next_part.to_owned(), SingleEncryptedFile::new());
                Ok(self.files.get_mut(next_part).unwrap())
            },
            (false, _, true) => self.directories.get_mut(next_part).unwrap().add_file(rest),
            (true, _, true) => Err(ContentError::DirectoryAlreadyExists),
            (true, true, false) => Err(ContentError::FileAlreadyExists),
            (false, _, false) => Err(ContentError::DirectoryDoesNotExist),
        }
    }

    pub(crate) fn add_file_with_path(&mut self, path: &str) -> DirectoryContentResult<&mut SingleEncryptedFile> {
        let (next_part, rest) = Self::get_next_and_rest(path);
        if next_part.is_empty() {
            return Err(ContentError::NameCanNotBeEmpty);
        }
        match (rest.is_empty(), self.files.contains_key(next_part), self.directories.contains_key(next_part)) {
            (true, false, false) => {
                self.files.insert(next_part.to_owned(), SingleEncryptedFile::new());
                Ok(self.files.get_mut(next_part).unwrap())
            },
            (false, _, true) => self.directories.get_mut(next_part).unwrap().add_file_with_path(rest),
            (true, _, true) => Err(ContentError::DirectoryAlreadyExists),
            (true, true, false) => Err(ContentError::FileAlreadyExists),
            (false, _, false) => self.add_directory(next_part).unwrap().add_file_with_path(rest),
        }
    }

    // pub(crate) fn get_or_create_file(&mut self, path: &str) -> DirectoryContentResult<&SingleEncryptedFile> {
    //     if self.get_file(path).is_some() {
    //         Ok(self.get_file(path).unwrap())
    //     }
    //     else {
    //         let x: &SingleEncryptedFile = self.add_file_with_path(path)?;
    //         Ok(x)
    //     }
    //     // todo!("Optimize it somehow")
    // }

    pub(crate) fn get_or_create_file_mut(&mut self, path: &str) -> DirectoryContentResult<&mut SingleEncryptedFile> {
        if self.get_file(path).is_some() {
            Ok(self.get_file_mut(path).unwrap())
        }
        else {
            self.add_file_with_path(path)
        }
        // todo!("Optimize it somehow - borrow checker does its best to stop me")
    }

    // pub(crate) fn get_or_create_dir(&mut self, path: &str) -> DirectoryContentResult<&DirectoryContent> {
    //     if self.get_dir(path).is_some() {
    //         Ok(self.get_dir(path).unwrap())
    //     }
    //     else {
    //         let x: &DirectoryContent = self.add_directory(path)?;
    //         Ok(x)
    //     }
    //     // todo!("Optimize it somehow")
    // }

    // pub(crate) fn get_or_create_dir_mut(&mut self, path: &str) -> DirectoryContentResult<&mut DirectoryContent> {
    //     if self.get_dir(path).is_some() {
    //         Ok(self.get_dir_mut(path).unwrap())
    //     }
    //     else {
    //         Ok(self.add_directory(path)?)
    //     }
    //     // todo!("Optimize it somehow")
    // }

    pub fn get_files_iter(&self) -> Iter<String, SingleEncryptedFile> {
        self.files.iter()
    }

    pub fn get_dir_iter(&self) -> Iter<String, DirectoryContent> {
        self.directories.iter()
    }

    // pub(crate) fn get_files_iter_mut(&mut self) -> IterMut<String, SingleEncryptedFile> {
    //     self.files.iter_mut()
    // }

    // pub(crate) fn get_dir_iter_mut(&mut self) -> IterMut<String, DirectoryContent> {
    //     self.directories.iter_mut()
    // }

    pub fn exists(&self, path: &str) -> bool {
        let (next_part, rest) = Self::get_next_and_rest(path);
        if next_part.is_empty() {
            return true;
        }
        match (rest.is_empty(), self.files.get(next_part), self.directories.get(next_part)) {
            (true, Some(_), _) | (true, None, Some(_)) => true,
            (false, _, Some(dir)) => dir.exists(rest),
            _ => false,
        }
    }
}
