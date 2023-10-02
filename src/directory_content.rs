use std::collections::{BTreeMap, btree_map::Iter};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use crate::error::{ContentError, DirectoryContentResult, DirectoryContentPathResult, DirectoryContentPathError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryContentPath(Vec<String>);

impl Default for DirectoryContentPath {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl DirectoryContentPath {
    fn verify(s: &str) -> DirectoryContentPathResult<String> {
        let mut ans = String::with_capacity(s.len());
        for c in s.trim().chars() {
            if !c.is_ascii() || c.is_ascii_control() || c == '/' || c == '\\' {
                continue;
            }
            ans.push(c);
        }
        if ans.is_empty() {
            return Err(DirectoryContentPathError::ElementCannotBeEmpty);
        }
        Ok(ans)
    }
    
    pub fn file_name(&self) -> Option<&str> {
        self.0.last().map(|v| v.as_str())
    }

    pub fn push(&mut self, element: &str) -> DirectoryContentPathResult<()> {
        self.0.push(Self::verify(element)?);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn root(&self) -> Option<&str> {
        self.0.first().map(|v| v.as_str())
    }

    pub fn get(&self, n: usize) -> Option<&str> {
        self.0.get(n).map(|v| v.as_str())
    }

    pub fn append(&mut self, mut other: Self) {
        self.0.append(&mut other.0);
    }

    pub fn pop(&mut self) -> Option<String> {
        self.0.pop()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.into_iter()
    }
}

impl<'a> Into<&'a [String]> for &'a DirectoryContentPath {
    fn into(self) -> &'a [String] {
        self.0.as_slice()
    }
}

impl std::fmt::Display for DirectoryContentPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", {
            let mut ans = String::new();
            if let Some(first) = self.0.first() {
                ans.push_str(first);
            }
            for path in self.0.iter().skip(1) {
                ans.push('/');
                ans.push_str(path);
            }
            ans
        })
    }
}

impl From<String> for DirectoryContentPath {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

impl From<&str> for DirectoryContentPath {
    fn from(value: &str) -> Self {
        let mut ans = Self::default();
        let mut next = String::new();
        for c in value.chars() {
            if c == '/' || c == '\\' {
                if !next.is_empty() {
                    let _ = ans.push(&next);
                    next.clear();
                }
                continue;
            }
            next.push(c);
        }
        if !next.is_empty() {
            let _ = ans.push(&next);
        }
        ans
    }
}

impl IntoIterator for DirectoryContentPath {
    type IntoIter = std::vec::IntoIter<String>;
    type Item = String;
    
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a DirectoryContentPath {
    type IntoIter = std::slice::Iter<'a, String>;
    type Item = &'a String;
    
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

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
    total_file_count: usize,
}

impl Default for DirectoryContent {
    #[inline]
    fn default() -> Self {
        Self { files: BTreeMap::new(), directories: BTreeMap::new(), total_file_count: 0 }
    }
}

impl DirectoryContent {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_dir(&self, path: &DirectoryContentPath) -> Option<&DirectoryContent> {
        self._get_dir(path.into())
    }

    fn _get_dir(&self, path: &[String]) -> Option<&DirectoryContent> {
        if let Some(next_part) = path.first() {
            match (path.len() == 1, self.directories.get(next_part)) {
                (true, Some(dir)) => Some(dir),
                (false, Some(dir)) => dir._get_dir(path.get(1..).expect("Check if size is >= 1")),
                (_, None) => None,
            }
        }
        else {
            Some(self)
        }
    }

    pub fn get_dir_mut(&mut self, path: &DirectoryContentPath) -> Option<&mut DirectoryContent> {
        self._get_dir_mut(path.into())
    }

    fn _get_dir_mut(&mut self, path: &[String]) -> Option<&mut DirectoryContent> {
        if let Some(next_part) = path.first() {
            match (path.len() == 1, self.directories.get_mut(next_part)) {
                (true, Some(dir)) => Some(dir),
                (false, Some(dir)) => dir._get_dir_mut(path.get(1..).expect("Check if size is >= 1")),
                (_, None) => None,
            }
        }
        else {
            Some(self)
        }
    }

    pub fn get_file(&self, path: &DirectoryContentPath) -> Option<&SingleEncryptedFile> {
        self._get_file(path.into())
    }

    fn _get_file(&self, path: &[String]) -> Option<&SingleEncryptedFile> {
        if let Some(next_part) = path.first() {
            match (path.len() == 1, self.files.get(next_part), self.directories.get(next_part)) {
                (true, Some(file), _) => Some(file),
                (false, _, Some(dir)) => dir._get_file(path.get(1..).expect("Check if size is > 1")),
                _ => None,
            }
        }
        else {
            None
        }
    }

    pub(crate) fn get_file_mut(&mut self, path: &DirectoryContentPath) -> Option<&mut SingleEncryptedFile> {
        self._get_file_mut(path.into())
    }

    fn _get_file_mut(&mut self, path: &[String]) -> Option<&mut SingleEncryptedFile> {
        if let Some(next_part) = path.first() {
            match (path.len() == 1, self.files.get_mut(next_part), self.directories.get_mut(next_part)) {
                (true, Some(file), _) => Some(file),
                (false, _, Some(dir)) => dir._get_file_mut(path.get(1..).expect("Check if size is > 1")),
                _ => None,
            }
        }
        else {
            None
        }
    }

    // Dead code
    #[cfg(test)]
    pub(crate) fn add_directory(&mut self, path: &DirectoryContentPath) -> DirectoryContentResult<&mut DirectoryContent> {
        self._add_directory(path.into())
    }

    fn _add_directory(&mut self, path: &[String]) -> DirectoryContentResult<&mut DirectoryContent> {
        if let Some(next_part) = path.first() {
            match (self.files.contains_key(next_part), self.directories.contains_key(next_part)) {
                (_, true) => self.directories.get_mut(next_part).unwrap()._add_directory(path.get(1..).expect("Check if size is >= 1")),
                (false, false) => {
                    self.directories.insert(next_part.to_owned(), DirectoryContent::new());
                    self.directories.get_mut(next_part).unwrap()._add_directory(path.get(1..).expect("Check if size is >= 1"))
                },
                (true, false) => Err(ContentError::FileAlreadyExists),
            }
        }
        else {
            Ok(self)
        }
    }

    // Dead code
    #[cfg(test)]
    pub(crate) fn add_file(&mut self, path: &DirectoryContentPath) -> DirectoryContentResult<&mut SingleEncryptedFile> {
        self._add_file(path.into())
    }

    // Dead code
    #[cfg(test)]
    fn _add_file(&mut self, path: &[String]) -> DirectoryContentResult<&mut SingleEncryptedFile> {
        if let Some(next_part) = path.first() {
            match (path.len() == 1, self.files.contains_key(next_part), self.directories.contains_key(next_part)) {
                (true, false, false) => {
                    self.files.insert(next_part.to_owned(), SingleEncryptedFile::new());
                    self.total_file_count += 1;
                    Ok(self.files.get_mut(next_part).unwrap())
                },
                (false, _, true) => {
                    let ans = self.directories.get_mut(next_part).unwrap()._add_file(path.get(1..).expect("Check if size is >= 1"));
                    self.total_file_count += ans.is_ok() as usize;
                    ans
                }
                (true, _, true) => Err(ContentError::DirectoryAlreadyExists),
                (true, true, false) => Err(ContentError::FileAlreadyExists),
                (false, _, false) => Err(ContentError::DirectoryDoesNotExist),
            }
        }
        else {
            Err(ContentError::NameCanNotBeEmpty)
        }
    }

    pub(crate) fn add_file_with_path(&mut self, path: &DirectoryContentPath) -> DirectoryContentResult<&mut SingleEncryptedFile> {
        self._add_file_with_path(path.into())
    }

    fn _add_file_with_path(&mut self, path: &[String]) -> DirectoryContentResult<&mut SingleEncryptedFile> {
        if let Some(next_part) = path.first() {
            match (path.len() == 1, self.files.contains_key(next_part), self.directories.contains_key(next_part)) {
                (true, false, false) => {
                    self.files.insert(next_part.to_owned(), SingleEncryptedFile::new());
                    self.total_file_count += 1;
                    Ok(self.files.get_mut(next_part).unwrap())
                },
                (false, _, true) => {
                    let ans = self.directories.get_mut(next_part).unwrap()._add_file_with_path(path.get(1..).expect("Check if size is > 1"));
                    self.total_file_count += ans.is_ok() as usize;
                    ans
                }
                (true, _, true) => Err(ContentError::DirectoryAlreadyExists),
                (true, true, false) => Err(ContentError::FileAlreadyExists),
                (false, _, false) => {
                    let _ = self._add_directory(&[next_part.to_owned()]); // TODO delete useless copying
                    let ans = self.directories.get_mut(next_part).unwrap()._add_file_with_path(path.get(1..).expect("Check if size is > 1"));
                    self.total_file_count += ans.is_ok() as usize;
                    ans
                }
            }
        }
        else {
            Err(ContentError::NameCanNotBeEmpty)
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

    pub(crate) fn get_or_create_file_mut(&mut self, path: &DirectoryContentPath) -> DirectoryContentResult<&mut SingleEncryptedFile> {
        // {
        //     if let Some(ans) = self.get_file_mut(path) {
        //         return Ok(ans);
        //     }
        // }
        // self.add_file_with_path(path)

        // One of those should work

        // match self.get_file_mut(path) {
        //     Some(ans) => Ok(ans),
        //     None => self.add_file_with_path(path),
        // }

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

    pub fn exists(&self, path: &DirectoryContentPath) -> bool {
        self._exists(path.into())
    }

    pub fn _exists(&self, path: &[String]) -> bool {
        if let Some(next_part) = path.first() {
            match (path.len() == 1, self.files.get(next_part), self.directories.get(next_part)) {
                (true, Some(_), _) | (true, None, Some(_)) => true,
                (false, _, Some(dir)) => dir._exists(path.get(1..).expect("Check if len is >= 1")),
                _ => false,
            }
        }
        else {
            true
        }
    }

    #[inline]
    pub fn get_total_file_count(&self) -> usize {
        self.total_file_count
    }
}
