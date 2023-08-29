use std::{collections::{BTreeMap, btree_map::Iter}, fmt::Display};
// use std::collections::btree_map::IterMut;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SingleEncryptedFile {
    has_content: bool,
    has_key: bool,
    is_signed: bool,
}

impl Default for SingleEncryptedFile {
    #[inline]
    fn default() -> Self {
        Self { has_content: false, has_key: false, is_signed: false }
    }
}

impl SingleEncryptedFile {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_val(has_content: bool, has_key: bool, is_signed: bool) -> Self {
        Self { has_content: has_content, has_key: has_key, is_signed: is_signed }
    }

    pub fn content(&mut self, content: bool) -> &mut Self {
        self.has_content = content;
        self
    }

    pub fn has_content(&self) -> bool {
        self.has_content
    }

    pub fn key(&mut self, key: bool) -> &mut Self {
        self.has_key = key;
        self
    }

    pub fn has_key(&self) -> bool {
        self.has_key
    }

    pub fn signed(&mut self, v: bool) -> &mut Self {
        self.is_signed = v;
        self
    }

    pub fn is_signed(&self) -> bool {
        self.is_signed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ContentErrors {
    FileAlreadyExists,
    DirectoryAlreadyExists,
    FileDoesNotExist,
    DirectoryDoesNotExit,
    NameCanNotBeEmpty,
}

impl Display for ContentErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            ContentErrors::FileAlreadyExists => "FileAlreadyExists",
            ContentErrors::DirectoryAlreadyExists => "DirectoryAlreadyExists",
            ContentErrors::FileDoesNotExist => "FileDoesNotExist",
            ContentErrors::DirectoryDoesNotExit => "DirectoryDoesNotExit",
            ContentErrors::NameCanNotBeEmpty => "NameCanNotBeEmpty",
        })
    }
}

impl std::error::Error for ContentErrors { }

type DirectoryContentResult<T> = Result<T, ContentErrors>;

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

    pub fn get_dir(&self, path: &str) -> Option<&DirectoryContent> {
        let (next_part, rest) = Self::get_next_and_rest(path);
        match (rest.is_empty(), self.directories.get(next_part)) {
            (true, Some(dir)) => Some(dir),
            (false, Some(dir)) => dir.get_dir(rest),
            (_, None) => None,
        }
    }

    pub fn get_dir_mut(&mut self, path: &str) -> Option<&mut DirectoryContent> {
        let (next_part, rest) = Self::get_next_and_rest(path);
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
            (true, false) => Err(ContentErrors::FileAlreadyExists),
        }
    }

    pub(crate) fn add_file(&mut self, path: &str) -> DirectoryContentResult<&mut SingleEncryptedFile> {
        let (next_part, rest) = Self::get_next_and_rest(path);
        if next_part.is_empty() {
            return Err(ContentErrors::NameCanNotBeEmpty);
        }
        match (rest.is_empty(), self.files.contains_key(next_part), self.directories.contains_key(next_part)) {
            (true, false, false) => {
                self.files.insert(next_part.to_owned(), SingleEncryptedFile::new());
                Ok(self.files.get_mut(next_part).unwrap())
            },
            (false, _, true) => self.directories.get_mut(next_part).unwrap().add_file(rest),
            (true, _, true) => Err(ContentErrors::DirectoryAlreadyExists),
            (true, true, false) => Err(ContentErrors::FileAlreadyExists),
            (false, _, false) => Err(ContentErrors::DirectoryDoesNotExit),
        }
    }

    pub(crate) fn add_file_with_path(&mut self, path: &str) -> DirectoryContentResult<&mut SingleEncryptedFile> {
        let (next_part, rest) = Self::get_next_and_rest(path);
        if next_part.is_empty() {
            return Err(ContentErrors::NameCanNotBeEmpty);
        }
        match (rest.is_empty(), self.files.contains_key(next_part), self.directories.contains_key(next_part)) {
            (true, false, false) => {
                self.files.insert(next_part.to_owned(), SingleEncryptedFile::new());
                Ok(self.files.get_mut(next_part).unwrap())
            },
            (false, _, true) => self.directories.get_mut(next_part).unwrap().add_file(rest),
            (true, _, true) => Err(ContentErrors::DirectoryAlreadyExists),
            (true, true, false) => Err(ContentErrors::FileAlreadyExists),
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
            Ok(self.add_file_with_path(path)?)
        }
        // todo!("Optimize it somehow")
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
}
