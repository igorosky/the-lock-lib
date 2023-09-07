extern crate tempdir;

mod test_utils {
    use std::{path::Path, fmt::Display, fs::{File, remove_file}, io::{Read, Write}};

    use rand::RngCore;
    use rsa::rand_core::OsRng;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct TestUtilError(String);

    impl Display for TestUtilError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self)
        }
    }

    impl std::error::Error for TestUtilError { }

    impl TestUtilError {
        pub(super) fn new(str: &str) -> TestUtilError {
            Self(str.to_owned())
        }
    }

    pub(super) struct MockFile {
        path: Box<Path>,
        content: Vec<u8>,
    }

    impl MockFile {
        pub(super) fn new<P: AsRef<Path>>(path: P) -> Result<Self, TestUtilError> {
            if path.as_ref().exists() {
                Err(TestUtilError::new("File already exists"))
            }
            else {
                let mut content = vec![0;32];
                OsRng.fill_bytes(&mut content);
                File::create(path.as_ref()).unwrap().write(&content).unwrap();
                Ok(Self { path: Box::from(path.as_ref()), content })
            }
        }

        pub(super) fn validate(&self) -> Result<(), TestUtilError> {
            self.validate_with(self.path.as_ref())
        }

        pub(super) fn validate_with<P: AsRef<Path>>(&self, path: P) -> Result<(), TestUtilError> {
            let mut buf = Vec::new();
            File::open(path.as_ref()).unwrap().read_to_end(&mut buf).unwrap();
            match buf == self.content {
                true => Ok(()),
                false => Err(TestUtilError::new("File is not valid")),
            }
        }

        pub(super) fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for MockFile {
        fn drop(&mut self) {
            if self.path.is_file() {
                let _ = remove_file(self.path.as_ref());
            }
        }
    }

}

mod lib_tests {
    use tempdir::TempDir;

    use crate::*;

    use super::test_utils::MockFile;

    use std::fs::create_dir;

    use crate::asymetric_key::*;

    const KEY_SIZE: usize = 4096;

    #[test]
    fn adding_file() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let mock_file = MockFile::new(tmp_dir.path().join("mock")).unwrap();
        let mut ef = EncryptedFile::new(tmp_dir.path().join("archive")).expect("Creating new EncryptedFile");
        let key = PrivateKey::new(KEY_SIZE).unwrap();
        ef.add_file(File::open(mock_file.path()).unwrap(), "test/testfile.txt", &key.into()).unwrap();
        ef.get_directory_content().unwrap();
    }

    #[test]
    fn adding_file_and_decrypting() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let mock_file = MockFile::new(tmp_dir.path().join("mock")).unwrap();
        let mut ef = EncryptedFile::new(tmp_dir.path().join("archive")).expect("Creating new EncryptedFile");
        let key = PrivateKey::new(KEY_SIZE).unwrap();
        ef.add_file(File::open(mock_file.path()).unwrap(), "test/testfile.txt", &(&key).into()).unwrap();
        assert!(ef.decrypt_file("test/testfile.txt", File::create(mock_file.path()).unwrap(), &key).unwrap());
        ef.get_directory_content().unwrap();
        mock_file.validate().unwrap();
    }

    #[test]
    fn decrypt_and_validate_signature() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let mock_file = MockFile::new(tmp_dir.path().join("mock")).unwrap();
        let mut ef = EncryptedFile::new(tmp_dir.path().join("archive")).expect("Creating new EncryptedFile");
        let key = PrivateKey::new(KEY_SIZE).unwrap();
        ef.add_file_and_sign(File::open(mock_file.path()).unwrap(), "test/testfile.txt", &(&key).into(), &key.get_rsa_private_key()).unwrap();
        assert!(ef.decrypt_file_and_verify("test/testfile.txt", File::create(mock_file.path()).unwrap(), &key, &key.get_rsa_public_key()).unwrap());
        ef.get_directory_content().unwrap();
        mock_file.validate().unwrap();
    }

    #[cfg(feature = "signers-list")]
    #[test]
    fn decrypt_file_and_find_signer() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let signers_dir = TempDir::new("the-lock-test").unwrap();
        let mock_file = MockFile::new(tmp_dir.path().join("mock")).unwrap();
        let mut ef = EncryptedFile::new(tmp_dir.path().join("archive")).expect("Creating new EncryptedFile");
        let key = PrivateKey::new(KEY_SIZE).unwrap();
        ef.add_file_and_sign(File::open(mock_file.path()).unwrap(), "test/testfile.txt", &(&key).into(), key.get_rsa_private_key()).unwrap();
        let mut signers_list = SignersList::new(signers_dir.path()).unwrap();
        signers_list.add_signer("Rafał", &key.get_rsa_public_key()).unwrap();
        signers_list.add_signer("Roman", &rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap().to_public_key()).unwrap();
        assert_eq!(Some("Rafał".to_owned()), ef.decrypt_file_and_find_signer("test/testfile.txt", File::create(mock_file.path()).unwrap(), &key, &signers_list).unwrap().1);
        ef.get_directory_content().unwrap();
        mock_file.validate().unwrap();
    }

    #[cfg(feature = "signers-list")]
    #[test]
    fn decrypt_file_and_find_signer_none() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let signers_dir = TempDir::new("the-lock-test").unwrap();
        let mock_file = MockFile::new(tmp_dir.path().join("mock")).unwrap();
        let mut ef = EncryptedFile::new(tmp_dir.path().join("archive")).expect("Creating new EncryptedFile");
        let key = PrivateKey::new(KEY_SIZE).unwrap();
        ef.add_file_and_sign(File::open(mock_file.path()).unwrap(), "test/testfile.txt", &(&key).into(), &key.get_rsa_private_key()).unwrap();
        let mut signers_list = SignersList::new(signers_dir.path()).unwrap();
        signers_list.add_signer("Roman", &rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap().to_public_key()).unwrap();
        signers_list.add_signer("Rafał", &rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap().to_public_key()).unwrap();
        assert_eq!(None, ef.decrypt_file_and_find_signer("test/testfile.txt", File::create(mock_file.path()).unwrap(), &key, &signers_list).unwrap().1);
        ef.get_directory_content().unwrap();
        mock_file.validate().unwrap();
    }
    
    #[test]
    fn encrypt_folder() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let dir_to_encrypt = tmp_dir.path().join("dir");
        create_dir(dir_to_encrypt.clone()).unwrap();
        create_dir(dir_to_encrypt.join("sdir")).unwrap();
        let _mock_file1 = MockFile::new(dir_to_encrypt.join("file1")).unwrap();
        let _mock_file2 = MockFile::new(dir_to_encrypt.join("file2")).unwrap();
        let _mock_file3 = MockFile::new(dir_to_encrypt.join("file3")).unwrap();
        let _mock_file4 = MockFile::new(dir_to_encrypt.join("sdir").join("file1")).unwrap();
        let _mock_file5 = MockFile::new(dir_to_encrypt.join("sdir").join("file2")).unwrap();
        let mut ef = EncryptedFile::new(tmp_dir.path().join("file")).unwrap();
        let key = PrivateKey::new(KEY_SIZE).unwrap();
        assert!(ef.add_directory(dir_to_encrypt, "folder", &key.into()).is_ok());
    }
    
    #[test]
    fn encrypt_folder_and_decrypt() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let dir_to_encrypt = tmp_dir.path().join("dir");
        create_dir(dir_to_encrypt.clone()).unwrap();
        create_dir(dir_to_encrypt.join("sdir")).unwrap();
        let mock_file1 = MockFile::new(dir_to_encrypt.join("file1")).unwrap();
        let mock_file2 = MockFile::new(dir_to_encrypt.join("file2")).unwrap();
        let mock_file3 = MockFile::new(dir_to_encrypt.join("file3")).unwrap();
        let mock_file4 = MockFile::new(dir_to_encrypt.join("sdir").join("file1")).unwrap();
        let mock_file5 = MockFile::new(dir_to_encrypt.join("sdir").join("file2")).unwrap();
        let mut ef = EncryptedFile::new(tmp_dir.path().join("file")).unwrap();
        let key = PrivateKey::new(KEY_SIZE).unwrap();
        assert!(ef.add_directory(dir_to_encrypt, "folder", &(&key).into()).is_ok());
        ef.decrypt_directory("folder/dir", tmp_dir.path(), &key).unwrap();
        create_dir(tmp_dir.path().join("output")).unwrap();
        ef.decrypt_directory("folder/dir", tmp_dir.path().join("output"), &key).unwrap();
        mock_file1.validate().unwrap();
        mock_file2.validate().unwrap();
        mock_file3.validate().unwrap();
        mock_file4.validate().unwrap();
        mock_file5.validate().unwrap();
    }

    // #[test]
    // fn add_empty_directory() {
    //     let tmp_dir = TempDir::new("the-lock-test").unwrap();
    //     let mut ef = EncryptedFile::new(tmp_dir.path().join("file")).unwrap();
    //     ef.add_empty_directory("nice").unwrap();
    //     drop(ef);
    //     let mut ef = EncryptedFile::new(tmp_dir.path().join("file")).unwrap();
    //     println!("{:?}", ef.get_directory_content());
    //     assert!(ef.get_directory_content().unwrap().get_dir("nice").is_some());
    // }
}

mod directory_content_tests {
    use crate::directory_content::DirectoryContent;

    #[test]
    fn cration() {
        let dir = DirectoryContent::new();
        assert!(dir.get_dir("abc").is_none());
        assert!(dir.get_file("abc").is_none());
        assert!(dir.get_file("abc/abc").is_none());
    }
    
    #[test]
    fn dir_test() {
        let mut dir = DirectoryContent::new();
        assert!(dir.add_directory("abc").is_ok());
        assert!(dir.get_dir("abc").is_some());
        assert!(dir.get_file("abc").is_none());
    }
    
    #[test]
    fn add_file_test() {
        let mut dir = DirectoryContent::new();
        assert!(dir.add_file("abc/file").is_err());
        assert!(dir.add_directory("abc").is_ok());
        assert!(dir.add_file("abc/file").is_ok());
        assert!(dir.get_dir("abc").is_some());
        assert!(dir.get_file("abc").is_none());
        assert!(dir.get_file("abc/file").is_some());
        assert!(dir.get_dir("abc").unwrap().get_file("file").is_some());
    }
    
    #[test]
    fn add_file_with_path_test() {
        let mut dir = DirectoryContent::new();
        assert!(dir.add_file_with_path("abc/file").is_ok());
        assert!(dir.get_file("abc/file").is_some());
        assert!(dir.add_directory("abc").is_ok());
        assert!(dir.add_file("abc/file").is_err());
        assert!(dir.get_dir("abc").is_some());
        assert!(dir.get_file("abc").is_none());
        assert!(dir.get_file("abc/file").is_some());
        assert!(dir.get_dir("abc").unwrap().get_file("file").is_some());
    }
    
    #[test]
    fn get_dir_mut() {
        let mut dir = DirectoryContent::new();
        assert!(dir.add_file("abc/file").is_err());
        assert!(dir.add_directory("abc").is_ok());
        assert!(dir.get_dir_mut("abc").is_some());
        assert!(dir.get_dir_mut("abc").unwrap().add_file("file").is_ok());
        assert!(dir.get_dir("abc").is_some());
        assert!(dir.get_file("abc").is_none());
        assert!(dir.get_file("abc/file").is_some());
        assert!(dir.get_dir("abc").unwrap().get_file("file").is_some());
    }

    #[test]
    fn exists() {
        let mut dir = DirectoryContent::new();
        assert!(dir.exists("/"));
        assert!(dir.get_dir("/").is_some());
        assert!(!dir.exists("abc/"));
        assert!(!dir.exists("abc/file"));
        assert!(dir.add_file("abc/file").is_err());
        assert!(!dir.exists("abc/file"));
        assert!(!dir.exists("abc/"));
        assert!(dir.add_directory("abc").is_ok());
        assert!(dir.exists("abc/"));
        assert!(!dir.exists("abc/file"));
        assert!(dir.get_dir_mut("abc").is_some());
        assert!(dir.get_dir_mut("abc").unwrap().add_file("file").is_ok());
        assert!(dir.get_dir("abc").is_some());
        assert!(dir.get_file("abc").is_none());
        assert!(dir.get_file("abc/file").is_some());
        assert!(dir.exists("abc/"));
        assert!(dir.exists("abc/file"));
        assert!(dir.get_dir("abc").unwrap().get_file("file").is_some());
        assert!(dir.exists("/"));
        assert!(dir.get_dir("/").is_some());
    }
}

#[cfg(feature = "signers-list")]
mod signers_list_tests {
    use rsa::{RsaPrivateKey, rand_core::OsRng};
    use tempdir::TempDir;

    use crate::signers_list::*;
    
    #[test]
    fn creating_new() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let mut signers_list = SignersList::new(tmp_dir.path()).unwrap();
        assert!(!signers_list.contains("Peter"));
        signers_list.add_signer("Peter", &RsaPrivateKey::new(&mut OsRng, 2048).unwrap().to_public_key()).unwrap();
        signers_list.add_signer("Stewie", &RsaPrivateKey::new(&mut OsRng, 2048).unwrap().to_public_key()).unwrap();
        assert!(signers_list.contains("Peter"));
        assert!(signers_list.is_valid("Peter").is_ok());
    }
    
    #[test]
    fn creating_new_and_reading() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let mut signers_list = SignersList::new(tmp_dir.path()).unwrap();
        assert!(!signers_list.contains("Peter"));
        signers_list.add_signer("Peter", &RsaPrivateKey::new(&mut OsRng, 2048).unwrap().to_public_key()).unwrap();
        signers_list.add_signer("Stewie", &RsaPrivateKey::new(&mut OsRng, 2048).unwrap().to_public_key()).unwrap();
        assert!(signers_list.contains("Peter"));
        signers_list.is_valid("Peter").unwrap();
        drop(signers_list);
        let signers_list = SignersList::open(tmp_dir.path()).unwrap();
        assert!(signers_list.contains("Stewie"));
        assert!(signers_list.is_valid("Stewie").is_ok());
        assert!(signers_list.contains("Stewie"));
        assert!(signers_list.is_valid("Stewie").is_ok());
        assert!(!signers_list.contains("Stewiee"));
        assert!(signers_list.is_valid("Stewiee").is_err());
    }

    #[test]
    fn deleting() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let mut signers_list = SignersList::new(tmp_dir.path()).unwrap();
        signers_list.add_signer("Peter", &RsaPrivateKey::new(&mut OsRng, 2048).unwrap().to_public_key()).unwrap();
        signers_list.add_signer("Stewie", &RsaPrivateKey::new(&mut OsRng, 2048).unwrap().to_public_key()).unwrap();
        assert!(signers_list.delete_signer("Peter").is_ok());
        assert!(signers_list.delete_signer("Peter").is_err());
        drop(signers_list);
        let signers_list = SignersList::open(tmp_dir.path()).unwrap();
        assert!(!signers_list.contains("Peter"));
        assert!(signers_list.is_valid("Peter").is_err());
        assert!(signers_list.contains("Stewie"));
        assert!(signers_list.is_valid("Stewie").is_ok());
        assert!(signers_list.contains("Stewie"));
        assert!(signers_list.is_valid("Stewie").is_ok());
        assert!(!signers_list.contains("Stewiee"));
        assert!(signers_list.is_valid("Stewiee").is_err());
    }
}

mod encryption_cipher_tests {
    use std::{fs::File, io::{Read, Write}};

    use tempdir::TempDir;

    use crate::{symmertic_cipher::*, tests::test_utils::MockFile};


    #[test]
    fn encryptiom_test() {
        const FILENAME: &str = "file";
        const ENCRYPTED_FILENAME: &str = "file.encrypted";
        let tmp_dir = TempDir::new("the-lock-prefix").unwrap();
        let src_file = MockFile::new(tmp_dir.path().join(FILENAME)).unwrap();
        let encrypted_file = tmp_dir.path().join(ENCRYPTED_FILENAME);
        let sc = SymmetricCipher::default();
        let key = SymmetricKey::new();
        sc.encrypt_file(
            &key,
            b"123",
            &mut File::open(src_file.path()).expect("File source"),
            &mut File::create(&encrypted_file).expect("File dst")
        ).expect("Encryption Fail");
        sc.decrypt_file(
            &key,
            b"123",
            &mut File::open(encrypted_file).expect("File source"),
            &mut File::create(src_file.path()).expect("File dst")
        ).expect("Decryption Fail");
        src_file.validate().unwrap();
    }

    #[test]
    fn key_serialization() {
        let tmp_dir = TempDir::new("the-lock-test").unwrap();
        let path = tmp_dir.path().join("sym.key");
        let mut key = SymmetricKey::new();
        let key_copy = key.clone();
        let key_bytes: [u8; 51] = key.into();
        File::create(&path).unwrap().write(&key_bytes).unwrap();
        let mut buf = Vec::new();
        File::open(path).unwrap().read_to_end(&mut buf).unwrap();
        key = SymmetricKey::try_from(buf).unwrap();
        assert_eq!(key, key_copy);
    }
}

mod asymetric_key_tests {
    use crate::{asymetric_key::*, symmertic_cipher::SymmetricKey};
    
    #[test]
    fn creating_new() {
        assert!(PrivateKey::new(MIN_RSA_KEY_SIZE).is_ok());
        assert!(PrivateKey::new(MIN_RSA_KEY_SIZE - 1).is_err());
    }

    #[test]
    fn encryption_decryption_test() {
        let key = PrivateKey::new(MIN_RSA_KEY_SIZE).unwrap();
        let data: [u8;51] = SymmetricKey::new().into();
        let encrypted = key.get_public_key().encrypt_symmetric_key(&data).unwrap();
        assert_ne!(data.to_vec(), encrypted);
        if let Ok(decrypted) = PrivateKey::new(MIN_RSA_KEY_SIZE).unwrap().decrypt_symmetric_key(&encrypted) {
            assert_ne!(decrypted, data);
        }
        assert_eq!(data.to_vec(), key.decrypt_symmetric_key(&encrypted).unwrap());
    }
}
