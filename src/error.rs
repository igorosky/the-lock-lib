use std::fmt::Display;

pub use zip::result::ZipError;
pub use rsa::errors::Error as RSAError;
pub use std::io::Error as IOError;
pub use rand::Error as RngError;
pub use chacha20poly1305::aead::Error as ChaChaError;

pub type DirectoryContentPathResult<T> = Result<T, DirectoryContentPathError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryContentPathError {
    ElementCannotBeEmpty,
}

impl Display for DirectoryContentPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::ElementCannotBeEmpty => "ElementCannotBeEmpty",
        }.to_string())
    }
}

impl std::error::Error for DirectoryContentPathError { }

pub type SymmetricCipherResult<T> = Result<T, SymmetricCipherError>;

#[derive(Debug)]
pub enum SymmetricCipherError {
    ConvertionError,
    IOError(IOError),
    XChaCha20Poly1305Error(ChaChaError),
}

impl Display for SymmetricCipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::ConvertionError => "ConvertionError".to_string(),
            Self::IOError(err) => err.to_string(),
            Self::XChaCha20Poly1305Error(err) => err.to_string(),
        })
    }
}

impl std::error::Error for SymmetricCipherError { }

impl From<IOError> for SymmetricCipherError {
    fn from(value: IOError) -> Self {
        Self::IOError(value)
    }
}

impl From<ChaChaError> for SymmetricCipherError {
    fn from(value: ChaChaError) -> Self {
        Self::XChaCha20Poly1305Error(value)
    }
}

pub type AsymetricKeyResult<T> = Result<T, AsymetricKeyError>;

#[derive(Debug)]
pub enum AsymetricKeyError {
    NotAValidSymmetricKey,
    KeySizeIsTooSmall,
    XChaCha20Poly1305Error(ChaChaError),
    RandError(RngError),
    RSAError(RSAError),
}

impl Display for AsymetricKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            AsymetricKeyError::NotAValidSymmetricKey => "NotAValidSymmetricKey".to_owned(),
            AsymetricKeyError::KeySizeIsTooSmall => format!("KeySizeIsTooSmall (at least {})", crate::asymetric_key::MIN_RSA_KEY_SIZE),
            AsymetricKeyError::XChaCha20Poly1305Error(err) => err.to_string(),
            AsymetricKeyError::RandError(err) => err.to_string(),
            AsymetricKeyError::RSAError(err) => err.to_string(),
        })
    }
}

impl std::error::Error for AsymetricKeyError { }

impl From<RngError> for AsymetricKeyError {
    fn from(value: RngError) -> Self {
        Self::RandError(value)
    }
}

impl From<RSAError> for AsymetricKeyError {
    fn from(value: RSAError) -> Self {
        Self::RSAError(value)
    }
}

impl From<ChaChaError> for AsymetricKeyError {
    fn from(value: chacha20poly1305::aead::Error) -> Self {
        Self::XChaCha20Poly1305Error(value)
    }
}

pub type DirectoryContentResult<T> = Result<T, ContentError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentError {
    FileAlreadyExists,
    DirectoryAlreadyExists,
    FileDoesNotExist,
    DirectoryDoesNotExist,
    NameCanNotBeEmpty,
}

impl Display for ContentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            ContentError::FileAlreadyExists => "FileAlreadyExists",
            ContentError::DirectoryAlreadyExists => "DirectoryAlreadyExists",
            ContentError::FileDoesNotExist => "FileDoesNotExist",
            ContentError::DirectoryDoesNotExist => "DirectoryDoesNotExist(Content)",
            ContentError::NameCanNotBeEmpty => "NameCanNotBeEmpty",
        })
    }
}

#[cfg(feature = "signers-list")]
mod signers_list_error {
    use std::fmt::Display;
    pub type SignersListResult<T> = Result<T, SignersListError>;
    
    #[derive(Debug)]
    pub enum SignersListError {
        DirectoryDoesNotExist,
        ItIsNotAnDirectory,
        SignerDoesNotExist,
        SignerIsNotValid,
        MoreThanOneSignerHasSameKeyFile,
        SignerAlreadyExist,
        IOError(std::io::Error),
        JSONSerdeError(serde_json::error::Error),
    }
    
    impl From<std::io::Error> for SignersListError {
        fn from(value: std::io::Error) -> Self {
            Self::IOError(value)
        }
    }
    
    impl From<serde_json::error::Error> for SignersListError {
        fn from(value: serde_json::error::Error) -> Self {
            Self::JSONSerdeError(value)
        }
    }
    
    impl Display for SignersListError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", match self {
                SignersListError::DirectoryDoesNotExist => "DirectoryDoesNotExist(SignersList)".to_owned(),
                SignersListError::ItIsNotAnDirectory => "ItIsNotAnDirectory".to_owned(),
                SignersListError::SignerDoesNotExist => "SignerDoesNotExist".to_owned(),
                SignersListError::SignerIsNotValid => "SignerIsNotValid".to_owned(),
                SignersListError::MoreThanOneSignerHasSameKeyFile => "MoreThanOneSignerHasSameKeyFile".to_owned(),
                SignersListError::SignerAlreadyExist => "SignerAlreadyExist".to_owned(),
                SignersListError::IOError(err) => err.to_string(),
                SignersListError::JSONSerdeError(err) => err.to_string(),
            })
        }
    }
    
    impl std::error::Error for SignersListError { }
}

#[cfg(feature = "signers-list")]
pub use signers_list_error::*;

pub type EncryptedFileResult<T> = Result<T, EncryptedFileError>;

#[derive(Debug)]
pub enum EncryptedFileError {
    FileAlreadyExists,
    // InvalidSignatureFile,
    FileDoesNotExist,
    FileIsNotSigned,
    FileKeyIsMissing,
    FileContentIsMissing,
    InvalidPath,
    DirectoryDoesNotExist,
    ThisIsNotADirectory,
    ContentIsUnknown,
    ZipError(ZipError),
    DirectoryContentError(ContentError),
    RSAError(RSAError),
    IOError(IOError),
    SymmetricCipherError(SymmetricCipherError),
    AsymetricKeyError(AsymetricKeyError),
}

impl From<ZipError> for EncryptedFileError {
    fn from(value: ZipError) -> Self {
        Self::ZipError(value)
    }
}

impl From<ContentError> for EncryptedFileError {
    fn from(value: ContentError) -> Self {
        Self::DirectoryContentError(value)
    }
}

impl From<RSAError> for EncryptedFileError {
    fn from(value: RSAError) -> Self {
        Self::RSAError(value)
    }
}

impl From<IOError> for EncryptedFileError {
    fn from(value: IOError) -> Self {
        Self::IOError(value)
    }
}

impl From<SymmetricCipherError> for EncryptedFileError {
    fn from(value: SymmetricCipherError) -> Self {
        Self::SymmetricCipherError(value)
    }
}

impl From<AsymetricKeyError> for EncryptedFileError {
    fn from(value: AsymetricKeyError) -> Self {
        Self::AsymetricKeyError(value)
    }
}

impl Display for EncryptedFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            EncryptedFileError::FileAlreadyExists => "FileAlreadyExists".to_owned(),
            // EncryptedFileError::InvalidSignatureFile => "InvalidSignatureFile".to_owned(),
            EncryptedFileError::FileDoesNotExist => "FileDoesNotExist".to_owned(),
            EncryptedFileError::FileIsNotSigned => "FileIsNotSigned".to_owned(),
            EncryptedFileError::FileKeyIsMissing => "FileKeyIsMissing".to_owned(),
            EncryptedFileError::FileContentIsMissing => "FileContentIsMissing".to_owned(),
            EncryptedFileError::InvalidPath => "InvalidPath".to_owned(),
            EncryptedFileError::DirectoryDoesNotExist => "DirectoryDoesNotExist(EncryptedFile)".to_owned(),
            EncryptedFileError::ThisIsNotADirectory => "ThisIsNotADirectory".to_owned(),
            EncryptedFileError::ContentIsUnknown => "ContentIsUnknown".to_owned(),
            EncryptedFileError::ZipError(err) => err.to_string(),
            EncryptedFileError::DirectoryContentError(err) => err.to_string(),
            EncryptedFileError::RSAError(err) => err.to_string(),
            EncryptedFileError::IOError(err) => err.to_string(),
            EncryptedFileError::SymmetricCipherError(err) => err.to_string(),
            EncryptedFileError::AsymetricKeyError(err) => err.to_string(),
        })
    }
}

impl std::error::Error for EncryptedFileError { }
