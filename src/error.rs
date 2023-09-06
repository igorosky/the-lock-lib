use std::fmt::Display;

pub use zip::result::ZipError;
pub use rsa::errors::Error as RSAError;
pub use std::io::Error as IOError;
pub use rand::Error as RngError;

pub type AsymetricKeyResult<T> = Result<T, AsymetricKeyError>;

#[derive(Debug)]
pub enum AsymetricKeyError {
    NotAValidSymmetricKey,
    KeySizeIsTooSmall,
    RandError(RngError),
    RSAError(RSAError),
}

impl Display for AsymetricKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            AsymetricKeyError::NotAValidSymmetricKey => "NotAValidSymmetricKey".to_owned(),
            AsymetricKeyError::KeySizeIsTooSmall => format!("KeySizeIsTooSmall (at least {})", crate::asymetric_key::MIN_RSA_KEY_SIZE),
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

pub type DirectoryContentResult<T> = Result<T, ContentError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentError {
    FileAlreadyExists,
    DirectoryAlreadyExists,
    FileDoesNotExist,
    DirectoryDoesNotExit,
    NameCanNotBeEmpty,
}

impl Display for ContentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            ContentError::FileAlreadyExists => "FileAlreadyExists",
            ContentError::DirectoryAlreadyExists => "DirectoryAlreadyExists",
            ContentError::FileDoesNotExist => "FileDoesNotExist",
            ContentError::DirectoryDoesNotExit => "DirectoryDoesNotExit",
            ContentError::NameCanNotBeEmpty => "NameCanNotBeEmpty",
        })
    }
}

impl std::error::Error for ContentError { }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertionError;

impl Display for ConvertionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Len should be equal to 51")
    }
}

impl std::error::Error for ConvertionError { }

pub type SignersListResult<T> = Result<T, SignersListError>;

#[derive(Debug)]
pub enum SignersListError {
    DirectoryDoesNotExit,
    ItIsNotAnDirectory,
    SignerDoesNotExist,
    SignerIsNotValid,
    MoreThanOneSignerHasSameKeyFile,
    SignerAlreadyExist,
    IOError(std::io::Error),
    RPMSerdeEncodeError(rmp_serde::encode::Error),
    RPMSerdeDecodeError(rmp_serde::decode::Error),
    JSONSerdeError(serde_json::error::Error),
}

impl From<std::io::Error> for SignersListError {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}

impl From<rmp_serde::encode::Error> for SignersListError {
    fn from(value: rmp_serde::encode::Error) -> Self {
        Self::RPMSerdeEncodeError(value)
    }
}

impl From<rmp_serde::decode::Error> for SignersListError {
    fn from(value: rmp_serde::decode::Error) -> Self {
        Self::RPMSerdeDecodeError(value)
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
            SignersListError::DirectoryDoesNotExit => "DirectoryDoesNotExit".to_owned(),
            SignersListError::ItIsNotAnDirectory => "ItIsNotAnDirectory".to_owned(),
            SignersListError::SignerDoesNotExist => "SignerDoesNotExist".to_owned(),
            SignersListError::SignerIsNotValid => "SignerIsNotValid".to_owned(),
            SignersListError::MoreThanOneSignerHasSameKeyFile => "MoreThanOneSignerHasSameKeyFile".to_owned(),
            SignersListError::SignerAlreadyExist => "SignerAlreadyExist".to_owned(),
            SignersListError::IOError(err) => err.to_string(),
            SignersListError::RPMSerdeEncodeError(err) => err.to_string(),
            SignersListError::RPMSerdeDecodeError(err) => err.to_string(),
            SignersListError::JSONSerdeError(err) => err.to_string(),
        })
    }
}

impl std::error::Error for SignersListError { }

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
    SymmetricKeyConvertionError,
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

impl From<ConvertionError> for EncryptedFileError {
    fn from(_: ConvertionError) -> Self {
        Self::SymmetricKeyConvertionError
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
            EncryptedFileError::DirectoryDoesNotExist => "DirectoryDoesNotExist".to_owned(),
            EncryptedFileError::ThisIsNotADirectory => "ThisIsNotADirectory".to_owned(),
            EncryptedFileError::ContentIsUnknown => "ContentIsUnknown".to_owned(),
            EncryptedFileError::ZipError(err) => err.to_string(),
            EncryptedFileError::DirectoryContentError(err) => err.to_string(),
            EncryptedFileError::RSAError(err) => err.to_string(),
            EncryptedFileError::IOError(err) => err.to_string(),
            EncryptedFileError::SymmetricKeyConvertionError => "SymmetricKeyConvertionError".to_owned(),
            EncryptedFileError::AsymetricKeyError(err) => err.to_string(),
        })
    }
}

impl std::error::Error for EncryptedFileError { }
