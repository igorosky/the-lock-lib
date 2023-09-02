use std::fmt::Display;

pub use zip::result::ZipError;
pub use rsa::errors::Error as RSAError;
pub use std::io::Error as IOError;

pub type DirectoryContentResult<T> = Result<T, ContentError>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

pub type RsaPrivateKeySerializerResult<T> = Result<T, RsaPrivateKeySerializerError>;

#[derive(Debug)]
pub enum RsaPrivateKeySerializerError {
    RequestedKeySizeIsTooSmall,
    KeyIsNotEncrypted,
    FileIsInvalid,
    NoKeyToDecrypt,
    KeyIsEncrypted,
    IOError(std::io::Error),
    RMPSerdeEncodeError(rmp_serde::encode::Error),
    RMPSerdeDecodeError(rmp_serde::decode::Error),
    RSAError(rsa::Error),
}

impl From<std::io::Error> for RsaPrivateKeySerializerError {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}

impl From<rmp_serde::encode::Error> for RsaPrivateKeySerializerError {
    fn from(value: rmp_serde::encode::Error) -> Self {
        Self::RMPSerdeEncodeError(value)
    }
}

impl From<rmp_serde::decode::Error> for RsaPrivateKeySerializerError {
    fn from(value: rmp_serde::decode::Error) -> Self {
        Self::RMPSerdeDecodeError(value)
    }
}

impl From<rsa::Error> for RsaPrivateKeySerializerError {
    fn from(value: rsa::Error) -> Self {
        Self::RSAError(value)
    }
}

impl Display for RsaPrivateKeySerializerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            RsaPrivateKeySerializerError::RequestedKeySizeIsTooSmall => "RequestedKeySizeIsTooSmall".to_owned(),
            RsaPrivateKeySerializerError::KeyIsNotEncrypted => "KeyIsNotEncrypted".to_owned(),
            RsaPrivateKeySerializerError::FileIsInvalid => "FileIsInvalid".to_owned(),
            RsaPrivateKeySerializerError::NoKeyToDecrypt => "NoKeyToDecrypt".to_owned(),
            RsaPrivateKeySerializerError::KeyIsEncrypted => "KeyIsEncrypted".to_owned(),
            RsaPrivateKeySerializerError::IOError(err) => err.to_string(),
            RsaPrivateKeySerializerError::RMPSerdeEncodeError(err) => err.to_string(),
            RsaPrivateKeySerializerError::RMPSerdeDecodeError(err) => err.to_string(),
            RsaPrivateKeySerializerError::RSAError(err) => err.to_string(),
        })
    }
}

impl std::error::Error for RsaPrivateKeySerializerError { }

pub type SignersListResult<T> = Result<T, SignersListError>;

#[derive(Debug)]
pub enum SignersListError {
    DirectoryDoesNotExit,
    ItIsNotAnDirectory,
    SignerDoesNotExist,
    SignerIsNotValid,
    MoreThanOneSignerHasSameKeyFile,
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
        })
    }
}

impl std::error::Error for EncryptedFileError { }
