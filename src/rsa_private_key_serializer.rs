use std::{io::{Write, Read}, fmt::Display};

use serde::{Serialize, Deserialize};
use rsa::RsaPrivateKey;
use rand::rngs::OsRng;
use libaes::{Cipher, AES_256_KEY_LEN};
use argon2::Argon2;

use crate::SResult;

#[derive(Debug, Clone, PartialEq, Eq)]
enum RsaPrivateKeySerializerError {
    RequestedKeySizeIsTooSmall,
    KeyIsNotEncrypted,
    FileIsInvalid,
    NoKeyToDecrypt,
    KeyIsEncrypted,
}

impl Display for RsaPrivateKeySerializerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            RsaPrivateKeySerializerError::RequestedKeySizeIsTooSmall => "RequestedKeySizeIsTooSmall",
            RsaPrivateKeySerializerError::KeyIsNotEncrypted => "KeyIsNotEncrypted",
            RsaPrivateKeySerializerError::FileIsInvalid => "FileIsInvalid",
            RsaPrivateKeySerializerError::NoKeyToDecrypt => "NoKeyToDecrypt",
            RsaPrivateKeySerializerError::KeyIsEncrypted => "KeyIsEncrypted",
        })
    }
}

impl std::error::Error for RsaPrivateKeySerializerError { }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPrivateKeySerializer {
    is_encrypted: bool,
    decrypted_key: Option<RsaPrivateKey>,
    encrypted_key: Option<Vec<u8>>,
}

impl RsaPrivateKeySerializer {
    pub fn new(bit_size: usize) -> SResult<RsaPrivateKey> {
        if bit_size < 512 {
            return Err(RsaPrivateKeySerializerError::RequestedKeySizeIsTooSmall.into());
        }
        Ok(RsaPrivateKey::new(&mut OsRng, bit_size)?)
    }

    pub fn read<R: Read>(read: &mut R) -> SResult<Self> {
        // TODO Check if file is not too big
        let ans: RsaPrivateKeySerializer = rmp_serde::from_read(read)?;
        match (ans.is_encrypted, ans.decrypted_key.is_none(), ans.encrypted_key.is_none()) {
            (true, true, false) => (),
            (false, false, true) => (),
            _ => return Err(RsaPrivateKeySerializerError::FileIsInvalid.into()),
        }
        Ok(ans)
    }

    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }

    pub fn get_key(self) -> SResult<RsaPrivateKey> {
        let mut ans = self.decrypted_key.ok_or(RsaPrivateKeySerializerError::KeyIsEncrypted)?;
        ans.validate()?;
        ans.precompute()?;
        Ok(ans)
    }

    pub fn get_encrypted_key(mut self, password: &[u8]) -> SResult<RsaPrivateKey> {
        self.read_and_decrypt(password)?;
        self.get_key()
    }

    fn read_and_decrypt(&mut self, password: &[u8]) -> SResult<()> {
        if !self.is_encrypted {
            return Err(RsaPrivateKeySerializerError::KeyIsNotEncrypted.into());
        }
        let (key, iv) = Self::copute_key_and_iv(password);
        let cipher = Cipher::new_256(&key);
        let decrypted = cipher.cbc_decrypt(&iv, &self.encrypted_key.take().ok_or(RsaPrivateKeySerializerError::NoKeyToDecrypt)?);
        self.decrypted_key = Some(rmp_serde::from_slice(&decrypted)?);
        Ok(())
    }

    pub fn save<W: Write>(key: RsaPrivateKey, output: &mut W) -> SResult<()> {
        output.write(&rmp_serde::to_vec(&Self { is_encrypted: false, decrypted_key: Some(key), encrypted_key: None })?)?;
        Ok(())
    }

    const IV_SIZE: usize = 32;

    fn copute_key_and_iv(password: &[u8]) -> ([u8; AES_256_KEY_LEN], [u8; Self::IV_SIZE]) { // Yep that iv is kinda pointless and it doesn't fulfill it's role
        let mut buf = [0; AES_256_KEY_LEN + Self::IV_SIZE];
        Argon2::default().hash_password_into(password, b"saltAndPeper", &mut buf).unwrap();
        let mut key = [0; AES_256_KEY_LEN];
        let mut iv = [0; Self::IV_SIZE];
        let _ = buf.iter().take(AES_256_KEY_LEN).enumerate().map(|(i, v)| key[i] = *v);
        let _ = buf.into_iter().skip(AES_256_KEY_LEN).enumerate().map(|(i, v)| iv[i] = v);
        (key, iv)
    }

    pub fn save_with_password<W: Write>(rsa_key: RsaPrivateKey, output: &mut W, password: &[u8]) -> SResult<()> {
        let (key, iv) = Self::copute_key_and_iv(password);
        output.write(&rmp_serde::to_vec(&Self {
            is_encrypted: true,
            decrypted_key: None,
            encrypted_key: Some(
                Cipher::new_256(&key).cbc_encrypt(
                    &iv,
                    &rmp_serde::to_vec(&rsa_key)?
                )
            )
        }).unwrap())?;
        Ok(())
    }
}
