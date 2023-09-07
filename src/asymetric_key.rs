use chacha20poly1305::{XChaCha20Poly1305, KeyInit, Key, XNonce, aead::Aead};
use rsa::{RsaPublicKey, RsaPrivateKey, Oaep};
use rand::{rngs::OsRng, Rng};
use crate::error::{AsymetricKeyResult, AsymetricKeyError};

pub const MIN_RSA_KEY_SIZE: usize = 2048;
const SYMMETRIC_KEY_SIZE: usize = 32;
const SYMMETRIC_NONE_SIZE: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    rsa_key: RsaPrivateKey,
    chacha_key: [u8; SYMMETRIC_KEY_SIZE],
    chacha_nonce: [u8; SYMMETRIC_NONE_SIZE],
}

impl PrivateKey {
    #[inline]
    pub fn new(size: usize) -> AsymetricKeyResult<Self> {
        if size < MIN_RSA_KEY_SIZE {
            return Err(AsymetricKeyError::KeySizeIsTooSmall);
        }
        let mut chacha_key = [0; SYMMETRIC_KEY_SIZE];
        OsRng.try_fill(&mut chacha_key)?;
        let mut chacha_nonce = [0; SYMMETRIC_NONE_SIZE];
        OsRng.try_fill(&mut chacha_nonce)?;
        Ok(Self { rsa_key: RsaPrivateKey::new(&mut OsRng, size)?, chacha_key, chacha_nonce })
    }

    #[inline]
    pub fn rsa_precomput(&mut self) -> AsymetricKeyResult<()> {
        Ok(self.rsa_key.precompute()?)
    }

    #[inline]
    pub fn get_rsa_private_key(&self) -> &RsaPrivateKey {
        &self.rsa_key
    }

    #[inline]
    pub fn get_rsa_public_key(&self) -> RsaPublicKey {
        self.rsa_key.to_public_key()
    }

    #[inline]
    pub fn get_public_key(&self) -> PublicKey {
        self.into()
    }

    #[inline]
    pub fn decrypt_symmetric_key(&self, data: &[u8]) -> AsymetricKeyResult<Vec<u8>> {
        Ok(
            XChaCha20Poly1305::new(&Key::from(self.chacha_key))
                .decrypt(
                    &XNonce::from(self.chacha_nonce),
                    self.rsa_key.decrypt(
                        Oaep::new::<sha2::Sha256>(),
                        data
                    )?.as_ref()
                )?
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    rsa_key: RsaPublicKey,
    chacha_key: [u8; SYMMETRIC_KEY_SIZE],
    chacha_nonce: [u8; SYMMETRIC_NONE_SIZE],
}

impl PublicKey {
    #[inline]
    pub fn encrypt_symmetric_key(&self, data: &[u8]) -> AsymetricKeyResult<Vec<u8>> {
        Ok(
            self.rsa_key.encrypt(
                &mut OsRng,
                Oaep::new::<sha2::Sha256>(),
                &XChaCha20Poly1305::new(&Key::from(self.chacha_key)).encrypt(&XNonce::from(self.chacha_nonce), data)?
            )?
        )
    }

    #[inline]
    pub fn get_rsa_public_key(&self) -> &RsaPublicKey {
        &self.rsa_key
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(value: PrivateKey) -> Self {
        Self::from(&value)
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(value: &PrivateKey) -> Self {
        Self { rsa_key: value.get_rsa_public_key(), chacha_key: value.chacha_key, chacha_nonce: value.chacha_nonce }
    }
}
