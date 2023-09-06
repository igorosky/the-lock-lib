use rsa::{RsaPublicKey, RsaPrivateKey, Oaep};
use rand::{rngs::OsRng, Rng};
use crate::{symmertic_cipher::{SYMMETRIC_KEY_SIZE, SYMMETRIC_NONE_SIZE}, error::{AsymetricKeyResult, AsymetricKeyError}};

pub const MIN_RSA_KEY_SIZE: usize = 1024;

const TOTAL_SYMMETRIC_KEY_SIZE: usize = SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    rsa_key: RsaPrivateKey,
    symmetric_key: [u8; TOTAL_SYMMETRIC_KEY_SIZE],
}

impl PrivateKey {
    #[inline]
    pub fn new(size: usize) -> AsymetricKeyResult<Self> {
        if size < MIN_RSA_KEY_SIZE {
            return Err(AsymetricKeyError::KeySizeIsTooSmall);
        }
        let mut symmetric_key = [0; TOTAL_SYMMETRIC_KEY_SIZE];
        OsRng.try_fill(&mut symmetric_key[..SYMMETRIC_KEY_SIZE])?;
        OsRng.try_fill(&mut symmetric_key[SYMMETRIC_KEY_SIZE..])?;
        Ok(Self { rsa_key: RsaPrivateKey::new(&mut OsRng, size)?, symmetric_key})
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
    pub fn decrypt_symmetric_key(&self, data: &Vec<u8>) -> AsymetricKeyResult<[u8; TOTAL_SYMMETRIC_KEY_SIZE]> {
        let decrypted: Vec<u8> = self.rsa_key.decrypt(Oaep::new::<sha2::Sha256>(), data)?
                                    .into_iter()
                                    .zip(self.symmetric_key)
                                    .map(|(data, key)| data ^ key)
                                    .collect();
        if decrypted.len() != TOTAL_SYMMETRIC_KEY_SIZE {
            return Err(AsymetricKeyError::NotAValidSymmetricKey);
        }
        let mut ans = [0; TOTAL_SYMMETRIC_KEY_SIZE];
        ans.iter_mut().zip(decrypted).for_each(|(v, a)| *v = a);
        Ok(ans)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    rsa_key: RsaPublicKey,
    symmetric_key: [u8; SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE],
}

impl PublicKey {
    #[inline]
    pub fn encrypt_symmetric_key(&self, data: &[u8; TOTAL_SYMMETRIC_KEY_SIZE]) -> AsymetricKeyResult<Vec<u8>> {
        Ok(
            self.rsa_key.encrypt(
                &mut OsRng,
                Oaep::new::<sha2::Sha256>(),
                &data.into_iter()
                        .zip(self.symmetric_key)
                        .map(|(data, key)| *data ^ key)
                        .collect::<Vec<u8>>()
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
        Self { rsa_key: value.get_rsa_public_key(), symmetric_key: value.symmetric_key }
    }
}
