use std::io::prelude::{Read, Write};

use chacha20poly1305::{XChaCha20Poly1305, aead::stream::DecryptorBE32};
use chacha20poly1305::aead::stream::EncryptorBE32;
use chacha20poly1305::aead::KeyInit;
use rand::RngCore;
use sha2::{Sha512, Digest};

use chacha20poly1305::Key;
use rand::rngs::OsRng;

use crate::error::ConvertionError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricCipher {
    buffor_size: usize,
}

impl Default for SymmetricCipher {
    fn default() -> Self {
        Self::new(256*1024*1024)
    }
}

impl SymmetricCipher {
    /***
     * buffor_size in B
     */
    pub fn new(buffor_size: usize) -> Self {
        Self { buffor_size: buffor_size }
    }

    /***
     * buffor_size in B
     */
    pub fn change_buffor_size(&mut self, buffor_size: usize) {
        self.buffor_size = buffor_size
    }

    /***
     * buffor_size in B
     */
    pub fn buffor_size(&self) -> usize {
        self.buffor_size
    }

    pub fn encrypt_file<I: Read, O: Write>(&self, key: &SymmetricKey, associated_data: &[u8], mut src: I, dst: &mut O) -> Result<Box<[u8; 64]>, std::io::Error> {
        let mut cipher = EncryptorBE32::from_aead(XChaCha20Poly1305::new(&key.get_key()), key.get_nonce().as_ref().into());
        let buffor_size = self.buffor_size;
        let mut buffor = vec![0; buffor_size];
        let mut count = src.read(&mut buffor)?;
        let mut hasher = Sha512::new();
        loop {
            if count == buffor_size {
                hasher.update(&buffor);
                cipher.encrypt_next_in_place(associated_data, &mut buffor).unwrap();
                dst.write(&buffor)?;
                buffor.resize(buffor_size, 0);
                count = src.read(&mut buffor)?;
            }
            else {
                buffor.resize(count, 0);
                hasher.update(&buffor);
                cipher.encrypt_last_in_place(associated_data, &mut buffor).unwrap();
                dst.write(&buffor)?;
                break;
            }
        }
        let mut ans = Box::new([0; 64]);
        for (i, v) in hasher.finalize().into_iter().enumerate() {
            ans[i] = v;
        }
        Ok(ans)
    }

    pub fn decrypt_file<I: Read, O: Write>(&self, key: &SymmetricKey, associated_data: &[u8], src: &mut I, dst: &mut O) -> Result<Box<[u8; 64]>, std::io::Error> {
        let mut cipher = DecryptorBE32::from_aead(XChaCha20Poly1305::new(&key.get_key()), key.get_nonce().as_ref().into());
        let buffor_size = self.buffor_size + 16;    // + 16 becouse thats what chacha adds - magic value
        let mut buffor = vec![0; buffor_size];
        let mut count = src.read(&mut buffor)?;
        let mut hasher = Sha512::new();
        loop {
            if count == buffor.len() {
                cipher.decrypt_next_in_place(associated_data, &mut buffor).unwrap();
                dst.write(&buffor)?;
                hasher.update(&buffor);
                buffor.resize(buffor_size, 0);
                count = src.read(&mut buffor)?;
            }
            else if count != 0 {
                buffor.resize(count, 0);
                cipher.decrypt_last_in_place(associated_data, &mut buffor).unwrap();
                dst.write(&buffor)?;
                hasher.update(&buffor);
                break;
            }
            else {
                break;
            }
        }
        let mut ans = Box::new([0; 64]);
        for (i, v) in hasher.finalize().into_iter().enumerate() {
            ans[i] = v;
        }
        Ok(ans)
    }
}

const SYMMETRIC_KEY_SIZE: usize = 32;
const SYMMETRIC_NONE_SIZE: usize = 19;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricKey {
    key: [u8; SYMMETRIC_KEY_SIZE],
    nonce: [u8; SYMMETRIC_NONE_SIZE],
}

impl From<[u8; SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE]> for SymmetricKey {
    fn from(value: [u8; SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE]) -> Self {
        Self {
            key: {
                let mut key = [0; SYMMETRIC_KEY_SIZE];
                key.iter_mut().zip(value).for_each(|(key, v)| *key = v);
                key
            },
            nonce: {
                let mut nonce = [0; SYMMETRIC_NONE_SIZE];
                nonce.iter_mut().zip(value.into_iter().skip(SYMMETRIC_KEY_SIZE)).for_each(|(nonce, v)| *nonce = v);
                nonce
            }
        }
    }
}

impl TryFrom<Vec<u8>> for SymmetricKey {
    type Error = ConvertionError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE {
            Err(ConvertionError)
        }
        else {
            Ok(Self {
                key: {
                    let mut key = [0; SYMMETRIC_KEY_SIZE];
                    key.iter_mut().zip(value.iter()).for_each(|(key, v)| *key = *v);
                    key
                },
                nonce: {
                    let mut nonce = [0; SYMMETRIC_NONE_SIZE];
                    nonce.iter_mut().zip(value.into_iter().skip(SYMMETRIC_KEY_SIZE)).for_each(|(nonce, v)| *nonce = v);
                    nonce
                }
            })
        }
    }
}

impl TryFrom<&Vec<u8>> for SymmetricKey {
    type Error = ConvertionError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE {
            Err(ConvertionError)
        }
        else {
            Ok(Self {
                key: {
                    let mut key = [0; SYMMETRIC_KEY_SIZE];
                    key.iter_mut().zip(value).for_each(|(key, v)| *key = *v);
                    key
                },
                nonce: {
                    let mut nonce = [0; SYMMETRIC_NONE_SIZE];
                    nonce.iter_mut().zip(value.into_iter().skip(SYMMETRIC_KEY_SIZE)).for_each(|(nonce, v)| *nonce = *v);
                    nonce
                }
            })
        }
    }
}

impl TryFrom<&[u8]> for SymmetricKey {
    type Error = ConvertionError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE {
            Err(ConvertionError)
        }
        else {
            Ok(Self {
                key: {
                    let mut key = [0; SYMMETRIC_KEY_SIZE];
                    key.iter_mut().zip(value).for_each(|(key, v)| *key = *v);
                    key
                },
                nonce: {
                    let mut nonce = [0; SYMMETRIC_NONE_SIZE];
                    nonce.iter_mut().zip(value.into_iter().skip(SYMMETRIC_KEY_SIZE)).for_each(|(nonce, v)| *nonce = *v);
                    nonce
                }
            })
        }
    }
}

impl Into<[u8; SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE]> for SymmetricKey {
    fn into(self) -> [u8; SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE] {
        let mut ans = [0; SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE];
        for (i, v) in self.key.into_iter().chain(self.nonce.into_iter()).enumerate() {
            ans[i] = v;
        }
        ans
    }
}

impl SymmetricKey {
    pub fn new() -> Self {
        let mut key = [0; SYMMETRIC_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        let mut nonce = [0; SYMMETRIC_NONE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        Self::from_key_and_nonce(key, nonce)
    }

    pub fn get_key(&self) -> Key {
        Key::from(self.key)
    }

    pub fn get_nonce(&self) -> &[u8; SYMMETRIC_NONE_SIZE] {
        &self.nonce
    }

    pub fn from_key_and_nonce(key: [u8; SYMMETRIC_KEY_SIZE], nonce: [u8; SYMMETRIC_NONE_SIZE]) -> Self {
        Self {
            key,
            nonce
        }
    }
}
