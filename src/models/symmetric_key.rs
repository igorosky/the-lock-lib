use serde::{Serialize, Deserialize};
use chacha20poly1305::{aead::{KeyInit, AeadCore}, XChaCha20Poly1305, Key};
use rand::rngs::OsRng;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymmetricKey {
    key: [u8; 32],
    nonce: [u8; 19],
}

impl From<[u8; 51]> for SymmetricKey {
    fn from(value: [u8; 51]) -> Self {
        Self { key: {
            let mut key = [0; 32];
            for (i, v) in value.iter().take(32).enumerate() {
                key[i] = *v;
            }
            key
        }, nonce: {
            let mut nonce = [0; 19];
            for (i, v) in value.into_iter().skip(32).enumerate() {
                nonce[i] = v;
            }
            nonce
        } }
    }
}

impl From<Vec<u8>> for SymmetricKey {
    fn from(value: Vec<u8>) -> Self {
        if value.len() != 51 {
            panic!("Wrong key length");
        }
        Self { key: {
            let mut key = [0; 32];
            for (i, v) in value.iter().take(32).enumerate() {
                key[i] = *v;
            }
            key
        }, nonce: {
            let mut nonce = [0; 19];
            for (i, v) in value.into_iter().skip(32).enumerate() {
                nonce[i] = v;
            }
            nonce
        } }
    }
}

impl From<&Vec<u8>> for SymmetricKey {
    fn from(value: &Vec<u8>) -> Self {
        if value.len() != 51 {
            panic!("Wrong key length");
        }
        Self { key: {
            let mut key = [0; 32];
            for (i, v) in value.iter().take(32).enumerate() {
                key[i] = *v;
            }
            key
        }, nonce: {
            let mut nonce = [0; 19];
            for (i, v) in value.into_iter().skip(32).enumerate() {
                nonce[i] = *v;
            }
            nonce
        } }
    }
}

impl From<&[u8]> for SymmetricKey {
    fn from(value: &[u8]) -> Self {
        if value.len() != 51 {
            panic!("Wrong key length");
        }
        Self { key: {
            let mut key = [0; 32];
            for (i, v) in value.iter().take(32).enumerate() {
                key[i] = *v;
            }
            key
        }, nonce: {
            let mut nonce = [0; 19];
            for (i, v) in value.into_iter().skip(32).enumerate() {
                nonce[i] = *v;
            }
            nonce
        } }
    }
}

impl Into<[u8; 51]> for SymmetricKey {
    fn into(self) -> [u8; 51] {
        let mut ans = [0; 51];
        for (i, v) in self.key.into_iter().chain(self.nonce.into_iter()).enumerate() {
            ans[i] = v;
        }
        ans
    }
}

impl SymmetricKey {
    pub fn new() -> Self {
        Self::from_ket_and_nonce(XChaCha20Poly1305::generate_key(&mut OsRng), {
            let mut ans = [0; 19];
            for (i, v) in XChaCha20Poly1305::generate_nonce(&mut OsRng).get(0..19).unwrap().into_iter().enumerate() {
                ans[i] = *v;
            }
            ans
        })
    }

    pub fn get_key(&self) -> Key {
        Key::from(self.key)
    }

    pub fn get_nonce(&self) -> &[u8; 19] {
        &self.nonce
    }

    pub fn from_ket_and_nonce(key: Key, nonce: [u8; 19]) -> Self {
        Self { key: {
            let mut ans = [0; 32];
            for (i, v) in key.into_iter().enumerate() {
                ans[i] = v;
            }
            ans
        },
        nonce: nonce }
    }
}

#[cfg(test)]
mod test {
    use std::{path::Path, fs::File, io::Read};

    use rsa::pkcs8::der::Writer;

    use super::SymmetricKey;

    #[test]
    fn key_serialization() {
        let path = Path::new("testing/sym.key");
        let mut key = SymmetricKey::new();
        let key_copy = key.clone();
        let key_bytes: [u8; 51] = key.into();
        File::create(path).unwrap().write(&key_bytes).unwrap();
        let mut buf = Vec::new();
        File::open(path).unwrap().read_to_end(&mut buf).unwrap();
        key = SymmetricKey::from(buf);
        assert_eq!(key, key_copy);
    }
}
