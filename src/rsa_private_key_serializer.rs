use std::io::{Write, Read};

use serde::{Serialize, Deserialize};
use rsa::RsaPrivateKey;
use rand::rngs::OsRng;
use libaes::{Cipher, AES_256_KEY_LEN};
use argon2::Argon2;

use crate::results::{SResult, JustError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPrivateKeySerializer {
    is_encrypted: bool,
    decrypted_key: Option<RsaPrivateKey>,
    encrypted_key: Option<Vec<u8>>,
}

impl RsaPrivateKeySerializer {
    pub fn new(bit_size: usize) -> SResult<RsaPrivateKey> {
        if bit_size < 512 {
            return Err(Box::new(JustError::new("too small key".to_owned())));
        }
        Ok(RsaPrivateKey::new(&mut OsRng, bit_size)?)
    }

    pub fn read<R: Read>(read: &mut R) -> SResult<Self> {
        // TODO Check if file is not too big
        let ans: RsaPrivateKeySerializer = serde_json::from_reader(read)?;
        match (ans.is_encrypted, ans.decrypted_key.is_none(), ans.encrypted_key.is_none()) {
            (true, true, false) => (),
            (false, false, true) => (),
            _ => return Err(Box::new(JustError::new("Invalid file".to_owned()))),
        }
        Ok(ans)
    }

    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }

    pub fn get_key(self) -> SResult<RsaPrivateKey> {
        let mut ans = self.decrypted_key.unwrap();
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
            return Err(Box::new(JustError::new("Key is not encrypted".to_owned())));
        }
        let (key, iv) = Self::copute_key_and_iv(password);
        let cipher = Cipher::new_256(&key);
        let decrypted = cipher.cbc_decrypt(&iv, &self.encrypted_key.take().ok_or(Box::new(JustError::new("No key".to_owned())))?).into_iter().map(|c| c as char).collect::<String>();
        self.decrypted_key = Some(serde_json::from_str(&decrypted)?);
        Ok(())
    }

    pub fn save<W: Write>(key: RsaPrivateKey, output: &mut W) -> SResult<()> {
        output.write(serde_json::to_string(&Self { is_encrypted: false, decrypted_key: Some(key), encrypted_key: None })?.as_bytes())?;
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
        output.write(&serde_json::to_vec(&Self {
            is_encrypted: true,
            decrypted_key: None,
            encrypted_key: Some(
                Cipher::new_256(&key).cbc_encrypt(
                    &iv,
                    &serde_json::to_vec(&rsa_key)?
                )
            )
        }).unwrap())?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::{fs::File, path::Path};

    use super::RsaPrivateKeySerializer;

    #[test]
    fn key_generation() {
        let _ = RsaPrivateKeySerializer::new(2048);
    }

    #[test]
    fn key_serialization() {
        const FILE_NAME: &str = "testing/key.pem";
        let key = RsaPrivateKeySerializer::new(2048).unwrap();
        RsaPrivateKeySerializer::save(key, &mut File::create(Path::new(FILE_NAME)).unwrap()).unwrap();
        let k = RsaPrivateKeySerializer::read(&mut File::open(Path::new(FILE_NAME)).unwrap()).unwrap();
        assert!(!k.is_encrypted());
        let _ = k.get_key().unwrap();
    }

    #[test]
    fn key_encrypted_serialization() {
        const FILE_NAME: &str = "testing/key_encrypted.pem";
        let key = RsaPrivateKeySerializer::new(2048).unwrap();
        RsaPrivateKeySerializer::save_with_password(key, &mut File::create(Path::new(FILE_NAME)).unwrap(), b"password").unwrap();
        let k = RsaPrivateKeySerializer::read(&mut File::open(Path::new(FILE_NAME)).unwrap()).unwrap();
        assert!(k.is_encrypted());
        let _ = k.get_encrypted_key(b"password").unwrap();
    }
}
