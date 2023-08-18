use std::io::prelude::{Read, Write};

use chacha20poly1305::{XChaCha20Poly1305, aead::stream::DecryptorBE32};
use chacha20poly1305::aead::stream::EncryptorBE32;
use chacha20poly1305::aead::KeyInit;
use sha2::{Sha512, Digest};

use crate::models::symmetric_key::SymmetricKey;

use super::results::SResult;


pub struct SymmetricCipher {
    pub buffor_size: usize,
}

impl SymmetricCipher {
    pub fn new() -> Self {
        Self { buffor_size: 256*1024*1024 }
    }

    pub fn new_with_buffor_size(buffor_size: usize) -> Self {
        Self { buffor_size: buffor_size }
    }

    pub fn encrypt_file<I: Read, O: Write>(&self, key: &SymmetricKey, associated_data: &[u8], src: &mut I, dst: &mut O) -> SResult<Box<[u8; 64]>> {
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

    pub fn decrypt_file<I: Read, O: Write>(&self, key: &SymmetricKey, associated_data: &[u8], src: &mut I, dst: &mut O) -> SResult<Box<[u8; 64]>> {
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

#[cfg(test)]
mod test {
    use std::{path::Path, fs::File};

    use crate::{symmertic_cipher::SymmetricCipher, models::symmetric_key::SymmetricKey};

    #[test]
    fn encryptiom_test() {
        let src_file = Path::new("test.zip");
        let encrypted_file = Path::new("test.encrypted");
        let dst_file = Path::new("test3.zip");
        let sc = SymmetricCipher::new();
        let key = SymmetricKey::new();
        assert_eq!(
            sc.encrypt_file(
                &key,
                b"123",
                &mut File::open(src_file).expect("File source"),
                &mut File::create(encrypted_file).expect("File dst")
            ).expect("Encryption Fail"),
            sc.decrypt_file(
                &key,
                b"123",
                &mut File::open(encrypted_file).expect("File source"),
                &mut File::create(dst_file).expect("File dst")
            ).expect("Decryption Fail")
        );
    }
}
