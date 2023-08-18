use std::fs::File;
use std::path::Path;
use std::io::prelude::*;

use rsa::pss::{SigningKey, Signature};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::rand_core::OsRng;
use rsa::rand_core::RngCore;
use libaes::{Cipher, AES_256_KEY_LEN};
use rsa::sha2::Sha512;

use crate::manifest_models::{SingleEncryptedFile, Signable};
use crate::manifest_models::SingleEncryptedFilePiece;
use crate::results::JustError;

use super::results::SResult;


pub struct SymmetricCipher {
    // key: [u8; AES_256_KEY_LEN],
    cipher: Cipher,
    iv: Vec<u8>,
    pub file_part_size: u64,
}

impl SymmetricCipher {
    pub fn new(key: [u8; AES_256_KEY_LEN], iv: Vec<u8>) -> Self {
        Self { /*key: key,*/ cipher: Cipher::new_256(&key), iv: iv, file_part_size: 256*1024*1024 }
    }

    fn sign_buf<P: AsRef<Path>>(signer: &SigningKey<Sha512>, buf: &Vec<u8>, signature_path: P) -> SResult<()> {
        let signature: Signature = signer.sign_with_rng(&mut rsa::rand_core::OsRng, &buf);
        File::create(signature_path.as_ref())?.write(signature.to_bytes().as_ref())?;
        Ok(())
    }

    pub fn encrypt_file(&self, src: &Path, dst_dic: &Path, signer_opt: Option<&SigningKey<Sha512>>) -> SResult<SingleEncryptedFile> {
        let mut file_pieces = Vec::new();
        let mut file = File::open(src)?;
        let file_size = file.metadata().unwrap().len();
        let mut buf = Vec::new();
        file_pieces.reserve_exact((file_size/self.file_part_size) as usize + 1);
        for i in 0..file_size/self.file_part_size {
            buf.resize(self.file_part_size as usize, 0);
            file.read_exact(buf.as_mut()).unwrap();
            let mut file_piece = SingleEncryptedFilePiece::new(Box::from(dst_dic.join(format!("wrapper.{}", i)).as_path()));
            if let Some(signer) = signer_opt {
                file_piece.signed(dst_dic.join(format!("wrapper.{}.signature", i)).as_path());
                Self::sign_buf(signer, &buf, file_piece.get_signature_path().unwrap())?;
            }
            File::create(file_piece.get_path())?.write(self.cipher.cbc_encrypt(&self.iv, &buf).as_ref())?;
            file_pieces.push(file_piece);
        }
        if file_size%self.file_part_size != 0 {
            buf.clear();
            file.read_to_end(&mut buf).unwrap();
            let mut file_piece = SingleEncryptedFilePiece::new(Box::from(dst_dic.join(format!("wrapper.{}", file_size/self.file_part_size)).as_path()));
            if let Some(signer) = signer_opt {
                file_piece.signed(dst_dic.join(format!("wrapper.{}.signature", file_size/self.file_part_size)).as_path());
                Self::sign_buf(signer, &buf, file_piece.get_signature_path().unwrap())?;
            }
            File::create(file_piece.get_path())?.write(self.cipher.cbc_encrypt(&self.iv, &buf).as_ref())?;
            file_pieces.push(file_piece);
        }
        Ok(SingleEncryptedFile::new(src.file_name().ok_or(JustError::new("No file name!".to_owned()))?.to_os_string(), file_pieces))
    }
    
    pub fn get_256_key() -> SResult<[u8; 32]> {
        let mut key = [0; AES_256_KEY_LEN];
        OsRng.fill_bytes(&mut key);
        Ok(key)
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use rsa::sha2::Sha512;

    use crate::symmertic_cipher::SymmetricCipher;

    #[test]
    fn randomness_test() {
        assert_ne!(SymmetricCipher::get_256_key().unwrap(), SymmetricCipher::get_256_key().unwrap());
    }

    #[test]
    fn encryptiom_test() {
        let sc = SymmetricCipher::new(SymmetricCipher::get_256_key().expect("Symmetric key generation"), b"jsjsjsjsjsjsjsjs".to_vec());
        println!("{:?}", sc.encrypt_file(
            Path::new("test.zip"), Path::new("D:\\Pulpit I\\Igor\\C++\\Projects\\TheLock\\rust-crate\\the-lock\\test_tmp"),
            Some(&rsa::pss::SigningKey::<Sha512>::new(rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("Key generating")))).expect("File encryption"));
    }
}
