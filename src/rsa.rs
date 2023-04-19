use openssl::{
    error::ErrorStack,
    rsa::{Padding, Rsa},
    symm::Cipher,
};
use std::{fs::File, io::Write, path::Path};

#[derive(Debug)]
pub struct RsaKeypair {
    pub public_key_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
}

impl RsaKeypair {
    pub fn new(passphrase: Option<&str>) -> Result<RsaKeypair, ErrorStack> {
        let rsa = Rsa::generate(4096)?;

        let private_key_pem = match passphrase {
            Some(passphrase) => {
                rsa.private_key_to_pem_passphrase(Cipher::aes_128_gcm(), passphrase.as_bytes())?
            }
            None => rsa.private_key_to_pem()?,
        };

        let public_key_pem = rsa.public_key_to_pem()?;

        Ok(RsaKeypair {
            public_key_pem,
            private_key_pem,
        })
    }

    pub fn save<P: AsRef<Path>>(
        &self,
        public_key_pem_path: P,
        private_key_pem_path: P,
    ) -> Result<(), std::io::Error> {
        let _ = File::create(public_key_pem_path)?.write(&self.public_key_pem)?;
        let _ = File::create(private_key_pem_path)?.write(&self.private_key_pem)?;

        Ok(())
    }
}

pub fn encrypt_data(
    data: &[u8],
    key_pair: &RsaKeypair,
    passphrase: Option<&str>,
) -> Result<Vec<u8>, ErrorStack> {
    let rsa = match passphrase {
        Some(passphrase) => {
            Rsa::private_key_from_pem_passphrase(&key_pair.private_key_pem, passphrase.as_bytes())?
        }
        None => Rsa::private_key_from_pem(&key_pair.private_key_pem)?,
    };

    let mut buffer = vec![0; rsa.size() as usize];
    rsa.private_encrypt(data, &mut buffer, Padding::PKCS1)?;

    Ok(buffer)
}

pub fn decrypt_data(data: &[u8], public_key_pem: Vec<u8>) -> Result<(usize, Vec<u8>), ErrorStack> {
    let rsa = Rsa::public_key_from_pem(&public_key_pem)?;

    let mut buffer = vec![0; rsa.size() as usize];

    let decrypted_bytes_count = rsa.public_decrypt(data, &mut buffer, Padding::PKCS1)?;

    Ok((decrypted_bytes_count, buffer))
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASSPHRASE: Option<&str> = Some("Hello, world!");

    #[test]
    fn test_generate_keypair() {
        let first_key_pair = RsaKeypair::new(PASSPHRASE).unwrap();
        let second_key_pair = RsaKeypair::new(PASSPHRASE).unwrap();

        assert_ne!(
            std::str::from_utf8(&first_key_pair.private_key_pem).unwrap(),
            std::str::from_utf8(&second_key_pair.private_key_pem).unwrap()
        );

        assert_ne!(
            std::str::from_utf8(&first_key_pair.public_key_pem).unwrap(),
            std::str::from_utf8(&second_key_pair.public_key_pem).unwrap()
        );
    }

    #[test]
    pub fn test_file_save() {
        let key_pair = RsaKeypair::new(PASSPHRASE).unwrap();

        key_pair.save("public_key.pem", "private_key.pem").unwrap();
    }

    #[test]
    pub fn test_encrypt_decrypt() {
        let key_pair = RsaKeypair::new(PASSPHRASE).unwrap();

        let data = Vec::from("Hello, world!");
        let encrypted = encrypt_data(&data, &key_pair, PASSPHRASE).unwrap();

        let (decrypted_bytes_count, decrypted) =
            decrypt_data(&encrypted, key_pair.public_key_pem).unwrap();

        assert_eq!(
            std::str::from_utf8(&data).unwrap(),
            std::str::from_utf8(&decrypted[..decrypted_bytes_count]).unwrap(),
        );
    }
}
