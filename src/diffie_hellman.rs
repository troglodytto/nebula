use crate::rsa::{decrypt_data, encrypt_data, RsaKeypair};
use num_primes::{BigUint, Generator};

/// Returns a large prime number and a generator
/// 2048-bit MODP Group with 256-bit Prime Order Subgroup
/// RFC 5114 Section 2.3
pub fn get_parameters() -> (BigUint, BigUint) {
    let prime = b"87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597";
    let generator = b"3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659";

    (
        BigUint::parse_bytes(prime, 16).expect("Failed to parse prime"),
        BigUint::parse_bytes(generator, 16).expect("Failed to parse primitive root"),
    )
}

/// Generates a random 512 bit Prime number to be used as a private key in DH
pub fn gen_private_key() -> BigUint {
    Generator::new_prime(512)
}

/// Generates a Key using the provided private key that can be shared across a public channel.
/// (G ^ Private Key) % P
pub fn gen_transfer_key(private_key: &BigUint) -> BigUint {
    let (p, g) = get_parameters();
    g.modpow(private_key, &p)
}

/// Encrypt the transfer key using RSA 4096, So that the reciever of the transfer key can guarantee that the sender of that key is
/// who they say they are by verifying it using [decrypt_transfer_key]
pub fn encrypt_transfer_key(
    transfer_key: &BigUint,
    rsa_keypair: &RsaKeypair,
    passphrase: Option<&str>,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    encrypt_data(&transfer_key.to_bytes_be(), rsa_keypair, passphrase)
}

/// Decrypt the recived encrypted transfer key that has been encryted using [encrypt_transfer_key] by using the public part of the sender's RSA key
pub fn decrypt_transfer_key(
    encrypted_transfer_key: Vec<u8>,
    rsa_public_key_pem: Vec<u8>,
) -> Result<BigUint, openssl::error::ErrorStack> {
    let (decrypted_bytes_count, decrypted_data) =
        decrypt_data(&encrypted_transfer_key, rsa_public_key_pem)?;

    Ok(BigUint::from_bytes_be(
        &decrypted_data[..decrypted_bytes_count],
    ))
}

/// Calculates a shared secret using self private key and recived transfer key
pub fn gen_shared_secret(self_key: &BigUint, transfer_key: &BigUint, prime: &BigUint) -> BigUint {
    transfer_key.modpow(self_key, prime)
}

#[cfg(test)]
mod tests {

    use crate::{
        diffie_hellman::{
            decrypt_transfer_key, encrypt_transfer_key, gen_private_key, gen_shared_secret,
            gen_transfer_key, get_parameters,
        },
        rsa::RsaKeypair,
    };

    #[test]
    fn test_get_parameters() {
        let (prime, generator) = get_parameters();
        assert_eq!(64, prime.to_u32_digits().len());
        assert_eq!(64, generator.to_u32_digits().len());
    }

    #[test]
    fn test_generate_public_key() {
        let alice_private_key = gen_private_key();
        let alice_rsa_keypair = RsaKeypair::new(None).unwrap();
        let alice_transfer_key = encrypt_transfer_key(
            &gen_transfer_key(&alice_private_key),
            &alice_rsa_keypair,
            None,
        )
        .unwrap();

        let bob_rsa_keypair = RsaKeypair::new(None).unwrap();
        let bob_private_key = gen_private_key();
        let bob_transfer_key =
            encrypt_transfer_key(&gen_transfer_key(&bob_private_key), &bob_rsa_keypair, None)
                .unwrap();

        let bob_recieved_key =
            decrypt_transfer_key(alice_transfer_key, alice_rsa_keypair.public_key_pem).unwrap();

        let alice_recieved_key =
            decrypt_transfer_key(bob_transfer_key, bob_rsa_keypair.public_key_pem).unwrap();

        let (p, _) = get_parameters();

        let alice_shared_secret = gen_shared_secret(&alice_private_key, &alice_recieved_key, &p);
        let bob_shared_secret = gen_shared_secret(&bob_private_key, &bob_recieved_key, &p);

        assert_eq!(alice_shared_secret, bob_shared_secret);
    }
}
