use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::{rand, symm};

use crate::cyphers::padding;
use crate::encoding::Digest;

pub fn generate_key() -> [u8; 16] {
    let mut key = [0; 16];
    rand::rand_bytes(&mut key).expect("key generation failed");
    key
}

/// Uses a given key to decrypt a given message digest
///
/// Thin wrapper around the openssl::symm::decrypt function
pub fn try_decrypt<T: Digest>(key: &[u8], message: T) -> Result<Vec<u8>, ErrorStack> {
    symm::decrypt(Cipher::aes_128_ecb(), key, None, message.bytes())
}

/// Uses a given key to decrypt a given message digest
///
/// Panics if decryption fails for any reason
pub fn decrypt<T: Digest>(key: &[u8], message: T) -> Vec<u8> {
    try_decrypt(key, message).expect("decryption failed")
}

/// Uses a given key to decrypt a given message digest
///
/// Thin wrapper around the openssl:symm:encrypt function
pub fn try_encrypt<T: Digest>(key: &[u8], message: T) -> Result<Vec<u8>, ErrorStack> {
    symm::encrypt(Cipher::aes_128_ecb(), key, None, message.bytes())
}

/// Uses a given key to encrypt a given message digest
///
/// Panics if a encryption fails for any reason
pub fn encrypt<T: Digest>(key: &[u8], message: T) -> Vec<u8> {
    try_encrypt(key, message).expect("decryption failed")
}

pub(crate) fn decrypt_block(key: &[u8], block: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut decrypter =
        Crypter::new(cipher, Mode::Decrypt, key, None).expect("openssl failed to build Crypter");

    // padding will be handled manually;
    decrypter.pad(false);

    let block_size = cipher.block_size();
    let input = padding::pkcs7(block, block_size);

    let mut decrypted_block = vec![0; input.len() + block_size];
    decrypter
        .update(&input, &mut decrypted_block)
        .expect("decryption update failed");

    decrypter
        .finalize(&mut decrypted_block[..])
        .expect("decryption finalize failed");

    decrypted_block.truncate(block_size);
    decrypted_block
}

pub(crate) fn encrypt_block(key: &[u8], block: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    let mut encrypter =
        Crypter::new(cipher, Mode::Encrypt, key, None).expect("openssl failed to build Crypter");

    // padding will be handled manually;
    encrypter.pad(false);

    let block_size = cipher.block_size();
    let input = padding::pkcs7(block, block_size);

    let mut encrypted_block = vec![0; input.len() + block_size];

    encrypter
        .update(&input, &mut encrypted_block)
        .expect("encryption update failed");

    encrypter
        .finalize(&mut encrypted_block[..])
        .expect("encryption finalize failed");

    encrypted_block.truncate(block_size);
    encrypted_block
}
