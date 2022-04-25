use openssl::error::ErrorStack;
use openssl::symm;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::cyphers::padding;
use crate::encoding::Digest;

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

pub(crate) fn decrypt_block(key: &[u8], chunk: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut decrypter =
        Crypter::new(cipher, Mode::Decrypt, key, None).expect("openssl failed to build Crypter");

    // padding is handled manually;
    decrypter.pad(false);

    let block_size = Cipher::aes_128_ecb().block_size();
    let input = padding::pkcs7(chunk, block_size);

    let mut decrypted_chunk = vec![0; chunk.len() + block_size];
    decrypter
        .update(&input, &mut decrypted_chunk)
        .expect("decryption update failed");

    decrypter
        .finalize(&mut decrypted_chunk[..])
        .expect("decryption finalize failed");

    decrypted_chunk.truncate(block_size);
    decrypted_chunk
}
