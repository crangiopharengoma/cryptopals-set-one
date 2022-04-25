use openssl::symm::{Cipher, Crypter, Mode};

use crate::cyphers::padding;

pub(crate) fn decrypt_block(key: &[u8], cipher: Cipher, chunk: &[u8]) -> Vec<u8> {
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
