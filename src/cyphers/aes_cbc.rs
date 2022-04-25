use openssl::symm::Cipher;

use crate::cyphers::aes_ecb;

pub fn decrypt(encrypted_message: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    let mut last_block = iv;
    println!("decrypting");
    encrypted_message
        .chunks(16)
        .flat_map(|chunk| {
            let next_block = decrypt_block(key, cipher, last_block, chunk);
            last_block = chunk;
            next_block
        })
        .collect()
}

fn decrypt_block(key: &[u8], cipher: Cipher, last_block: &[u8], chunk: &[u8]) -> Vec<u8> {
    let decrypted_chunk = aes_ecb::decrypt_block(key, cipher, chunk);

    decrypted_chunk
        .iter()
        // pad with zero if less than 16 bytes; zip will cut off any excess padding
        .chain([0b0; 16].iter())
        .zip(last_block.iter())
        .map(|(x, y)| x ^ y)
        .collect()
}
