use crate::cyphers::aes::{self, ecb};
use crate::encoding::Digest;

pub struct EncryptedMessage {
    pub cipher_text: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub fn encrypt<T: Digest>(plain_text: &T, key: &[u8], nonce: &[u8]) -> EncryptedMessage {
    let cipher_text = plain_text
        .bytes()
        .chunks(16)
        .enumerate()
        .flat_map(|(count, block)| {
            block
                .iter()
                .zip(ecb::encrypt(
                    key,
                    [nonce, &count.to_le_bytes()[..]].concat(),
                ))
                .map(|(x, y)| x ^ y)
                .collect::<Vec<u8>>()
        })
        .collect();

    let nonce = nonce.to_vec();
    EncryptedMessage { cipher_text, nonce }
}

pub fn decrypt(cipher_text: &EncryptedMessage, key: &[u8]) -> Vec<u8> {
    encrypt(&cipher_text.cipher_text, key, &cipher_text.nonce).cipher_text
}
