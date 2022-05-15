use crate::cyphers::aes::{ecb, get_random_bytes};
use crate::encoding::base64::Base64;
use crate::encoding::Digest;

#[derive(Debug)]
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

pub struct CTRSampleEncryptions {
    key: Vec<u8>,
}

impl Default for CTRSampleEncryptions {
    fn default() -> Self {
        let key = get_random_bytes(16);
        CTRSampleEncryptions { key }
    }
}

impl CTRSampleEncryptions {
    pub fn new() -> Self {
        CTRSampleEncryptions::default()
    }

    pub fn encrypt<T: Digest>(&self, plain_text: &T, nonce: Vec<u8>) -> EncryptedMessage {
        encrypt(plain_text, &self.key, &nonce)
    }

    pub fn encrypt_messages(&self) -> Vec<EncryptedMessage> {
        let messages = Base64::from_file_multi("18.txt").unwrap();
        let nonce: u64 = 0;
        let nonce = nonce.to_le_bytes();
        messages
            .into_iter()
            .map(|plain_text| encrypt(&plain_text, &self.key, &nonce))
            .collect()
    }
}
