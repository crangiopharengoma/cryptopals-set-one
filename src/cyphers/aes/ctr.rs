use crate::cyphers::aes::{ecb, get_random_bytes};
use crate::encoding::base64::Base64;
use crate::encoding::Digest;

const BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    pub cipher_text: Vec<u8>,
    pub nonce: u64,
}

pub fn encrypt<T: Digest>(plain_text: &T, key: &[u8], nonce: u64) -> EncryptedMessage {
    let cipher_text = plain_text
        .bytes()
        .chunks(BLOCK_SIZE)
        .enumerate()
        .flat_map(|(count, block)| {
            let encrypted = block
                .iter()
                .zip(ecb::encrypt(
                    key,
                    [&nonce.to_le_bytes(), &count.to_le_bytes()[..]].concat(),
                ))
                .map(|(x, y)| x ^ y)
                .collect::<Vec<u8>>();
            encrypted
        })
        .collect();

    EncryptedMessage { cipher_text, nonce }
}

pub fn decrypt(cipher_text: &EncryptedMessage, key: &[u8]) -> Vec<u8> {
    encrypt(&cipher_text.cipher_text, key, cipher_text.nonce).cipher_text
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

    pub fn decrypt(&self, cipher_text: EncryptedMessage) -> Vec<u8> {
        decrypt(&cipher_text, &self.key)
    }

    pub fn encrypt<T: Digest>(&self, plain_text: &T) -> EncryptedMessage {
        encrypt(plain_text, &self.key, rand::random())
    }

    pub fn edit<T: Digest>(
        &self,
        cipher_text: EncryptedMessage,
        offset: usize,
        new_text: &T,
    ) -> EncryptedMessage {
        let mut count = (offset / BLOCK_SIZE) as u64;
        let alignment = offset % BLOCK_SIZE;
        let aligned_text = [[0].repeat(alignment), new_text.bytes().to_vec()].concat();
        let nonce = cipher_text.nonce.to_le_bytes();
        let new_cipher_text: Vec<u8> = aligned_text
            .chunks(BLOCK_SIZE)
            .flat_map(|block| {
                let encrypted = block
                    .iter()
                    .zip(ecb::encrypt(
                        &self.key,
                        [&nonce, &count.to_le_bytes()[..]].concat(),
                    ))
                    .map(|(x, y)| x ^ y)
                    .collect::<Vec<u8>>();
                count += 1;
                encrypted
            })
            .collect();

        let (_, new_cipher_text) = new_cipher_text.split_at(alignment);

        let (prefix, rest) = cipher_text.cipher_text.split_at(offset);
        let (_, suffix) = rest.split_at(new_text.len());
        let new_cipher_text = [prefix, new_cipher_text, suffix].concat();

        EncryptedMessage {
            cipher_text: new_cipher_text,
            nonce: cipher_text.nonce,
        }
    }

    pub fn encrypt_messages_with_fixed_nonce(&self, file_path: &str) -> Vec<EncryptedMessage> {
        let messages = Base64::from_file_multi(file_path).unwrap();
        messages
            .into_iter()
            .map(|plain_text| encrypt(&plain_text, &self.key, 0))
            .collect()
    }
}
