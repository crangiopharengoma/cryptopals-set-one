use std::str::FromStr;

use rand::Rng;

use crate::cyphers::aes::oracles::cbc_oracle::EncryptionResult;
use crate::cyphers::aes::{self, cbc};
use crate::cyphers::padding::pkcs7;
use crate::encoding::base64::Base64;
use crate::encoding::Digest;

fn calculate_padding_iv(block_length: usize, flipped_block: &mut [u8; 16], i: usize) -> [u8; 16] {
    let target_byte = block_length - i;
    let padding_iv: Vec<u8> = flipped_block
        .iter_mut()
        .zip(
            vec![
                vec![0; block_length - target_byte + 1],
                vec![target_byte as u8; target_byte - 1],
            ]
            .into_iter()
            .flatten()
            .into_iter(),
        )
        .map(|(x, y)| *x ^ y)
        .collect();
    padding_iv.try_into().unwrap()
}

pub trait PaddingOracle {
    fn is_valid_padding(&self, message: &EncryptionResult) -> bool;

    fn decrypt(&self, encrypted: &EncryptionResult) -> Vec<u8> {
        let cipher_text = encrypted.cipher_text.clone();
        let mut last_block = encrypted.iv.to_vec();
        let block_length = last_block.len();

        let mut decrypted = Vec::new();
        cipher_text.chunks(block_length).for_each(|block| {
            let mut zero_iv = [0; 16];
            for i in (0..16).rev() {
                let mut padding_iv = calculate_padding_iv(block_length, &mut zero_iv, i);
                *zero_iv.get_mut(i).unwrap() =
                    self.find_dec_key_value(block, 16, &mut padding_iv, i);
            }
            let mut decrypted_block: Vec<u8> = zero_iv
                .iter()
                .zip(last_block.iter())
                .map(|(x, y)| x ^ y)
                .collect();
            decrypted.append(&mut decrypted_block);
            last_block = block.to_vec()
        });

        pkcs7::try_unpad(&decrypted, block_length).unwrap()
    }

    fn find_dec_key_value(
        &self,
        cipher_text: &[u8],
        block_length: usize,
        iv: &mut [u8; 16],
        index: usize,
    ) -> u8 {
        for i in 0..=255 {
            *iv.get_mut(index).unwrap() = i;
            let trial_message = EncryptionResult {
                cipher_text: cipher_text.to_vec(),
                iv: *iv,
            };
            if self.is_valid_padding(&trial_message) {
                if index == 0 {
                    return i ^ (block_length - index) as u8;
                } else {
                    *iv.get_mut(index - 1).unwrap() = 1;
                    let trial_message = EncryptionResult {
                        cipher_text: cipher_text.to_vec(),
                        iv: *iv,
                    };
                    if self.is_valid_padding(&trial_message) {
                        return i ^ (block_length - index) as u8;
                    }
                    *iv.get_mut(index - 1).unwrap() = 0;
                }
            }
        }

        // we'll only get here if the target oracle is not using cbc/validating padding
        panic!("invalid padding oracle");
    }
}

pub struct SamplePaddingOracle {
    key: [u8; 16],
}

impl PaddingOracle for SamplePaddingOracle {
    fn is_valid_padding(&self, message: &EncryptionResult) -> bool {
        let message = cbc::decrypt(&message.cipher_text, &self.key, &message.iv);
        let unpadded = pkcs7::try_unpad(&message, self.key.len());
        unpadded.is_ok()
    }
}

impl Default for SamplePaddingOracle {
    fn default() -> Self {
        let key = aes::generate_16_bit_key();
        SamplePaddingOracle { key }
    }
}

impl SamplePaddingOracle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encrypt_rand(&self) -> EncryptionResult {
        let strings = vec![
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ];

        let selection = strings
            .get(rand::thread_rng().gen_range(0..strings.len()))
            .unwrap();
        let decoded = Base64::from_str(selection).unwrap();
        let iv = aes::generate_16_bit_key();

        EncryptionResult {
            cipher_text: cbc::encrypt(decoded.bytes(), &self.key, &iv),
            iv,
        }
    }
}
