use std::collections::HashMap;
use std::str::FromStr;

use openssl::rand as ssl_rand;
use rand::Rng;

use crate::cyphers::aes_ecb::generate_key;
use crate::cyphers::encryption_oracle::AesMode::{CBC, ECB};
use crate::cyphers::{aes_cbc, aes_ecb};
use crate::encoding::base64::Base64;
use crate::encoding::Digest;

fn prefix_length(iteration: usize, key_length: usize) -> usize {
    let modulus = iteration % key_length;
    if modulus == 0 {
        0
    } else {
        key_length - modulus
    }
}

#[derive(Debug, PartialEq)]
pub enum AesMode {
    ECB,
    CBC,
}

pub trait ECBOracle {
    fn encrypt<T: Digest>(&self, stimulus: T) -> Vec<u8>;

    /// Decrypts the message encoded by the oracle
    ///
    /// Assumptions:
    /// The oracle uses a consistent key and fixed length plain text
    ///
    /// The plain text may have arbitrary nonsense appended
    /// prior to the stimulus supplied by the encrypt method
    /// If so, this nonsense is always the same sequence of bytes
    /// (This method may still work if the value of the bytes changes,
    /// but the length remains the same, but this is not guaranteed
    ///
    fn decrypt(&self) -> Vec<u8> {
        let key_length = self.find_key_length().expect("key length > 128");
        let (known_byte_index, known_bytes_needed) = self.locate_known_bytes(key_length);

        let encrypted_message = self.encrypt("A".repeat(known_bytes_needed).as_bytes().to_vec());
        let junk_byte_length = known_byte_index + key_length;
        let target_decryption_length = encrypted_message.len() - junk_byte_length;
        let positioning_bytes = known_bytes_needed - key_length;

        let mut decrypted_message = Vec::new();
        (1..target_decryption_length).for_each(|i| {
            let prefix = "A"
                .repeat(positioning_bytes + prefix_length(i, key_length))
                .into_bytes();
            let known_bytes = [&prefix, &decrypted_message[..]].concat();
            let byte_map = self.last_byte_map(&known_bytes, known_byte_index, positioning_bytes);
            let encrypted_message = self.encrypt(&prefix.to_vec());

            // if the decrypted message + key_length is more than the encrypted message then we've reached the end
            // there may be up to key_length - 1 extra padding bytes
            // this method will fall over at this point because the pkcs#7 padding standard means the decrypted byte is different
            // i.e. the first iteration will end '\x01', the second '\x02\x02' etc
            if decrypted_message.len() + known_byte_index + key_length < encrypted_message.len() {
                decrypted_message.push(
                    *byte_map
                        .get(
                            &encrypted_message[known_byte_index
                                ..=(known_byte_index + (known_bytes.len() - positioning_bytes))],
                        )
                        .expect("no matching byte"),
                );
            }
        });
        decrypted_message
    }

    /// given a slice of known bytes, returns a map of slices with every possible byte appended
    /// map is keyed on the possible slices, the value being the appended byte
    fn last_byte_map(
        &self,
        known_bytes: &[u8],
        index: usize,
        positioning_bytes: usize,
    ) -> HashMap<Vec<u8>, u8> {
        (0..=255)
            .map(|i| {
                let mut last_byte_possibility = known_bytes.to_vec();
                last_byte_possibility.push(i);
                last_byte_possibility = self.encrypt(last_byte_possibility);
                last_byte_possibility = last_byte_possibility
                    [index..=(index + known_bytes.len() - positioning_bytes)]
                    .to_vec();
                (last_byte_possibility, i)
            })
            .collect()
    }

    /// Returns the index in the cipher text that represents the end of an unknown prefix,
    /// and the number of bytes stimulus required to pad that prefix to a a full block
    /// if used for an oracle that does not prepend a random byte sequence will return (0, 0)o
    ///
    /// Currently this method will never return if either the random byte sequence or the target
    /// cipher text contains duplicated blocks.
    /// Fixing this would require tracking the frequency of each duplicate block and tracking
    /// which one increases as the outer loop repeats
    ///
    fn locate_known_bytes(&self, key_length: usize) -> (usize, usize) {
        for i in 3.. {
            let known_bytes = "A".repeat(key_length * i).into_bytes();
            let encrypted_known_bytes = self.encrypt(known_bytes);
            let duplicate_blocks = encrypted_known_bytes.map_duplicate_blocks(key_length);

            // if only 1 duplicate, must be this and therefore complete
            if duplicate_blocks.len() == 1 {
                let (known_block, occurrences) = duplicate_blocks.into_iter().next().unwrap();
                // find last instance of encrypted known i
                let last_known_byte_index = encrypted_known_bytes
                    .chunks(key_length)
                    .enumerate()
                    .find(|(_, block)| block == &known_block)
                    .map(|(i, _)| i)
                    .unwrap()
                    * key_length;

                let mut known_bytes_needed = 0;
                for j in (0..(i * key_length)).rev() {
                    let known_bytes = "A".repeat(j).into_bytes();
                    let encrypted_known_bytes = self.encrypt(known_bytes);
                    let duplicate_blocks = encrypted_known_bytes.map_duplicate_blocks(key_length);

                    if duplicate_blocks.into_values().next().unwrap_or(0) < occurrences {
                        known_bytes_needed = j + 1;
                        known_bytes_needed -= (occurrences - 1) * key_length;
                        break;
                    }
                }

                return (last_known_byte_index, known_bytes_needed);
            }
        }

        // note; this is actually unreachable
        (0, 0)
    }
    /// finds the length of the key being used by the oracle
    /// Returns none if the key is longer than 128 bytes or if a block cypher is not used
    ///
    /// Panics
    /// If the encryption type is not ECB
    fn find_key_length(&self) -> Option<usize> {
        let mut key_length = None;
        (1..128).for_each(|i| {
            let test_message_a = "A".repeat(i).into_bytes();
            let encrypted_message_a = self.encrypt(test_message_a);

            let test_message_b = "A".repeat(i + 1).into_bytes();
            let encrypted_message_b = self.encrypt(test_message_b);

            if encrypted_message_b.len() > encrypted_message_a.len() {
                key_length = Some(encrypted_message_b.len() - encrypted_message_a.len());
            }
        });

        if let Some(length) = key_length {
            let aes_mode = detect_aes_type(self.encrypt("A".repeat(length * 3).into_bytes()));
            if aes_mode != ECB {
                panic!("ECBOracle not using ECB mode");
            }
        }

        key_length
    }
}

pub struct RandomPrefixECBOracle {
    key: [u8; 16],
    prefix: Vec<u8>,
    suffix: Base64,
}

impl Default for RandomPrefixECBOracle {
    fn default() -> Self {
        let key = generate_key();

        let prefix_length = rand::thread_rng().gen_range(1..=255);
        let mut prefix = vec![0; prefix_length];
        ssl_rand::rand_bytes(&mut prefix).expect("ssl rand failed");

        let suffix = Base64::from_str(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
        ).unwrap();

        RandomPrefixECBOracle {
            key,
            prefix,
            suffix,
        }
    }
}

impl ECBOracle for RandomPrefixECBOracle {
    fn encrypt<T: Digest>(&self, message: T) -> Vec<u8> {
        let message = [&self.prefix, message.bytes(), self.suffix.bytes()].concat();
        aes_ecb::encrypt(&self.key, message)
    }
}

impl RandomPrefixECBOracle {
    pub fn new() -> Self {
        RandomPrefixECBOracle::default()
    }
}

pub struct BasicECBOracle {
    key: [u8; 16],
}

impl Default for BasicECBOracle {
    /// Returns a new ECBOracle with a randomly generated 128 bit key
    fn default() -> Self {
        let key = generate_key();
        BasicECBOracle { key }
    }
}

impl ECBOracle for BasicECBOracle {
    /// Encrypts some plain text using ECB mode
    /// Randomly generates a key
    fn encrypt<T: Digest>(&self, message: T) -> Vec<u8> {
        let suffix = Base64::from_str(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
        ).unwrap();

        let final_message = [message.bytes(), suffix.bytes()].concat();
        aes_ecb::encrypt(&self.key, final_message)
    }
}

impl BasicECBOracle {
    /// Returns a new ECBOracle with a randomly generated 128 bit key
    pub fn new() -> Self {
        Self::default()
    }
}

/// Encrypts some plain text using a randomly generated 128 bit key
///
/// Randomly uses either aes_cbc or aes_ecb; if cbc randomly generates a 128 bit iv
pub fn encrypt<T: Digest>(message: T) -> Vec<u8> {
    let key = aes_ecb::generate_key();

    let plain_text = surround_with_random_bytes(message);

    if rand::thread_rng().gen_bool(0.50) {
        aes_ecb::encrypt(&key, plain_text)
    } else {
        // a key is 16 random bytes; an IV is the same
        let iv = aes_ecb::generate_key();
        aes_cbc::encrypt(&plain_text, &key, &iv)
    }
}

fn surround_with_random_bytes<T: Digest>(message: T) -> Vec<u8> {
    let plain_text = {
        let mut prefix = random_bytes();
        let suffix = random_bytes();

        prefix.extend_from_slice(message.bytes());
        prefix.extend_from_slice(&suffix);
        prefix
    };
    plain_text
}

fn random_bytes() -> Vec<u8> {
    let len = rand::thread_rng().gen_range(5..11);
    let mut rand_bytes = [0; 10];
    ssl_rand::rand_bytes(&mut rand_bytes).expect("encryption_oracle::random_bytes() failed");
    rand_bytes[..len].to_vec()
}

pub fn detect_aes_type<T: Digest>(encrypted_message: T) -> AesMode {
    if detect_aes_ecb(encrypted_message) {
        ECB
    } else {
        CBC
    }
}

/// Scans an encrypted message and guesses if it has been encrypted using aes_ecb with a 128 bit key
pub fn detect_aes_ecb<T: Digest>(encrypted_message: T) -> bool {
    encrypted_message.duplicate_blocks(16)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::cyphers::encryption_oracle::{BasicECBOracle, ECBOracle, RandomPrefixECBOracle};
    use crate::encoding::base64::Base64;
    use crate::encoding::Digest;

    #[test]
    fn unprefixed_oracle_decrypts() {
        let oracle = BasicECBOracle::new();
        let expected = Base64::from_str("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap().bytes().to_vec();

        let result = oracle.decrypt();

        assert_eq!(expected, result);
    }

    #[test]
    fn prefixing_oracle_decrypts() {
        let oracle = RandomPrefixECBOracle::new();
        let expected = Base64::from_str("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap().bytes().to_vec();

        let result = oracle.decrypt();

        assert_eq!(expected, result);
    }
}
