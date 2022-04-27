use std::collections::HashMap;

use openssl::rand as ssl_rand;
use rand::Rng;

use crate::cyphers::encryption_oracle::AesType::{CBC, ECB};
use crate::cyphers::{aes_cbc, aes_ecb};
use crate::encoding::Digest;

pub enum AesType {
    ECB,
    CBC,
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

pub fn detect_aes_type<T: Digest>(encrypted_message: T) -> AesType {
    if detect_aes_ecb(encrypted_message) {
        ECB
    } else {
        CBC
    }
}

/// Scans an encrypted message and guesses if it has been encrypted using aes_ecb with a 128 bit key
pub fn detect_aes_ecb<T: Digest>(encrypted_message: T) -> bool {
    let mut map: HashMap<&[u8], usize> = HashMap::new();
    encrypted_message.bytes().chunks(16).for_each(|chunk| {
        map.entry(chunk).and_modify(|e| *e += 1).or_insert(1);
    });
    // println!("ecb map {map:?}");
    *map.values()
        .reduce(|accum, val| if val > accum { val } else { accum })
        .unwrap()
        > 1
}
