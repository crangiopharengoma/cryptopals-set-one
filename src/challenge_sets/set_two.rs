use std::collections::HashMap;

use cryptopals::cyphers::encryption_oracle::{AesMode, ECBOracle};
use cryptopals::cyphers::{aes_cbc, encryption_oracle, padding};
use cryptopals::encoding::base64::Base64;
use cryptopals::encoding::Digest;

pub fn run() {
    print!("Starting Challenge Nine... ");
    challenge_nine();
    println!("Success!");

    print!("Starting Challenge Ten... ");
    challenge_ten();
    println!("Success!");

    print!("Starting Challenge Eleven... ");
    challenge_eleven();
    println!("Success!");

    println!("Starting Challenge Twelve... ");
    challenge_twelve();
    println("Success!");
}

/// https://cryptopals.com/sets/2/challenges/9
fn challenge_nine() {
    let plain_text = "YELLOW SUBMARINE";
    let target_len = 20;
    let expected_padded = "YELLOW SUBMARINE\x04\x04\x04\x04";

    let padded = padding::pkcs7(plain_text.as_bytes(), target_len);

    assert_eq!(expected_padded.as_bytes(), padded)
}

/// https://cryptopals.com/sets/2/challenges/10
fn challenge_ten() {
    let encrypted_message = Base64::from_file("10.txt").unwrap();

    let decrypted_message = aes_cbc::decrypt(
        encrypted_message.bytes(),
        "YELLOW SUBMARINE".as_bytes(),
        &[0b0; 16][..],
    );

    println!(
        "The message is: {}",
        String::from_utf8_lossy(&decrypted_message)
    );
}

/// https://cryptopals.com/sets/2/challenges/11
fn challenge_eleven() {
    let meaningless_jibber_jabber = "X".repeat(48).as_bytes().to_vec();

    (0..11).for_each(|_| {
        let encrypted_message = encryption_oracle::encrypt(&meaningless_jibber_jabber);
        let aes_type = encryption_oracle::detect_aes_type(encrypted_message);
        match aes_type {
            AesMode::CBC => println!("CBC encryption used"),
            AesMode::ECB => println!("ECB encryption used"),
        };
    })
}

/// https://cryptopals.com/sets/2/challenges/12
fn challenge_twelve() {
    let oracle = ECBOracle::new();
    let key_length = find_key_length(&oracle).expect("key length > 128");
    println!("key length is {}", key_length);

    let aes_mode = encryption_oracle::detect_aes_type(&oracle.encrypt("A".repeat(48).into_bytes()));
    assert_eq!(aes_mode, AesMode::ECB);

    let decrypted_message = decrypt_oracle(&oracle, key_length);

    print!(
        "The message is {}",
        String::from_utf8_lossy(&decrypted_message)
    );
}

fn decrypt_oracle(oracle: &ECBOracle, key_length: usize) -> Vec<u8> {
    let mut decrypted_message = Vec::new();
    let encrypted_message = oracle.encrypt("".as_bytes().to_vec());

    (1..encrypted_message.len()).for_each(|i| {
        let prefix = "A".repeat(prefix_length(i, key_length)).into_bytes();
        let known_bytes = [&prefix, &decrypted_message[..]].concat();
        let byte_map = last_byte_map(oracle, &known_bytes);
        let encrypted_message = oracle.encrypt(&prefix.to_vec());

        // if the decrypted message + key_length is more than the encrypted message then we've reached the end
        // there may be up to key_length - 1 extra padding bytes
        // this method will fall over at this point because the pkcs#7 padding standard means the decrypted byte is different
        // i.e. the first iteration will end '\x01', the second '\x02\x02' etc
        // potentially up to '\x15...\x15' if there are 15 bytes of padding in the message we are decrypting
        if decrypted_message.len() + key_length < encrypted_message.len() {
            decrypted_message.push(
                *byte_map
                    .get(&encrypted_message[..known_bytes.len() + 1])
                    .expect("no matching byte"),
            );
        }
    });
    decrypted_message
}

fn prefix_length(iteration: usize, key_length: usize) -> usize {
    let modulus = iteration % key_length;
    if modulus == 0 {
        0
    } else {
        key_length - modulus
    }
}

fn last_byte_map(oracle: &ECBOracle, known_bytes: &[u8]) -> HashMap<Vec<u8>, u8> {
    let last_byte_dict: HashMap<Vec<u8>, u8> = (0..255)
        .map(|i| {
            let mut last_byte_possibility = known_bytes.to_vec();
            last_byte_possibility.push(i);
            last_byte_possibility = oracle.encrypt(last_byte_possibility);
            last_byte_possibility.truncate(known_bytes.len() + 1);
            (last_byte_possibility, i)
        })
        .collect();
    last_byte_dict
}

fn find_key_length(oracle: &ECBOracle) -> Option<usize> {
    let mut key_length = None;
    (1..128).for_each(|i| {
        let test_message_a = "A".repeat(i).into_bytes();
        let encrypted_message_a = oracle.encrypt(test_message_a);

        let test_message_b = "A".repeat(i + 1).into_bytes();
        let encrypted_message_b = oracle.encrypt(test_message_b);

        if encrypted_message_b.len() > encrypted_message_a.len() {
            key_length = Some(encrypted_message_b.len() - encrypted_message_a.len());
        }
    });
    key_length
}
