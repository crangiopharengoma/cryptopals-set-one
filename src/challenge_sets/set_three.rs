use std::str::FromStr;

use cryptopals::cyphers::aes::ctr;
use cryptopals::cyphers::aes::ctr::EncryptedMessage;
use cryptopals::cyphers::aes::oracles::padding_oracle::{PaddingOracle, SamplePaddingOracle};
use cryptopals::cyphers::vigenere;
use cryptopals::encoding::base64::Base64;
use cryptopals::encoding::Digest;

pub fn run() {
    print!("Starting Challenge Seventeen... ");
    challenge_seventeen();
    println!("Success!");

    print!("Starting Challenge Eighteen... ");
    challenge_eighteen();
    println!("Success!");

    print!("Starting Challenge Nineteen... ");
    challenge_nineteen();
    println!("Success!");

    print!("Starting Challenge Twenty... ");
    challenge_twenty();
    println!("Success!");

    print!("Starting Challenge Twenty-One... ");
    challenge_twenty_one();
    println!("Success!");

    println!("Starting Challenge Twenty-Two... ");
    challenge_twenty_two();
    println!("Success!");

    println!("Starting Challenge Twenty-Three... ");
    challenge_twenty_three();
    println!("Success!");

    println!("Starting Challenge Twenty-Four... ");
    challenge_twenty_four();
    println!("Success!");
}

/// https://cryptopals.com/sets/3/challenges/17
fn challenge_seventeen() {
    for _ in 0..=1 {
        let oracle = SamplePaddingOracle::new();
        let encryption = oracle.encrypt_rand();
        let decrypted = oracle.decrypt(&encryption);
        println!("result: {}", String::from_utf8_lossy(&decrypted));
    }
}

/// https://cryptopals.com/sets/3/challenges/18
fn challenge_eighteen() {
    let cipher_text = Base64::from_str(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
    )
    .unwrap()
    .bytes()
    .to_vec();
    let nonce: u64 = 0;
    let nonce = nonce.to_le_bytes().to_vec();
    let key = "YELLOW SUBMARINE".as_bytes();

    let encrypted = EncryptedMessage { cipher_text, nonce };

    let decrypted = ctr::decrypt(&encrypted, key);

    println!("Message is: {}", String::from_utf8_lossy(&decrypted));
}

///https://cryptopals.com/sets/3/challenges/19
fn challenge_nineteen() {
    println!("Challenge nineteen solution is a standalone binary");
    println!("To try the solution use 'cargo run --bin ctr-cracker'");
}

fn challenge_twenty() {
    let source_base64 = Base64::from_file_multi("20.txt").expect("failed to load file");
    let min_len = source_base64
        .iter()
        .min_by_key(|base64| base64.len())
        .expect("no min length found")
        .len();

    let cipher_texts: Vec<u8> = source_base64
        .clone()
        .into_iter()
        .flat_map(|mut base64| {
            base64.truncate(min_len);
            base64.bytes().to_vec()
        })
        .collect();

    let key = vigenere::brute_force_key(&cipher_texts, min_len);

    // removing the truncation should result in errors after min_len chars
    // In this case it doesn't seem to - I don't understand why yet
    let plain_texts: Vec<String> = source_base64
        .into_iter()
        .map(|base64| {
            let decrypted = vigenere::decrypt(base64, &key);
            String::from_utf8(decrypted)
                .expect("invalid utf-8 found")
                .to_string()
        })
        .collect();

    println!("plain_texts: {:#?}", plain_texts);
}

fn challenge_twenty_one() {
    assert!(false);
}

fn challenge_twenty_two() {
    assert!(false);
}

fn challenge_twenty_three() {
    assert!(false);
}

fn challenge_twenty_four() {
    assert!(false);
}
