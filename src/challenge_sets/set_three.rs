use std::str::FromStr;

use cryptopals::cyphers::aes::ctr;
use cryptopals::cyphers::aes::ctr::EncryptedMessage;
use cryptopals::cyphers::aes::oracles::padding_oracle::{PaddingOracle, SamplePaddingOracle};
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
    assert!(false);
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
