use std::str::FromStr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;

use cryptopals::cyphers::aes::ctr;
use cryptopals::cyphers::aes::ctr::{CTRSampleEncryptions, EncryptedMessage};
use cryptopals::cyphers::aes::oracles::padding_oracle::{PaddingOracle, SamplePaddingOracle};
use cryptopals::cyphers::vigenere;
use cryptopals::encoding::base64::Base64;
use cryptopals::encoding::Digest;
use cryptopals::random::mersenne_twister::MersenneTwister;

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

    let encrypter = CTRSampleEncryptions::new();
    let encrypted_messages = encrypter.encrypt_messages("20.txt");

    let cipher_text: Vec<u8> = encrypted_messages
        .clone()
        .into_iter()
        .flat_map(|mut cipher_text| {
            cipher_text.cipher_text.truncate(min_len);
            cipher_text.cipher_text
        })
        .collect();

    let key = vigenere::brute_force_key(&cipher_text, min_len);

    let plain_texts: Vec<String> = encrypted_messages
        .into_iter()
        .map(|mut encrypted_message| {
            encrypted_message.cipher_text.truncate(min_len);
            let decrypted = vigenere::decrypt(encrypted_message.cipher_text, &key);
            String::from_utf8(decrypted)
                .expect("invalid utf-8 found")
                .to_string()
        })
        .collect();

    println!("plain_texts: {:#?}", plain_texts);
}

fn challenge_twenty_one() {
    let mt = MersenneTwister::default();
    let mut numbers = Vec::new();
    (0..=5).for_each(|_| numbers.push(mt.extract_number()));
    println!("Here are some random numbers with the default seed: {numbers:?}");

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let mt = MersenneTwister::new(seed as u32);
    let mut numbers = Vec::new();
    (0..=5).for_each(|_| numbers.push(mt.extract_number()));
    println!("Here are some random numbers with a seed derived from the system clock: {numbers:?}");
}

fn challenge_twenty_two() {
    let secs = rand::thread_rng().gen_range(40..=1000);
    thread::sleep(Duration::from_secs(secs));

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let mt = MersenneTwister::new(seed as u32);
    let first_num = mt.extract_number();

    let secs = rand::thread_rng().gen_range(40..=1000);
    thread::sleep(Duration::from_secs(secs));

    // println!("The number is: {first_num}");

    let timestamp_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32;

    for offset in 0..=2_000_000 {
        let potential_timestamp = timestamp_now - offset;
        // println!("testing {potential_timestamp} seeking {}", seed as u32);
        let mt = MersenneTwister::new(potential_timestamp);
        let test_num = mt.extract_number();
        if first_num == test_num {
            println!("The seed was: {potential_timestamp}!");
            // lets prove that I got this right...
            assert_eq!(seed as u32, potential_timestamp);
            return;
        }
    }

    assert!(false);
}

fn challenge_twenty_three() {
    assert!(false);
}

fn challenge_twenty_four() {
    assert!(false);
}
