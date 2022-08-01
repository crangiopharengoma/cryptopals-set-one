use std::str::FromStr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openssl::rand as ssl_rand;
use rand::Rng;

use cryptopals::cyphers::aes::ctr;
use cryptopals::cyphers::aes::ctr::{CTRSampleEncryptions, EncryptedMessage};
use cryptopals::cyphers::aes::oracles::padding_oracle::{PaddingOracle, SamplePaddingOracle};
use cryptopals::cyphers::mersenne_twister::Encrypter;
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
    let encrypted_messages = encrypter.encrypt_messages_with_fixed_nonce("20.txt");

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
    let mt = MersenneTwister::default();

    // this will work regardless of how far through it's internal state is
    for _ in 0..20 {
        mt.extract_number();
    }

    let history = (0..624)
        .map(|_| {
            let number = mt.extract_number();
            MersenneTwister::untemper(number)
        })
        .collect();

    let mut spliced_mt = MersenneTwister::default();
    spliced_mt.splice(history);

    let actual_values: Vec<u32> = (0..624).map(|_| mt.extract_number()).collect();

    let predicted_values: Vec<u32> = (0..624).map(|_| spliced_mt.extract_number()).collect();

    actual_values
        .into_iter()
        .zip(predicted_values)
        .for_each(|(actual, prediction)| {
            if actual != prediction {
                println!("Prediction error: expected {actual} found {prediction}");
                assert!(false);
            }
        });

    println!("All predictions correct");
}

fn challenge_twenty_four() {
    let mt = MersenneTwister::from_timestamp();
    let seed = mt.extract_number() as u16;
    let mt_encrypter = Encrypter::new(seed);

    let len = rand::thread_rng().gen_range(20..40);
    let mut rand_bytes = [0; 40];
    ssl_rand::rand_bytes(&mut rand_bytes).expect("ssl random_bytes() failed");
    let message = {
        let message = rand_bytes[..len].to_vec();
        let message = String::from_utf8_lossy(&message);
        let known_text = "A".repeat(14);
        let mut message = message.to_string();
        message.push_str(known_text.as_str());
        message
    };

    let cipher_text = mt_encrypter.encrypt(message.as_bytes().to_vec());

    for potential_seed in 0..=u16::MAX {
        let mt_encrypter = Encrypter::new(potential_seed);
        let message = mt_encrypter.decrypt(cipher_text.clone());
        // This method assumes that the plain text being decrypted will always be valid utf-8
        if let Ok(message) = String::from_utf8(message) {
            let (unknown_text, known_text) = message.split_at(message.len() - 14);
            if known_text == "A".repeat(14).as_str() {
                println!("Seed was: {potential_seed}, unknown text is {unknown_text}");
                assert_eq!(seed, potential_seed);
                break;
            }
        }
    }

    let timestamp_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u16;

    let mt_encrypter = Encrypter::new(timestamp_now as u16);
    let mt = MersenneTwister::new(timestamp_now.into());
    let password_reset_token = mt_encrypter.encrypt(mt.extract_number().to_be_bytes().as_slice());

    for offset in 0..=u16::MAX {
        let potential_seed = timestamp_now - offset;
        let mt_encrypter = Encrypter::new(potential_seed);
        let mt = MersenneTwister::new(potential_seed.into());
        let potential_token = mt_encrypter.encrypt(mt.extract_number().to_be_bytes().as_slice());
        if potential_token == password_reset_token {
            println!("Password reset token encrypted by MT19937 stream cipher");
            assert_eq!(timestamp_now, potential_seed);
            return;
        }
    }
    // if we get here we've failed
    assert!(false);
}
