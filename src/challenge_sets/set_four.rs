use std::time::Instant;

use openssl::symm;
use openssl::symm::Cipher;
use reqwest::StatusCode;

use cryptopals::cyphers::aes::ctr::CTRSampleEncryptions;
use cryptopals::cyphers::aes::oracles::cbc_oracle::CBCOracle;
use cryptopals::encoding::base64::Base64;
use cryptopals::encoding::hex::Hex;
use cryptopals::encoding::Digest;
use cryptopals::mac::{md4, sha_1};

pub fn run() {
    print!("Starting Challenge Twenty-Five... ");
    challenge_twenty_five();
    println!("Success!");

    print!("Starting Challenge Twenty-Six... ");
    challenge_twenty_six();
    println!("Success!");

    print!("Starting Challenge Twenty-Seven... ");
    challenge_twenty_seven();
    println!("Success!");

    print!("Starting Challenge Twenty-Eight... ");
    challenge_twenty_eight();
    println!("Success!");

    print!("Starting Challenge Twenty-Nine... ");
    challenge_twenty_nine();
    println!("Success!");

    print!("Starting Challenge Thirty... ");
    challenge_thirty();
    println!("Success!");

    print!("Starting Challenge Thirty-One... ");
    challenge_thirty_one();
    println!("Success!");

    print!("Starting Challenge Twenty-Two... ");
    challenge_thirty_two();
    println!("Success!");
}

pub fn challenge_twenty_five() {
    let input_text = Base64::from_file("25.txt").expect("error reading file");
    let key = "YELLOW SUBMARINE".as_bytes();
    let cipher = Cipher::aes_128_ecb();

    let plain_text =
        symm::decrypt(cipher, key, None, input_text.bytes()).expect("decryption failed");

    let encrypter = CTRSampleEncryptions::new();
    let cipher_text = encrypter.encrypt(&plain_text);

    let known_text = "A".repeat(cipher_text.cipher_text.len());
    let known_cipher = encrypter.edit(cipher_text.clone(), 0, &known_text.as_bytes());

    let key_stream: Vec<u8> = known_text
        .as_bytes()
        .to_vec()
        .iter()
        .zip(known_cipher.cipher_text.iter())
        .map(|(x, y)| x ^ y)
        .collect();

    let original_text: Vec<u8> = key_stream
        .iter()
        .zip(cipher_text.cipher_text.iter())
        .map(|(x, y)| x ^ y)
        .collect();

    let original_string = String::from_utf8_lossy(&original_text);

    println!("The original text was {original_string}");
}

pub fn challenge_twenty_six() {
    let oracle = CTRSampleEncryptions::new();
    let attack_text = ":admin?true".as_bytes().to_vec();

    let mut encrypted_message = oracle.bit_flip_demo(&attack_text);
    let mut cipher_text = encrypted_message.cipher_text;

    let semi_colon_mask = 0b_01;
    let equal_sign_mask = 0b_10;

    // Based on the structure of the prepended text and the attack text encrypted identify which bits to flip
    let positions = vec![(32, semi_colon_mask), (38, equal_sign_mask)];

    positions.into_iter().for_each(|(pos, mask)| {
        let target = cipher_text.remove(pos);
        let target = target ^ mask;
        cipher_text.insert(pos, target);
    });

    encrypted_message.cipher_text = cipher_text;
    assert!(oracle.bit_flip_success(encrypted_message));
}

pub fn challenge_twenty_seven() {
    let cbc_encrypter = CBCOracle::new();
    let message = "One block length".repeat(3);
    let mut cipher_text = cbc_encrypter.encrypt_key_is_iv(&message.as_bytes());

    let (block_one, _) = cipher_text.cipher_text.split_at(16);

    // strictly this should (probably) fail due invalid padding (since we don't know block_one ends with valid padding)
    // the cbc_oracle here doesn't check for valid padding (or strip it) because the padding_oracle::PaddingOracle demonstrates this
    let altered_text = [block_one, [0; 16].as_slice(), block_one].concat();
    cipher_text.cipher_text = altered_text;

    let result = cbc_encrypter.decrypt_and_validate(&cipher_text);

    let decrypted_key: Vec<u8> = match result {
        Ok(()) => {
            println!("Not an error");
            Vec::new()
        }
        Err(text) => {
            let (block_one, rest) = text.split_at(16);
            let (_, block_three) = rest.split_at(16);
            block_one
                .iter()
                .zip(block_three.iter())
                .map(|(x, y)| x ^ y)
                .collect()
        }
    };

    let actual_key = cbc_encrypter.key.to_vec();
    assert_eq!(decrypted_key, actual_key);
}

pub fn challenge_twenty_eight() {
    let encrypter = CBCOracle::new();
    let test_message = "this is a test";
    let mac = sha_1::generate_mac(&encrypter.key, test_message.as_bytes());

    let mut encrypted_message = encrypter.encrypt(test_message.as_bytes());
    let (block_one, _) = encrypted_message.cipher_text.split_at(16);

    // strictly this should (probably) fail due invalid padding (since we don't know block_one ends with valid padding)
    // the cbc_oracle here doesn't check for valid padding (or strip it) because the padding_oracle::PaddingOracle demonstrates this
    let altered_text = [block_one, [0; 16].as_slice(), block_one].concat();
    encrypted_message.cipher_text = altered_text;

    let decrypted = encrypter.decrypt(&encrypted_message);

    // if this is implemented correctly, this should return false;
    assert!(!sha_1::validate_mac(&encrypter.key, &decrypted, mac));
    println!("Tampered MAC detected!");
}

pub fn challenge_twenty_nine() {
    let encrypter = CTRSampleEncryptions::new();
    let test_message =
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let mac = sha_1::generate_mac(&encrypter.key, test_message.as_bytes());
    let encrypted_message = encrypter.encrypt(&test_message.as_bytes());

    // calculate the potential length (in bits) of the final message
    // since aes has three different key length specs, we'll try once with each
    let potential_lengths = [
        encrypted_message.cipher_text.len() + 16,
        encrypted_message.cipher_text.len() + 24,
        encrypted_message.cipher_text.len() + 32,
    ];

    let potential_macs: Vec<(Vec<u8>, [u8; 20])> = potential_lengths
        .into_iter()
        .map(|len| sha_1::forge_mac(len as u64, ";admin=true".as_bytes(), mac))
        .collect();

    for (appended_message, forged_mac) in potential_macs.into_iter() {
        let full_message = [test_message.as_bytes(), &appended_message].concat();
        if sha_1::validate_mac(&encrypter.key, &full_message, forged_mac) {
            println!("SHA1 Forged mac validated!");
            return;
        }
    }

    // returns early after mac successfully forged
    assert!(false, "Failed to forge SHA1 mac");
}

pub fn challenge_thirty() {
    let encrypter = CTRSampleEncryptions::new();
    let test_message =
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let mac = md4::generate_mac(&encrypter.key, test_message.as_bytes());
    let encrypted_message = encrypter.encrypt(&test_message.as_bytes());

    // calculate the potential length (in bits) of the final message
    // since aes has three different key length specs, we'll try once with each
    let potential_lengths = [
        encrypted_message.cipher_text.len() + 16,
        encrypted_message.cipher_text.len() + 24,
        encrypted_message.cipher_text.len() + 32,
    ];

    let potential_macs: Vec<(Vec<u8>, [u8; 16])> = potential_lengths
        .into_iter()
        .map(|len| md4::forge_mac(len as u64, ";admin=true".as_bytes(), mac))
        .collect();

    for (appended_message, forged_mac) in potential_macs.into_iter() {
        let full_message = [test_message.as_bytes(), &appended_message].concat();
        if md4::validate_mac(&encrypter.key, &full_message, forged_mac) {
            println!("MD4 Forged mac validated!");
            return;
        }
    }

    // returns early after mac successfully forged
    assert!(false, "Failed to forge MD4 mac");
}

pub fn challenge_thirty_one() {
    let message = "foo";
    let mut hmac = [0; 20];

    for pos in 0..20 {
        for hmac_component in 0..=u8::MAX {
            if hmac_component == 0 {
                println!("current hmac: {hmac:?}")
            }
            hmac[pos] = hmac_component;
            let hmac_hex = Hex::new(&hmac[..]);
            let url = format!(
                "http://127.0.0.1:8080/challenge31?file={}&signature={}",
                message,
                hmac_hex.to_string()
            );

            // println!("querying {url}");
            let start = Instant::now();
            let resp = reqwest::blocking::get(url).unwrap();
            let finish = start.elapsed();
            // println!("{:#?}", resp);

            if resp.status() == StatusCode::OK {
                println!("HMAC for {message} is {hmac:?}");
                return;
            }

            if resp.status() != StatusCode::INTERNAL_SERVER_ERROR {
                println!(
                    "Something unexpected went wrong: {} - {}",
                    resp.status().as_str(),
                    resp.text().unwrap_or(String::from("No text in response"))
                );
            }

            println!(
                "Position is {pos}, tested byte is {hmac_component} duration was {}, target was {}",
                finish.as_millis(),
                pos * 60 + 50
            );
            // since thread::sleep isn't millisecond perfect, add a couple of extra milliseconds here to avoid getting false positives
            if finish.as_millis() > (50 + pos * 60) as u128 {
                println!("Byte in {pos} is {hmac_component}");
                break;
            }
        }
    }

    assert!(false, "Failed to break HMAC");
}

pub fn challenge_thirty_two() {
    assert!(false);
}
