use std::collections::HashMap;
use std::fs;
use std::str::FromStr;

use openssl::symm;
use openssl::symm::Cipher;

use cryptopals::cyphers::{caesar_cypher, vigenere};
use cryptopals::encoding::base64::Base64;
use cryptopals::encoding::hex::Hex;
use cryptopals::encoding::Digest;

pub fn run() {
    print!("Challenge one beginning... ");
    challenge_one();
    println!("Success!");

    print!("Challenge two beginning... ");
    challenge_two();
    println!("Success!");

    print!("Challenge three beginning... ");
    challenge_three();
    println!("Success!");

    print!("Challenge four beginning... ");
    challenge_four();
    println!("Success!");

    print!("Challenge five beginning... ");
    challenge_five();
    println!("Success!");

    print!("Challenge six beginning... ");
    challenge_six();
    println!("Success!");

    print!("Challenge seven beginning... ");
    challenge_seven();
    println!("Success!");

    print!("Challenge eight beginning... ");
    challenge_eight();
}

fn challenge_one() {
    let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let hex_input = Hex::from_str(hex_str).unwrap();
    let base64_expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let base64_converted = Base64::from_hex(hex_input);

    assert_eq!(base64_expected, base64_converted.to_string());
}

fn challenge_two() {
    let hex_one = Hex::from_str("1c0111001f010100061a024b53535009181c").unwrap();
    let hex_two = Hex::from_str("686974207468652062756c6c277320657965").unwrap();
    let expected_hex = Hex::from_str("746865206b696420646f6e277420706c6179").unwrap();

    assert_eq!(expected_hex, hex_one ^ hex_two)
}

fn challenge_three() {
    let hex = Hex::from_str("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        .unwrap();

    let key = caesar_cypher::find_key(&hex);
    if let Some(key) = key {
        let decoded = caesar_cypher::decrypt(&hex, key);
        println!("The message is: {}", String::from_utf8_lossy(&decoded));
    } else {
        println!("No key found; message not encrypted by single-character xor")
    }
}

fn challenge_four() {
    let possible_messages = fs::read_to_string("4.txt").expect("file read failed");

    let mut highest_score = 0;
    let mut decrypted_message = Vec::new();
    for line in possible_messages.lines() {
        let hex = Hex::from_str(line);
        // may be Err if invalid hex, in which case we should just continue since
        // it's not valid data (in the scope of challenge 4)
        if let Ok(hex) = hex {
            let key = caesar_cypher::find_key(&hex);
            // may be None if line is empty, in which case we can just continue
            if let Some(key) = key {
                let decrypted = caesar_cypher::decrypt(&hex, key);
                let score = decrypted.english_score();
                if score > highest_score {
                    highest_score = score;
                    decrypted_message = decrypted;
                }
            }
        }
    }

    println!(
        "The message is: {}",
        String::from_utf8_lossy(&decrypted_message)
    );
}

fn challenge_five() {
    // it looks like the supplied encryption was down with unix line endings, so altered string to enforce that here
    let plain_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        .as_bytes()
        .to_vec();
    let key = "ICE".as_bytes();
    let expected_encrypted = Hex::from_str("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();

    let encrypted = vigenere::encrypt(&plain_text, key);

    assert_eq!(expected_encrypted.bytes(), encrypted);
}

fn challenge_six() {
    let encrypted_message = Base64::from_file("6.txt").expect("failed to read file");
    let decrypted_message = vigenere::break_encryption(&encrypted_message);

    println!(
        "The message is: {}",
        String::from_utf8_lossy(&decrypted_message)
    );
}

fn challenge_seven() {
    let encrypted_message = Base64::from_file("7.txt").expect("failed to read file");
    let key = "YELLOW SUBMARINE".as_bytes();
    let cipher = Cipher::aes_128_ecb();

    let decrypted_message =
        symm::decrypt(cipher, key, None, encrypted_message.bytes()).expect("decryption failed");

    println!(
        "The message is: {}",
        String::from_utf8_lossy(&decrypted_message)
    );
}

/// https://cryptopals.com/sets/1/challenges/8
fn challenge_eight() {
    let hex_strings = fs::read_to_string("8.txt").expect("failed to read file");
    let hexes: Vec<Hex> = hex_strings
        .lines()
        .map(|line| Hex::from_str(line).unwrap())
        .collect();

    let ecb_encrypted = hexes
        .iter()
        .max_by_key(|hex| {
            let mut map: HashMap<&[u8], usize> = HashMap::new();
            hex.bytes().chunks(16).for_each(|chunk| {
                map.entry(chunk).and_modify(|e| *e += 1).or_insert(1);
            });
            *map.values()
                .reduce(|accum, val| if val > accum { val } else { accum })
                .unwrap()
        })
        .unwrap();

    println!("ECB encrypted hex is: {:?}", ecb_encrypted);
}
