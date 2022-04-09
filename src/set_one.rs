use std::fs;
use std::str::FromStr;

use cryptopals::base64::Base64;
use cryptopals::cyphers::{caesar_cypher, repeating_key_xor};
use cryptopals::hex::Hex;
use cryptopals::string_heuristics;

pub fn set_one() {
    print!("challenge one beginning... ");
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
    let hex = Hex::from_str("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();

    let key = caesar_cypher::find_key(hex.raw_bytes());
    if let Some(key) = key {
        let decoded = caesar_cypher::decrypt(hex.raw_bytes(), key);
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
            let key = caesar_cypher::find_key(hex.raw_bytes());
            // may be None if line is empty, in which case we can just continue
            if let Some(key) = key {
                let decrypted = caesar_cypher::decrypt(hex.raw_bytes(), key);
                let score = string_heuristics::score_suspected_string(&decrypted);
                if score > highest_score {
                    highest_score = score;
                    decrypted_message = decrypted;
                }
            }
        }
    }

    println!("The message is: {}", String::from_utf8_lossy(&decrypted_message));
}

fn challenge_five() {}