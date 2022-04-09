use std::str::FromStr;

use cryptopals::{caesar_cypher, string_heuristics};
use cryptopals::base64::Base64;
use cryptopals::hex::Hex;

pub fn set_one() {
    challenge_one();
    println!("challenge one success");

    challenge_two();
    println!("challenge two success");

    challenge_three();
    println!("challenge three success");
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
        println!("Challenge 3 solution: The message is: {}", String::from_utf8_lossy(&decoded));
    } else {
        println!("No key found; message not encrypted by single-character xor")
    }
}