use std::str::FromStr;

use set_one::base64::Base64;
use set_one::hex::Hex;

fn main() {
    challenge_one();
    println!("challenge one success");

    challenge_two();
    println!("challenge two success");
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

    assert_eq!(expected_hex, hex_one.xor(&hex_two))
}
