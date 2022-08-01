use openssl::symm;
use openssl::symm::Cipher;

use cryptopals::cyphers::aes::ctr::{encrypt, CTRSampleEncryptions};
use cryptopals::encoding::base64::Base64;
use cryptopals::encoding::Digest;

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

    println!("Starting Challenge Thirty... ");
    challenge_thirty();
    println!("Success!");

    println!("Starting Challenge Thirty-One... ");
    challenge_thirty_one();
    println!("Success!");

    println!("Starting Challenge Twenty-Two... ");
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
    assert!(false);
}

pub fn challenge_twenty_seven() {
    assert!(false);
}

pub fn challenge_twenty_eight() {
    assert!(false);
}

pub fn challenge_twenty_nine() {
    assert!(false);
}

pub fn challenge_thirty() {
    assert!(false);
}

pub fn challenge_thirty_one() {
    assert!(false);
}

pub fn challenge_thirty_two() {
    assert!(false);
}
