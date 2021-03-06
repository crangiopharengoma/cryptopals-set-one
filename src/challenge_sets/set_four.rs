use openssl::symm;
use openssl::symm::Cipher;

use cryptopals::cyphers::aes::ctr::CTRSampleEncryptions;
use cryptopals::cyphers::aes::oracles::cbc_oracle::CBCOracle;
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
