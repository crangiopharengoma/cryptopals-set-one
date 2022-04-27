use cryptopals::cyphers::encryption_oracle::AesType;
use cryptopals::cyphers::{aes_cbc, encryption_oracle, padding};
use cryptopals::encoding::base64::Base64;
use cryptopals::encoding::Digest;

pub fn run() {
    print!("Starting Challenge Nine... ");
    challenge_nine();
    println!("Success!");

    print!("Starting Challenge Ten... ");
    challenge_ten();
    println!("Success!");

    print!("Starting Challenge Eleven... ");
    challenge_eleven();
    println!("Success!");
}

/// https://cryptopals.com/sets/2/challenges/9
fn challenge_nine() {
    let plain_text = "YELLOW SUBMARINE";
    let target_len = 20;
    let expected_padded = "YELLOW SUBMARINE\x04\x04\x04\x04";

    let padded = padding::pkcs7(plain_text.as_bytes(), target_len);

    assert_eq!(expected_padded.as_bytes(), padded)
}

/// https://cryptopals.com/sets/2/challenges/10
fn challenge_ten() {
    let encrypted_message = Base64::from_file("10.txt").unwrap();

    let decrypted_message = aes_cbc::decrypt(
        encrypted_message.bytes(),
        "YELLOW SUBMARINE".as_bytes(),
        &[0b0; 16][..],
    );

    println!(
        "The message is: {}",
        String::from_utf8_lossy(&decrypted_message)
    );
}

/// https://cryptopals.com/sets/2/challenges/11
fn challenge_eleven() {
    let meaningless_jibber_jabber = "X".repeat(48).as_bytes().to_vec();

    (0..11).for_each(|_| {
        let encrypted_message = encryption_oracle::encrypt(&meaningless_jibber_jabber);
        let aes_type = encryption_oracle::detect_aes_type(encrypted_message);
        match aes_type {
            AesType::CBC => println!("CBC encryption used"),
            AesType::ECB => println!("ECB encryption used"),
        };
    })
}
