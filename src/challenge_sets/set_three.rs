use std::io;
use std::str::FromStr;

use cryptopals::cyphers::aes::ctr;
use cryptopals::cyphers::aes::ctr::{CTRSampleEncryptions, EncryptedMessage};
use cryptopals::cyphers::aes::oracles::padding_oracle::{PaddingOracle, SamplePaddingOracle};
use cryptopals::encoding::base64::Base64;
use cryptopals::encoding::Digest;

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
    let encrypter = CTRSampleEncryptions::new();
    let messages = encrypter.encrypt_messages();

    // messages.iter().for_each(|message| {
    //     println!(
    //         "encrypted: {}, bytes {:?}",
    //         String::from_utf8_lossy(&message.cipher_text),
    //         message.cipher_text
    //     );
    // });

    let mut transposed: Vec<Vec<u8>> = Vec::new();
    messages.iter().enumerate().for_each(|(count, message)| {
        message.cipher_text.iter().for_each(|byte| {
            let position_vec = transposed.get_mut(count);
            match position_vec {
                Some(position_vec) => {
                    position_vec.push(*byte);
                }
                None => {
                    let position_vec = vec![*byte];
                    transposed.push(position_vec);
                }
            }
        })
    });

    let mut suspected_key_stream: Vec<u8> = Vec::with_capacity(transposed.len());
    let control_message = &messages
        .iter()
        .max_by_key(|message| message.cipher_text.len())
        .unwrap()
        .cipher_text;
    let mut count = 0;
    loop {
        println!("guess a/some char(s)");
        let mut guess = String::new();

        io::stdin()
            .read_line(&mut guess)
            .expect("Failed to read line");

        let guess = guess.trim();
        let guess_as_bytes = guess.as_bytes().to_vec();
        let mut guessed_key_values = control_message[count..]
            .iter()
            .zip(guess_as_bytes.iter())
            .map(|(x, y)| x ^ y)
            .collect();
        suspected_key_stream.append(&mut guessed_key_values);

        println!("This is what your guess looks like: ");

        messages.iter().enumerate().for_each(|(count, message)| {
            let decrypted: Vec<u8> = message
                .cipher_text
                .clone()
                .iter()
                .zip(&suspected_key_stream)
                .map(|(x, y)| x ^ y)
                .collect();
            println!("Message {count} is {}", String::from_utf8_lossy(&decrypted));
        });

        println!("Are you happy with this?");

        let mut guess = String::new();
        io::stdin()
            .read_line(&mut guess)
            .expect("Failed to read line");

        if guess.trim() == "yes" {
            count += guess_as_bytes.len();
            if (count + 1) == control_message.len() {
                println!("You've broken the code!");
                break;
            } else {
                println!("Great! On to the next letter!");
            }
        } else {
            suspected_key_stream.truncate(count);
            println!("Lets try again");
        }
    }
}

fn challenge_twenty() {
    assert!(false);
}

fn challenge_twenty_one() {
    assert!(false);
}

fn challenge_twenty_two() {
    assert!(false);
}

fn challenge_twenty_three() {
    assert!(false);
}

fn challenge_twenty_four() {
    assert!(false);
}
