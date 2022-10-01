use std::str::FromStr;

use rand::RngCore;

use cryptopals::cyphers::aes;
use cryptopals::cyphers::aes::cbc;
use cryptopals::encoding::hex::Hex;
use cryptopals::encoding::Digest;
use cryptopals::kex::diffie_hellman;

pub fn run() {
    println!("Starting Challenge Thirty-Three ... ");
    challenge_thirty_three();
    println!("Success!");

    println!("Starting Challenge Thirty-Four ... ");
    challenge_thirty_four();
    println!("Success!");

    println!("Starting Challenge Thirty-Five ... ");
    challenge_thirty_five();
    println!("Success!");

    println!("Starting Challenge Thirty-Six ... ");
    challenge_thirty_six();
    println!("Success!");

    println!("Starting Challenge Thirty-Seven... ");
    challenge_thirty_seven();
    println!("Success!");

    println!("Starting Challenge Thirty-Eight... ");
    challenge_thirty_eight();
    println!("Success!");

    println!("Starting Challenge Thirty-Nine... ");
    challenge_thirty_nine();
    println!("Success!");

    println!("Starting Challenge Forty... ");
    challenge_forty();
    println!("Success!");
}

fn challenge_thirty_three() {
    let key = diffie_hellman::generate_session_key();
    println!("Session key: {key:?}");
}

fn challenge_thirty_four() {
    fn build_path(endpoint: &str) -> String {
        format!("http://127.0.0.1:8080/{endpoint}")
    }

    // Standard protocol
    dh_kex_then_send_message(
        build_path("challenge34-kex"),
        build_path("challenge34-message"),
    );

    // With MITM attack
    dh_kex_then_send_message(
        build_path("challenge34-mitm-kex"),
        build_path("challenge34-mitm-message"),
    )
}

fn dh_kex_then_send_message(kex_endpoint: String, message_endpoint: String) {
    let client = reqwest::blocking::ClientBuilder::new()
        .cookie_store(true)
        .build()
        .expect("building failed");

    let session_key = diffie_hellman::demo_key_exchange(&client, kex_endpoint);
    let plain_text = "This is a test message";

    let encrypted_message = {
        let iv = aes::get_random_bytes(16);
        let mut encrypted_message = cbc::encrypt(plain_text.as_bytes(), &session_key, &iv);
        encrypted_message.extend_from_slice(&iv);
        encrypted_message
    };

    let url = format!("{message_endpoint}?hex={}", Hex::new(&encrypted_message));

    let res = client.get(&url).send().expect("failed to receive response");
    let returned_message = Hex::from_str(&res.text().expect("response body not text"))
        .expect("invalid hex received")
        .bytes()
        .to_vec();

    let (message, iv) = returned_message.split_at(returned_message.len() - 16);
    let returned_plain_text = cbc::decrypt(&message, &session_key, iv);

    println!(
        "Exchanged keys and sent {}, and received {}",
        plain_text,
        String::from_utf8(returned_plain_text).unwrap()
    );
}

fn challenge_thirty_five() {
    panic!("not yet implemented")
}

fn challenge_thirty_six() {
    panic!("not yet implemented")
}

fn challenge_thirty_seven() {
    panic!("not yet implemented")
}

fn challenge_thirty_eight() {
    panic!("not yet implemented")
}

fn challenge_thirty_nine() {
    panic!("not yet implemented")
}

fn challenge_forty() {
    panic!("not yet implemented")
}
