use std::str::FromStr;

use actix_session::Session;
use actix_web::web::Query;
use actix_web::{get, HttpResponse};
use num::BigUint;
use rand::RngCore;
use serde::Deserialize;

use cryptopals::cyphers::aes::cbc;
use cryptopals::encoding::hex::Hex;
use cryptopals::encoding::Digest;
use cryptopals::kex::diffie_hellman;

#[derive(Deserialize)]
pub(crate) struct EncryptedMessage {
    hex: String,
}

#[derive(Deserialize)]
pub(crate) struct DiffieHellman {
    p: String,
    g: String,
    A: String,
}

#[get("/challenge34-mitm-kex")]
pub(crate) async fn exchange_keys_mitm(
    key_params: Query<DiffieHellman>,
    session: Session,
) -> HttpResponse {
    let client = reqwest::ClientBuilder::new()
        .cookie_store(true)
        .build()
        .expect("building failed");

    let p = &key_params.p;
    let g = &key_params.g;

    let response = client
        .get(format!(
            "http://127.0.0.1:8080/challenge34-kex?p={p}&g={g}&A={p}"
        ))
        .send()
        .await
        .expect("invalid request")
        .text()
        .await
        .expect("body not_text");
    let key = parse_string_to_big_uint(&response);

    let p_big_uint = parse_string_to_big_uint(p);
    let session_key = diffie_hellman::generate_secret_key(&p_big_uint, &key, &p_big_uint, 16);

    session
        .insert("enc_key", session_key)
        .expect("session insertion failed");
    HttpResponse::Ok().body(p.to_string())
}

#[get("/challenge34-mitm-message")]
pub(crate) async fn exchange_message_mitm(
    message: Query<EncryptedMessage>,
    session: Session,
) -> HttpResponse {
    let secret_key = session
        .get::<Vec<u8>>("enc_key")
        .expect("session retrieval failed")
        .expect("key storage failed");

    let message = Hex::from_str(&message.hex)
        .expect("invalid hex received")
        .bytes()
        .to_vec();

    let (message, iv) = message.split_at(message.len() - 16);

    let plain_text = cbc::decrypt(&message, &secret_key, iv);
    println!(
        "received: {}",
        String::from_utf8(plain_text.clone()).unwrap()
    );

    let iv = {
        let mut bytes = [0; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    };

    // to fully complete challenge 34 at this point the message should also be passed to the challenge34-message endpoint (doctored if needed)
    // since reqwest client isn't serialisable that requires repeating the logic in exchange_key_mitm which is a bit tedious so omitted

    let mut response = cbc::encrypt(&plain_text, &secret_key, &iv);
    response.extend_from_slice(&iv);
    let response = Hex::new(&response);

    HttpResponse::Ok().body(response.to_string())
}

#[get("/challenge34-kex")]
pub(crate) async fn exchange_keys(
    key_params: Query<DiffieHellman>,
    session: Session,
) -> HttpResponse {
    let p = parse_string_to_big_uint(&key_params.p);
    let g = parse_string_to_big_uint(&key_params.g);
    let A = parse_string_to_big_uint(&key_params.A);
    let rand = BigUint::from(rand::thread_rng().next_u32());
    let public_key = diffie_hellman::generate_public_key(&p, &g, &rand);

    let session_key = diffie_hellman::generate_secret_key(&A, &rand, &p, 16);

    session
        .insert("enc_key", session_key)
        .expect("session insertion failed");

    let public_key_hex = Hex::new(&public_key.to_bytes_be());
    HttpResponse::Ok().body(public_key_hex.to_string())
}

#[get("/challenge34-message")]
pub(crate) async fn exchange_message(
    message: Query<EncryptedMessage>,
    session: Session,
) -> HttpResponse {
    let secret_key = session
        .get::<Vec<u8>>("enc_key")
        .expect("session retrieval failed")
        .expect("key storage failed");

    let message = Hex::from_str(&message.hex)
        .expect("invalid hex received")
        .bytes()
        .to_vec();

    let (message, iv) = message.split_at(message.len() - 16);

    let plain_text = cbc::decrypt(&message, &secret_key, iv);
    println!(
        "received: {}",
        String::from_utf8(plain_text.clone()).unwrap()
    );

    let iv = {
        let mut bytes = [0; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    };

    let mut response = cbc::encrypt(&plain_text, &secret_key, &iv);
    response.extend_from_slice(&iv);
    let response = Hex::new(&response);

    HttpResponse::Ok().body(response.to_string())
}

fn parse_string_to_big_uint(hex_rep: &str) -> BigUint {
    let hex = Hex::from_str(hex_rep).expect("invalid hex string");
    BigUint::from_bytes_be(hex.bytes())
}
