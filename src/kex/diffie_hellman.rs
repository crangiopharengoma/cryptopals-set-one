use std::str::FromStr;

use num::BigUint;
use rand::RngCore;
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};

use crate::encoding::hex::Hex;
use crate::encoding::Digest as MyDigest;
use crate::hashes::sha_1::Sha1;

pub fn get_p_value() -> BigUint {
    let hex = Hex::from_str("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff").expect("invalid hex string");
    BigUint::from_bytes_be(hex.bytes())
}

pub fn generate_public_key(p: &BigUint, g: &BigUint, secret_random: &BigUint) -> BigUint {
    g.modpow(secret_random, p)
}

/// Takes the first len bytes of the hash of the supplied key
/// Assumes that len is < 20
/// Cryptopals (so far) has only used AES128 so that's an okay limitation for this
pub fn generate_secret_key(
    received_public_key: &BigUint,
    secret_random: &BigUint,
    p: &BigUint,
    len: usize,
) -> Vec<u8> {
    let session_key = received_public_key.modpow(secret_random, p);
    let mut bytes = Sha1::from(session_key.to_bytes_le())
        .digest()
        .bytes()
        .to_vec();
    bytes.truncate(len);
    bytes
}

pub fn generate_session_key() -> Vec<u8> {
    let p = get_p_value();
    let g = BigUint::from(2u8);

    let a = rand::thread_rng().next_u32() % &p;
    let public_key_a = g.modpow(&a, &p);

    let b = rand::thread_rng().next_u32() % &p;
    let public_key_b = g.modpow(&b, &p);

    let s = public_key_b.modpow(&a, &p);

    assert_eq!(s, public_key_a.modpow(&b, &p));

    let mut hasher = Sha256::new();
    let bytes = s.to_bytes_le();
    hasher.update(bytes);
    let result = hasher.finalize();

    result[..16].to_owned()
}

/// Simulates a key exchange with the supplied endpoint
/// Assumes that the endpoint is expecting parameters named 'p', 'g' and 'A'
pub fn demo_key_exchange(client: &Client, endpoint: String) -> Vec<u8> {
    let p = get_p_value();
    let g = BigUint::from(2u8);
    let rand = BigUint::from(rand::thread_rng().next_u32());

    let public_key = generate_public_key(&p, &g, &rand);

    let hex_p = Hex::new(&p.to_bytes_be());
    let hex_g = Hex::new(&g.to_bytes_be());
    let hex_public_key = Hex::new(&public_key.to_bytes_be());

    let url = format!("{endpoint}?p={hex_p}&g={hex_g}&A={hex_public_key}");

    let res = client.get(&url).send().expect("response not received");
    let returned_public_key = {
        let key = res.text().expect("body not text");
        let key = Hex::from_str(&key).expect("invalid hex");
        BigUint::from_bytes_be(key.bytes())
    };

    generate_secret_key(&returned_public_key, &rand, &p, 16)
}
