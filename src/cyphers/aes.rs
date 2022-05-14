use openssl::rand;

pub mod cbc;
pub mod ecb;
pub mod oracles;

#[derive(Debug, PartialEq)]
pub enum AesMode {
    ECB,
    CBC,
}

pub fn generate_key() -> [u8; 16] {
    let mut key = [0; 16];
    rand::rand_bytes(&mut key).expect("key generation failed");
    key
}
