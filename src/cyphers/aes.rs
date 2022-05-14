use openssl::rand;

pub mod cbc;
pub mod ctr;
pub mod ecb;
pub mod oracles;

#[derive(Debug, PartialEq)]
pub enum AesMode {
    ECB,
    CBC,
    CTR,
}

pub fn get_random_bytes(length: usize) -> Vec<u8> {
    let mut key = vec![0; length];
    rand::rand_bytes(&mut key).expect("key generation failed");
    key
}

pub fn generate_16_bit_key() -> [u8; 16] {
    let mut key = [0; 16];
    rand::rand_bytes(&mut key).expect("key generation failed");
    key
}

#[cfg(test)]
mod test {
    use crate::cyphers::aes::get_random_bytes;

    #[test]
    fn key_length_is_correct() {
        let key = get_random_bytes(8);
        let expected = 8;

        assert_eq!(expected, key.len());
    }
}
