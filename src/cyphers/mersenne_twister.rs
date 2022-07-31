use crate::encoding::Digest;
use crate::random::mersenne_twister::MersenneTwister;

pub struct Encrypter {
    key: u16,
}

impl Encrypter {
    pub fn new(key: u16) -> Encrypter {
        Encrypter { key }
    }

    pub fn encrypt<T: Digest>(&self, plain_text: T) -> Vec<u8> {
        let mt = MersenneTwister::new(self.key.into());
        plain_text
            .bytes()
            .chunks(4)
            .flat_map(|chunk| {
                let key = mt.extract_number().to_be_bytes();
                chunk
                    .iter()
                    .zip(key.iter())
                    .map(|(key, value)| key ^ value)
                    .collect::<Vec<u8>>()
            })
            .collect()
    }

    pub fn decrypt(&self, cipher_text: Vec<u8>) -> Vec<u8> {
        self.encrypt(cipher_text)
    }
}
