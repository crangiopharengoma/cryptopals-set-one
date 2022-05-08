use crate::cyphers::{aes_cbc, aes_ecb};
use crate::encoding::Digest;

pub struct CBCOracle {
    key: [u8; 16],
    iv: [u8; 16],
}

impl Default for CBCOracle {
    fn default() -> Self {
        let key = aes_ecb::generate_key();
        let iv = aes_ecb::generate_key();
        Self { key, iv }
    }
}

impl CBCOracle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encrypt<T: Digest>(&self, message: &T) -> Vec<u8> {
        let prefix = "comment1=cooking%20MCs;userdata=".as_bytes();
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

        let message =
            String::from_utf8(message.bytes().to_vec()).expect("message is not valid utf8");
        let message = message.replace('=', "\"=\"").replace(';', "\";\"");

        let message = [prefix, message.as_bytes(), suffix].concat();

        aes_cbc::encrypt(&message, &self.key, &self.iv)
    }

    pub fn is_admin(&self, cipher_text: &[u8]) -> bool {
        let plain_text = aes_cbc::decrypt(cipher_text, &self.key, &self.iv);
        if let Ok(message) = String::from_utf8(plain_text) {
            message.contains(";admin=true;")
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cyphers::aes_cbc;
    use crate::cyphers::oracles::cbc_oracle::CBCOracle;

    #[test]
    fn encrypt_correctly_sanitises_text() {
        let oracle = CBCOracle::new();
        let encrypted = oracle.encrypt(&";admin=true;".as_bytes().to_vec());

        let is_admin = oracle.is_admin(&encrypted);
        assert!(!is_admin);
    }

    #[test]
    fn cipher_text_contains_admin() {
        let oracle = CBCOracle::new();
        let encrypted = aes_cbc::encrypt(";admin=true;".as_bytes(), &oracle.key, &oracle.iv);

        let is_admin = oracle.is_admin(&encrypted);
        assert!(is_admin);
    }

    #[test]
    fn cipher_text_does_not_contain_admin() {
        let oracle = CBCOracle::new();
        let encrypted = oracle.encrypt(&"this is a test".as_bytes().to_vec());

        let is_admin = oracle.is_admin(&encrypted);
        assert!(!is_admin);
    }
}
