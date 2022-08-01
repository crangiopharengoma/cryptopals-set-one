use crate::cyphers::aes;
use crate::cyphers::aes::cbc;
use crate::encoding::Digest;

pub struct CBCOracle {
    key: [u8; 16],
    iv: [u8; 16],
}

pub struct EncryptionResult {
    pub cipher_text: Vec<u8>,
    pub iv: [u8; 16],
}

impl Default for CBCOracle {
    fn default() -> Self {
        let key = aes::generate_16_bit_key();
        let iv = aes::generate_16_bit_key();
        Self { key, iv }
    }
}

impl CBCOracle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encrypt<T: Digest>(&self, message: &T) -> EncryptionResult {
        let prefix = "comment1=cooking%20MCs;userdata=".as_bytes();
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

        let message =
            String::from_utf8(message.bytes().to_vec()).expect("message is not valid utf8");
        let message = message.replace('=', "\"=\"").replace(';', "\";\"");

        let message = [prefix, message.as_bytes(), suffix].concat();

        EncryptionResult {
            cipher_text: cbc::encrypt(&message, &self.key, &self.iv),
            iv: self.iv,
        }
    }

    pub fn is_admin(&self, cipher_text: &[u8]) -> bool {
        let plain_text = cbc::decrypt(cipher_text, &self.key, &self.iv);
        // checking for valid utf-8 will cause the attack in challenge 16 to fail most of the time
        let message = String::from_utf8_lossy(&plain_text);
        message.contains(";admin=true;")
        // if let Ok(message) = String::from_utf8(plain_text) {
        //     message.contains(";admin=true;")
        // } else {
        //     false
        // }
    }
}

#[cfg(test)]
mod tests {
    use crate::cyphers::aes::cbc;
    use crate::cyphers::aes::oracles::cbc_oracle::CBCOracle;

    #[test]
    fn encrypt_correctly_sanitises_text() {
        let oracle = CBCOracle::new();
        let encrypted = oracle.encrypt(&";admin=true;".as_bytes().to_vec());

        let is_admin = oracle.is_admin(&encrypted.cipher_text);
        assert!(!is_admin);
    }

    #[test]
    fn cipher_text_contains_admin() {
        let oracle = CBCOracle::new();
        let encrypted = cbc::encrypt(";admin=true;".as_bytes(), &oracle.key, &oracle.iv);

        let is_admin = oracle.is_admin(&encrypted);
        assert!(is_admin);
    }

    #[test]
    fn cipher_text_does_not_contain_admin() {
        let oracle = CBCOracle::new();
        let encrypted = oracle.encrypt(&"this is a test".as_bytes().to_vec());

        let is_admin = oracle.is_admin(&encrypted.cipher_text);
        assert!(!is_admin);
    }
}
