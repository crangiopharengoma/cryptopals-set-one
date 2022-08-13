use crate::cyphers::aes;
use crate::cyphers::aes::cbc;
use crate::encoding::Digest;

pub struct CBCOracle {
    pub key: [u8; 16],
    iv: [u8; 16],
}

pub struct EncryptedMessage {
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

    fn build_message<T: Digest>(&self, message: &T) -> Vec<u8> {
        let prefix = "comment1=cooking%20MCs;userdata=".as_bytes();
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

        let message =
            String::from_utf8(message.bytes().to_vec()).expect("message is not valid utf8");
        let message = message.replace('=', "\"=\"").replace(';', "\";\"");

        [prefix, message.as_bytes(), suffix].concat()
    }

    pub fn encrypt_key_is_iv<T: Digest>(&self, message: &T) -> EncryptedMessage {
        EncryptedMessage {
            cipher_text: cbc::encrypt(message.bytes(), &self.key, &self.key),
            iv: [0; 16],
        }
    }

    pub fn decrypt(&self, message: &EncryptedMessage) -> Vec<u8> {
        cbc::decrypt(&message.cipher_text, &self.key, &self.key)
    }

    pub fn encrypt(&self, plain_text: &[u8]) -> EncryptedMessage {
        EncryptedMessage {
            cipher_text: cbc::encrypt(plain_text, &self.key, &self.iv),
            iv: self.iv,
        }
    }

    /// This is weird unidiomatic rust to fulfill the criteria of the application
    ///
    /// This will return Ok(decrypted_message) if the message decrypts AND is valid ascii (byte values < 128)
    /// This will return Err(decrypted_message) if the message decrypts AND is not valid ascii (at least one byte is > 127)
    pub fn decrypt_and_validate(&self, message: &EncryptedMessage) -> Result<(), Vec<u8>> {
        let plain_text = cbc::decrypt(&message.cipher_text, &self.key, &self.key);

        if self.is_valid_ascii(&plain_text) {
            Ok(())
        } else {
            Err(plain_text)
        }
    }

    pub fn encrypt_with_message<T: Digest>(&self, message: &T) -> EncryptedMessage {
        let message = self.build_message(message);

        EncryptedMessage {
            cipher_text: cbc::encrypt(&message, &self.key, &self.iv),
            iv: self.iv,
        }
    }

    fn is_valid_ascii(&self, text: &[u8]) -> bool {
        for i in text {
            if *i > 128 {
                return false;
            }
        }
        true
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
        let encrypted = oracle.encrypt_with_message(&";admin=true;".as_bytes().to_vec());

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
        let encrypted = oracle.encrypt_with_message(&"this is a test".as_bytes().to_vec());

        let is_admin = oracle.is_admin(&encrypted.cipher_text);
        assert!(!is_admin);
    }
}
