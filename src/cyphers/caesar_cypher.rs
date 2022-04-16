use crate::encoding::Digest;

/// Attempts to find the key used to 'encrypt' an english phrase by single-character xor
///
/// Given a slice of u8 will try every possible key and using character frequency analysis will
/// try to guess what key was used to encrypt the phrase
///
/// Will return none if none of the bytes is valid ascii after xor against every possible u8 value
pub fn find_key(message: &dyn Digest) -> Option<u8> {
    (0..u8::MAX).max_by_key(|key| {
        message.bytes()
            .iter()
            .map(|byte| byte ^ key)
            .collect::<Vec<u8>>()
            .english_score()
    })
}

/// Encrypts a message with the given key using single-character xor
pub fn encrypt(message: &dyn Digest, key: u8) -> Vec<u8> {
    message.bytes()
        .iter()
        .map(|byte| byte ^ key)
        .collect()
}

/// Decrypts a message encrypted by single-character xor
///
/// Returns a vec containing the decrypted bytes
pub fn decrypt(message: &dyn Digest, key: u8) -> Vec<u8> {
    encrypt(message, key)
}