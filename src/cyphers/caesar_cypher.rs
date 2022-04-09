use crate::string_heuristics;

/// Attempts to find the key used to 'encrypt' an english phrase by single-character xor
///
/// Given a slice of u8 will try every possible key and using character frequency analysis will
/// try to guess what key was used to encrypt the phrase
///
/// Will return none if none of the bytes is valid ascii after xor against every possible u8 value
pub fn find_key(bytes: &[u8]) -> Option<u8> {
    (0..u8::MAX).max_by_key(|key| {
        let decrypted: Vec<u8> = bytes.iter().map(|byte| byte ^ key).collect();
        string_heuristics::score_suspected_string(&decrypted)
    })
}

/// Decrypts a message encrypted by single-character xor
///
/// Returns a vec containing the decrypted bytes
pub fn decrypt(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes.iter().map(|byte| byte ^ key).collect()
}