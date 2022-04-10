pub fn encrypt(message: &[u8], key: &[u8]) -> Vec<u8> {
    // this will actually make the key 3x longer than the message, but the zip will handle that
    key.repeat(message.len()).iter()
        .zip(message.iter())
        .map(|(x, y)| x ^ y)
        .collect()
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::cyphers::repeating_key_xor;
    use crate::hex::Hex;

    #[test]
    fn string_is_encrypted() {
        let plain_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();
        let key = "ICE".as_bytes();
        let expected_encrypted = Hex::from_str("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();

        let encrypted = repeating_key_xor::encrypt(plain_text, key);

        assert_eq!(expected_encrypted.raw_bytes(), encrypted);
    }
}