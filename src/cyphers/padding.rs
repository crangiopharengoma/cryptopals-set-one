pub fn pkcs7(plain_text: &[u8], target_length: usize) -> Vec<u8> {
    let mut owned = plain_text.to_vec();
    let padding = target_length - owned.len();

    (0..padding).for_each(|_| owned.push(padding as u8));

    owned
}

#[cfg(Test)]
mod test {
    use crate::cyphers::padding;

    #[test]
    fn padding_appends_bytes() {
        let plain_text = "YELLOW SUBMARINE";
        let target_len = 20;
        let expected_padded = "YELLOW SUBMARINE\x04\x04\x04\x04";

        let padded = padding::pkcs7(plain_text.as_bytes(), target_len);

        assert_eq!(expected_padded.as_bytes(), padded)
    }

    #[test]
    fn padding_does_not_append_bytes() {
        let plain_text = "YELLOW SUBMARINE";
        let target_len = 16;

        let padded = padding::pkcs7(plain_text.as_bytes(), target_len);

        assert_eq!(plain_text.as_bytes(), padded);
    }
}
