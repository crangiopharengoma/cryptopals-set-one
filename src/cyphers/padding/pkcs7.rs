use crate::cyphers::padding::PaddingError;
use crate::Error;

/// pads a given plain text to the target length using the pkcs#7 standard
pub fn pad(plain_text: &[u8], target_length: usize) -> Vec<u8> {
    let mut owned = plain_text.to_vec();
    let padding = target_length - owned.len();

    (0..padding).for_each(|_| owned.push(padding as u8));

    owned
}

/// validates and unpads a given plain text that has been padded using pkcs#7
/// returns Error if the padding is not valid
///
/// Panics
/// If the plain_text slice is empty
pub fn try_unpad(plain_text: &[u8], block_length: usize) -> Result<Vec<u8>, Error> {
    let last_byte = *plain_text.last().unwrap();

    // assume any value greater than 16 is valid padding
    // (i.e. the block did not require padding)
    if last_byte as usize > block_length {
        return Ok(plain_text.to_vec());
    }

    let mut result = plain_text.to_vec();
    for _ in (plain_text.len() - last_byte as usize)..plain_text.len() {
        let byte = *result.last().unwrap();
        if byte != last_byte {
            return Err(Box::new(PaddingError::InvalidPadding(format!(
                "expected {last_byte} found {byte}"
            ))));
        } else {
            result.pop();
        }
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use crate::cyphers::padding::pkcs7::{pad, try_unpad};

    #[test]
    fn padding_appends_bytes() {
        let plain_text = "YELLOW SUBMARINE";
        let target_len = 20;
        let expected_padded = "YELLOW SUBMARINE\x04\x04\x04\x04";

        let padded = pad(plain_text.as_bytes(), target_len);

        assert_eq!(expected_padded.as_bytes(), padded)
    }

    #[test]
    fn padding_does_not_append_bytes() {
        let plain_text = "YELLOW SUBMARINE";
        let target_len = 16;

        let padded = pad(plain_text.as_bytes(), target_len);

        assert_eq!(plain_text.as_bytes(), padded);
    }

    #[test]
    fn plain_text_is_unpadded() {
        let target_len = 16;
        let plain_text = "ICE ICE BABY\x04\x04\x04\x04";
        let expected = "ICE ICE BABY".as_bytes();

        let result = try_unpad(plain_text.as_bytes(), target_len).unwrap();

        assert_eq!(expected, result);
    }

    #[test]
    fn invalid_padding_is_detected() {
        let target_len = 16;

        let plain_text = "ICE ICE BABY\x05\x05\x05\x05";
        let result = try_unpad(plain_text.as_bytes(), target_len);
        assert!(result.is_err());

        let plain_text = "ICE ICE BABY\x01\x02\x03\x04";
        let result = try_unpad(plain_text.as_bytes(), target_len);

        assert!(result.is_err());
    }
}
