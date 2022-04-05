use std::fmt::{Display, Formatter};

use crate::hex::Hex;

pub struct Base64 {
    bytes: Vec<u8>,
}

impl Display for Base64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Self::encode(&self.bytes))
    }
}

impl Base64 {
    pub fn new(bytes: &[u8]) -> Base64 {
        let bytes = bytes.to_vec();
        Base64 { bytes }
    }

    pub fn from_hex(hex: Hex) -> Base64 {
        let bytes = hex.raw_bytes().to_vec();
        Base64 { bytes }
    }

    /// Takes a slice of raw bytes and converts into base64 encoded bytes
    /// Panics
    /// If slice of raw bytes has len > 4
    fn encode_bytes(bytes: &[u8]) -> [u8; 4] {
        if bytes.len() > 4 {
            panic!("encode_bytes given too many bytes");
        }

        let chunk_array = {
            let mut chunk_array = [0u8; 4];
            // final chunk may be less than 3 bytes
            let chunk_start = 4 - bytes.len();
            chunk_array[chunk_start..].copy_from_slice(bytes);
            chunk_array
        };

        let value: u32 = u32::from_be_bytes(chunk_array);

        let low_six_bytes_mask = 0b11_1111;
        let first_val = (value & low_six_bytes_mask) as u8;
        let second_val = (value >> 6 & low_six_bytes_mask) as u8;
        let third_val = (value >> 12 & low_six_bytes_mask) as u8;
        let fourth_val = (value >> 18 & low_six_bytes_mask) as u8;

        [fourth_val, third_val, second_val, first_val]
    }

    pub fn encode(bytes: &[u8]) -> String {
        let mut result = String::new();

        for chunk in bytes.chunks(3) {
            let encoded_bytes = Self::encode_bytes(chunk);
            Self::string_from_encoded_bytes(&mut result, chunk.len(), encoded_bytes);
        }

        result
    }

    fn string_from_encoded_bytes(result: &mut String, raw_byte_length: usize, encoded_bytes: [u8; 4]) {
        if raw_byte_length == 3 {
            result.push(Self::ascii_char_from_encoded_byte(encoded_bytes[0]));
            result.push(Self::ascii_char_from_encoded_byte(encoded_bytes[1]));
            result.push(Self::ascii_char_from_encoded_byte(encoded_bytes[2]));
            result.push(Self::ascii_char_from_encoded_byte(encoded_bytes[3]));
        } else if raw_byte_length == 2 {
            result.push(Self::ascii_char_from_encoded_byte(encoded_bytes[0]));
            result.push(Self::ascii_char_from_encoded_byte(encoded_bytes[1]));
            result.push(Self::ascii_char_from_encoded_byte(encoded_bytes[2]));
            result.push('=');
        } else {
            result.push(Self::ascii_char_from_encoded_byte(encoded_bytes[0]));
            result.push(Self::ascii_char_from_encoded_byte(encoded_bytes[1]));
            result.push('=');
            result.push('=');
        }
    }


    fn ascii_char_from_encoded_byte(converted: u8) -> char {
        if converted < 26 {
            (converted + 65) as char
        } else if converted < 52 {
            (converted + 71) as char
        } else if converted < 62 {
            (converted - 4) as char
        } else if converted == 63 {
            '+'
        } else {
            '/'
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::base64::Base64;

    #[test]
    fn base_64_from_bytes() {
        let bytes_input = [73, 39, 109, 32, 107, 105]; // hex: 49276d
        let base64_expected = "SSdtIGtp";

        let base64_converted = Base64::encode(&bytes_input);

        assert_eq!(base64_expected, base64_converted);
    }
}
