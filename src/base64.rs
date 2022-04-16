use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::Error;
use crate::hex::Hex;

pub struct Base64 {
    bytes: Vec<u8>,
}

impl Display for Base64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Self::encode(&self.bytes))
    }
}

impl FromStr for Base64 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes()
            .chunks(4)
            .flat_map(Self::encoded_bytes_from_chunk)
            .collect();

        Ok(Base64 { bytes })
    }
}

impl Base64 {
    pub fn raw_bytes(&self) -> &[u8] {
        &self.bytes
    }

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

        let low_six_bits_mask = 0b11_1111;
        let first_val = (value & low_six_bits_mask) as u8;
        let second_val = (value >> 6 & low_six_bits_mask) as u8;
        let third_val = (value >> 12 & low_six_bits_mask) as u8;
        let fourth_val = (value >> 18 & low_six_bits_mask) as u8;

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
        } else if converted == 62 {
            '+'
        } else {
            '/'
        }
    }

    fn encoded_bytes_from_chunk(chunk: &[u8]) -> Vec<u8> {
        if chunk.len() != 4 {
            panic!("invalid chunk length");
        }

        let chunk_value = chunk.iter()
            .fold(0, |accum, chunk| {
                (accum << 6) + (Self::decimal_value_from_ascii_byte(*chunk) as u32)
            });

        let last_byte_mask = 0b1111_1111;

        vec!(
            (chunk_value >> 16 & last_byte_mask) as u8,
            (chunk_value >> 8 & last_byte_mask) as u8,
            (chunk_value & last_byte_mask) as u8
        )
    }

    fn decimal_value_from_ascii_byte(ascii_byte: u8) -> u8 {
        let ascii_char = ascii_byte as char;
        if ascii_char == '+' {
            62
        } else if ascii_char == '/' {
            63
        } else if ascii_char == '=' {
            0
        } else if ascii_byte < 58 {
            ascii_byte + 4
        } else if ascii_byte < 91 {
            ascii_byte - 65
        } else {
            ascii_byte - 71
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::base64::Base64;

    #[test]
    fn base_64_from_bytes() {
        let bytes_input = [73, 39, 109, 32, 107, 105]; // hex: 49276d
        let base64_expected = "SSdtIGtp";

        let base64_converted = Base64::encode(&bytes_input);

        assert_eq!(base64_expected, base64_converted);
    }

    #[test]
    fn base_64_from_string() {
        let string_input = "SSdtIGtp";
        let expected_bytes = [73, 39, 109, 32, 107, 105];

        let calculated_base64 = Base64::from_str(string_input).unwrap();

        assert_eq!(expected_bytes, calculated_base64.raw_bytes())
    }
}
