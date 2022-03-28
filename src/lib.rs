use std::fmt::{Display, Formatter};
use std::str;

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

    pub fn from_hex(hex: &str) -> Base64 {
        let mut bytes: Vec<u8> = Vec::new();
        for byte in hex.as_bytes().chunks(2) {
            bytes.push(Self::parse_two_hex_ascii_bytes_to_u8(byte))
        }

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
            println!("interim result {:?}", result);
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

    fn parse_two_hex_ascii_bytes_to_u8(byte: &[u8]) -> u8 {
        let ones = byte[1];
        let ones = Self::u8_from_hex_ascii_byte(ones);

        if byte.len() == 2 {
            let sixteens = byte[0];
            ones + Self::u8_from_hex_ascii_byte(sixteens) * 16
        } else {
            ones
        }
    }

    fn u8_from_hex_ascii_byte(char_as_u8: u8) -> u8 {
        if char_as_u8 < 58 {
            char_as_u8 - 48
        } else {
            char_as_u8 - 87
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
    use crate::Base64;

    #[test]
    fn hex_to_base64() {
        let hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64_expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let base64_converted = Base64::from_hex(hex_input);

        assert_eq!(base64_expected, base64_converted.to_string());
    }

    #[test]
    fn hex_to_bytes() {
        let hex_input = "49276d";
        let expected_bytes = [73, 39, 109];

        let converted_bytes = Base64::from_hex(hex_input).bytes;

        assert_eq!(expected_bytes, converted_bytes.as_slice())
    }

    #[test]
    fn two_char_hex_str_to_u8() {
        let hex_input = "49";
        let u8_expected: u8 = 73;

        let u8_converted = Base64::parse_two_hex_ascii_bytes_to_u8(hex_input.as_bytes());

        assert_eq!(u8_expected, u8_converted);
    }

    #[test]
    fn base_64_from_bytes() {
        let bytes_input = [73, 39, 109, 32, 107, 105]; // hex: 49276d
        let base64_expected = "SSdtIGtp";

        let base64_converted = Base64::encode(&bytes_input);

        assert_eq!(base64_expected, base64_converted);
    }
}
