use std::fmt::{Display, Formatter};
use std::fs;
use std::str::FromStr;

use crate::encoding::hex::Hex;
use crate::encoding::Digest;
use crate::Error;

pub struct Base64 {
    bytes: Vec<u8>,
}

impl Digest for Base64 {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Digest for &Base64 {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Display for Base64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Self::encode(&self.bytes))
    }
}

impl FromStr for Base64 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s
            .as_bytes()
            .chunks(4)
            .flat_map(Self::encoded_bytes_from_chunk)
            .collect();

        Ok(Base64 { bytes })
    }
}

impl Base64 {
    pub fn new(bytes: &[u8]) -> Base64 {
        let bytes = bytes.to_vec();
        Base64 { bytes }
    }

    pub fn from_hex(hex: Hex) -> Base64 {
        let bytes = hex.bytes().to_vec();
        Base64 { bytes }
    }

    /// Tries to create a Base64 from a file
    ///
    /// Assumptions:
    /// The file contains only the base64 encoded chars and linebreaks
    /// Linebreaks are ignored - the entire file is a read as a single encoded value
    ///
    /// Errors
    /// If file can't be opened/read
    /// If file contains invalid base64 chars
    pub fn from_file(path: &str) -> Result<Base64, Error> {
        let file_contents = fs::read_to_string(path)?;

        let base64_string = file_contents.lines().collect::<Vec<&str>>().join("");

        Base64::from_str(&base64_string)
    }

    /// Tries to create a Vec<Base64> from a file
    ///
    /// Assumptions:
    /// The file contains only the base64 encoded chars and linebreaks.
    /// Linebreaks always signify the end of Base64 encoded string - there cannot be multi-line encodings.
    /// Note that this may not be detected;
    /// if the line break splits a Base64 into two valid base64s this method will return Ok
    ///
    /// Errors
    /// If file can't be opened/read
    /// If file contains invalid base64 chars
    /// If file contains multi-line encodings resulting in an invalid base64 encoding on a single line
    pub fn from_file_multi(path: &str) -> Result<Vec<Base64>, Error> {
        let file_contents = fs::read_to_string(path)?;

        let mut result = Vec::with_capacity(file_contents.lines().count());
        for line in file_contents.lines() {
            result.push(Base64::from_str(line)?);
        }

        Ok(result)
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

    fn string_from_encoded_bytes(
        result: &mut String,
        raw_byte_length: usize,
        encoded_bytes: [u8; 4],
    ) {
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

        let chunk_value = chunk.iter().fold(0, |accum, chunk| {
            (accum << 6) + (Self::decimal_value_from_ascii_byte(*chunk) as u32)
        });

        let last_byte_mask = 0b1111_1111;

        vec![
            (chunk_value >> 16 & last_byte_mask) as u8,
            (chunk_value >> 8 & last_byte_mask) as u8,
            (chunk_value & last_byte_mask) as u8,
        ]
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
mod test {
    use std::str::FromStr;

    use crate::encoding::base64::Base64;
    use crate::encoding::Digest;

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

        assert_eq!(expected_bytes, calculated_base64.bytes())
    }
}
