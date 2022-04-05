use std::str::FromStr;

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hex {
    bytes: Vec<u8>,
}

impl FromStr for Hex {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = Vec::new();
        for byte in s.as_bytes().chunks(2) {
            bytes.push(Hex::parse_two_hex_ascii_bytes_to_u8(byte))
        }
        Ok(Hex { bytes })
    }
}

impl Hex {
    pub fn new(bytes: &[u8]) -> Hex {
        let bytes = bytes.to_vec();
        Hex { bytes }
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn xor(&self, other: &Hex) -> Hex {
        let bytes = self.raw_bytes().iter()
            .zip(other.raw_bytes().iter())
            .map(|(x, y)| x ^ y)
            .collect();
        Hex { bytes }
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
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::hex::Hex;

    #[test]
    fn xor_two_hex_values() {
        let hex_one = Hex::from_str("52f0f0").unwrap();
        let hex_two = Hex::from_str("cdff00").unwrap();

        let expected_hex = Hex::from_str("9f0ff0").unwrap();

        let xor_hex = hex_one.xor(&hex_two);

        assert_eq!(expected_hex, xor_hex);
    }

    #[test]
    fn hex_to_bytes() {
        let hex_input = "49276d";
        let expected_bytes = [73, 39, 109];

        let converted_bytes = Hex::from_str(hex_input).unwrap().bytes;

        assert_eq!(expected_bytes, converted_bytes.as_slice())
    }

    #[test]
    fn two_char_hex_str_to_u8() {
        let hex_input = "49";
        let u8_expected: u8 = 73;

        let u8_converted = Hex::parse_two_hex_ascii_bytes_to_u8(hex_input.as_bytes());

        assert_eq!(u8_expected, u8_converted);
    }
}
