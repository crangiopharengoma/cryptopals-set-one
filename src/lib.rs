use std::cmp::Ordering;

pub mod cyphers;
pub mod encoding;

pub type Error = Box<dyn std::error::Error>;

#[derive(PartialOrd, PartialEq, Debug)]
pub struct OrderedFloat(f64);

impl Eq for OrderedFloat {}

// wrapper for f64 that will guarantee is always a number
#[allow(clippy::derive_ord_xor_partial_ord)]
impl Ord for OrderedFloat {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.partial_cmp(&other.0).expect("ordered float is always a number")
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::encoding::base64::Base64;
    use crate::encoding::hex::Hex;

    #[test]
    fn hex_to_base64() {
        let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let hex_input = Hex::from_str(hex_str).unwrap();
        let base64_expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let base64_converted = Base64::from_hex(hex_input);

        assert_eq!(base64_expected, base64_converted.to_string());
    }
}
