pub mod base64;
pub mod hex;

pub type Error = Box<dyn std::error::Error>;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::base64::Base64;
    use crate::hex::Hex;

    #[test]
    fn hex_to_base64() {
        let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let hex_input = Hex::from_str(hex_str).unwrap();
        let base64_expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let base64_converted = Base64::from_hex(hex_input);

        assert_eq!(base64_expected, base64_converted.to_string());
    }
}
