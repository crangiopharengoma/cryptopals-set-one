use std::error::Error as stdError;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use crate::encoding::structured_cookie::CookieEncodingError::ValuePairFormatInvalid;
use crate::Error;

#[derive(Debug)]
enum CookieEncodingError {
    ValuePairFormatInvalid(String),
}

impl Display for CookieEncodingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl stdError for CookieEncodingError {}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct StructuredCookie {
    members: Vec<ValuePair>,
}

impl StructuredCookie {
    pub fn get(&self, key: &str) -> Option<String> {
        let value_pair = self
            .members
            .iter()
            .find(|value_pair| value_pair.key == key)?;
        Some(value_pair.value.clone())
    }
}

impl Display for StructuredCookie {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let member_strings: Vec<String> = self.members.iter().map(|kv| kv.to_string()).collect();
        let joined = member_strings.join("&");
        write!(f, "{}", joined)
    }
}

impl FromStr for StructuredCookie {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let try_members: Result<Vec<ValuePair>, Self::Err> =
            s.split('&').map(ValuePair::from_str).collect();

        let members = try_members?;
        Ok(StructuredCookie { members })
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
struct ValuePair {
    key: String,
    value: String,
}

impl FromStr for ValuePair {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.contains('=') {
            return Err(Box::new(ValuePairFormatInvalid(
                "key pairs not denoted with '='".to_string(),
            )));
        }

        let split: Vec<&str> = s.split('=').collect();
        if split.len() != 2 {
            return Err(Box::new(ValuePairFormatInvalid(
                "multiple key pairs found".to_string(),
            )));
        }

        Ok(ValuePair {
            key: split.get(0).unwrap().to_string(),
            value: split.get(1).unwrap().to_string(),
        })
    }
}

impl Display for ValuePair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::encoding::structured_cookie::{StructuredCookie, ValuePair};

    #[test]
    fn key_value_pair_created_from_string() {
        let expected = ValuePair {
            key: "test".to_string(),
            value: "pair".to_string(),
        };
        let result = ValuePair::from_str("test=pair").unwrap();

        assert_eq!(expected, result);
    }

    #[test]
    #[should_panic(expected = "key pairs not denoted with '='")]
    fn key_value_pair_returns_err_if_multiple() {
        ValuePair::from_str("test::pair").unwrap();
    }

    #[test]
    #[should_panic(expected = "multiple key pairs found")]
    fn key_value_pair_panics_if_multiple() {
        ValuePair::from_str("test=pair;fun=some").unwrap();
    }

    #[test]
    fn structure_cookie_created_from_string() {
        let members = vec![
            ValuePair::from_str("test=pair").unwrap(),
            ValuePair::from_str("other=next").unwrap(),
            ValuePair::from_str("key=value").unwrap(),
        ];
        let expected = StructuredCookie { members };

        let result = StructuredCookie::from_str("test=pair&other=next&key=value").unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn key_value_display_impl() {
        let expected = "test=pair";
        let key_pair = ValuePair::from_str("test=pair").unwrap();
        let result = key_pair.to_string();

        assert_eq!(expected, result);
    }

    #[test]
    fn structured_cookie_display_impl() {
        let expected = "test=pair&other=next&key=value";

        let structured_cookie =
            StructuredCookie::from_str("test=pair&other=next&key=value").unwrap();
        let result = structured_cookie.to_string();

        assert_eq!(expected, result);
    }
}
