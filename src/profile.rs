use std::error::Error as stdError;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::cyphers::aes::{self, ecb};
use crate::encoding::structured_cookie::StructuredCookie;
use crate::profile::ProfileErrors::MissingValue;
use crate::Error;

#[derive(Debug)]
enum ProfileErrors {
    MissingValue(String),
}

impl stdError for ProfileErrors {}

impl Display for ProfileErrors {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

pub struct ProfileEncrypter {
    key: [u8; 16],
}

impl Default for ProfileEncrypter {
    fn default() -> Self {
        let key = aes::generate_16_bit_key();
        ProfileEncrypter { key }
    }
}

impl ProfileEncrypter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encrypt(&self, profile: &Profile) -> Vec<u8> {
        let structured_cookie: StructuredCookie = profile.into();
        ecb::encrypt(&self.key, structured_cookie.to_string().into_bytes())
    }

    pub fn decrypt(&self, cipher_text: &[u8]) -> Profile {
        let plain_text = ecb::decrypt(&self.key, cipher_text.to_vec());
        StructuredCookie::from_str(&String::from_utf8(plain_text).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Profile {
    email: String,
    uid: String,
    role: String,
}

impl Profile {
    pub fn profile_for(email: &str) -> Profile {
        let email = email.replace(&['=', '&'], "");

        Profile {
            email,
            uid: "32".to_string(),
            role: "user".to_string(),
        }
    }
}

impl Display for Profile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "email: {}, uid: {}, role: {}",
            self.email, self.uid, self.role
        )
    }
}

impl TryFrom<StructuredCookie> for Profile {
    type Error = Error;

    fn try_from(value: StructuredCookie) -> Result<Self, Error> {
        let email = value
            .get("email")
            .ok_or_else(|| Box::new(MissingValue("email not provided".to_string())))?;
        let uid = value
            .get("uid")
            .ok_or_else(|| Box::new(MissingValue("uid not provided".to_string())))?;
        let role = value
            .get("role")
            .ok_or_else(|| Box::new(MissingValue("role not provided".to_string())))?;

        Ok(Profile { email, uid, role })
    }
}

impl From<Profile> for StructuredCookie {
    fn from(value: Profile) -> Self {
        let cookie_string = format!(
            "email={}&uid={}&role={}",
            value.email, value.uid, value.role
        );
        Self::from_str(&cookie_string).unwrap()
    }
}

impl From<&Profile> for StructuredCookie {
    fn from(value: &Profile) -> Self {
        let cookie_string = format!(
            "email={}&uid={}&role={}",
            value.email, value.uid, value.role
        );
        Self::from_str(&cookie_string).unwrap()
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::encoding::structured_cookie::StructuredCookie;
    use crate::profile::{Profile, ProfileEncrypter};

    #[test]
    fn create_profile_from_structured_cookie() {
        let cookie_string = "email=test@gmail.com&uid=10&role=user".to_string();
        let structured_cookie = StructuredCookie::from_str(&cookie_string).unwrap();

        let expected = Profile {
            email: "test@gmail.com".to_string(),
            uid: "10".to_string(),
            role: "user".to_string(),
        };

        let result = Profile::try_from(structured_cookie).unwrap();

        assert_eq!(expected, result);
    }

    #[test]
    fn create_structured_cookie_from_profile() {
        let profile = Profile {
            email: "test@gmail.com".to_string(),
            uid: "10".to_string(),
            role: "user".to_string(),
        };

        let cookie_string = "email=test@gmail.com&uid=10&role=user".to_string();
        let expected = StructuredCookie::from_str(&cookie_string).unwrap();

        let result: StructuredCookie = profile.into();

        assert_eq!(expected, result);
    }

    #[test]
    fn profile_for_sanitises_metacharacters() {
        let expected = Profile {
            email: "test@gmail.com".to_string(),
            uid: "32".to_string(),
            role: "user".to_string(),
        };

        let result = Profile::profile_for("test=@gm&ail.com&");

        assert_eq!(expected, result);
    }

    #[test]
    fn round_trip_encryption() {
        let expected = Profile {
            email: "test@gmail.com".to_string(),
            uid: "32".to_string(),
            role: "user".to_string(),
        };
        let profile_encrypter = ProfileEncrypter::new();

        let encrypted = profile_encrypter.encrypt(&expected);
        let decrypted = profile_encrypter.decrypt(&encrypted);

        assert_eq!(expected, decrypted)
    }

    #[test]
    fn profile_for_round_trip_encryption() {
        let expected = Profile {
            email: "test@gmail.com".to_string(),
            uid: "32".to_string(),
            role: "user".to_string(),
        };

        let for_profile = Profile::profile_for("test@gmail.com");
        let profile_encrypter = ProfileEncrypter::new();
        let encrypted = profile_encrypter.encrypt(&for_profile);
        let decrypted = profile_encrypter.decrypt(&encrypted);

        assert_eq!(expected, decrypted);
    }
}
