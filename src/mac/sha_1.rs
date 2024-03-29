use std::array::TryFromSliceError;
use std::ops::{Index, IndexMut, RangeFull};

use crate::hashes::sha_1::Sha1;
use crate::mac::Hmac;

/// When forging a mac, ths is the new message that has been appended to the original message verified by the supplied mac
/// This also includes the padding that has been added to join the original message and new message together
pub type AppendedMessage = Vec<u8>;
/// Type alias for [u8; 20]; the generated mac for some message
pub type Sha1Mac = [u8; 20];

/// New typing an array but also implementing HMAC trait
#[derive(PartialEq, Debug, Default, Clone)]
pub struct Sha1Hmac([u8; 20]);

impl TryFrom<Vec<u8>> for Sha1Hmac {
    type Error = Vec<u8>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let hmac = value.try_into()?;
        Ok(Sha1Hmac(hmac))
    }
}

impl TryFrom<&[u8]> for Sha1Hmac {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let hmac = value.try_into()?;
        Ok(Sha1Hmac(hmac))
    }
}

impl Index<RangeFull> for Sha1Hmac {
    type Output = [u8];

    fn index(&self, index: RangeFull) -> &Self::Output {
        &self.0[index]
    }
}

impl Index<usize> for Sha1Hmac {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Sha1Hmac {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Hmac for Sha1Hmac {
    type HmacFormat = Sha1Hmac;
    type HmacIterator = Sha1HmacIter;

    fn hash(bytes: &[u8]) -> Vec<u8> {
        Sha1::from(bytes).digest().bytes().into()
    }

    fn iter(&self) -> Sha1HmacIter {
        Sha1HmacIter {
            hmac: self.clone(),
            position: 0,
        }
    }
}

pub struct Sha1HmacIter {
    hmac: Sha1Hmac,
    position: usize,
}

impl Iterator for Sha1HmacIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.hmac.0.len() {
            None
        } else {
            let next_value = self.hmac[self.position];
            self.position += 1;
            Some(next_value)
        }
    }
}

/// Generates a mac by calculating SHA1(key || message)
pub fn generate_mac(key: &[u8], message: &[u8]) -> Sha1Mac {
    let mut hasher = Sha1::new();
    hasher.update(&[key, message].concat());
    hasher.digest().bytes()
}

/// validates that a given mac is the result of calculating SHA1(key || message)
pub fn validate_mac(key: &[u8], message: &[u8], mac: [u8; 20]) -> bool {
    let calculated_mac = generate_mac(key, message);
    calculated_mac == mac
}

/// For a given mac, key length and new_message produces a new mac, such that the validate mac function
/// will return 'true' as though the message was actually 'message || padding || new_message' and the text appended
/// to the old message (i.e. 'padding || new_message')
pub fn forge_mac(
    original_message_len: u64,
    new_message: &[u8],
    mac: [u8; 20],
) -> (AppendedMessage, Sha1Mac) {
    let sha1_initial_state: Vec<u32> = mac
        .chunks(4)
        .into_iter()
        .map(|block| u32::from_be_bytes(<[u8; 4]>::try_from(block).expect("array length wrong")))
        .collect();

    let remainder = (original_message_len % 64) as usize;
    // Padding rules for SHA1 mean that every message (assuming 1 byte chars) will be padded by at least 9 bytes
    // SHA1 works in blocks of 512 buts (64 bytes), so the padding requirements are based on len mod 64
    // If that's > 56 then the minimum padding will flow into a new block, meaning we'll need additional padding
    // of at 57-64 bytes. Otherwise, the minimum padding won't flow into a new block and the additional padding requirement will be
    // between 0-56 bytes. MMinimum padding consists of 0x80 and u64 bit length Additional padding is all zeroes
    let padding_len = if remainder > 56 {
        64 + remainder
    } else {
        56 - remainder
    };

    // initialise an SHA1 hasher with the state derived from the known mac
    // we add the padding to this because that will be part of the message for the forged mac
    let mut hasher = Sha1::new_from_state(
        sha1_initial_state.try_into().expect("array length wrong"),
        original_message_len + padding_len as u64 + 8, // padding len does not include the u64 bit length of the initial hash
    );

    hasher.update(new_message);

    let padding = {
        let mut padding = [0; 64];
        padding[0] = 0x80;
        padding
    };

    let bit_len = original_message_len * 8;

    (
        [
            &padding[..padding_len],
            &bit_len.to_be_bytes()[..],
            new_message,
        ]
        .concat(),
        hasher.digest().bytes(),
    )
}
