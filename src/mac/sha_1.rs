use std::thread;
use std::time::Duration;

use crate::hashes::sha_1::Sha1;

/// When forging a mac, ths is the new message that has been appended to the original message verified by the supplied mac
/// This also includes the padding that has been added to join the original message and new message together
pub type AppendedMessage = Vec<u8>;
/// Type alias for [u8; 20]; the generated mac for some message
pub type Sha1Mac = [u8; 20];
pub type Sha1Hmac = [u8; 20];

/// Generates a mac by calculating SHA1(key || message)
pub fn generate_mac(key: &[u8], message: &[u8]) -> Sha1Mac {
    let mut hasher = Sha1::new();
    hasher.update(&[key, message].concat());
    hasher.digest().bytes()
}

/// Generate hmac using SHA1
pub fn generate_hmac(key: &[u8], message: &[u8]) -> Sha1Hmac {
    // since we've only used various AES128 modes so far, for now let's assume the key is always 16 bytes
    let padded_key = [key, &[0; 48]].concat();

    let outer_padded_key: Vec<u8> = padded_key
        .iter()
        .zip([0x5c; 64])
        .map(|(x, y)| x ^ y)
        .collect();
    let inner_padded_key: Vec<u8> = padded_key
        .iter()
        .zip([0x36; 64])
        .map(|(x, y)| x ^ y)
        .collect();

    let mut inner_hash = Sha1::new();
    inner_hash.update(&[&inner_padded_key, message].concat());

    let mut outer_hash = Sha1::new();
    outer_hash.update(&[&outer_padded_key, &inner_hash.digest().bytes()[..]].concat());

    outer_hash.digest().bytes()
}

/// validates that a given mac is the result of calculating SHA1(key || message)
pub fn validate_mac(key: &[u8], message: &[u8], mac: [u8; 20]) -> bool {
    let calculated_mac = generate_mac(key, message);
    calculated_mac == mac
}

/// validates that a hmac for a given message is the correct result
pub fn validate_hmac(key: &[u8], message: &[u8], hmac: Sha1Hmac) -> bool {
    let calculated_hmac = generate_hmac(key, message);
    calculated_hmac == hmac
}

/// insecurely validates that a hmac for a given message is the correct result
/// compares artificially slowly going byte-by-byte and exiting early
pub fn validate_hmac_insecure(key: &[u8], message: &[u8], hmac: Sha1Hmac) -> bool {
    let calculated_hmac = generate_hmac(key, message);
    for (x, y) in hmac.iter().zip(calculated_hmac.iter()) {
        if y == x {
            thread::sleep(Duration::from_millis(50));
        } else {
            return false;
        }
    }
    true
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
