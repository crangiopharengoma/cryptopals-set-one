use digest::Digest;

use crate::hashes::md4::{self, Md4};

/// When forging a mac, ths is the new message that has been appended to the original message verified by the supplied mac
/// This also includes the padding that has been added to join the original message and new message together
pub type AppendedMessage = Vec<u8>;
/// Type alias for [u8; 16]; the generated mac for some message
pub type Md4Mac = [u8; 16];

/// Generates a mac by calculating MD4(key || message)
pub fn generate_mac(key: &[u8], message: &[u8]) -> Md4Mac {
    let mut hasher = Md4::new();
    hasher.update(&[key, message].concat());
    hasher.finalize().into()
}

/// validates that a given mac is the result of calculating MD4(key || message)
pub fn validate_mac(key: &[u8], message: &[u8], mac: Md4Mac) -> bool {
    let calculated_mac = generate_mac(key, message);
    calculated_mac == mac
}

/// For a given mac, key length and new_message produces a new mac, such that the validate mac function
/// will return 'true' as though the message was actually 'message || padding || new_message' and the text appended
/// to the old message (i.e. 'padding || new_message')
pub fn forge_mac(
    original_message_len: u64,
    new_message: &[u8],
    mac: Md4Mac,
) -> (AppendedMessage, Md4Mac) {
    // println!("mac len {:?}", mac.len());
    let md4_initial_state: Vec<u32> = mac
        .chunks(4)
        .into_iter()
        .map(|block| {
            u32::from_be_bytes(<[u8; 4]>::try_from(block).expect("array length wrong")).to_be()
        })
        .collect();

    let remainder = (original_message_len % 64) as usize;
    // Padding rules for MD4 mean that every message (assuming 1 byte chars) will be padded by at least 9 bytes
    // MD4 works in blocks of 512 buts (64 bytes), so the padding requirements are based on len mod 64
    // If that's > 56 then the minimum padding will flow into a new block, meaning we'll need additional padding
    // of at 57-64 bytes. Otherwise, the minimum padding won't flow into a new block and the additional padding requirement will be
    // between 0-56 bytes. MMinimum padding consists of 0x80 and u64 bit length Additional padding is all zeroes
    let padding_len = if remainder > 56 {
        64 + remainder
    } else {
        56 - remainder
    };

    // initialise an MD4 hasher with the state derived from the known mac
    // we add the padding to this because that will be part of the message for the forged mac
    let mut hasher = md4::new_from_state(
        md4_initial_state.try_into().expect("array length wrong"),
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
            &bit_len.to_le_bytes()[..],
            new_message,
        ]
        .concat(),
        hasher.finalize().into(),
    )
}
