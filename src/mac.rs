use std::fmt::Debug;
use std::ops::{Index, IndexMut, RangeFull};
use std::thread;
use std::time::Duration;

pub mod md4;
pub mod sha_1;
pub mod timing_attack;

pub trait Hmac:
    Index<usize, Output = u8>
    + IndexMut<usize>
    + Index<RangeFull, Output = [u8]>
    + Default
    + Sized
    + Debug
    + Clone
{
    type HmacFormat: Hmac + PartialEq + Debug + TryFrom<Vec<u8>, Error = Vec<u8>>;
    type HmacIterator: Iterator<Item = u8>;

    fn hash(bytes: &[u8]) -> Vec<u8>;

    fn iter(&self) -> Self::HmacIterator;

    /// Generate a HMAC using a implementation-specific hash
    fn generate_hmac(key: &[u8], message: &[u8]) -> Self::HmacFormat {
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

        let inner_hash = Self::hash(&[&inner_padded_key, message].concat());
        let outer_hash = Self::hash(&[outer_padded_key, inner_hash].concat());

        // This should never fail if the try from implementation of HmacFormat is correct
        // because we know that we've just generated a valid hmac
        outer_hash
            .try_into()
            .expect("try from implementation for associated type wrong")
    }

    /// validates that a hmac for a given message is the correct result
    fn validate_hmac(key: &[u8], message: &[u8], hmac: Self::HmacFormat) -> bool {
        let calculated_hmac = Self::generate_hmac(key, message);
        calculated_hmac == hmac
    }

    /// insecurely validates that a hmac for a given message is the correct result
    /// compares artificially slowly going byte-by-byte and exiting early
    fn validate_hmac_insecure(
        &self,
        key: &[u8],
        message: &[u8],
        // hmac: Self::HmacFormat,
        pause: u64,
    ) -> bool {
        let calculated_hmac = Self::generate_hmac(key, message);
        for (x, y) in self.clone().iter().zip(calculated_hmac.iter()) {
            if y == x {
                println!("match x: {x} y: {y}");
                thread::sleep(Duration::from_millis(pause));
            } else {
                return false;
            }
        }
        true
    }
}
