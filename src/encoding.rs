use std::collections::HashMap;

use crate::OrderedFloat;

pub mod base64;
pub mod hex;
pub mod structured_cookie;

impl Digest for Vec<u8> {
    fn bytes(&self) -> &[u8] {
        self
    }
}

impl Digest for &Vec<u8> {
    fn bytes(&self) -> &[u8] {
        self
    }
}

impl Digest for &[u8] {
    fn bytes(&self) -> &[u8] {
        self
    }
}

/// A Digest represents a sequence of bytes that contain some message
///
/// No assumptions are made about the encoding of the message,
/// other than that it is valid to analyse the message byte-by-byte
pub trait Digest {
    fn bytes(&self) -> &[u8];

    /// The length of the message in bytes
    fn len(&self) -> usize {
        self.bytes().len()
    }

    /// true if the message length in bytes is 0
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Scores how likely this Digest is to some valid English text
    /// Assumes that the correct digest will always be valid utf8
    fn english_score(&self) -> usize {
        if String::from_utf8(self.bytes().to_vec()).is_err() {
            return 0;
        }

        self.bytes()
            .iter()
            .fold(0, |score, x| score + score_char(*x))
    }

    /// Returns the Hamming distance or edit distance between two Digests
    ///
    /// This method takes two Digests and assumes that they are valid strings of equal length.
    /// If either invariant is not met this will still return a usize.
    /// This will effectively be the same as truncating the longer string to the length of the shorter
    fn hamming_distance<T: Digest>(&self, other: T) -> usize {
        hamming_distance(self.bytes(), other.bytes())
    }

    /// Calculates the normalized edit distance for a slice of u8 for a given key size
    ///
    /// Takes the first four slices of keysize length and finds the average normalized edit distance
    /// between the first two and second two. It then averages these two distances.
    ///
    /// Panics
    /// If the keysize is > 4 times the length of the encrypted message
    fn normalized_edit_distance(&self, keysize: &usize) -> OrderedFloat {
        let chunks: Vec<&[u8]> = self.bytes().chunks(*keysize).collect();

        OrderedFloat(
            vec![
                hamming_distance(chunks[0], chunks[1]),
                hamming_distance(chunks[1], chunks[2]),
                hamming_distance(chunks[2], chunks[3]),
                hamming_distance(chunks[0], chunks[2]),
                hamming_distance(chunks[0], chunks[3]),
                hamming_distance(chunks[1], chunks[3]),
            ]
            .iter()
            .map(|dist| *dist as f64 / *keysize as f64)
            .sum::<f64>()
                / 6.0,
        )
    }

    /// detects whether a given Digest contains duplicated chunks of a given length
    fn duplicate_blocks(&self, block_size: usize) -> bool {
        let map = self.map_blocks(block_size);
        *map.values()
            .reduce(|accum, val| if val > accum { val } else { accum })
            .unwrap()
            > 1
    }

    /// returns a map of the unique blocks contained in the digest
    /// keyed on the blocks themselves
    /// value is the count of those blocks
    fn map_blocks(&self, block_size: usize) -> HashMap<Vec<u8>, usize> {
        let mut map: HashMap<Vec<u8>, usize> = HashMap::new();
        self.bytes().chunks(block_size).for_each(|block| {
            map.entry(block.to_vec())
                .and_modify(|e| *e += 1)
                .or_insert(1);
        });
        map
    }

    /// returns a map of the blocks that appear more than once in the digest
    /// keyed on the blocks themselves
    fn map_duplicate_blocks(&self, block_size: usize) -> HashMap<Vec<u8>, usize> {
        self.map_blocks(block_size)
            .into_iter()
            .filter(|(_, v)| *v > 1)
            .collect()
    }
}

/// Returns the Hamming distance or edit distance between two strings
///
/// This method takes slices of u8s and assumes that they are valid strings of equal length.
/// If either invariant is not met this will still return a usize.
/// This will effectively be the same as truncating the longer string to the length of the shorter
fn hamming_distance(string_one: &[u8], string_two: &[u8]) -> usize {
    string_one
        .iter()
        .zip(string_two.iter())
        .map(|(x, y)| x ^ y)
        .fold(0, |accum, byte| accum + byte.count_ones() as usize)
}

/// Uses inverted scrabble scoring to calculate the approximate frequency of letters
fn score_char(byte: u8) -> usize {
    // score invalid ascii and control characters as 0
    if !(32..=127).contains(&byte) {
        return 0;
    }
    let char = char::from(byte);
    match char.to_ascii_lowercase() {
        'a' | 'e' | 'i' | 'l' | 'n' | 'o' | 'r' | 's' | 't' | 'u' => 12,
        'd' | 'g' => 10,
        'b' | 'c' | 'm' | 'p' | ' ' => 7,
        'f' | 'h' | 'v' | 'w' | 'y' => 6,
        'k' => 5,
        'j' | 'x' => 4,
        'q' | 'z' => 3,
        _ => 1,
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::encoding::base64::Base64;
    use crate::encoding::hex::Hex;
    use crate::encoding::{hamming_distance, Digest};

    #[test]
    fn phrase_is_scored_correctly() {
        let phrase: Vec<u8> = "The quick brown fox jumps over the lazy dog. Oh yeah!"
            .as_bytes()
            .to_vec();
        let expected_score = 445;

        let calculated_score = phrase.english_score();

        assert_eq!(expected_score, calculated_score);
    }

    #[test]
    fn hamming_distance_calculated() {
        let string_one = "this is a test".as_bytes();
        let string_two = "wokka wokka!!!".as_bytes();
        let expected_distance = 37;

        let calculated_distance = hamming_distance(string_one, string_two);

        assert_eq!(expected_distance, calculated_distance);
    }

    #[test]
    fn hex_to_base64() {
        let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let hex_input = Hex::from_str(hex_str).unwrap();
        let base64_expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let base64_converted = Base64::from_hex(hex_input);

        assert_eq!(base64_expected, base64_converted.to_string());
    }
}
