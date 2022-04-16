use crate::OrderedFloat;

/// Takes a slice of u8 bytes and 'scores' how likely it is to be a valid English phrase
/// Scoring is based on letter frequency
///
/// Panics
/// If the possible phrase len == 0
pub fn score_suspected_string(possible_phrase: &[u8]) -> usize {
    possible_phrase.iter().fold(0, |score, x| score + score_char(*x))
}

/// Returns the Hamming distance or edit distance between two strings
///
/// This method takes slices of u8s and assumes that they are valid strings of equal length.
/// If either invariant is not met this will still return a usize.
/// This will effectively be the same as truncating the longer string to the length of the shorter
pub fn hamming_distance(string_one: &[u8], string_two: &[u8]) -> usize {
    string_one.iter()
        .zip(string_two.iter())
        .map(|(x, y)| x ^ y)
        .fold(0, |accum, byte| accum + byte.count_ones() as usize)
}

/// Calculates the normalized edit distance for a slice of u8 for a given key size
///
/// Takes the first four slices of keysize length and finds the normalized edit distance
/// between the first two and second two. It then averages these two distances.
///
/// Panics
/// If the keysize is > 4 times the length of the encrypted message
pub fn normalized_edit_distance(encrypted_message: &[u8], keysize: &usize) -> OrderedFloat {
    // println!("keysize: {keysize} ");
    let chunks: Vec<&[u8]> = encrypted_message.chunks(*keysize).collect();
    // print!("chunks are {chunks:?} ");

    let edit_distances = vec!(
        hamming_distance(chunks[0], chunks[1]),
        hamming_distance(chunks[1], chunks[2]),
        hamming_distance(chunks[2], chunks[3]),
        hamming_distance(chunks[0], chunks[2]),
        hamming_distance(chunks[0], chunks[3]),
        hamming_distance(chunks[1], chunks[3])
    );
    // println!("edit distances: {edit_distances:?}");

    let normalized_edit_distances: Vec<f64> = edit_distances.iter().map(|dist| *dist as f64 / *keysize as f64).collect();
    // println!("normalized edit distances: {normalized_edit_distances:?}");

    let average = normalized_edit_distances.iter().sum::<f64>() / (normalized_edit_distances.len() as f64);
    // println!("keysize {keysize} has average edit distance {average}");
    OrderedFloat(average)
}

/// Uses inverted scrabble scoring to calculate the approximate frequency of letters
fn score_char(byte: u8) -> usize {
    let char = char::from(byte);
    match char {
        'a' | 'e' | 'i' | 'l' | 'n' | 'o' | 'r' | 's' | 't' | 'u' => 10,
        'A' | 'E' | 'I' | 'L' | 'N' | 'O' | 'R' | 'S' | 'T' | 'U' => 9,
        'd' | 'g' => 8,
        'D' | 'G' => 7,
        'b' | 'c' | 'm' | 'p' | ' ' => 5,
        'B' | 'C' | 'M' | 'P' => 4,
        'f' | 'h' | 'v' | 'w' | 'y' => 4,
        'F' | 'H' | 'V' | 'W' | 'Y' => 3,
        'k' => 3,
        'K' => 2,
        'j' | 'x' => 2,
        'J' | 'X' => 2,
        'q' | 'z' => 1,
        // Q and Z omitted
        _ => 0
    }
}

#[cfg(test)]
mod test {
    use crate::string_heuristics::{hamming_distance, score_suspected_string};

    #[test]
    fn phrase_is_scored_correctly() {
        let phrase = "The quick brown fox jumps over the lazy dog. Oh yeah!";
        let expected_score = 339;

        let calculated_score = score_suspected_string(phrase.as_bytes());

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
}