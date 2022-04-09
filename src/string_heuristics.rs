/// Takes a slice of u8 bytes and 'scores' how likely it is to be a valid English phrase
/// Scoring is based on letter frequency
pub fn score_suspected_string(possible_phrase: &[u8]) -> usize {
    possible_phrase.iter().fold(0, |score, x| score + score_char(*x))
}

fn score_char(byte: u8) -> usize {
    let char = char::from(byte);
    match char.to_ascii_lowercase() {
        'a' | 'e' | 'i' | 'l' | 'n' | 'o' | 'r' | 's' | 't' | 'u' => 10,
        'd' | 'g' => 8,
        'b' | 'c' | 'm' | 'p' => 5,
        'f' | 'h' | 'v' | 'w' | 'y' => 4,
        'k' => 3,
        'j' | 'x' => 2,
        'q' | 'z' => 1,
        _ => 0
    }
}

#[cfg(test)]
mod test {
    use crate::string_heuristics::score_suspected_string;

    #[test]
    fn phrase_is_scored_correctly() {
        let phrase = "The quick brown fox jumps over the lazy dog. Oh yeah!";
        let expected_score = 291;

        let calculated_score = score_suspected_string(phrase.as_bytes());

        assert_eq!(expected_score, calculated_score);
    }
}