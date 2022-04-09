/// Takes a slice of u8 bytes and 'scores' how likely it is to be a valid English phrase
/// Scoring is based on letter frequency
pub fn score_suspected_string(possible_phrase: &[u8]) -> usize {
    possible_phrase.iter().fold(0, |score, x| score + score_char(*x))
}

fn score_char(byte: u8) -> usize {
    let char = char::from(byte);
    match char {
        'a' | 'e' | 'i' | 'l' | 'n' | 'o' | 'r' | 's' | 't' | 'u' => 10,
        'A' | 'E' | 'I' | 'L' | 'N' | 'O' | 'R' | 'S' | 'T' | 'U' => 9,
        'd' | 'g' => 8,
        'D' | 'G' => 7,
        'b' | 'c' | 'm' | 'p' => 5,
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
    use crate::string_heuristics::score_suspected_string;

    #[test]
    fn phrase_is_scored_correctly() {
        let phrase = "The quick brown fox jumps over the lazy dog. Oh yeah!";
        let expected_score = 289;

        let calculated_score = score_suspected_string(phrase.as_bytes());

        assert_eq!(expected_score, calculated_score);
    }
}