//! An implementation of the MT19937 Mersenne Twister RNG
//! Based on the pseudo code found here: https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode
use std::cell::Cell;

/// An implementation of the MT19937 Mersenne Twister RNG
/// Based on the pseudo code found here: https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode
pub struct MersenneTwister {
    state: Vec<Cell<u32>>,
    index: Cell<u128>,
    lower_mask: Cell<u128>,
    upper_mask: Cell<u128>,
}

// The constant f forms another parameter to the generator, though not part of the algorithm proper.
const INITIALISATION_FACTOR: u128 = 1812433253;

// w: word size (in number of bits)
const WORD_SIZE: u128 = 32;
const LOW_W_BITS: u128 = 0xFFFF_FFFF;

// n: degree of recurrence
const DEGREE_OF_RECURRENCE: u128 = 624;

// m: middle word, an offset used in the recurrence relation defining the series x, 1 <= m < n
const MIDDLE_WORD: u128 = 397;

// r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w − 1
const SEPARATION_POINT: u128 = 31;

// a: coefficients of the rational normal form twist matrix
const COEFFICIENT: u128 = 0x9908B0DF;

// b, c: TGFSR(R) tempering bitmasks
const B: u128 = 0x9D2C5680;
const C: u128 = 0xEFC60000;

// s, t: TGFSR(R) tempering bit shifts
const S: u128 = 7;
const T: u128 = 15;

// u, d, l: additional Mersenne Twister tempering bit shifts/masks
const U: u128 = 11;
const D: u128 = 0xFFFFFFFF;
const L: u128 = 18;

impl Default for MersenneTwister {
    fn default() -> Self {
        // copying the approach from reference C code
        Self::new(5489)
    }
}

impl MersenneTwister {
    pub fn new(seed: u32) -> Self {
        let state = Vec::with_capacity(WORD_SIZE as usize);
        let index = Cell::new(DEGREE_OF_RECURRENCE + 1);
        let lower_mask = Cell::new((1 << SEPARATION_POINT) - 1);
        let upper_mask = Cell::new(LOW_W_BITS & (!lower_mask.get()));
        let mut mt = MersenneTwister {
            state,
            index,
            lower_mask,
            upper_mask,
        };
        mt.seed(seed);
        mt
    }

    pub fn extract_number(&self) -> u32 {
        if self.index.get() >= DEGREE_OF_RECURRENCE {
            // Generator is guaranteed to always be seeded
            self.twist();
        }

        let mut y: u128 = self.get_value(self.index.get() as usize) as u128;
        // println!("pre-tempering value: {y}");
        y ^= (y >> U) & D;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;
        // println!("post-tempering value: {y}");

        self.index.replace(self.index.get() + 1);

        // this guarantees that all bits apart from the last 32 are non-zero
        (LOW_W_BITS & y) as u32
    }

    fn seed(&mut self, seed: u32) {
        self.index.replace(DEGREE_OF_RECURRENCE);
        self.state.push(Cell::new(seed));
        (1..DEGREE_OF_RECURRENCE).for_each(|index| {
            let last = self.state.last().expect("Vec can never be empty").get() as u128;
            self.state.push(Cell::new(
                (LOW_W_BITS & (INITIALISATION_FACTOR * (last ^ (last >> (WORD_SIZE - 2))) + index))
                    as u32,
            ));
        });
    }

    fn twist(&self) {
        self.state.iter().enumerate().for_each(|(index, value)| {
            // println!("pre twist value = {}", value.get());
            let other_index = (index + 1) % (DEGREE_OF_RECURRENCE as usize);
            let other_value = self.get_value(other_index) as u128;
            let x = ((value.get() as u128) & self.upper_mask.get())
                + (other_value & self.lower_mask.get());
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= COEFFICIENT
            }
            let third_index = (index + (MIDDLE_WORD as usize)) % (DEGREE_OF_RECURRENCE as usize);
            let third_value = self.get_value(third_index) as u128;
            // println!("post twist value = {}", value.get());
            value.set((third_value ^ x_a) as u32)
        });
        self.index.set(0);
    }

    /// Convenience method for retrieve some indexed value from the current state
    /// Does not check for safety, so will blow up if wrong, so not part of the public API
    fn get_value(&self, index: usize) -> u32 {
        self.state
            .get(index)
            .expect("index will always exist")
            .get()
    }
}

#[cfg(test)]
mod test {
    use crate::random::mersenne_twister::{MersenneTwister, DEGREE_OF_RECURRENCE};

    #[test]
    pub fn mersenne_twister_with_known_seed() {
        let mt = MersenneTwister::default();
        let random = mt.extract_number();

        assert_eq!(3499211612, random);
    }

    #[test]
    pub fn does_not_panic_after_n_calls() {
        // testing that this won't panic if called more than DEGREE_OF_RECURRENCE times
        let mt = MersenneTwister::default();
        let end = DEGREE_OF_RECURRENCE + 1;
        (0..=end).for_each(|_| {
            mt.extract_number();
        });
        assert!(true);
    }
}
