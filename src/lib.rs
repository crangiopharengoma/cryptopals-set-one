use std::cmp::Ordering;

pub mod cyphers;
pub mod encoding;
pub mod profile;

pub type Error = Box<dyn std::error::Error>;

#[derive(PartialOrd, PartialEq, Debug)]
pub struct OrderedFloat(f64);

impl Eq for OrderedFloat {}

// wrapper for f64 that will guarantee is always a number
#[allow(clippy::derive_ord_xor_partial_ord)]
impl Ord for OrderedFloat {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .partial_cmp(&other.0)
            .expect("ordered float is always a number")
    }
}
