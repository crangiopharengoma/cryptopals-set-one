use challenge_sets::set_one;
use challenge_sets::set_two;

use crate::challenge_sets::set_three;

mod challenge_sets;

fn main() {
    println!("Starting cryptopals challenges!");
    set_one::run();
    println!("Set one completed!");

    println!("Start set two!");
    set_two::run();
    println!("Set three completed!");

    println!("Starting set three!");
    set_three::run();
    println!("set four completed!");
}
