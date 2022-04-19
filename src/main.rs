use challenge_sets::set_one;

mod challenge_sets;

fn main() {
    println!("Starting cryptopals challenges!");
    set_one::run();
    println!("Set one completed!");

    println!("Start set two!");
    set_two::run();
}
