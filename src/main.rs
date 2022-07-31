use challenge_sets::set_four;
use challenge_sets::set_one;
use challenge_sets::set_three;
use challenge_sets::set_two;

mod challenge_sets;

fn main() {
    if false {
        println!("Starting cryptopals challenges!");
        set_one::run();
        println!("Set one completed!");

        println!("Starting set two!");
        set_two::run();
        println!("Set three completed!");

        println!("Starting set three!");
        set_three::run();
        println!("Set three completed!");
    }

    println!("Starting set four!");
    set_four::run();
    println!("Set four completed!")
}
