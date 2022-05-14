use cryptopals::cyphers::aes::oracles::padding_oracle::{PaddingOracle, SamplePaddingOracle};

pub fn run() {
    print!("Starting Challenge Seventeen... ");
    challenge_seventeen();
    println!("Success!");

    print!("Starting Challenge Eighteen... ");
    challenge_eighteen();
    println!("Success!");

    print!("Starting Challenge Nineteen... ");
    challenge_nineteen();
    println!("Success!");

    print!("Starting Challenge Twenty... ");
    challenge_twenty();
    println!("Success!");

    print!("Starting Challenge Twenty-One... ");
    challenge_twenty_one();
    println!("Success!");

    println!("Starting Challenge Twenty-Two... ");
    challenge_twenty_two();
    println!("Success!");

    println!("Starting Challenge Twenty-Three... ");
    challenge_twenty_three();
    println!("Success!");

    println!("Starting Challenge Twenty-Four... ");
    challenge_twenty_four();
    println!("Success!");
}

/// https://cryptopals.com/sets/3/challenges/17
fn challenge_seventeen() {
    for _ in 0..=50 {
        let oracle = SamplePaddingOracle::new();
        let encryption = oracle.encrypt_rand();
        let decrypted = oracle.decrypt(&encryption);
        println!("result: {}", String::from_utf8_lossy(&decrypted));
    }
}

fn challenge_eighteen() {
    assert!(false);
}

fn challenge_nineteen() {
    assert!(false);
}

fn challenge_twenty() {
    assert!(false);
}

fn challenge_twenty_one() {
    assert!(false);
}

fn challenge_twenty_two() {
    assert!(false);
}

fn challenge_twenty_three() {
    assert!(false);
}

fn challenge_twenty_four() {
    assert!(false);
}
