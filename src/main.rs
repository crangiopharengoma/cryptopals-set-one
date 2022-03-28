use set_one::base64::Base64;

fn main() {
    let byte_sample: [u8; 7] = [12, 54, 84, 64, 97, 255, 123];
    let base64 = Base64::new(&byte_sample);

    println!("Base64 encoded: {base64}");
}