use cryptopals::cyphers::encryption_oracle::{
    AesMode, BasicECBOracle, ECBOracle, RandomPrefixECBOracle,
};
use cryptopals::cyphers::{aes_cbc, encryption_oracle, padding};
use cryptopals::encoding::base64::Base64;
use cryptopals::encoding::Digest;
use cryptopals::profile::{Profile, ProfileEncrypter};

pub fn run() {
    print!("Starting Challenge Nine... ");
    challenge_nine();
    println!("Success!");

    print!("Starting Challenge Ten... ");
    challenge_ten();
    println!("Success!");

    print!("Starting Challenge Eleven... ");
    challenge_eleven();
    println!("Success!");

    print!("Starting Challenge Twelve... ");
    challenge_twelve();
    println!("Success!");

    print!("Starting Challenge Thirteen... ");
    challenge_thirteen();
    println!("Success!");

    println!("Starting Challenge Fourteen... ");
    challenge_fourteen();
    println!("Success!");
}

/// https://cryptopals.com/sets/2/challenges/9
fn challenge_nine() {
    let plain_text = "YELLOW SUBMARINE";
    let target_len = 20;
    let expected_padded = "YELLOW SUBMARINE\x04\x04\x04\x04";

    let padded = padding::pkcs7(plain_text.as_bytes(), target_len);

    assert_eq!(expected_padded.as_bytes(), padded)
}

/// https://cryptopals.com/sets/2/challenges/10
fn challenge_ten() {
    let encrypted_message = Base64::from_file("10.txt").unwrap();

    let decrypted_message = aes_cbc::decrypt(
        encrypted_message.bytes(),
        "YELLOW SUBMARINE".as_bytes(),
        &[0b0; 16][..],
    );

    println!(
        "The message is: {}",
        String::from_utf8_lossy(&decrypted_message)
    );
}

/// https://cryptopals.com/sets/2/challenges/11
fn challenge_eleven() {
    let meaningless_jibber_jabber = "X".repeat(48).as_bytes().to_vec();

    (0..11).for_each(|_| {
        let encrypted_message = encryption_oracle::encrypt(&meaningless_jibber_jabber);
        let aes_type = encryption_oracle::detect_aes_type(encrypted_message);
        match aes_type {
            AesMode::CBC => println!("CBC encryption used"),
            AesMode::ECB => println!("ECB encryption used"),
        };
    })
}

/// https://cryptopals.com/sets/2/challenges/12
fn challenge_twelve() {
    let oracle = BasicECBOracle::new();
    let key_length = oracle.find_key_length().expect("key length > 128");
    println!("key length is {}", key_length);

    let decrypted_message = oracle.decrypt();

    print!(
        "The message is: \n{}\n",
        String::from_utf8_lossy(&decrypted_message)
    );
}

///https://cryptopals.com/sets/2/challenges/13
fn challenge_thirteen() {
    let target_email = "sam.rosenberg@secret.com".to_string();

    let oracle = ProfileOracle {
        profile_encrypter: ProfileEncrypter::new(),
        target_email,
    };
    let key_length = oracle.find_key_length().expect("key length > 128");

    // with email=target_email at the start of a string we may need to push extra bytes
    // to ensure that the "admin..." string is encoded as a single block
    let mut padded_admin = "A"
        .repeat(key_length - ((oracle.target_email.len() + 6) % key_length))
        .into_bytes();
    padded_admin.extend_from_slice(&padding::pkcs7("admin".as_bytes(), key_length));
    let encrypted_admin = oracle.encrypt(padded_admin);

    let byte_remainder = (0..key_length).find(|i| {
        let encrypted_a = oracle.encrypt(&"A".repeat(*i).into_bytes());
        let encrypted_b = oracle.encrypt(&"A".repeat(i + 1).into_bytes());
        encrypted_b.len() > encrypted_a.len()
    });

    let target_remainder = {
        match byte_remainder {
            Some(remainder) => key_length + 5 - remainder,
            None => 5,
        }
    };

    let mut trojan_encrypted = oracle.encrypt(&"A".repeat(target_remainder).into_bytes());
    trojan_encrypted.truncate(trojan_encrypted.len() - 16);

    trojan_encrypted.extend_from_slice(&encrypted_admin[key_length * 2..key_length * 3]);

    println!(
        "decrypted is: {}",
        oracle.profile_encrypter.decrypt(&trojan_encrypted)
    );
}

struct ProfileOracle {
    profile_encrypter: ProfileEncrypter,
    target_email: String,
}

impl ECBOracle for ProfileOracle {
    fn encrypt<T: Digest>(&self, message: T) -> Vec<u8> {
        let mut known_bytes = self.target_email.clone().into_bytes();
        known_bytes.extend_from_slice(message.bytes());
        let profile = Profile::profile_for(&String::from_utf8(known_bytes).unwrap());
        self.profile_encrypter.encrypt(&profile)
    }
}

fn challenge_fourteen() {
    let oracle = RandomPrefixECBOracle::new();

    let decrypted_message = oracle.decrypt();
    print!(
        "The message is: \n{}\n",
        String::from_utf8_lossy(&decrypted_message)
    );
}