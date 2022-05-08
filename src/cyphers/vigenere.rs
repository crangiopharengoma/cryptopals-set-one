use crate::cyphers::caesar_cypher;
use crate::encoding::Digest;

pub fn encrypt<T: Digest>(message: T, key: &[u8]) -> Vec<u8> {
    // this will actually make the key 3x longer than the message, but the zip will handle that
    key.repeat(message.len())
        .iter()
        .zip(message.bytes().iter())
        .map(|(x, y)| x ^ y)
        .collect()
}

pub fn decrypt<T: Digest>(message: T, key: &[u8]) -> Vec<u8> {
    // decrypting is just repeating the process of encrypting
    encrypt(message, key)
}

pub fn break_encryption<T: Digest>(encrypted_message: T) -> Vec<u8> {
    let max_key_length = if encrypted_message.len() > 200 {
        50
    } else {
        encrypted_message.len() / 4
    };

    let key_size = (2..max_key_length)
        .min_by_key(|key_size| encrypted_message.normalized_edit_distance(key_size))
        .unwrap();

    let key: Vec<u8> = (0..key_size)
        .map(|i| {
            caesar_cypher::find_key(
                &encrypted_message
                    .bytes()
                    .chunks(key_size)
                    .map(|chunk| if chunk.len() > i { chunk[i] } else { 0 })
                    .collect::<Vec<u8>>(),
            )
            .expect("key brute force failed")
        })
        .collect();

    decrypt(encrypted_message, &key)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::cyphers::vigenere::{decrypt, encrypt};
    use crate::encoding::hex::Hex;
    use crate::encoding::Digest;

    #[test]
    fn string_is_encrypted() {
        let plain_text =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .as_bytes()
                .to_vec();
        let key = "ICE".as_bytes();
        let expected_encrypted = Hex::from_str("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();

        let encrypted = encrypt(&plain_text, key);

        assert_eq!(expected_encrypted.bytes(), encrypted);
    }

    #[test]
    fn decryption_reverses_encryption() {
        let plain_text = "This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6. There's a file here. It's been base64'd after being encrypted with repeating-key XOR. Decrypt it. Here's how: Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between: this is a test and wokka wokka!!! is 37. Make sure your code agrees before you proceed. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on. Solve each block as if it was single-character XOR. You already have code to do this. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key. This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR (Vigenere) statistically is obviously an academic exercise, a Crypto 101 thing. But more people know how to break it than can actually break it, and a similar technique breaks something much more important".as_bytes().to_vec();
        let key = "THISISALONGERKEY".as_bytes();

        let encrypted = encrypt(&plain_text, key);
        let decrypted = decrypt(&encrypted, key);

        assert_eq!(plain_text, decrypted);
    }
}
