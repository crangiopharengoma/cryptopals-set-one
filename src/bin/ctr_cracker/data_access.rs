use cryptopals::cyphers::aes::ctr::EncryptedMessage;

#[derive(Debug, Clone)]
pub struct DecryptionOutcome {
    pub outcome: u8,
    pub likely: bool,
}

#[derive(Debug, Clone)]
pub struct DecryptionProgress {
    pub cipher_texts: Vec<EncryptedMessage>,
    pub transposed: Vec<Vec<u8>>,
    pub suspected_key_stream: Vec<Option<u8>>,
    pub progress_text: Vec<Vec<Option<DecryptionOutcome>>>,
}

impl DecryptionProgress {
    pub fn new(cipher_texts: Vec<EncryptedMessage>) -> DecryptionProgress {
        let mut transposed: Vec<Vec<u8>> = Vec::new();
        cipher_texts
            .iter()
            .enumerate()
            .for_each(|(count, cipher_text)| {
                cipher_text.cipher_text.iter().for_each(|byte| {
                    let position_vec = transposed.get_mut(count);
                    match position_vec {
                        Some(position_vec) => {
                            position_vec.push(*byte); // if type hint elided then this type can't be inferred
                        }
                        None => {
                            let position_vec = vec![*byte];
                            transposed.push(position_vec);
                        }
                    }
                })
            });

        let suspected_key_stream = vec![None; transposed.len()];
        let progress_text = cipher_texts
            .iter()
            .map(|cipher_text| cipher_text.cipher_text.iter().map(|_| None).collect())
            .collect();

        DecryptionProgress {
            cipher_texts,
            transposed,
            suspected_key_stream,
            progress_text,
        }
    }

    pub fn guess_char(&mut self, cipher_text_index: usize, char_position: usize, char: Option<u8>) {
        let key_value = if let Some(value) = char {
            Some(
                self.cipher_texts
                    .get(cipher_text_index)
                    .expect("char index always valid")
                    .cipher_text
                    .get(char_position)
                    .expect("char position always valid")
                    ^ value,
            )
        } else {
            None
        };

        let current_key = self
            .suspected_key_stream
            .get_mut(char_position)
            .expect("char position always valid");
        *current_key = key_value;

        self.progress_text = self
            .cipher_texts
            .iter()
            .map(|cipher_text| {
                cipher_text
                    .cipher_text
                    .iter()
                    .zip(&self.suspected_key_stream)
                    .map(|(text_byte, key_byte)| match key_byte {
                        Some(key_byte) => {
                            let outcome = text_byte ^ key_byte;
                            let likely = Self::is_likely_byte(outcome);
                            Some(DecryptionOutcome { outcome, likely })
                        }
                        None => None,
                    })
                    .collect()
            })
            .collect();
    }

    pub fn cipher_text_length(&self, cipher_text_index: usize) -> Option<usize> {
        if let Some(cipher_text) = self.cipher_texts.get(cipher_text_index) {
            Some(cipher_text.cipher_text.len())
        } else {
            None
        }
    }

    fn is_likely_byte(byte: u8) -> bool {
        match byte {
            32..=126 => true,
            _ => false,
        }
    }
}
//
// ///https://cryptopals.com/sets/3/challenges/19
// fn challenge_nineteen() {
//     let encrypter = CTRSampleEncryptions::new();
//     let messages = encrypter.encrypt_messages();
//
//     let mut transposed: Vec<Vec<u8>> = Vec::new();
//     messages.iter().enumerate().for_each(|(count, message)| {
//         message.cipher_text.iter().for_each(|byte| {
//             let position_vec = transposed.get_mut(count);
//             match position_vec {
//                 Some(position_vec) => {
//                     position_vec.push(*byte);
//                 }
//                 None => {
//                     let position_vec = vec![*byte];
//                     transposed.push(position_vec);
//                 }
//             }
//         })
//     });
//
//     let mut suspected_key_stream: Vec<u8> = Vec::with_capacity(transposed.len());
//     let control_message = &messages
//         .iter()
//         .max_by_key(|message| message.cipher_text.len())
//         .unwrap()
//         .cipher_text;
//     let mut count = 0;
//     loop {
//         println!("guess a/some char(s)");
//         let mut guess = String::new();
//
//         io::stdin()
//             .read_line(&mut guess)
//             .expect("Failed to read line");
//
//         let guess = guess.trim();
//         let guess_as_bytes = guess.as_bytes().to_vec();
//         let mut guessed_key_values = control_message[count..]
//             .iter()
//             .zip(guess_as_bytes.iter())
//             .map(|(x, y)| x ^ y)
//             .collect();
//         suspected_key_stream.append(&mut guessed_key_values);
//
//         println!("This is what your guess looks like: ");
//
//         messages.iter().enumerate().for_each(|(count, message)| {
//             let decrypted: Vec<u8> = message
//                 .cipher_text
//                 .clone()
//                 .iter()
//                 .zip(&suspected_key_stream)
//                 .map(|(x, y)| x ^ y)
//                 .collect();
//             println!("Message {count} is {}", String::from_utf8_lossy(&decrypted));
//         });
//
//         println!("Are you happy with this?");
//
//         let mut guess = String::new();
//         io::stdin()
//             .read_line(&mut guess)
//             .expect("Failed to read line");
//
//         if guess.trim() == "yes" {
//             count += guess_as_bytes.len();
//             if (count + 1) == control_message.len() {
//                 println!("You've broken the code!");
//                 break;
//             } else {
//                 println!("Great! On to the next letter!");
//             }
//         } else {
//             suspected_key_stream.truncate(count);
//             println!("Lets try again");
//         }
//     }
// }
