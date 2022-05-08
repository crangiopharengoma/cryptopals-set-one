pub mod aes_cbc;
pub mod aes_ecb;
pub mod caesar_cypher;
pub mod oracles;
pub mod padding;
pub mod vigenere;

#[derive(Debug, PartialEq)]
pub enum AesMode {
    ECB,
    CBC,
}
