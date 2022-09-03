use std::str::FromStr;

use num::bigint::Sign;
use num::BigInt;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::encoding::hex::Hex;
use crate::encoding::Digest as MyDigest;

pub fn generate_session_key() -> Vec<u8> {
    let hex = Hex::from_str("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff").expect("invalid hex string");
    let p = BigInt::from_bytes_be(Sign::Plus, hex.bytes());
    let g = BigInt::from(2);

    let a = rand::thread_rng().next_u32() % &p;
    let A = g.modpow(&a, &p);

    let b = rand::thread_rng().next_u32() % &p;
    let B = g.modpow(&b, &p);

    let s = B.modpow(&a, &p);

    assert_eq!(s, A.modpow(&b, &p));

    let mut hasher = Sha256::new();
    let (_, bytes) = s.to_bytes_le();
    hasher.update(bytes);
    let result = hasher.finalize();

    result[..16].to_vec()
}
