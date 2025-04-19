use num_bigint::{BigInt, Sign};
use rand::rngs::OsRng;
use rand::TryRngCore;

use sha2::{Digest, Sha512};

use super::constants;

#[derive(Debug)]
pub struct Keypair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

pub fn secret_expand(private_key: &[u8; 32]) -> (BigInt, [u8; 32]) {
    let hashed_private_key: [u8; 64] = Sha512::digest(private_key).try_into().unwrap();

    let mut nbr = BigInt::from_bytes_le(Sign::Plus, &hashed_private_key[..32]);

    let and_constant = (BigInt::from(1) << 254) - 8;
    let or_constant = BigInt::from(1) << 254;

    nbr &= and_constant;
    nbr |= or_constant;

    (nbr, hashed_private_key[32..].try_into().unwrap())
}

pub fn private_to_public_key(private_key: [u8; 32]) -> [u8; 32] {
    let g = constants::get_point_g();

    let (scalar, _) = secret_expand(&private_key);

    (g * &scalar).compress()
}

pub fn gen_keypair() -> Keypair {
    let mut private_key = [0u8; 32];

    OsRng
        .try_fill_bytes(&mut private_key)
        .expect("Could not open OS random number generator");

    Keypair {
        public_key: private_to_public_key(private_key),
        private_key,
    }
}
