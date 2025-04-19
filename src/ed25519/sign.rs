use num_bigint::{BigInt, Sign};
use num_traits::Euclid;
use sha2::{Digest, Sha512};

use crate::ed25519::utils;

use super::constants;
use super::keygen;

pub fn sign(private_key: &[u8; 32], msg: &Vec<u8>) -> [u8; 64] {
    let g = constants::get_point_g();
    let q = constants::get_const_q();

    let (a, prefix) = keygen::secret_expand(private_key);
    let public_key: &[u8; 32] = &(&g * &a).compress();

    let mut hasher = Sha512::new();
    hasher.update(&prefix);
    hasher.update(&msg);

    let r = BigInt::from_bytes_le(Sign::Plus, &hasher.finalize()).rem_euclid(&q);
    let point_r = &g * &r;
    let point_r_compressed = point_r.compress();

    hasher = Sha512::new();
    hasher.update(&point_r_compressed);
    hasher.update(&public_key);
    hasher.update(msg);
    let h = BigInt::from_bytes_le(Sign::Plus, &hasher.finalize()).rem_euclid(&q);

    let right_half_signature = (r + h * a).rem_euclid(&q);
    let right_half_signature_bytes = utils::bigint_to_32bytes(right_half_signature);

    let mut result = [0u8; 64];
    result[..32].copy_from_slice(&point_r_compressed);
    result[32..].copy_from_slice(&right_half_signature_bytes);

    result
}
