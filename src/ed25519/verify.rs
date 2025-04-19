use crate::ed25519::{constants, points::Point};
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha512};

use num_traits::Euclid;

pub fn verify(public_key: &[u8; 32], msg: &Vec<u8>, signature: &[u8; 64]) -> bool {
    let q = constants::get_const_q();
    let g = constants::get_point_g();

    let point_public_key = match Point::decompress(*public_key) {
        Ok(point) => point,
        Err(_) => return false,
    };

    let point_r_compressed: [u8; 32] = signature[..32].try_into().unwrap();
    let point_r = match Point::decompress(point_r_compressed) {
        Ok(point) => point,
        Err(_) => return false,
    };

    let right_half_signature = BigInt::from_bytes_le(Sign::Plus, &signature[32..]);
    if right_half_signature >= q {
        return false;
    }

    let mut hasher = Sha512::new();
    hasher.update(point_r_compressed);
    hasher.update(public_key);
    hasher.update(msg);

    let h = BigInt::from_bytes_le(Sign::Plus, &hasher.finalize());

    let expected_point_r = Point::straus_multiexponentiation(
        &right_half_signature,
        &g,
        &(-h).rem_euclid(&q),
        &point_public_key,
    );

    expected_point_r == point_r
}
