use core::panic;

use num_bigint::BigInt;
use num_bigint::Sign::Plus;
use num_traits::Euclid;

use super::constants;

pub fn modp_inv(x: &BigInt) -> BigInt {
    let p = constants::get_const_p();

    x.modpow(&(&p - 2), &p)
}

/** Transform to [u8; 32] and fills with 0s if necessary */
pub fn bigint_to_32bytes(x: BigInt) -> [u8; 32] {
    let (sign, bytes) = x.to_bytes_le();

    if sign != Plus {
        panic!("cannot transform non-positive number to 32 bytes");
    }

    if bytes.len() > 32 {
        panic!(
            "this bigint is too large to fit in 32 bytes ({} bytes)",
            bytes.len()
        );
    }

    let mut result = [0u8; 32];

    result[..bytes.len()].copy_from_slice(&bytes);

    result
}

pub fn recover_x(y: &BigInt, sign: bool) -> Result<BigInt, &str> {
    let p = constants::get_const_p();
    let d = constants::get_const_d();
    let modp_sqrt_m1 = constants::get_modp_sqrt_m1();
    let one = BigInt::from(1);

    if y >= &p {
        return Err("y is greater than p");
    }

    let x2 = (y * y - &one) * modp_inv(&(d * y * y + &one));

    if x2 == BigInt::ZERO {
        if sign {
            return Err("x2 is zero and sign is true");
        } else {
            return Ok(BigInt::from(0));
        }
    }

    let mut x = x2.modpow(&((&p + 3) / BigInt::from(8)), &p);

    if (&x * &x - &x2).rem_euclid(&p) != BigInt::ZERO {
        x = (x * modp_sqrt_m1).rem_euclid(&p);
    }

    if (&x * &x - &x2).rem_euclid(&p) != BigInt::ZERO {
        return Err("x is not a square root of x2");
    }

    if (&x & &one).bit(0) != sign {
        x = &p - &x;
    }

    Ok(x)
}
