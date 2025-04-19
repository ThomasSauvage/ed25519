use std::ops::{Add, Mul};

use num_bigint::{BigInt, Sign};
use num_traits::Euclid;

use super::{
    constants::{self, get_const_p},
    utils,
};

// (X, Y, Z, T)

#[derive(Clone, Debug)]
pub struct Point {
    x: BigInt,
    y: BigInt,
    z: BigInt,
    t: BigInt,
}

impl Point {
    pub fn zero() -> Point {
        Point {
            x: BigInt::ZERO,
            y: BigInt::from(1),
            z: BigInt::from(1),
            t: BigInt::ZERO,
        }
    }

    pub fn new(x: BigInt, y: BigInt, z: BigInt, t: BigInt) -> Self {
        Self { x, y, z, t }
    }

    pub fn new_from_i32(x: i32, y: i32, z: i32, t: i32) -> Self {
        Self {
            x: BigInt::from(x),
            y: BigInt::from(y),
            z: BigInt::from(z),
            t: BigInt::from(t),
        }
    }

    pub fn compress(&self) -> [u8; 32] {
        let p = get_const_p();

        let z_inv = utils::modp_inv(&self.z);

        let x = (&self.x * &z_inv).rem_euclid(&p);
        let y = (&self.y * &z_inv).rem_euclid(&p);

        let res = y | ((x & BigInt::from(1)) << 255);

        utils::bigint_to_32bytes(res)
    }

    pub fn decompress(bytes: [u8; 32]) -> Result<Point, String> {
        let p = get_const_p();
        let one = BigInt::from(1);

        let mut y = BigInt::from_bytes_le(Sign::Plus, &bytes);
        let sign = (&y >> 255) & &one == one;
        let and_constant = (BigInt::from(1) << 255) - 1;

        y &= and_constant;

        let x = utils::recover_x(&y.clone(), sign)?;

        Ok(Point {
            t: (&x * &y).rem_euclid(&p),
            x,
            y: y.clone(),
            z: one,
        })
    }

    /// Computes aP + bQ
    pub fn straus_multiexponentiation(a: &BigInt, p: &Point, b: &BigInt, q: &Point) -> Point {
        let t = [[Point::zero(), q.clone()], [p.clone(), p + q]];

        let mut result = Point::zero();

        for i in (0..256).rev() {
            result = &result + &result + &t[a.bit(i) as usize][b.bit(i) as usize];
        }

        result
    }
}

impl Add for &Point {
    type Output = Point;

    fn add(self, other: &Point) -> Point {
        let p = constants::get_const_p();
        let d = constants::get_const_d();

        let a = ((&self.y - &self.x) * (&other.y - &other.x)).rem_euclid(&p);
        let b = ((&self.y + &self.x) * (&other.y + &other.x)).rem_euclid(&p);
        let c = (BigInt::from(2) * &self.t * &other.t * d).rem_euclid(&p);
        let d = (BigInt::from(2) * &self.z * &other.z).rem_euclid(&p);
        let e = (&b - &a).rem_euclid(&p);
        let f = (&d - &c).rem_euclid(&p);
        let g = (&d + &c).rem_euclid(&p);
        let h = (&b + &a).rem_euclid(&p);

        Point {
            x: (&e * &f).rem_euclid(&p),
            y: (&g * &h).rem_euclid(&p),
            z: (&f * &g).rem_euclid(&p),
            t: (e * h).rem_euclid(&p),
        }
    }
}

impl Add for Point {
    type Output = Point;

    fn add(self, other: Point) -> Point {
        &self + &other
    }
}

impl Add<&Point> for Point {
    type Output = Point;

    fn add(self, other: &Point) -> Point {
        &self + other
    }
}

impl Add<Point> for &Point {
    type Output = Point;

    fn add(self, other: Point) -> Point {
        self + &other
    }
}

// Scalar multiplication
impl Mul<&BigInt> for &Point {
    type Output = Point;

    fn mul(self, scalar: &BigInt) -> Self::Output {
        let mut point_p = self.clone();
        let mut local_scalar = scalar.clone();

        let mut point_q = Point::new_from_i32(0, 1, 1, 0);

        while &local_scalar > &BigInt::ZERO {
            if local_scalar.bit(0) {
                point_q = &point_q + &point_p;
            }

            point_p = &point_p + &point_p;

            local_scalar >>= 1;
        }

        point_q
    }
}

impl Mul<BigInt> for Point {
    type Output = Point;

    fn mul(self, scalar: BigInt) -> Point {
        &self * &scalar
    }
}

impl Mul<&BigInt> for Point {
    type Output = Point;

    fn mul(self, scalar: &BigInt) -> Point {
        &self * scalar
    }
}

impl Mul<BigInt> for &Point {
    type Output = Point;

    fn mul(self, scalar: BigInt) -> Point {
        self * &scalar
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        let p = constants::get_const_p();

        (&self.x * &other.z - &self.z * &other.x).rem_euclid(&p) == BigInt::from(0)
            && (&self.y * &other.z - &self.z * &other.y).rem_euclid(&p) == BigInt::from(0)
    }
}
