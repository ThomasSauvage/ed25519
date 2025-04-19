use std::str::FromStr;

use num_bigint::BigInt;

use super::points;

pub fn get_const_p() -> BigInt {
    BigInt::from_str(
        "57896044618658097711785492504343953926634992332820282019728792003956564819949",
    )
    .unwrap()
}

pub fn get_const_d() -> BigInt {
    BigInt::from_str(
        "37095705934669439343138083508754565189542113879843219016388785533085940283555",
    )
    .unwrap()
}

pub fn get_const_q() -> BigInt {
    BigInt::from_str("7237005577332262213973186563042994240857116359379907606001950938285454250989")
        .unwrap()
}

pub fn get_modp_sqrt_m1() -> BigInt {
    BigInt::from_str(
        "19681161376707505956807079304988542015446066515923890162744021073123829784752",
    )
    .unwrap()
}

pub fn get_point_g() -> points::Point {
    points::Point::new(
        BigInt::from_str(
            "15112221349535400772501151409588531511454012693041857206046113283949847762202",
        )
        .unwrap(),
        BigInt::from_str(
            "46316835694926478169428394003475163141307993866256225615783033603165251855960",
        )
        .unwrap(),
        BigInt::from(1),
        BigInt::from_str(
            "46827403850823179245072216630277197565144205554125654976674165829533817101731",
        )
        .unwrap(),
    )
}
