pub fn hex_decode_32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

pub fn hex_decode_64(s: &str) -> [u8; 64] {
    hex::decode(s).unwrap().try_into().unwrap()
}

pub fn hex_decode_msg(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
