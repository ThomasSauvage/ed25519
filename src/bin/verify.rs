use std::fs;

use ed25519_signature::ed25519;

fn main() {
    let matches = clap::Command::new("ed25519 Signature Verification")
        .version("1.0")
        .author("Thomas Sauvage")
        .about("Will generate a signature using the ed25519 algorithm")
        .arg(
            clap::Arg::new("public_key_filename")
                .help("Will use the <public_key_filename> to verify the signature. You must include the .pk extension")
                .required(true)
                .index(1),
        )
        .arg(
            clap::Arg::new("data_filename")
                .help("Will verify the signature for the data in the <data_filename> file")
                .required(true)
                .index(2),
        )
        .arg(
            clap::Arg::new("signature_filename")
                .help("Will verify the signature in the <signature_filename> file")
                .required(true)
                .index(3),
        )
        .get_matches();

    let public_key_filename: &String = matches.get_one("public_key_filename").unwrap();
    let data_filename: &String = matches.get_one("data_filename").unwrap();
    let signature_filename: &String = matches.get_one("signature_filename").unwrap();

    let public_key: [u8; 32] = fs::read(public_key_filename)
        .expect("The public key file could not be read")
        .try_into()
        .expect("The length of the public key should be 32 bytes");

    let data: Vec<u8> = fs::read(data_filename).expect("The data file could not be read");

    let signature: [u8; 64] = fs::read(signature_filename)
        .expect("The signature file could not be read")
        .try_into()
        .expect("The length of the signature should be 64 bytes");

    let is_valid = ed25519::verify(&public_key, &data, &signature);

    if is_valid {
        println!("ACCEPT");
    } else {
        println!("REJECT");
    }
}
