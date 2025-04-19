use std::fs;

use ed25519_signature::ed25519;

fn main() {
    let matches = clap::Command::new("ed25519 Signature Generation")
        .version("1.0")
        .author("Thomas Sauvage")
        .about("Will generate a signature using the ed25519 algorithm")
        .arg(
            clap::Arg::new("private_key_filename")
                .help("Will use the <private_key_filename> file to generate the signature. If the file name containes a file extension, it is necessary to specify it.")
                .required(true)
                .index(1),
        )
        .arg(
            clap::Arg::new("data_filename")
                .help("Will generate the signature for the data in the <data_filename> file")
                .required(true)
                .index(2),
        )
        .arg(
            clap::Arg::new("signature_output_filename")
                .help("Will output the signature in the <signature_output_filename> file")
                .required(true)
                .index(3),
        )
        .get_matches();

    let private_key_filename: &String = matches.get_one("private_key_filename").unwrap();
    let data_filename: &String = matches.get_one("data_filename").unwrap();
    let signature_output_filename: &String = matches.get_one("signature_output_filename").unwrap();

    let private_key: [u8; 32] = fs::read(private_key_filename)
        .expect("The private key file could not be read")
        .try_into()
        .expect("The length of the private key should be 32 bytes");

    let data: Vec<u8> = fs::read(data_filename).expect("The data file could not be read");

    let signature = ed25519::sign(&private_key, &data);

    fs::write(signature_output_filename, signature).expect("Unable to write signature");
}
