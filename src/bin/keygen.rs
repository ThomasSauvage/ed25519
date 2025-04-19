use std::fs;

use ed25519_signature::ed25519;

fn main() {
    let matches = clap::Command::new("ed25519 Keypair Generation")
        .version("1.0")
        .author("Thomas Sauvage")
        .about("Will generate a random ed25519 keypair")
        .arg(
            clap::Arg::new("keypair_output_filename")
                .help("Will output the keypair in the <keypair_output_filename>.pk and <keypair_output_filename>.sk files")
                .required(true)

                .index(1),
        )
        .get_matches();

    let keypair_output_filename: &String = matches.get_one("keypair_output_filename").unwrap();

    let keypair = ed25519::gen_keypair();

    let pk_filename = format!("{}.pk", keypair_output_filename);
    let sk_filename = format!("{}.sk", keypair_output_filename);

    fs::write(pk_filename, keypair.public_key).expect("Unable to write public key");
    fs::write(sk_filename, keypair.private_key).expect("Unable to write private key");
}
