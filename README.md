# ed25519 Signature

⚠️ DO NOT USE IN PRODUCTION. I made this project to learn the cryptographic principles behind this algorithm, with few considerations for side-channel attacks.

Made as part of the Advanced Cryptography course at [École polytechnique](https://www.polytechnique.edu/en), by Prof. Benjamin Smith.

Author: Thomas Sauvage.

## Extension

- I implemented Multiexponentiation with Straus’ algorithm. See the `straus_multiexponentiation` function in `src/ed25519/points.rs`.

## Installation

- [Install Rust](https://www.rust-lang.org/tools/install)

## Usage

- See the doc :

```sh
cargo run --bin keygen -- --help
cargo run --bin sign   -- --help
cargo run --bin verify -- --help
```

- You can also build the app with the following command, the executable will be at `target/release`

```sh
cargo build --release
cd target/release
```

### Examples

```sh
cargo run --bin keygen examples/key
cargo run --bin sign examples/key.sk README.md examples/README_sig
cargo run --bin verify examples/key.pk README.md examples/README_sig
```

## Tests

- Launch automated tests:

```sh
cargo test --release
```

Note: This test runs more than a 4000 signatures and verifications so it may take some time (5.5s on my machine).
