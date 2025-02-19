# module-LWE

![example workflow](https://github.com/lattice-based-cryptography/module-lwe/actions/workflows/basic.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/module-lwe.svg)](https://crates.io/crates/module-lwe)

Implmentation of lattice-based encryption method module-LWE in pure Rust.

**Description**: This provides the basic PKE (keygen, encryption, and decryption) operations for the module learning-with-errors scheme.

**Disclaimer**: This is not secure. It is not written in constant-time nor resistant to other side-channel attacks. This is intended for educational use and not for real-world applications.

**Usage**: In the `src` directory,

`cargo build`

To build the binary.

`cargo test`

- Performs keygen/encrypt/decrypt for a test message.
- Checks homomorphic addition and multiplcation hold for small values.

_Note_: Parameters optional via 

- `--params <n> <q> <k>`

where `n` is polynomial degree, `q` is modulus, `k` is the module rank.

If ommitted, the default parameters will be used.

`cargo run -- keygen`

This will generate a public/secret keypair. 

`cargo run -- encrypt <public_key> <message>`

Generates the ciphertext.

`cargo run -- decrypt <secret_key> <ciphertext>`

Decrypts the ciphertext given a secret key, printing the plaintext message.

**Benchmarks**:

| n   | q     | k | keygen    | encrypt   | decrypt   | keygen_string | encrypt_string | decrypt_string |
|-----|-------|---|-----------|-----------|-----------|---------------|----------------|----------------|
| 256 | 12289 | 2 | 146.66 µs | 194.11 µs | 61.535 µs | 230.43 µs     | 255.60 µs      | 88.291 µs      |
| 256 | 12289 | 4 | 562.56 µs | 622.29 µs | 118.37 µs | 819.22 µs     | 787.60 µs      | 167.38 µs      |
| 384 | 12289 | 4 | 1.1774 ms | 1.3473 ms | 260.02 µs | 1.5546 ms     | 1.5829 ms      | 332.87 µs      |
| 512 | 12289 | 4 | 1.1959 ms | 1.3597 ms | 260.77 µs | 1.7172 ms     | 1.6976 ms      | 356.75 µs      |
| 512 | 12289 | 8 | 4.6993 ms | 4.8762 ms | 518.81 µs | 6.4127 ms     | 5.7918 ms      | 677.05 µs      |