# Cerberus

## Overview
`cerberus`  is a Rust library for generating, verifying, and extracting data from secure tokens similar to JWT, but with symmetric encryption, Zstd compression, and RSA signature.
Designed for seamless integration with Java applications via JNI, it offers enhanced security and flexibility.

## Features

- AES-GCM symmetric encryption for header and payload.

- Zstd compression to reduce token size.

- RSA signature and verification with SHA-256.

- Private and public key management in PEM format.

- Decryption of symmetric keys protected by RSA private key.

- Core functions to create, verify, and extract token data.

- CLI tools for generating RSA keys and encrypted symmetric keys.

- Easy Java integration via JNI.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your_username/jcerberus-rs.git
cd jcerberus-rs
```

2. Build the library
```bash
cargo build --release
```

This produces the dynamic library (libjcerberus.so, libjcerberus.dylib, or jcerberus.dll depending on your platform) for Java integration.

## CLI Usage
Generate RSA key pair and encrypted symmetric key:

```bash
cargo run --bin jcerberus-cli -- generate-rsa --out private.pem public.pem
cargo run --bin jcerberus-cli -- generate-sym-key --out encrypted_sym_key.bin --cert public.pem
```

## Java Integration
This Rust library is designed to be used alongside the jcerberus Java library, which invokes these native functions via JNI.

See [JCerberus](https://github.com/Marck-G/jcerberus)