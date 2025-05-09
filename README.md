# VaultFile
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/hallyg/vaultfile/master.yaml)](https://github.com/HallyG/vaultfile/actions/workflows/master.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/hallyg/vaultfile?label=latest%20release)](https://github.com/HallyG/vaultfile/releases/latest)
[![License](https://img.shields.io/github/license/hallyg/vaultfile)](https://github.com/HallyG/vaultfile/blob/master/LICENSE)
![Go Version](https://img.shields.io/github/go-mod/go-version/hallyg/vaultfile)

A CLI for encrypting and decrypting file content using the experimental VaultFile format.

## Table of Contents
- [Disclaimer](#disclaimer)
- [Installation](#installation)
  - [Install via Go](#install-via-go)
  - [From Source](#from-source)
- [Overview](#overview)
  - [Binary Format](#binary-format)
    - [Encryption Process](#encryption-process)
    - [Decryption Process](#decryption-process)
- [Planned Improvements](#planned-improvements)
- [Design Decisions](#design-decisions)
- [License](#license)

## Disclaimer
This project is intended for educational purposes only and should not be used in production environments. It does not implement all security practices required for handling sensitive data securely.

## Installation

### Install via Go
1. Ensure you have [Go 1.24](https://go.dev/doc/install) or later installed.
2. Install the clu:
   ```bash
   go install github.com/HallyG/vaultfile@latest
   ```

### From Source
1. Ensure you have [Go 1.24](https://go.dev/doc/install) or later installed.
2. Clone the repository:
   ```bash
   git clone https://github.com/HallyG/vaultfile.git
   cd vaultfile
   ```
3. Build the project:
   ```bash
   make build
   ```

## Overview
VaultFile is a Go-based CLI tool for encrypting and decrypting files using the Vault V1 binary format. It uses XChaCha20-Poly1305 for authenticated encryption, Argon2id for password-based key derivation, and a SHA-256 HMAC to authenticate file headers.

### Binary Format
The Vault V1 binary format begins with a fixed 88-byte header, followed by the encrypted ciphertext. All numeric values are encoded in big-endian format.

| Field             | Length (Bytes) | Description                                                                              |
|-------------------|----------------|------------------------------------------------------------------------------------------|
| Magic Number      | 4              | ASCII string HGVF, identifying the file as using the Vault V1 format                     |
| Version           | 1              | Format version number; always set to 1 for V1                                            |
| Salt              | 16             | Random salt used during Argon2id key derivation                                          |
| Nonce             | 24             | Random nonce used with XChaCha20-Poly1305 for encryption/decryption                      |
| KDF Parameters    | 9              | Argon2id parameters: Memory (4 bytes), Iterations (4 bytes), Threads (1 byte)            |
| Total File Length | 2              | Total length of the file (header + ciphertext) in bytes; maximum size is 65,535 bytes    |
| HMAC              | 32             | SSHA-256 HMAC of the header fields (excluding ciphertext)                                | 
| Ciphertext        | Variable       | Encrypted payload; length = Total File Length − 88 bytes (header length)                 |

#### Encryption Process
1. Generate a 16-byte random salt.
2. Derive an encryption key from the password, salt, and specified KDF parameters.
3. Derive an HMAC key using the same password, salt, and KDF parameters.
4. Encrypt the plaintext using XChaCha20-Poly1305, producing ciphertext and a 24-byte random nonce.
5. Construct the header using: Magic Number, Version, Salt, Nonce, KDF Parameters, and Total File Length.
6. Compute the HMAC over the header fields and append it to the header.
7. Write the header and ciphertext to the output.

#### Decryption Process
1. Read and parse the 88-byte header.
2. Validate the Magic Number (`HGVF`) and Version (`1`).
3. Extract the Salt, Nonce, KDF Parameters, Total File Length, and HMAC from the header.
4. Parse and validate the KDF Parameters.
5. Derive the HMAC key from the password, salt, and KDF parameters.
6. Recalculate the HMAC over the header fields and verify it matches the HMAC in the header.
7. Read the ciphertext from the file, based on the Total File Length.
8. Validate that the ciphertext size is consistent with the header.
9. Derive the decryption key from the password, salt, and nonce.
10. Decrypt the ciphertext using XChaCha20-Poly1305.

## Planned Improvements
- **HKDF for Key Derivation**: Experiment with HKDF (HMAC-based Key Derivation Function) for deriving encryption and HMAC keys from a single master key.
- **Fuzz Testing**: Fuzz testing to identify malformed headers, invalid ciphertexts, etc.

## Design Decisions
- **Identification Bytes**: Simple sanity check that we're reading a file with contents that we expected.
- **Version Field**: Simple addition to allow the format to evolve. "Serial" version for simplicity.
- **Total File Length**: Easy to detect if the file was truncated (e.g. if being streamed over a network).
- **Fixed Header**: For predictable parsing, validation and a simpler implementation.
- **Argon2id for Key Derivation**: Chosen to prevent brute-force attacks.
- **HMAC for Header Integrity**: Protects against header field tampering. At the end so it can be constructed as the header is written.
- **Separate HMAC Key**: Derived with fixed Argon2id parameters to prevent attackers from manipulating KDF parameters in the header to exhaust resources.
- **Constant-Time HMAC Comparison**: Constant time HMAC comparison to prevent timing attacks.

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.