# VaultFile
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/hallyg/vaultfile/master.yaml)](https://github.com/HallyG/vaultfile/actions/workflows/master.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/hallyg/vaultfile?label=latest%20release)](https://github.com/hallyg/vaultfile/releases/latest)
[![License](https://img.shields.io/github/license/hallyg/vaultfile)](https://github.com/HallyG/vaultfile/blob/master/LICENSE)
![Go Version](https://img.shields.io/github/go-mod/go-version/hallyg/vaultfile)

An experimental CLI for encrypting and decrypting file content using the VaultFile format.

## Table of Contents
- [Disclaimer](#disclaimer)
- [Overview](#overview)
  - [Binary Format](#binary-format)
    - [Header Details](#header-details)
    - [Encryption Process](#encryption-process)
    - [Decryption Process](#decryption-process)
- [Planned Improvements](#planned-improvements)
- [Design Decisions](#design-decisions)
- [License](#license)

## Disclaimer
This project is intended for educational purposes only and should not be used in production environments. It does not implement all security practices required for handling sensitive data securely.

## Overview
VaultFile is a Go-based CLI tool for encrypting and decrypting files using the Vault V1 binary format. It uses XChaCha20-Poly1305 for authenticated encryption, Argon2id for password-based key derivation, and a SHA-256 HMAC to authenticate file headers.

### Binary Format
The Vault V1 binary format has a fixed 88-byte header followed by the encrypted ciphertext.

| Field            | Length (Bytes) | Description                                                                    |
|------------------|----------------|--------------------------------------------------------------------------------|
| Magic Number     | 4              | Fixed string "HGVF" identifying the file as Vault V1 format.                   |
| Version          | 1              | Version number, set to 1 for V1.                                               |
| Salt             | 16             | Salt used with password during Argon2id key derivation.                        |
| Nonce            | 24             | Nonce used with XChaCha20-Poly1305.                                            |
| KDF Parameters   | 9              | Argon2id parameters: Memory (4 bytes), Iterations (4 bytes), Threads (1 byte). |
| Total File Length| 2              | Total length of the file (header + ciphertext) in bytes.                       |
| HMAC             | 32             | SHA-256 HMAC of the previous header fields.                                    |
| Ciphertext       | Variable       | Encrypted data (length = Total File Length - 88 bytes (header length)).        |

#### Header Details
- **Total Header Length**: 88 bytes.
- **Magic Number**: The ASCII string "HGVF" identifies the file as a Vault V1 encrypted file.
- **Version**: A single byte set to `1` to indicate the V1 format.
- **Salt**: A 16-byte random value used in Argon2id key derivation to prevent rainbow table attacks.
- **Nonce**: A random 24-byte value used by the XChaCha20-Poly1305 cipher for encryption/decryption.
- **KDF Parameters**:
  - **MemoryKiB**: 4 bytes (big-endian uint32) specifying memory usage in kibibytes for Argon2id.
  - **NumIterations**: 4 bytes (big-endian uint32) specifying the number of iterations for Argon2id.
  - **NumThreads**: 1 byte (uint8) specifying the number of threads for Argon2id.
- **Total File Length**: 2 bytes (big-endian uint16) indicating the total file size (header + ciphertext).
- **HMAC**: A 32-byte SHA-256 HMAC computed over the previous header fields using a password-derived HMAC key.

#### Encryption Process
1. A 16-byte random salt is generated.
2. An encryption key is derived from the password, salt and the specified Argon2id parameters.
3. An HMAC key is derived from the password, salt and the specified Argon2id parameters.
4. The plaintext is encrypted using XChaCha20-Poly1305, producing ciphertext and a random 24-byte nonce.
5. The header is constructed with the magic number, version, salt, nonce, KDF parameters, and total file length.
6. An HMAC is generated from the constructed header and appended to the header.
6. The header and ciphertext are written to the output.

#### Decryption Process
1. The 88-byte header is read and parsed.
2. The magic number ("HGVF") and version (1) are validated.
3. The salt, nonce, KDF parameters, total file length, and HMAC are extracted fromt he parsed header.
4. The KDF parameters are parsed and validated.
5. The HMAC key is recomputed from the password, salt and the specified Argon2id parameters.
6. The HMAC key is used to calculate an HMAC from the parsed header and verify it against the HMAC in the header.
5. The ciphertext is read based on the total file length (from the header).
6. Verify that the cipher text size matches the expected total file length.
6. The ciphertext is decrypted using XChaCha20-Poly1305 whose key is derived from the password, the parsed nonce and salt.

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