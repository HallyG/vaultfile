# VaultFile
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/hallyg/vaultfile/release.yaml)](https://github.com/HallyG/vaultfile/actions/workflows/release.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/hallyg/vaultfile?label=latest%20release)](https://github.com/HallyG/vaultfile/releases/latest)
[![License](https://img.shields.io/github/license/hallyg/vaultfile)](https://github.com/HallyG/vaultfile/blob/master/LICENSE)
![Go Version](https://img.shields.io/github/go-mod/go-version/hallyg/vaultfile)

A CLI for encrypting and decrypting content with a password using the experimental VaultFile format.

## Table of Contents
- [Disclaimer](#disclaimer)
- [Installation](#installation)
  - [Install via Go](#install-via-go)
  - [From Source](#from-source)
- [Documentation](#documentation)
- [Examples](#examples)
  - [Encrypting Content](#encrypting-content)
  - [Decrypting Content](#decrypting-content)
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

## Documentation
Documentation about the `vaultfile` binary format can be found [here](./docs/vaultfile-v1.md).

## Examples

Below are some basic usage examples. More can be found in the [examples directory](./examples).

### Encrypting Content

1. Encrypt content from a file:
   ```bash
   cat plaintext.txt | vaultfile encrypt > encrypted.vault
   ```

2. Encrypt text directly:
   ```bash
   echo "hello-world" | vaultfile encrypt > encrypted.vault
   ```

3. Encrypt using input redirection:
   ```bash
   vaultfile encrypt < plaintext.txt > encrypted.vault
   ```

You will be prompted for a password during encryption:
```bash
Enter password:
Confirm password:
```

### Decrypting Content

1. Decrypt to a file:
   ```bash
   cat encrypted.vault | vaultfile decrypt > decrypted.txt
   ```

2. Decrypt and display directly:
   ```bash
   cat encrypted.vault | vaultfile decrypt
   ```

3. Decrypt using input redirection:
   ```bash
   vaultfile decrypt < encrypted.vault > decrypted.txt
   ```

You will be prompted for a password during decryption:
```bash
Enter password:
```

### Chaining Operations

```bash
# Compress then encrypt
tar czf - my-directory/ | vaultfile encrypt > backup.vault

# Decrypt then extract
cat backup.vault | vaultfile decrypt | tar xzf -

# Encrypt data from a web request
curl -s https://api.example.com/data.json | vaultfile encrypt > api-data.vault
```

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.