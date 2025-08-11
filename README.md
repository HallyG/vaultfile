# VaultFile
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/hallyg/vaultfile/release.yaml)](https://github.com/HallyG/vaultfile/actions/workflows/release.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/hallyg/vaultfile?label=latest%20release)](https://github.com/HallyG/vaultfile/releases/latest)
[![License](https://img.shields.io/github/license/hallyg/vaultfile)](https://github.com/HallyG/vaultfile/blob/master/LICENSE)
![Go Version](https://img.shields.io/github/go-mod/go-version/hallyg/vaultfile)

A CLI for encrypting and decrypting file content using the experimental VaultFile format.

## Table of Contents
- [Disclaimer](#disclaimer)
- [Installation](#installation)
  - [Install via Go](#install-via-go)
  - [From Source](#from-source)
- [Documentation](#documentation)
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

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.