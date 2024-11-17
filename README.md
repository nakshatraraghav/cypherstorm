# CypherStorm 🔐

CypherStorm is a powerful, flexible cryptographic suite that allows you to securely compress and encrypt files and directories using various algorithms. Built with Go, it provides a seamless CLI experience for file security operations.

## 🚀 Features

- **Multiple Compression Algorithms**

  - GZIP (fast, widely supported)
  - ZSTD (excellent compression ratio/speed)
  - LZ4 (extremely fast)
  - BZIP2 (high compression ratio)
  - LZMA (highest compression ratio)

- **Strong Encryption Options**

  - AES-256-GCM (fast, secure)
  - ChaCha20-Poly1305 (modern, excellent for mobile)
  - XChaCha20-Poly1305 (extended nonce version)
  - AES-256-CBC with HMAC
  - Twofish

- **File Hashing**

  - SHA-256
  - SHA-512
  - BLAKE2b
  - SHA3-256
  - BLAKE3

- **Advanced Features**
  - Stream processing for files larger than RAM
  - Progress tracking
  - Flexible key management
  - Directory archival support

## 📋 Prerequisites

- Go 1.19 or higher
- Git

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cypherstorm.git

# Navigate to the project directory
cd cypherstorm

# Build the project
go build -o cypherstorm
```

## Full Commands References

```bash
CypherStorm is a cryptographic suite of tools for compressing, encrypting, and hashing files or folders with customizable algorithms, providing flexible, high-security file management

Usage:
  cypherstorm [flags]
  cypherstorm [command]

Aliases:
  cypherstorm, cypher, cstorm

Available Commands:
  benchmark   Benchmark all combination of algorithms
  completion  Generate the autocompletion script for the specified shell
  hash        Calculate and display file hashes
  help        Help about any command
  protect     Compress and encrypt files or directories in a secure pipeline
  restore     Decompress and decrypt files in a secure pipeline
  version     cypherstorm version

Flags:
  -h, --help   help for cypherstorm

Use "cypherstorm [command] --help" for more information about a command.
```

### Benchmark Command

```bash
Generate performance report for all compression and encryption combinations

Usage:
  cypherstorm benchmark [flags]

Flags:
  -h, --help                help for benchmark
  --input-path string   input path of the files to benchmark

```

### Hash Command

```bash
The "hash" command allows you to calculate and display the hash values of files or directories.

Available Hashing Algorithms:
- md5
- sha1
- sha256
- sha384
- sha512

Usage:
  cypherstorm hash [flags]

Flags:
  --algorithm string    choose required hashing algorithm. Available algorithms: md5, sha1, sha256, sha384, sha512 (default "sha256")
  -h, --help                help for hash
  --input-path string   input path of the file/files you want to hash
```

### Protect Command

```bash
The "protect" command allows you to compress and encrypt a specified file or directory.
It provides options to choose the compression and encryption algorithms, ensuring secure and efficient storage or transfer of data.

Available Compression Algorithms:
  - gzip
  - bzip2
  - lz4
  - lzma
  - zstd

Available Encryption Algorithms:
  - aes-256-gcm
  - xchacha20poly1305

Usage:
  cypherstorm protect [flags]

Flags:
  --compression-algo string   choose the compression algorithm (optional) (default "gzip")
  --encryption-algo string    choose the encryption algorithm (optional) (default "aes-256-gcm")
  -h, --help                      help for protect
  --input-path string         input path of the files to process
  --key-file-path string      file containing the password to encrypt the files with (optional)
  --output-path string        choose where you want the processed file to output to
  --password string           password to encrypt the files with (optional)

```

### Restore Command

```bash
The "restore" command allows you to decompress and decrypt a specified file or directory.
It provides options to choose the compression and encryption algorithms, ensuring the recovery of the original data.

Available Compression Algorithms:
  - gzip
  - bzip2
  - lz4
  - lzma
  - zstd

Available Encryption Algorithms:
  - aes-256-gcm
  - xchacha20poly1305

Usage:
  cypherstorm restore [flags]

Flags:
  --compression-algo string   choose the compression algorithm (optional) (default "gzip")
  --encryption-algo string    choose the encryption algorithm (optional) (default "aes-256-gcm")
  -h, --help                      help for restore
  --input-path string         input path of the files to process
  --key-file-path string      file containing the password to encrypt the files with (optional)
  --output-path string        choose where you want the processed file to output to
  --password string           password to encrypt the files with (optional)

```

## 🔒 Security Features

Secure password-based key derivation using Argon2
Authentication using modern AEAD ciphers
Safe handling of sensitive data in memory
Secure file wiping after operations
Protection against timing attacks
