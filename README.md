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
cypherstorm [command] [flags] <input-path>

Commands:
  encrypt    Encrypt files/directories
  decrypt    Decrypt files
  hash       Calculate file hash

Flags:
  --compression-algo    Compression algorithm to use
  --encryption-algo     Encryption algorithm to use
  --key-file           Path to key file
  --password           Password (or prompt if not provided)
  --chunk-size         Size of chunks for large file processing
  --output             Output path
```

## 🔒 Security Features

Secure password-based key derivation using Argon2
Authentication using modern AEAD ciphers
Safe handling of sensitive data in memory
Secure file wiping after operations
Protection against timing attacks
