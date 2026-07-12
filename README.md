# CypherStorm

CypherStorm is a Go CLI/TUI for securely protecting and restoring files and directories. It archives input, compresses it, and writes an authenticated encrypted container. Hashing, benchmarks, key management, recipient exchange, rekeying, signatures, inspection, verification, and archive listing are built in.

## Current format

CypherStorm writes and reads one canonical protected-file format: **wire version 2** (`CYSV2\0\0\0`). Legacy formats are intentionally unsupported and fail explicitly. There is no `--format` selector and no compatibility decoder.

The canonical container supports:

- AES-256-GCM and XChaCha20-Poly1305 payload encryption;
- gzip, zstd, lz4, bzip2, and lzma compression;
- password, exact 32-byte raw-key, and X25519 public-key recipients;
- encrypted private metadata, optional public hints, recipient QR exchange, and rekeying;
- detached Ed25519 signatures with trusted-signer pinning.

## Build and test

Requires Go 1.23.2 or newer.

```sh
make build     # ./cypherstorm
make test      # go test ./...
make clean
```

Useful release checks:

```sh
go vet ./...
go test -race ./...
staticcheck ./...
govulncheck ./...
```

## Common commands

```sh
# Password-protected archive. Password is read from stdin, never argv.
printf '%s\n' 'correct horse battery staple' | \
  ./cypherstorm protect --input-path ./document.txt --output-path ./document.cys --password-stdin

# Restore and fully authenticate it.
printf '%s\n' 'correct horse battery staple' | \
  ./cypherstorm verify ./document.cys --password-stdin
printf '%s\n' 'correct horse battery staple' | \
  ./cypherstorm restore --input-path ./document.cys --output-path ./restored --password-stdin

# Raw-key protection. Keys must be exactly 32 binary bytes and 0600 on Unix.
make key-gen
./cypherstorm protect --input-path ./tree --output-path ./tree.cys --key-file ./key.bin
./cypherstorm restore --input-path ./tree.cys --output-path ./restored-tree --key-file ./key.bin

# X25519 recipient protection.
./cypherstorm identity generate --type x25519 --output recipient.key
./cypherstorm identity public recipient.key --output recipient.pub
./cypherstorm protect --input-path ./document.txt --output-path ./shared.cys --recipient recipient.pub
./cypherstorm restore --input-path ./shared.cys --output-path ./shared-restored --identity recipient.key

# Rekey recipients without re-encrypting payload records.
./cypherstorm rekey ./shared.cys --identity recipient.key --add-recipient another-recipient.pub --output ./rekeyed.cys

# Sign and verify with an explicit trusted signer.
./cypherstorm identity generate --type signing --output signer.key
./cypherstorm identity public signer.key --output signer.pub
./cypherstorm sign ./shared.cys --identity signer.key --output ./shared.cys.sig
./cypherstorm signature verify ./shared.cys ./shared.cys.sig --signer signer.pub
```

Run `./cypherstorm --help` or `./cypherstorm <command> --help` for the complete command surface. Running `./cypherstorm` interactively opens the terminal UI.

## Security properties

- **Authenticated encryption:** every payload record uses AEAD with a unique monotonic nonce. An authenticated final record commits record count and byte counts, rejecting truncation, replay, reordering, duplication, malformed final records, and trailing bytes.
- **Bounded input handling:** canonical closed-schema headers reject unknown/duplicate/noncanonical JSON; header, metadata, record, recipient, Argon2, QR-image, decompressor, and archive-extraction limits are enforced before costly work where applicable.
- **Key separation:** fresh content keys and payload IDs are generated per archive. HKDF separates payload, metadata, and raw-key wrapping keys. Password recipients use bounded Argon2id; at most one password stanza is accepted per container.
- **Safe publication:** work occurs in private staging. Protected files publish atomically; failed/cancelled protect and restore operations do not publish partial output.
- **Archive defense:** extraction rejects traversal, absolute and Windows-ambiguous paths, unsafe symlink targets, hardlinks, devices, sockets, FIFOs, and configured size/depth/entry-limit violations.
- **Trusted signatures:** signature verification requires `--signer` as a trusted signing public identity or fingerprint. A signature carrying an arbitrary attacker key is rejected.
- **Credential handling:** passwords never enter command-line arguments; raw-key and private-identity loading validates stable regular non-symlink files. Mutable secret byte buffers are best-effort cleared after use.

## Operational notes

- There is no password, raw-key, or private-identity recovery mechanism.
- Public hints are visible before authentication; keep sensitive information in private metadata instead.
- `restore` defaults to a nonexistent destination. Explicit `--conflict skip|rename|overwrite` modes stage and merge existing trees safely, but replacement is rollback-capable rather than crash-atomic; an interrupted replacement can leave a same-parent `.cypherstorm-backup-*` directory for manual recovery.
- Go cannot guarantee complete secure-memory erasure or protect against a fully privileged local attacker.

## Package layout

```text
internal/security/    canonical container, AEAD suites, KDF, hashing, wiping
internal/credential/  identities, raw keys, keychain credentials, QR exchange
internal/storage/     archive, compression, filesystem publication, selection
internal/app/         UI-neutral orchestration
internal/ui/          Cobra CLI and Bubble Tea TUI
```
