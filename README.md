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

## What changed recently

**Canonical-format cutover**
- Removed the legacy v1 writer/reader/framing implementation entirely; v1 magic now fails explicitly with `ErrUnsupportedProtectedFormat`.
- Promoted the former `internal/v2` package to the sole implementation, moved to `internal/security/container`.
- Removed the CLI `--format` selector; merged `FORMAT_V2.md` into a single canonical spec, later consolidated into this README.
- Regrouped `internal/` by domain: `security/` (container, crypto, kdf, hashing, wipe), `credential/` (identity, keymanage, credentialstore, qrexchange), `storage/` (archive, compress, fsutil, selection), plus `app/`, `config/`, `report/`, `ui/`.

**Security and correctness fixes**
- Credential-store index reads are fail-closed; `Put`/`Delete` no longer clobber an unreadable index, and index-write failures roll back the prior secret.
- `signature verify` requires an explicit `--signer` (trusted public identity or fingerprint); an untrusted embedded signer is rejected.
- Canonical headers reject duplicate/unknown fields and noncanonical JSON; at most one password recipient is accepted per container, closing an Argon2id amplification DoS.
- `context.Context` reaches KDF derivation, with a pre-execution cancellation check before running Argon2.
- QR recipient import bounds input bytes and image dimensions before decoding.
- Config resolution correctly applies configured record size and default destination; secret-key detection scans TOML keys instead of comment/value text.
- Batch protect no longer hardcodes cipher/codec; it applies configured app defaults.
- Restore conflict/overwrite semantics are hardened: replacement rejects symlink path components and uses a recoverable, same-parent backup directory rather than a crash-unsafe rename.
- Raw-key and private-identity loading validates stable, regular, non-symlink files with strict Unix permissions.
- Mutable secret byte buffers are cleared through one shared `security/wipe` helper instead of duplicated per-package logic.

**Terminal UI redesign**
- Grouped the flat action list into a dashboard: **Secure files**, **Inspect & validate**, and **Tools & reports**, each opening a focused submenu before a form.
- Rebuilt the visual system as a strict monochrome (grayscale) theme, consistent across light and dark terminals.
- Forms group controls by intent (`LOCATION`, `ACCESS`, `OPTIONS`, `REVIEW`).
- Added a determinate/indeterminate progress bar driven by the operation's reported current/total counts.
- Added fuzzy finding to the file picker, backed by **junegunn/fzf**'s real matching engine (`fzf.FuzzyMatchV2`): `/` filters, `↑`/`↓` ranks, `Enter` selects, `Esc` clears then closes.

## Build and test

Requires Go 1.23.2 or newer.

```sh
make build     # ./cypherstorm
make test      # go test ./...
make clean
```

Release checks:

```sh
go vet ./...
go test -race ./...
staticcheck ./...
govulncheck ./...
```

## Feature reference

Every example below is copy-pasteable and non-interactive. Secrets are never passed as arguments; `--password-stdin` reads a password from stdin instead, which is why examples pipe a value in with `printf '%s\n'` rather than typing it at a prompt — there's no terminal to prompt inside a shell script or a code block, and passing a password as a CLI flag would leak it into shell history and `ps` output. Interactively, omit `--password-stdin` and CypherStorm will prompt with masked input instead.

### Protect and restore (password)

```sh
printf '%s\n' 'correct horse battery staple' | \
  cypherstorm protect --input-path ./dataset --output-path ./dataset.cys --password-stdin

printf '%s\n' 'correct horse battery staple' | \
  cypherstorm restore --input-path ./dataset.cys --output-path ./restored --password-stdin
```

### Protect and restore (raw key)

Keys must be exactly 32 binary bytes and `0600` or stricter on Unix.

```sh
make key-gen   # writes ./key.bin

cypherstorm protect --input-path ./tree --output-path ./tree.cys --key-file ./key.bin
cypherstorm restore --input-path ./tree.cys --output-path ./restored-tree --key-file ./key.bin
```

### X25519 recipient encryption (encrypt for someone else, no shared password)

```sh
cypherstorm identity generate --type x25519 --output recipient.key
cypherstorm identity public recipient.key --output recipient.pub

cypherstorm protect --input-path ./dataset --output-path ./dataset.cys --recipient recipient.pub
cypherstorm restore --input-path ./dataset.cys --output-path ./restored --identity recipient.key
```

### QR-based public-key exchange

Exchange an X25519 public identity out of band without a file transfer.

```sh
cypherstorm identity qr recipient.pub --output recipient-qr.png
cypherstorm recipient import-qr recipient-qr.png --output imported-recipient.pub
```

### Inspect (no credential required)

Read a container's public header before deciding whether to authenticate it.

```sh
cypherstorm inspect ./dataset.cys
```

### Verify (full authentication)

```sh
printf '%s\n' 'correct horse battery staple' | \
  cypherstorm verify ./dataset.cys --password-stdin --mode full
```

### List archive contents

Authenticate and preview archived paths before restoring.

```sh
printf '%s\n' 'correct horse battery staple' | \
  cypherstorm list ./dataset.cys --password-stdin --long
```

### Selective restore and conflict policy

```sh
printf '%s\n' 'correct horse battery staple' | \
  cypherstorm restore --input-path ./dataset.cys --output-path ./restored \
    --path reports/2026 --password-stdin

printf '%s\n' 'correct horse battery staple' | \
  cypherstorm restore --input-path ./dataset.cys --output-path ./restored \
    --password-stdin  # existing destination policy: --conflict skip|rename|overwrite
```

### Rekey (add/remove recipients without re-encrypting payload)

```sh
printf '%s\n' 'correct horse battery staple' | \
  cypherstorm rekey ./dataset.cys --password-stdin \
    --add-recipient another-recipient.pub \
    --output ./dataset-rekeyed.cys
```

### Sign and verify with a trusted signer

```sh
cypherstorm identity generate --type signing --output signer.key
cypherstorm identity public signer.key --output signer.pub

cypherstorm sign ./dataset.cys --identity signer.key --output ./dataset.cys.sig
cypherstorm signature verify ./dataset.cys ./dataset.cys.sig --signer signer.pub
```

### Saved OS-keychain credentials

```sh
printf '%s\n' 'correct horse battery staple' | \
  cypherstorm credential add work-backup --password-stdin

cypherstorm protect --input-path ./dataset --output-path ./dataset.cys --credential work-backup
cypherstorm credential list
cypherstorm credential remove work-backup
```

### Batch protect/restore

```sh
printf '%s\n' 'correct horse battery staple' | \
  cypherstorm batch protect ./dataset-a ./dataset-b ./dataset-c \
    --destination ./protected --password-stdin --continue-on-error
```

### Manifests and change detection

```sh
cypherstorm manifest create ./dataset --output dataset.manifest
# ...later, after changes...
cypherstorm manifest create ./dataset --output dataset-new.manifest
cypherstorm compare dataset.manifest dataset-new.manifest
```

### Hashing

```sh
cypherstorm hash --input-path ./dataset --algorithm sha256
```

### Compression recommendation

```sh
cypherstorm recommend ./dataset --optimize ratio
```

### Benchmark every compression + cipher combination

```sh
cypherstorm benchmark --input-path ./dataset --output-path ./report
```

### Configuration and policy profiles

```sh
cypherstorm config show --effective
cypherstorm config validate
cypherstorm policy show default
```

Run `./cypherstorm --help` or `./cypherstorm <command> --help` for the complete flag surface. Running `./cypherstorm` with no arguments opens the terminal UI.

## Terminal UI

The TUI opens on a dashboard grouped into three workspaces:

```text
Secure files          Protect files, Restore files
Inspect & validate     Inspect header, Verify archive, Browse contents
Tools & reports        Hash input, Benchmark
Help & about
```

- `↑`/`↓`/`Tab` navigate, `Enter` selects, `Esc` goes back.
- File pickers support fuzzy finding: `/` opens a query, results are ranked with fzf's matching engine, `Enter` opens/selects, `Esc` clears the query then closes the picker.
- Running operations show a progress bar with phase, percentage, and count when the operation can report one, or an explicit "not measurable" indicator when it can't.
- The whole interface is monochrome — grayscale only, adapting to light and dark terminal themes.

## Security properties

- **Authenticated encryption:** every payload record uses AEAD with a unique monotonic nonce. An authenticated final record commits record count and byte counts, rejecting truncation, replay, reordering, duplication, malformed final records, and trailing bytes.
- **Bounded input handling:** canonical closed-schema headers reject unknown/duplicate/noncanonical JSON; header, metadata, record, recipient, Argon2, QR-image, decompressor, and archive-extraction limits are enforced before costly work where applicable.
- **Key separation:** fresh content keys and payload IDs are generated per archive. HKDF separates payload, metadata, and raw-key wrapping keys. Password recipients use bounded Argon2id; at most one password stanza is accepted per container.
- **Safe publication:** work occurs in private staging. Protected files publish atomically; failed/cancelled protect and restore operations do not publish partial output.
- **Archive defense:** extraction rejects traversal, absolute and Windows-ambiguous paths, unsafe symlink targets, hardlinks, devices, sockets, FIFOs, and configured size/depth/entry-limit violations.
- **Trusted signatures:** signature verification requires `--signer` as a trusted signing public identity or fingerprint. A signature carrying an arbitrary attacker key is rejected.
- **Credential handling:** passwords never enter command-line arguments; raw-key and private-identity loading validates stable regular non-symlink files. Mutable secret byte buffers are best-effort cleared after use through a shared wipe helper.

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
