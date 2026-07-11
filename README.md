# CypherStorm

CypherStorm is a Go application for authenticated file protection and restoration, structured hashing, and deterministic compression/encryption benchmarks. The same UI-neutral application service powers both the Cobra CLI and the Bubble Tea terminal interface.

## Security status

The current source tree uses the versioned CypherStorm v1 protected-file format. The legacy unversioned formats were deleted because they reused AEAD nonces and could not restore password-protected output. Legacy artifacts are intentionally unsupported and are rejected; there is no compatibility shim.

The v1 implementation currently provides:

- AES-256-GCM and XChaCha20-Poly1305 suites;
- a fresh per-file salt and HKDF-derived, cipher-domain-separated file key;
- bounded Argon2id password derivation with serialized parameters;
- unique monotonic record nonces and sequence-bound associated data;
- an authenticated final record committing record and byte counts;
- bounded record/header parsing;
- private per-operation staging and atomic final publication;
- transactional restore into a new destination directory;
- bounded archive extraction with portable path and symlink validation.

See [SECURITY.md](SECURITY.md) for the security model and [FORMAT.md](FORMAT.md) for the compatibility contract.

## Requirements

- Go 1.23.2 or newer; `go.mod` is authoritative.
- A terminal for the full-screen TUI. Explicit CLI commands work noninteractively.
- OpenSSL only for the optional `make key-gen` helper.

## Build and test

```sh
make build
make test
```

The binary is written to `./cypherstorm`.

## Entry behavior

```text
cypherstorm              interactive stdin/stdout: open TUI Home
cypherstorm              noninteractive: print plain help and exit
cypherstorm tui          explicitly open the TUI
cypherstorm --help       always print Cobra help; never open the TUI
```

Explicit `protect`, `restore`, `hash`, `benchmark`, and `version` commands always stay on the CLI path.

## Credentials

Password values are not accepted as command-line arguments. Without a credential flag, `protect` and `restore` read a masked password from an interactive terminal. Protect asks for confirmation.

For automation, pass the password on standard input:

```sh
cypherstorm protect \
  --input-path ./document.txt \
  --output-path ./document.cys \
  --password-stdin < ./password-input
```

A raw-key file is a separate credential kind. It must be a regular, non-symlink file containing exactly 32 binary bytes. On Unix, its permissions must be `0600` or stricter.

```sh
make key-gen
cypherstorm protect \
  --input-path ./document.txt \
  --output-path ./document.cys \
  --key-file ./key.bin
```

Do not lose the password or raw key. CypherStorm has no recovery mechanism.

## Protect

```sh
cypherstorm protect \
  --input-path INPUT \
  --output-path OUTPUT.cys \
  [--compression gzip|zstd|lz4|bzip2|lzma] \
  [--cipher aes-256-gcm|xchacha20poly1305] \
  [--key-file KEY.bin | --password-stdin] \
  [--overwrite]
```

A file or symlink input is archived under its basename. A directory input contributes its contents without an extra wrapper directory. Existing protected output is rejected unless `--overwrite` is explicit. Publication is atomic, including no-replace enforcement when overwrite is disabled.

## Restore

```sh
cypherstorm restore \
  --input-path INPUT.cys \
  --output-path NEW_DESTINATION \
  [--key-file KEY.bin | --password-stdin]
```

Restore never asks for a cipher or compression codec. It reads authenticated v1 metadata and selects both automatically. The destination must not exist. Restore does not merge into or overwrite directory trees; it extracts privately and publishes the complete tree only after decryption, decompression, archive validation, and metadata restoration succeed.

## Hash

```sh
cypherstorm hash --input-path INPUT [--algorithm sha256|sha384|sha512]
```

Hashing returns deterministic path/digest rows. Directory traversal hashes regular files in lexical order, skips symlinks, and rejects special filesystem nodes instead of opening FIFOs or devices.

## Benchmark

```sh
cypherstorm benchmark \
  --input-path INPUT \
  --output-path benchmark.xlsx
```

Benchmark runs the deterministic cross product of all five codecs and both cipher suites. It returns complete successes and failures, prints a text summary, and atomically publishes an XLSX report. XLSX support is retained as a product feature despite its larger dependency graph; renderer errors are propagated.

## Terminal interface

The TUI provides Protect, Restore, Hash, Benchmark, and Help screens in a warm, minimal, conversation-oriented visual style. File, folder, destination, and raw-key locations are selected with an in-terminal filesystem browser; operation forms do not require typing paths. Compression, encryption, credential kind, and hash algorithm use pop-up dropdown menus. Passwords remain masked and protect requires confirmation.

Choosing a destination folder derives the final output name:

- protect: `<source-name>.cys`;
- restore: `<container-name-without-.cys>-restored`;
- benchmark: `benchmark.xlsx`.

Core keys:

```text
Forms:      Tab/Shift+Tab move; Enter opens or continues
Dropdowns:  Up/Down choose; Enter selects; Esc closes
Browser:    Up/Down move; Right opens a folder; Enter selects
Browser:    S selects the currently displayed folder
Running:    Esc, Q, or Ctrl+C requests safe cancellation
Home:       Esc or Ctrl+C quits
```

The TUI retains bounded/coalesced progress, operation IDs, asynchronous service commands, responsive resize handling, keyboard-only navigation, and cancellation that waits for staging cleanup. Color is supplemental; focus and status always have text markers.

## Supported algorithms

Compression, deterministic order:

1. gzip
2. zstd
3. lz4
4. bzip2
5. lzma

Encryption, deterministic order:

1. aes-256-gcm
2. xchacha20poly1305

Hashing:

1. sha256
2. sha384
3. sha512

## Verification

The repository includes focused tests for:

- password and raw-key round trips;
- both ciphers, every codec, record boundary sizes, single files, and directories;
- wrong credentials, hostile KDF fields, tampered/reordered/duplicated/truncated records, final-record tampering, and trailing bytes;
- archive traversal, symlink, Windows-ambiguous path, size, entry, depth, and metadata boundaries;
- atomic no-replace publication, cancellation cleanup, and concurrent workspaces;
- CLI password/raw-key round trips;
- TUI model state, secret redaction, cancellation, resize behavior, and stale messages;
- pseudo-terminal password/raw-key round trips, interactive default routing, non-TTY help, help bypass, and terminal restoration.
