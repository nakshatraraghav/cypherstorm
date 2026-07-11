# Security Policy

## Supported format

Only the CypherStorm v1 protected-file format is supported. Legacy formats are deliberately rejected and cannot be migrated safely:

- legacy password output omitted the random derivation salt and is not recoverable;
- legacy AES-GCM and XChaCha20-Poly1305 output reused a nonce across chunks;
- legacy AES records were not reliably framed.

Do not rename or reintroduce legacy decoders as compatibility helpers.

## Credential model

A credential is exactly one of:

- a nonempty password, hardened with Argon2id using parameters and a fresh 32-byte salt stored in the v1 header;
- an exact 32-byte binary raw key.

Both credential kinds are expanded with HKDF-SHA-256 into a per-file, cipher-domain-separated encryption key. Raw key files must be regular, non-symlink files. CLI and TUI adapters never accept password values as command-line arguments. Interactive passwords are masked; automation uses standard input.

Go cannot guarantee that every compiler/runtime copy of secret material is erased. Mutable buffers are cleared best-effort when forms, requests, and operations release them. This is not a secure-memory guarantee.

## Argon2 resource policy

Argon2 header values are unauthenticated until the first record is authenticated, so they are validated before KDF execution:

```text
key length:   exactly 32 bytes
time:         1..10
memory:       1..262144 KiB, and at least 8 KiB per thread
parallelism:  1..16
```

New files currently use time 3, memory 65536 KiB, parallelism 4, and key length 32. Unit matrices use cheaper valid settings; a production-default round-trip test remains.

## Record security

Each protected file uses a fresh salt and file key. Data and final records use a unique monotonic nonce. Associated data includes the exact encoded header, record type, and record index. The authenticated final record commits:

- total data record count;
- total plaintext bytes;
- total ciphertext bytes.

Restore rejects unknown IDs/versions, noncontiguous indices, reordered or duplicated records, malformed lengths, missing or duplicated final records, count mismatches, trailing bytes, and authentication failures. Plaintext records produced before final-record authentication are written only to private disposable staging and are never published on failure.

Plaintext record size is bounded to 16 MiB. The application default is 64 KiB. Ciphertext allocations are independently capped at 64 MiB.

## Filesystem and archive policy

Protect uses a unique private `0700` workspace and `0600` staging files. Final protected output is a same-directory temporary file published atomically only after compression finalization, encryption, synchronization, and close succeed. No-overwrite publication uses operating-system no-replace primitives.

Restore requires a nonexistent destination. It decrypts into private staging, decompresses and extracts into a fresh same-parent `0700` directory, applies directory metadata after children, and publishes the directory only after the complete operation succeeds. It never merges trees and does not support restore overwrite.

Archive extraction accepts only regular files, directories, and symlinks. It rejects:

- absolute names, NUL bytes, backslashes, Windows drive/UNC-like forms, and `..` segments;
- paths escaping the staging root or traversing an existing symlink;
- absolute, platform-ambiguous, or escaping symlink targets;
- hardlinks, devices, sockets, FIFOs, and other special entries;
- configured entry count, entry size, total size, and depth violations.

The violating regular file is removed on size failure. Extraction occurs only inside an inaccessible fresh staging root, mitigating path check/use races before atomic publication.

## Operational limits

Default archive limits are finite:

```text
entries:       100000
single entry:  4 GiB
total files:   16 GiB
path depth:    64
```

Decompression streams directly into bounded archive extraction; intermediate data remains private and disposable. Callers may cancel operations through `context.Context`. TUI cancellation waits for cleanup and ignores stale messages from prior operation IDs.

## Reporting vulnerabilities

Do not include passwords, raw-key bytes, protected plaintext, or production artifacts in an issue. Report the affected version, platform, minimal reproduction using synthetic data, and expected security property through the repository owner's private security-reporting channel.

## Verification boundary

Security claims apply to the tested source tree and v1 format only. They do not claim secure memory erasure, OS keychain integration, resistance to a fully privileged local attacker, or recovery of legacy artifacts. Dependency reachability is checked with `govulncheck`; reachable findings block release until fixed or explicitly removed from the product surface.
