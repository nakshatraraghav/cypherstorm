# CypherStorm v1 Format

This document defines the compatibility and authentication contract for protected files produced by the current source tree. Multi-byte integers are unsigned big-endian values.

## Compatibility

- Magic: `CYPHRSTM`
- Version: `1`
- Header length: exactly 60 bytes
- Legacy unversioned formats are unsupported and intentionally rejected.
- Unknown versions, cipher IDs, codec IDs, KDF IDs, record types, and noncanonical v1 header lengths fail closed.
- Restore selects the cipher, codec, and password KDF parameters from the header. Users do not provide these values during restore.

## Header

```text
offset  size  field
0       8     magic: CYPHRSTM
8       1     version: 1
9       2     total header length: 60
11      1     cipher ID
12      1     compression codec ID
13      1     KDF ID
14      4     Argon2id time
18      4     Argon2id memory KiB
22      1     Argon2id parallelism
23      1     Argon2id key length
24      32    per-file random salt
56      4     maximum plaintext record size
```

Cipher IDs:

```text
1  AES-256-GCM
2  XChaCha20-Poly1305
```

Codec IDs:

```text
1  gzip
2  zstd
3  lz4
4  bzip2
5  lzma
```

KDF IDs:

```text
0  raw 32-byte key; all Argon2 fields must be zero
1  Argon2id password; every Argon2 field must satisfy SECURITY.md policy
```

The salt is always 32 bytes, including raw-key mode, because HKDF uses it to derive a unique per-file key. Record size must be in `1..16777216`; the application writes 65536.

## Key derivation

Password credential:

```text
master = Argon2id(password, header salt, serialized bounded parameters)
```

Raw-key credential:

```text
master = exact 32-byte key-file content
```

Both modes derive the actual AEAD key:

```text
file_key = HKDF-SHA-256(master, header salt, "cypherstorm/v1/<cipher-id>")
```

The domain string prevents cross-suite key reuse.

## Records

The header is followed by one or more framed records. Empty input still has an authenticated final record.

```text
offset  size  field
0       1     record type: 1 data, 2 final
1       8     record index
9       4     ciphertext length
13      N     ciphertext
```

Indices begin at zero and are contiguous. Ciphertext length is nonzero and no greater than 64 MiB. The crypto engine additionally bounds data ciphertext by the authenticated header record size plus AEAD overhead and requires the exact final ciphertext length.

Each record authenticates this associated data:

```text
exact 60-byte header || record type || record index
```

Nonce construction is cipher-specific but deterministic from the monotonic record index under a fresh per-file key. Index overflow is rejected.

## Final record

The final record plaintext is exactly 24 bytes:

```text
0       8     total data record count
8       8     total plaintext bytes
16      8     total ciphertext bytes across data records
```

The final payload is AEAD-authenticated. Restore rejects a missing, malformed, duplicated, or nonterminal final record; count mismatches; and any trailing byte after it.

## Processing pipeline

Protect:

```text
filesystem input -> safe tar -> selected compression -> v1 encryption -> atomic output
```

Restore:

```text
v1 authentication/decryption -> authenticated codec selection -> bounded decompression/tar extraction -> atomic new directory
```

The tar and compression formats are internal payload details committed by the authenticated v1 header. A restore implementation must not publish decrypted records until the final record, decompressor finalization, archive validation, metadata application, and destination publication all succeed.
