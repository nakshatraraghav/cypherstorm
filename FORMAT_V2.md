# CypherStorm v2 Protected-File Format

Status: version 2, canonical implementation in `internal/v2`. Integers are unsigned big-endian. All limits are checked before allocation or expensive work.

## Container

```text
0       8   magic: 43 59 53 56 32 00 00 00 ("CYSV2\0\0\0")
8       4   JSON header length, uint32, 1..1,048,576
12      N   canonical compact UTF-8 JSON header
12+N    ... authenticated payload records
```

The JSON header is a closed schema: unknown fields are rejected. Its fields, in canonical struct order, are:

- `version`: integer `2`;
- `payload_id`: raw-base64 32 random bytes;
- `cipher`: `aes-256-gcm` or `xchacha20poly1305`;
- `codec`: `gzip`, `zstd`, `lz4`, `bzip2`, or `lzma`;
- `record_size`: 1..16 MiB;
- `nonce_prefix`: raw-base64 random bytes of length `AEAD.NonceSize()-8`;
- `metadata_nonce`: raw-base64 24-byte XChaCha20-Poly1305 nonce;
- `metadata`: raw-base64 authenticated ciphertext, at most 1 MiB plaintext;
- `recipients`: 1..64 recipient stanzas;
- `public_hint`: optional UTF-8 string, at most 256 bytes.

No recursive, indefinite-length, duplicate singleton, or unknown fields are accepted. Recipient fields and encoded identities are bounded by the total header bound.

## Immutable payload header

Payload records authenticate the canonical JSON encoding of this exact ordered structure:

```json
{"version":2,"payload_id":"…","cipher":"…","codec":"…","record_size":65536,"nonce_prefix":"…"}
```

The recipient envelope, encrypted metadata, and public hint are excluded. Therefore a recipient-envelope rewrite does not change payload ciphertext, while immutable-parameter transplantation makes every payload record fail authentication.

## Key hierarchy

Protection generates a fresh random 32-byte content key and 32-byte payload identifier. HKDF-SHA-256 derives:

```text
payload key  = HKDF(content key, payload ID, "cypherstorm/v2/payload")
metadata key = HKDF(content key, payload ID, "cypherstorm/v2/metadata")
```

The payload key length is the selected payload AEAD key length. The metadata key is 32 bytes and is used only with XChaCha20-Poly1305. Keys are never serialized directly.

## Recipient stanzas

Every stanza is independently authenticated and bound to the 32-byte payload identifier.

### Password

Fields: `type=password`, 32-byte salt, bounded Argon2id parameters, 24-byte nonce, wrapped content key. Argon2id derives a 32-byte key-encryption key. XChaCha20-Poly1305 wraps the content key with associated data `payload_id || "password"`.

### Raw key

Fields: `type=raw-key`, 32-byte salt, 24-byte nonce, wrapped content key. HKDF-SHA-256 derives the key-encryption key with domain `cypherstorm/v2/raw-wrap`. XChaCha20-Poly1305 uses associated data `payload_id || "raw-key"`.

### X25519 public recipient

Fields: `type=x25519`, domain-separated public identity fingerprint, and a bounded age X25519 stanza. The reviewed `filippo.io/age` X25519 construction encrypts `payload_id || content_key`; unwrap succeeds only if the embedded payload identifier matches. Duplicate recipient fingerprints are rejected.

## Private metadata

The metadata JSON is encrypted with XChaCha20-Poly1305. Associated data is the immutable payload-header encoding. Supported bounded fields are original name/type, RFC 3339 protection time, description, tags, credential hint, and credential fingerprint. It is unavailable before a recipient is accepted. `public_hint` is the only intentionally public descriptive field.

## Payload records

```text
0       1   type: 1=data, 2=final
1       8   contiguous index, starting at zero
9       4   ciphertext length
13      N   AEAD ciphertext
```

Nonce construction is `nonce_prefix || uint64(index)`. Associated data is `immutable_header || type || uint64(index)`.

The final plaintext is exactly 24 bytes:

```text
0       8   data record count
8       8   total plaintext bytes
16      8   total data-record ciphertext bytes
```

The final record is AEAD-authenticated at the next contiguous index. Missing, duplicated, reordered, oversized, truncated, malformed-final, commitment-mismatched, or trailing records fail closed.

## Rekeying

Rekey authenticates an existing stanza, unwraps the content key, filters/replaces/adds stanzas, writes a canonical replacement header, and copies every byte after the original header unchanged. The resulting container is authenticated before atomic publication. Rekeying invalidates detached signatures and cannot revoke older copies.

## Compatibility

V1 magic remains `CYPHRSTM` and its bytes and cryptographic semantics are unchanged. Inspect, verify, list, and restore dispatch by exact magic. Protection defaults to v1; v2 is selected explicitly with `--format v2`. Unknown magic or versions fail closed.

## Synthetic vectors

Executable round-trip, tamper, mixed-recipient, metadata, and rekey-payload-identity vectors are in `internal/v2/v2_test.go`. Test credentials and identities are synthetic and never production material.
