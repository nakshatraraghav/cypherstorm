// Package kdf derives protected-file encryption keys from a credential
// source. It has no knowledge of the on-disk container format; callers
// (internal/crypto) supply the header salt and receive back key material.
//
// Two credential sources are supported, both funneled through the same
// two-stage derivation:
//
//  1. A "master key" is obtained from the credential:
//     - Password: Argon2id(password, salt, params) -> MasterKeySize bytes.
//     - Raw key: the provided key bytes themselves, exact-length validated.
//  2. A unique per-file key is derived from the master key with
//     HKDF-SHA-256, using the header salt and a domain-separated info
//     string (see DeriveFileKey), so raw-key sources never use the same
//     literal bytes as the actual encryption key across two files, and
//     password-derived master keys are never used directly as AEAD keys.
package kdf

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// MasterKeySize is the fixed output length of Argon2id derivation and the
// required exact length of a raw-key credential.
const MasterKeySize = 32

// Argon2 policy bounds limit both locally selected encryption parameters and
// unauthenticated parameters decoded during restore. Keep these limits small
// enough that a hostile header cannot force unbounded CPU or memory use.
const (
	MaxArgon2Time        uint32 = 10
	MaxArgon2MemoryKiB   uint32 = 256 * 1024
	MaxArgon2Parallelism uint8  = 16
)

// SourceKind identifies where credential material comes from.
type SourceKind uint8

const (
	SourceUnknown SourceKind = iota
	// SourceRaw is a raw, high-entropy key supplied directly (e.g. a key
	// file), used as the master key without a password-hardening KDF.
	SourceRaw
	// SourcePassword is a low-entropy user password requiring Argon2id
	// hardening before use as a master key.
	SourcePassword
)

// Credential is exactly one of a raw key or a password, tagged by Kind.
type Credential struct {
	Kind     SourceKind
	RawKey   []byte // valid when Kind == SourceRaw; must be MasterKeySize bytes
	Password []byte // valid when Kind == SourcePassword; must be nonempty
}

// Argon2Params are the serialized-with-the-header Argon2id parameters.
// Restore must use the parameters read from the header, never hardcoded
// defaults, so a file always reproduces its original master key.
type Argon2Params struct {
	Time        uint32
	MemoryKiB   uint32
	Parallelism uint8
	KeyLength   uint8
}

// DefaultArgon2Params returns the parameters used for newly protected
// files. Chosen for interactive CLI use: ~64 MiB memory, moderate time cost.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Time:        3,
		MemoryKiB:   64 * 1024,
		Parallelism: 4,
		KeyLength:   MasterKeySize,
	}
}

// Validate rejects parameters outside the v1 resource policy before Argon2
// is invoked. Header parameters are unauthenticated at this point during
// restore, so every cost field requires a strict upper bound.
func (p Argon2Params) Validate() error {
	if p.Time == 0 {
		return fmt.Errorf("kdf: argon2id time parameter must be nonzero")
	}
	if p.Time > MaxArgon2Time {
		return fmt.Errorf("kdf: argon2id time parameter %d exceeds maximum %d", p.Time, MaxArgon2Time)
	}
	if p.MemoryKiB == 0 {
		return fmt.Errorf("kdf: argon2id memory parameter must be nonzero")
	}
	if p.MemoryKiB > MaxArgon2MemoryKiB {
		return fmt.Errorf("kdf: argon2id memory parameter %d KiB exceeds maximum %d KiB", p.MemoryKiB, MaxArgon2MemoryKiB)
	}
	if p.Parallelism == 0 {
		return fmt.Errorf("kdf: argon2id parallelism parameter must be nonzero")
	}
	if p.Parallelism > MaxArgon2Parallelism {
		return fmt.Errorf("kdf: argon2id parallelism parameter %d exceeds maximum %d", p.Parallelism, MaxArgon2Parallelism)
	}
	if p.MemoryKiB < 8*uint32(p.Parallelism) {
		return fmt.Errorf("kdf: argon2id memory parameter must be at least 8 KiB per parallel thread")
	}
	if p.KeyLength != MasterKeySize {
		return fmt.Errorf("kdf: argon2id key length must be exactly %d bytes, got %d", MasterKeySize, p.KeyLength)
	}
	return nil
}

// DeriveMasterKey obtains a master key from cred. For SourcePassword this
// runs Argon2id with salt and params; for SourceRaw it validates and
// returns a copy of the raw key bytes. Argon2id itself cannot be interrupted,
// so ctx is checked before starting the expensive derivation.
func DeriveMasterKey(ctx context.Context, cred Credential, params Argon2Params, salt []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch cred.Kind {
	case SourcePassword:
		if len(cred.Password) == 0 {
			return nil, fmt.Errorf("kdf: password credential is empty")
		}
		if err := params.Validate(); err != nil {
			return nil, err
		}
		if len(salt) == 0 {
			return nil, fmt.Errorf("kdf: salt is required for password derivation")
		}
		key := argon2.IDKey(cred.Password, salt, params.Time, params.MemoryKiB, params.Parallelism, uint32(params.KeyLength))
		return key, nil

	case SourceRaw:
		if len(cred.RawKey) != MasterKeySize {
			return nil, fmt.Errorf("kdf: raw key must be exactly %d bytes, got %d", MasterKeySize, len(cred.RawKey))
		}
		out := make([]byte, MasterKeySize)
		copy(out, cred.RawKey)
		return out, nil

	default:
		return nil, fmt.Errorf("kdf: unknown credential source kind %d", cred.Kind)
	}
}

// DeriveFileKey expands masterKey into a unique per-file key of keyLen
// bytes using HKDF-SHA-256 with salt and a domain-separated info string.
// info should identify the format version and cipher suite (e.g.
// "cypherstorm/v1/aes-256-gcm") so keys derived for different ciphers or
// future format versions from the same master key never collide.
func DeriveFileKey(masterKey, salt []byte, info string, keyLen int) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("kdf: master key is empty")
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("kdf: salt is required for file key derivation")
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("kdf: requested key length must be positive, got %d", keyLen)
	}

	reader := hkdf.New(sha256.New, masterKey, salt, []byte(info))
	out := make([]byte, keyLen)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, fmt.Errorf("kdf: hkdf expand failed: %w", err)
	}
	return out, nil
}
