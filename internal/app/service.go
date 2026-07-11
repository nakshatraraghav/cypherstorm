// Package app provides UI-neutral orchestration for CypherStorm operations.
// It owns filesystem policy, staging, capability selection, and publication;
// adapters only collect input and render structured results and events.
package app

import (
	"fmt"
	"time"

	"github.com/nakshatraraghav/cypherstorm/internal/archive"
	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/format"
	"github.com/nakshatraraghav/cypherstorm/internal/hashing"
	"github.com/nakshatraraghav/cypherstorm/internal/kdf"
)

const DefaultRecordSize uint32 = 64 * 1024

type CredentialKind uint8

const (
	CredentialUnknown CredentialKind = iota
	CredentialRawKey
	CredentialPassword
)

type Credential struct {
	Kind     CredentialKind
	Password []byte
	RawKey   []byte
}

func (c Credential) kdfCredential() (kdf.Credential, error) {
	switch c.Kind {
	case CredentialPassword:
		if len(c.Password) == 0 {
			return kdf.Credential{}, fmt.Errorf("app: password credential is empty")
		}
		return kdf.Credential{Kind: kdf.SourcePassword, Password: c.Password}, nil
	case CredentialRawKey:
		if len(c.RawKey) != kdf.MasterKeySize {
			return kdf.Credential{}, fmt.Errorf("app: raw key must be exactly %d bytes, got %d", kdf.MasterKeySize, len(c.RawKey))
		}
		return kdf.Credential{Kind: kdf.SourceRaw, RawKey: c.RawKey}, nil
	default:
		return kdf.Credential{}, fmt.Errorf("app: unknown credential kind %d", c.Kind)
	}
}

type Config struct {
	Argon2        kdf.Argon2Params
	RecordSize    uint32
	ArchiveLimits archive.ExtractLimits
}

type Service struct {
	argon2          kdf.Argon2Params
	recordSize      uint32
	archiveLimits   archive.ExtractLimits
	now             func() time.Time
	benchmarkRunner benchmarkRunner
}

func NewService() (*Service, error) {
	return NewServiceWithConfig(Config{})
}

func NewServiceWithConfig(config Config) (*Service, error) {
	if config.Argon2 == (kdf.Argon2Params{}) {
		config.Argon2 = kdf.DefaultArgon2Params()
	}
	if err := config.Argon2.Validate(); err != nil {
		return nil, fmt.Errorf("app: invalid Argon2 policy: %w", err)
	}
	if config.RecordSize == 0 {
		config.RecordSize = DefaultRecordSize
	}
	if config.RecordSize > format.MaxRecordSize {
		return nil, fmt.Errorf("app: record size %d exceeds maximum %d", config.RecordSize, format.MaxRecordSize)
	}
	return &Service{
		argon2:        config.Argon2,
		recordSize:    config.RecordSize,
		archiveLimits: config.ArchiveLimits,
		now:           time.Now,
	}, nil
}

func wireCodecID(id compress.CompressionID) (format.CodecID, error) {
	switch id {
	case compress.CompressionGzip:
		return format.CodecGzip, nil
	case compress.CompressionZstd:
		return format.CodecZstd, nil
	case compress.CompressionLZ4:
		return format.CodecLZ4, nil
	case compress.CompressionBzip2:
		return format.CodecBzip2, nil
	case compress.CompressionLZMA:
		return format.CodecLZMA, nil
	default:
		return format.CodecUnknown, fmt.Errorf("app: unsupported compression codec %q", id)
	}
}

func codecFromWireID(id format.CodecID) (compress.Codec, error) {
	var codecID compress.CompressionID
	switch id {
	case format.CodecGzip:
		codecID = compress.CompressionGzip
	case format.CodecZstd:
		codecID = compress.CompressionZstd
	case format.CodecLZ4:
		codecID = compress.CompressionLZ4
	case format.CodecBzip2:
		codecID = compress.CompressionBzip2
	case format.CodecLZMA:
		codecID = compress.CompressionLZMA
	default:
		return nil, fmt.Errorf("app: unsupported wire codec id %d", id)
	}
	return compress.NewCodec(codecID)
}

type ProtectRequest struct {
	InputPath  string
	OutputPath string
	Credential Credential
	Cipher     crypto.CipherID
	Codec      compress.CompressionID
	Overwrite  bool
}

type ProtectResult struct {
	OutputPath  string
	InputBytes  int64
	OutputBytes int64
}

type RestoreRequest struct {
	InputPath  string
	OutputPath string
	Credential Credential
	Overwrite  bool
}

type RestoreResult struct {
	OutputPath string
}

type HashRequest struct {
	InputPath string
	Algorithm hashing.ID
}

type HashResult struct {
	Path   string
	Digest []byte
}

type BenchmarkRequest struct {
	InputPath  string
	OutputPath string
}
