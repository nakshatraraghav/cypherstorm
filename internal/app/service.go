// Package app provides UI-neutral orchestration for CypherStorm operations.
// It owns filesystem policy, staging, capability selection, and publication;
// adapters only collect input and render structured results and events.
package app

import (
	"fmt"
	"time"

	"github.com/nakshatraraghav/cypherstorm/internal/credential/credentialstore"
	"github.com/nakshatraraghav/cypherstorm/internal/security/container"
	"github.com/nakshatraraghav/cypherstorm/internal/security/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/security/hashing"
	"github.com/nakshatraraghav/cypherstorm/internal/security/kdf"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/archive"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/compress"
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

type Config struct {
	Argon2          kdf.Argon2Params
	RecordSize      uint32
	ArchiveLimits   archive.ExtractLimits
	CredentialStore credentialstore.Store
	DefaultCodec    compress.CompressionID
	DefaultCipher   crypto.CipherID
	VerifyAfter     bool
}

type Service struct {
	argon2          kdf.Argon2Params
	recordSize      uint32
	archiveLimits   archive.ExtractLimits
	credentialStore credentialstore.Store
	now             func() time.Time
	benchmarkRunner benchmarkRunner
	defaultCodec    compress.CompressionID
	defaultCipher   crypto.CipherID
	verifyAfter     bool
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
	if config.RecordSize > container.MaxRecordSize {
		return nil, fmt.Errorf("app: record size %d exceeds maximum %d", config.RecordSize, container.MaxRecordSize)
	}
	if config.DefaultCodec == "" {
		config.DefaultCodec = compress.CompressionGzip
	}
	if _, err := compress.NewCodec(config.DefaultCodec); err != nil {
		return nil, err
	}
	if config.DefaultCipher == "" {
		config.DefaultCipher = crypto.AES256GCM
	}
	if _, err := crypto.NewCipherSuite(config.DefaultCipher); err != nil {
		return nil, err
	}
	if config.CredentialStore == nil {
		config.CredentialStore = credentialstore.New()
	}
	return &Service{
		argon2:          config.Argon2,
		recordSize:      config.RecordSize,
		archiveLimits:   config.ArchiveLimits,
		credentialStore: config.CredentialStore,
		now:             time.Now,
		defaultCodec:    config.DefaultCodec,
		defaultCipher:   config.DefaultCipher,
		verifyAfter:     config.VerifyAfter,
	}, nil
}

type ProtectRequest struct {
	InputPath      string
	OutputPath     string
	Credential     Credential
	Cipher         crypto.CipherID
	Codec          compress.CompressionID
	Overwrite      bool
	Includes       []string
	Excludes       []string
	ExcludeVCS     bool
	ExcludeCache   bool
	DryRun         bool
	VerifyAfter    bool
	RecipientPaths []string
	CredentialHint string
	PublicHint     string
}

type ProtectResult struct {
	OutputPath   string           `json:"output_path"`
	InputBytes   int64            `json:"input_bytes"`
	OutputBytes  int64            `json:"output_bytes"`
	DryRun       bool             `json:"dry_run"`
	Selection    SelectionPreview `json:"selection"`
	Verification *VerifyResult    `json:"verification,omitempty"`
}

type ConflictPolicy string

const (
	ConflictFail      ConflictPolicy = "fail"
	ConflictSkip      ConflictPolicy = "skip"
	ConflictRename    ConflictPolicy = "rename"
	ConflictOverwrite ConflictPolicy = "overwrite"
)

type RestoreRequest struct {
	InputPath     string
	OutputPath    string
	Credential    Credential
	Overwrite     bool
	Includes      []string
	Excludes      []string
	Paths         []string
	Conflict      ConflictPolicy
	IdentityPaths []string
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
