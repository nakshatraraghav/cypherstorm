package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/nakshatraraghav/cypherstorm/internal/security/container"
	"github.com/nakshatraraghav/cypherstorm/internal/security/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/security/kdf"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/archive"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/fsutil"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/selection"
)

type InspectRequest struct {
	InputPath     string
	Authenticate  bool
	Credential    Credential
	IdentityPaths []string
}

type InspectResult struct {
	Path                string                 `json:"path"`
	FormatVersion       uint8                  `json:"format_version"`
	HeaderLength        uint32                 `json:"header_length"`
	Cipher              crypto.CipherID        `json:"cipher"`
	Codec               compress.CompressionID `json:"compression"`
	CredentialKind      CredentialKind         `json:"credential_kind"`
	Argon2              *kdf.Argon2Params      `json:"argon2,omitempty"`
	RecordSize          uint32                 `json:"record_size"`
	ContainerBytes      int64                  `json:"container_bytes"`
	HeaderAuthenticated bool                   `json:"header_authenticated"`
	RecipientCount      int                    `json:"recipient_count,omitempty"`
	PublicHint          string                 `json:"public_hint,omitempty"`
	PrivateMetadata     *container.Metadata    `json:"private_metadata,omitempty"`
}

type VerifyMode string

const (
	VerifyQuick VerifyMode = "quick"
	VerifyFull  VerifyMode = "full"
)

var ErrUnsupportedProtectedFormat = errors.New("app: unsupported protected-file format")

type VerifyRequest struct {
	InputPath     string
	Credential    Credential
	Mode          VerifyMode
	IdentityPaths []string
}

type VerifyResult struct {
	Path             string              `json:"path"`
	Mode             VerifyMode          `json:"mode"`
	Authenticated    bool                `json:"authenticated"`
	ArchiveValidated bool                `json:"archive_validated"`
	Summary          archive.ScanSummary `json:"summary"`
}

type ListRequest struct {
	InputPath     string
	Credential    Credential
	FilesOnly     bool
	MaxDepth      int
	Match         string
	IdentityPaths []string
}

type ListResult struct {
	Path    string              `json:"path"`
	Entries []archive.Entry     `json:"entries"`
	Summary archive.ScanSummary `json:"summary"`
}

func (s *Service) Inspect(ctx context.Context, req InspectRequest, sink EventSink) (InspectResult, error) {
	if err := ctx.Err(); err != nil {
		return InspectResult{}, err
	}
	emit(sink, Event{Phase: Phase("inspecting")})
	f, info, err := openRegular(req.InputPath)
	if err != nil {
		return InspectResult{}, err
	}
	defer f.Close()
	var magic [8]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return InspectResult{}, err
	}
	if magic != container.Magic {
		return InspectResult{}, fmt.Errorf("%w: expected CypherStorm v2", ErrUnsupportedProtectedFormat)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return InspectResult{}, err
	}
	inspected, err := container.Inspect(f)
	if err != nil {
		return InspectResult{}, err
	}
	result := InspectResult{
		Path: req.InputPath, FormatVersion: container.Version, HeaderLength: inspected.HeaderLength,
		Cipher: crypto.CipherID(inspected.Header.Cipher), Codec: compress.CompressionID(inspected.Header.Codec),
		RecordSize: inspected.Header.RecordSize, ContainerBytes: info.Size(),
		RecipientCount: len(inspected.Header.Recipients), PublicHint: inspected.Header.PublicHint,
	}
	if !req.Authenticate {
		return result, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return InspectResult{}, err
	}
	options := container.DecryptOptions{IdentityPaths: req.IdentityPaths}
	switch req.Credential.Kind {
	case CredentialPassword:
		options.Password = req.Credential.Password
	case CredentialRawKey:
		options.RawKey = req.Credential.RawKey
	}
	_, metadata, err := container.Decrypt(ctx, f, io.Discard, options)
	if err != nil {
		return InspectResult{}, err
	}
	result.HeaderAuthenticated = true
	result.PrivateMetadata = &metadata
	return result, nil
}

func (s *Service) Verify(ctx context.Context, req VerifyRequest, sink EventSink) (VerifyResult, error) {
	if req.Mode == "" {
		req.Mode = VerifyFull
	}
	if req.Mode != VerifyQuick && req.Mode != VerifyFull {
		return VerifyResult{}, fmt.Errorf("app: invalid verify mode %q", req.Mode)
	}
	workspace, payload, codecID, err := s.decodeAuthenticated(ctx, req.InputPath, req.Credential, req.IdentityPaths, sink)
	if err != nil {
		return VerifyResult{}, err
	}
	defer workspace.Close()
	result := VerifyResult{Path: req.InputPath, Mode: req.Mode, Authenticated: true}
	if req.Mode == VerifyQuick {
		return result, nil
	}
	summary, err := s.scanPayload(ctx, payload, codecID, nil)
	if err != nil {
		return VerifyResult{}, err
	}
	result.ArchiveValidated, result.Summary = true, summary
	return result, nil
}

func (s *Service) List(ctx context.Context, req ListRequest, sink EventSink) (ListResult, error) {
	workspace, payload, codecID, err := s.decodeAuthenticated(ctx, req.InputPath, req.Credential, req.IdentityPaths, sink)
	if err != nil {
		return ListResult{}, err
	}
	defer workspace.Close()
	entries := make([]archive.Entry, 0, 128)
	summary, err := s.scanPayload(ctx, payload, codecID, func(entry archive.Entry) error {
		if req.FilesOnly && entry.Type != archive.EntryFile {
			return nil
		}
		if req.MaxDepth > 0 {
			depth := 1
			for _, c := range entry.Path {
				if c == '/' {
					depth++
				}
			}
			if depth > req.MaxDepth {
				return nil
			}
		}
		if req.Match != "" {
			matched, err := selection.Match(req.Match, entry.Path)
			if err != nil {
				return err
			}
			if !matched {
				return nil
			}
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return ListResult{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return ListResult{Path: req.InputPath, Entries: entries, Summary: summary}, nil
}

func openRegular(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("app: inspect protected input %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("app: protected input %q must be a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("app: open protected input: %w", err)
	}
	return f, info, nil
}

func (s *Service) decodeAuthenticated(ctx context.Context, input string, credential Credential, identityPaths []string, sink EventSink) (*fsutil.Workspace, string, compress.CompressionID, error) {
	protected, _, err := openRegular(input)
	if err != nil {
		return nil, "", "", err
	}
	defer protected.Close()
	var magic [8]byte
	if _, err := io.ReadFull(protected, magic[:]); err != nil {
		return nil, "", "", err
	}
	if magic != container.Magic {
		return nil, "", "", fmt.Errorf("%w: expected CypherStorm v2", ErrUnsupportedProtectedFormat)
	}
	if _, err := protected.Seek(0, io.SeekStart); err != nil {
		return nil, "", "", err
	}
	workspace, err := fsutil.NewWorkspace()
	if err != nil {
		return nil, "", "", err
	}
	failed := true
	defer func() {
		if failed {
			_ = workspace.Close()
		}
	}()
	out, err := workspace.CreateFile("authenticated.payload")
	if err != nil {
		return nil, "", "", err
	}
	emit(sink, Event{Phase: Phase("authenticating")})
	options := container.DecryptOptions{IdentityPaths: identityPaths}
	switch credential.Kind {
	case CredentialPassword:
		options.Password = credential.Password
	case CredentialRawKey:
		options.RawKey = credential.RawKey
	}
	codecID, _, decErr := container.Decrypt(ctx, protected, out, options)
	if decErr == nil {
		decErr = out.Sync()
	}
	decErr = errors.Join(decErr, out.Close())
	if decErr != nil {
		return nil, "", "", decErr
	}
	failed = false
	return workspace, filepath.Join(workspace.Root(), "authenticated.payload"), codecID, nil
}

func (s *Service) scanPayload(ctx context.Context, payload string, codecID compress.CompressionID, visit func(archive.Entry) error) (archive.ScanSummary, error) {
	codec, err := compress.NewCodec(codecID)
	if err != nil {
		return archive.ScanSummary{}, err
	}
	f, err := os.Open(payload)
	if err != nil {
		return archive.ScanSummary{}, fmt.Errorf("app: open authenticated payload: %w", err)
	}
	defer f.Close()
	decoder, err := codec.NewReader(f)
	if err != nil {
		return archive.ScanSummary{}, fmt.Errorf("app: create %s decompressor: %w", codec.ID(), err)
	}
	summary, scanErr := archive.ScanTar(ctx, decoder, archive.ScanOptions{Limits: s.archiveLimits, Visit: visit})
	return summary, errors.Join(scanErr, decoder.Close())
}
