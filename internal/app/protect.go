package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/nakshatraraghav/cypherstorm/internal/credential/identity"
	"github.com/nakshatraraghav/cypherstorm/internal/credential/keymanage"
	"github.com/nakshatraraghav/cypherstorm/internal/security/container"
	"github.com/nakshatraraghav/cypherstorm/internal/security/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/archive"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/fsutil"
)

func (s *Service) Protect(ctx context.Context, req ProtectRequest, sink EventSink) (result ProtectResult, retErr error) {
	emit(sink, Event{Phase: PhaseValidating})
	if _, err := validateSource(req.InputPath); err != nil {
		return ProtectResult{}, err
	}
	var preview SelectionPreview
	createOptions, err := createSelectionOptions(req.Includes, req.Excludes, req.ExcludeVCS, req.ExcludeCache, &preview)
	if err != nil {
		return ProtectResult{}, err
	}
	if req.DryRun {
		if req.OutputPath == "" {
			return ProtectResult{}, fmt.Errorf("app: output path is required")
		}
		if err := fsutil.ValidateNoContainment(req.InputPath, req.OutputPath); err != nil {
			return ProtectResult{}, err
		}
		if err := archive.CreateTarWithOptions(ctx, req.InputPath, io.Discard, createOptions); err != nil {
			return ProtectResult{}, err
		}
		if err := validateNonemptySelection(preview); err != nil {
			return ProtectResult{}, err
		}
		return ProtectResult{OutputPath: req.OutputPath, InputBytes: preview.IncludedBytes, DryRun: true, Selection: preview}, nil
	}
	if err := prepareOutput(req.InputPath, req.OutputPath, req.Overwrite); err != nil {
		return ProtectResult{}, err
	}
	if req.Codec == "" {
		req.Codec = s.defaultCodec
	}
	if req.Cipher == "" {
		req.Cipher = s.defaultCipher
	}
	if s.verifyAfter {
		req.VerifyAfter = true
	}
	codec, err := compress.NewCodec(req.Codec)
	if err != nil {
		return ProtectResult{}, err
	}
	if _, err := crypto.NewCipherSuite(req.Cipher); err != nil {
		return ProtectResult{}, err
	}

	workspace, err := fsutil.NewWorkspace()
	if err != nil {
		return ProtectResult{}, err
	}
	defer func() {
		retErr = errors.Join(retErr, workspace.Close())
	}()

	compressedPath, err := buildCompressedArchive(ctx, req.InputPath, codec, workspace, sink, createOptions)
	if err != nil {
		return ProtectResult{}, fmt.Errorf("app: prepare protected payload: %w", err)
	}
	compressed, err := os.Open(compressedPath)
	if err != nil {
		return ProtectResult{}, fmt.Errorf("app: open compressed archive: %w", err)
	}

	emit(sink, Event{Phase: PhaseEncrypting, Detail: string(req.Cipher)})
	publishErr := fsutil.PublishAtomic(req.OutputPath, req.Overwrite, func(output *os.File) error {
		publicKeys := make([]identity.Public, 0, len(req.RecipientPaths))
		for _, path := range req.RecipientPaths {
			publicKey, err := identity.LoadPublic(path)
			if err != nil {
				return err
			}
			publicKeys = append(publicKeys, publicKey)
		}
		recipients := container.RecipientOptions{PublicKeys: publicKeys}
		switch req.Credential.Kind {
		case CredentialPassword:
			recipients.Password = req.Credential.Password
		case CredentialRawKey:
			recipients.RawKey = req.Credential.RawKey
		}
		info, err := os.Lstat(req.InputPath)
		if err != nil {
			return err
		}
		sourceType := "file"
		if info.IsDir() {
			sourceType = "directory"
		} else if info.Mode()&os.ModeSymlink != 0 {
			sourceType = "symlink"
		}
		credentialFingerprint := ""
		if req.Credential.Kind == CredentialRawKey {
			credentialFingerprint, err = keymanage.Fingerprint(req.Credential.RawKey)
			if err != nil {
				return err
			}
		}
		return container.Encrypt(ctx, compressed, output, container.EncryptOptions{
			Cipher: req.Cipher, Codec: req.Codec, RecordSize: s.recordSize, Argon2: s.argon2, Recipients: recipients,
			Metadata:   container.Metadata{OriginalName: info.Name(), SourceType: sourceType, ProtectedAt: s.now().UTC().Format(time.RFC3339), CredentialHint: req.CredentialHint, CredentialFingerprint: credentialFingerprint},
			PublicHint: req.PublicHint,
		})
	})
	closeErr := compressed.Close()
	if publishErr != nil || closeErr != nil {
		return ProtectResult{}, errors.Join(publishErr, wrapError("app: close compressed archive", closeErr))
	}

	outputInfo, err := os.Stat(req.OutputPath)
	if err != nil {
		return ProtectResult{}, fmt.Errorf("app: stat protected output: %w", err)
	}
	result = ProtectResult{OutputPath: req.OutputPath, InputBytes: preview.IncludedBytes, OutputBytes: outputInfo.Size(), Selection: preview}
	if req.VerifyAfter {
		verified, verifyErr := s.Verify(ctx, VerifyRequest{InputPath: req.OutputPath, Credential: req.Credential, Mode: VerifyFull}, sink)
		if verifyErr != nil {
			return result, fmt.Errorf("app: protected artifact published at %q but post-protection verification failed: %w", req.OutputPath, verifyErr)
		}
		result.Verification = &verified
	}
	emit(sink, Event{Phase: PhaseComplete, Current: outputInfo.Size(), Total: outputInfo.Size(), Detail: req.OutputPath})
	return result, nil
}
