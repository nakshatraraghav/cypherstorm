package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nakshatraraghav/cypherstorm/internal/archive"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/fsutil"
)

func (s *Service) Restore(ctx context.Context, req RestoreRequest, sink EventSink) (result RestoreResult, retErr error) {
	emit(sink, Event{Phase: PhaseValidating})
	inputInfo, err := os.Lstat(req.InputPath)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("app: inspect protected input %q: %w", req.InputPath, err)
	}
	if !inputInfo.Mode().IsRegular() || inputInfo.Mode()&os.ModeSymlink != 0 {
		return RestoreResult{}, fmt.Errorf("app: protected input %q must be a regular file", req.InputPath)
	}
	if req.Overwrite {
		return RestoreResult{}, fmt.Errorf("app: restore overwrite is unsupported; destination must not exist")
	}
	if err := prepareOutput(req.InputPath, req.OutputPath, false); err != nil {
		return RestoreResult{}, err
	}
	credential, err := req.Credential.kdfCredential()
	if err != nil {
		return RestoreResult{}, err
	}

	workspace, err := fsutil.NewWorkspace()
	if err != nil {
		return RestoreResult{}, err
	}
	defer func() {
		retErr = errors.Join(retErr, workspace.Close())
	}()

	compressed, err := workspace.CreateFile("decrypted.compressed")
	if err != nil {
		return RestoreResult{}, err
	}
	protected, err := os.Open(req.InputPath)
	if err != nil {
		_ = compressed.Close()
		return RestoreResult{}, fmt.Errorf("app: open protected input: %w", err)
	}

	emit(sink, Event{Phase: PhaseDecrypting})
	wireCodec, decryptErr := crypto.Decrypt(ctx, protected, compressed, credential)
	inputCloseErr := protected.Close()
	var compressedCloseErr error
	if decryptErr == nil {
		if syncErr := compressed.Sync(); syncErr != nil {
			decryptErr = fmt.Errorf("app: sync authenticated compressed payload: %w", syncErr)
		}
	}
	if closeErr := compressed.Close(); closeErr != nil {
		compressedCloseErr = fmt.Errorf("app: close authenticated compressed payload: %w", closeErr)
	}
	if decryptErr != nil || inputCloseErr != nil || compressedCloseErr != nil {
		return RestoreResult{}, errors.Join(decryptErr, wrapError("app: close protected input", inputCloseErr), compressedCloseErr)
	}

	codec, err := codecFromWireID(wireCodec)
	if err != nil {
		return RestoreResult{}, err
	}
	compressedInput, err := os.Open(filepath.Join(workspace.Root(), "decrypted.compressed"))
	if err != nil {
		return RestoreResult{}, fmt.Errorf("app: reopen compressed payload: %w", err)
	}
	decoder, err := codec.NewReader(compressedInput)
	if err != nil {
		_ = compressedInput.Close()
		return RestoreResult{}, fmt.Errorf("app: create %s decompressor: %w", codec.ID(), err)
	}

	parent := filepath.Dir(req.OutputPath)
	stagedRoot, err := os.MkdirTemp(parent, ".cypherstorm-restore-*")
	if err != nil {
		_ = decoder.Close()
		_ = compressedInput.Close()
		return RestoreResult{}, fmt.Errorf("app: create restore staging directory: %w", err)
	}
	if err := os.Chmod(stagedRoot, 0o700); err != nil {
		_ = os.RemoveAll(stagedRoot)
		_ = decoder.Close()
		_ = compressedInput.Close()
		return RestoreResult{}, fmt.Errorf("app: secure restore staging directory: %w", err)
	}
	published := false
	defer func() {
		if !published {
			retErr = errors.Join(retErr, wrapError("app: remove restore staging directory", os.RemoveAll(stagedRoot)))
		}
	}()

	emit(sink, Event{Phase: PhaseDecompressing, Detail: string(codec.ID())})
	emit(sink, Event{Phase: PhaseExtracting, Detail: req.OutputPath})
	extractErr := archive.ExtractTar(ctx, decoder, stagedRoot, s.archiveLimits)
	decoderCloseErr := decoder.Close()
	compressedInputCloseErr := compressedInput.Close()
	if extractErr != nil || decoderCloseErr != nil || compressedInputCloseErr != nil {
		return RestoreResult{}, errors.Join(
			extractErr,
			wrapError("app: close decompressor", decoderCloseErr),
			wrapError("app: close compressed payload", compressedInputCloseErr),
		)
	}

	emit(sink, Event{Phase: PhasePublishing, Detail: req.OutputPath})
	if err := fsutil.PublishDirectory(stagedRoot, req.OutputPath); err != nil {
		return RestoreResult{}, err
	}
	published = true
	emit(sink, Event{Phase: PhaseComplete, Detail: req.OutputPath})
	return RestoreResult{OutputPath: req.OutputPath}, nil
}
