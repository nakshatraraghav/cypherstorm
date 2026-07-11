package app

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/nakshatraraghav/cypherstorm/internal/compress"
	"github.com/nakshatraraghav/cypherstorm/internal/crypto"
	"github.com/nakshatraraghav/cypherstorm/internal/fsutil"
)

func (s *Service) Protect(ctx context.Context, req ProtectRequest, sink EventSink) (result ProtectResult, retErr error) {
	emit(sink, Event{Phase: PhaseValidating})
	if _, err := validateSource(req.InputPath); err != nil {
		return ProtectResult{}, err
	}
	if err := prepareOutput(req.InputPath, req.OutputPath, req.Overwrite); err != nil {
		return ProtectResult{}, err
	}
	credential, err := req.Credential.kdfCredential()
	if err != nil {
		return ProtectResult{}, err
	}
	codec, err := compress.NewCodec(req.Codec)
	if err != nil {
		return ProtectResult{}, err
	}
	wireCodec, err := wireCodecID(req.Codec)
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

	compressedPath, err := buildCompressedArchive(ctx, req.InputPath, codec, workspace, sink)
	if err != nil {
		return ProtectResult{}, fmt.Errorf("app: prepare protected payload: %w", err)
	}
	compressed, err := os.Open(compressedPath)
	if err != nil {
		return ProtectResult{}, fmt.Errorf("app: open compressed archive: %w", err)
	}

	emit(sink, Event{Phase: PhaseEncrypting, Detail: string(req.Cipher)})
	publishErr := fsutil.PublishAtomic(req.OutputPath, req.Overwrite, func(output *os.File) error {
		return crypto.Encrypt(ctx, compressed, output, crypto.EncryptOptions{
			Credential: credential,
			CipherID:   req.Cipher,
			CodecID:    wireCodec,
			Argon2:     s.argon2,
			RecordSize: s.recordSize,
		})
	})
	closeErr := compressed.Close()
	if publishErr != nil || closeErr != nil {
		return ProtectResult{}, errors.Join(publishErr, wrapError("app: close compressed archive", closeErr))
	}

	inputBytes, err := sourceSize(ctx, req.InputPath)
	if err != nil {
		return ProtectResult{}, err
	}
	outputInfo, err := os.Stat(req.OutputPath)
	if err != nil {
		return ProtectResult{}, fmt.Errorf("app: stat protected output: %w", err)
	}
	emit(sink, Event{Phase: PhaseComplete, Current: outputInfo.Size(), Total: outputInfo.Size(), Detail: req.OutputPath})
	return ProtectResult{OutputPath: req.OutputPath, InputBytes: inputBytes, OutputBytes: outputInfo.Size()}, nil
}
