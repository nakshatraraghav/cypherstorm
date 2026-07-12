package app

import (
	"context"
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/credential/keymanage"
	"github.com/nakshatraraghav/cypherstorm/internal/security/wipe"
)

type KeyGenerateRequest struct{ OutputPath string }
type KeyResult struct {
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
	Valid       bool   `json:"valid"`
}

func (s *Service) KeyGenerate(ctx context.Context, req KeyGenerateRequest, sink EventSink) (KeyResult, error) {
	if err := ctx.Err(); err != nil {
		return KeyResult{}, err
	}
	if req.OutputPath == "" {
		return KeyResult{}, fmt.Errorf("app: key output path is required")
	}
	emit(sink, Event{Phase: Phase("generating-key")})
	if err := keymanage.Generate(req.OutputPath); err != nil {
		return KeyResult{}, err
	}
	key, err := keymanage.Load(req.OutputPath)
	if err != nil {
		return KeyResult{}, err
	}
	defer clearSecret(key)
	fp, err := keymanage.Fingerprint(key)
	if err != nil {
		return KeyResult{}, err
	}
	return KeyResult{Path: req.OutputPath, Fingerprint: fp, Valid: true}, nil
}
func (s *Service) KeyValidate(ctx context.Context, path string) (KeyResult, error) {
	if err := ctx.Err(); err != nil {
		return KeyResult{}, err
	}
	key, err := keymanage.Load(path)
	if err != nil {
		return KeyResult{}, err
	}
	defer clearSecret(key)
	fp, err := keymanage.Fingerprint(key)
	return KeyResult{Path: path, Fingerprint: fp, Valid: err == nil}, err
}
func (s *Service) KeyFingerprint(ctx context.Context, path string) (KeyResult, error) {
	return s.KeyValidate(ctx, path)
}
func clearSecret(b []byte) {
	wipe.Bytes(b)
}
