package app

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/nakshatraraghav/cypherstorm/internal/credential/identity"
	"github.com/nakshatraraghav/cypherstorm/internal/security/container"
	"github.com/nakshatraraghav/cypherstorm/internal/storage/fsutil"
)

type RekeyRequest struct {
	InputPath          string
	OutputPath         string
	Credential         Credential
	IdentityPaths      []string
	NewCredential      Credential
	AddRecipientPaths  []string
	RemoveRecipientIDs []string
}
type RekeyResult struct {
	OutputPath           string `json:"output_path"`
	PayloadBytes         int64  `json:"payload_bytes"`
	SignatureInvalidated bool   `json:"signature_invalidated"`
}

func (s *Service) Rekey(ctx context.Context, req RekeyRequest, sink EventSink) (RekeyResult, error) {
	if req.OutputPath == "" {
		return RekeyResult{}, fmt.Errorf("app: rekey output path is required")
	}
	if err := prepareOutput(req.InputPath, req.OutputPath, false); err != nil {
		return RekeyResult{}, err
	}
	input, _, err := openRegular(req.InputPath)
	if err != nil {
		return RekeyResult{}, err
	}
	defer input.Close()
	auth := container.DecryptOptions{IdentityPaths: req.IdentityPaths}
	switch req.Credential.Kind {
	case CredentialPassword:
		auth.Password = req.Credential.Password
	case CredentialRawKey:
		auth.RawKey = req.Credential.RawKey
	}
	add := container.RecipientOptions{}
	replaceSymmetric := false
	switch req.NewCredential.Kind {
	case CredentialPassword:
		add.Password = req.NewCredential.Password
		replaceSymmetric = true
	case CredentialRawKey:
		add.RawKey = req.NewCredential.RawKey
		replaceSymmetric = true
	}
	for _, path := range req.AddRecipientPaths {
		p, e := identity.LoadPublic(path)
		if e != nil {
			return RekeyResult{}, e
		}
		add.PublicKeys = append(add.PublicKeys, p)
	}
	emit(sink, Event{Phase: Phase("rekeying")})
	var payloadBytes int64
	err = fsutil.PublishAtomic(req.OutputPath, false, func(output *os.File) error {
		var e error
		payloadBytes, e = container.Rekey(ctx, input, output, auth, add, req.RemoveRecipientIDs, replaceSymmetric)
		if e != nil {
			return e
		}
		if e = output.Sync(); e != nil {
			return e
		}
		if _, e = output.Seek(0, io.SeekStart); e != nil {
			return e
		}
		verify := auth
		if replaceSymmetric {
			verify = container.DecryptOptions{IdentityPaths: req.IdentityPaths}
			switch req.NewCredential.Kind {
			case CredentialPassword:
				verify.Password = req.NewCredential.Password
			case CredentialRawKey:
				verify.RawKey = req.NewCredential.RawKey
			}
		}
		_, _, e = container.Decrypt(ctx, output, io.Discard, verify)
		return e
	})
	if err != nil {
		return RekeyResult{}, err
	}
	return RekeyResult{OutputPath: req.OutputPath, PayloadBytes: payloadBytes, SignatureInvalidated: true}, nil
}
