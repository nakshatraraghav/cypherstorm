package app

import (
	"context"

	"github.com/nakshatraraghav/cypherstorm/internal/identity"
	"github.com/nakshatraraghav/cypherstorm/internal/qrexchange"
)

type QRResult struct {
	Path        string          `json:"path,omitempty"`
	Terminal    string          `json:"terminal,omitempty"`
	Fingerprint string          `json:"fingerprint"`
	Public      identity.Public `json:"public"`
}

func (s *Service) IdentityQR(ctx context.Context, publicPath, output string) (QRResult, error) {
	if err := ctx.Err(); err != nil {
		return QRResult{}, err
	}
	public, err := identity.LoadPublic(publicPath)
	if err != nil {
		return QRResult{}, err
	}
	fp, err := identity.Fingerprint(public)
	if err != nil {
		return QRResult{}, err
	}
	r := QRResult{Path: output, Fingerprint: fp, Public: public}
	if output == "" {
		r.Terminal, err = qrexchange.Terminal(public)
	} else {
		err = qrexchange.PNG(public, output)
	}
	return r, err
}
func (s *Service) RecipientImportQR(ctx context.Context, imagePath, output string) (QRResult, error) {
	if err := ctx.Err(); err != nil {
		return QRResult{}, err
	}
	public, err := qrexchange.ImportPNG(imagePath)
	if err != nil {
		return QRResult{}, err
	}
	if err = identity.WritePublic(public, output); err != nil {
		return QRResult{}, err
	}
	fp, err := identity.Fingerprint(public)
	return QRResult{Path: output, Fingerprint: fp, Public: public}, err
}
