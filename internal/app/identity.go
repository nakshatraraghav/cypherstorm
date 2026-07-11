package app

import (
	"context"

	"github.com/nakshatraraghav/cypherstorm/internal/identity"
)

type IdentityResult struct {
	Path        string           `json:"path"`
	Type        string           `json:"type"`
	Fingerprint string           `json:"fingerprint"`
	Public      *identity.Public `json:"public,omitempty"`
}
type SignatureResult struct {
	Path      string              `json:"path"`
	Valid     bool                `json:"valid"`
	Signature *identity.Signature `json:"signature,omitempty"`
}

func (s *Service) IdentityGenerate(ctx context.Context, kind, path string) (IdentityResult, error) {
	if err := ctx.Err(); err != nil {
		return IdentityResult{}, err
	}
	if err := identity.Generate(kind, path); err != nil {
		return IdentityResult{}, err
	}
	pub, err := identity.PublicFromPrivate(path)
	if err != nil {
		return IdentityResult{}, err
	}
	fp, err := identity.Fingerprint(pub)
	return IdentityResult{Path: path, Type: kind, Fingerprint: fp, Public: &pub}, err
}
func (s *Service) IdentityPublic(ctx context.Context, privatePath, output string) (IdentityResult, error) {
	if err := ctx.Err(); err != nil {
		return IdentityResult{}, err
	}
	pub, err := identity.PublicFromPrivate(privatePath)
	if err != nil {
		return IdentityResult{}, err
	}
	if err = identity.WritePublic(pub, output); err != nil {
		return IdentityResult{}, err
	}
	fp, err := identity.Fingerprint(pub)
	return IdentityResult{Path: output, Type: pub.Type, Fingerprint: fp, Public: &pub}, err
}
func (s *Service) IdentityFingerprint(ctx context.Context, path string) (IdentityResult, error) {
	if err := ctx.Err(); err != nil {
		return IdentityResult{}, err
	}
	pub, err := identity.LoadPublic(path)
	if err != nil {
		return IdentityResult{}, err
	}
	fp, err := identity.Fingerprint(pub)
	return IdentityResult{Path: path, Type: pub.Type, Fingerprint: fp}, err
}
func (s *Service) Sign(ctx context.Context, input, privatePath, output, label string) (SignatureResult, error) {
	if err := ctx.Err(); err != nil {
		return SignatureResult{}, err
	}
	if err := identity.Sign(input, privatePath, output, label); err != nil {
		return SignatureResult{}, err
	}
	sig, err := identity.InspectSignature(output)
	return SignatureResult{Path: output, Valid: err == nil, Signature: &sig}, err
}
func (s *Service) SignatureInspect(ctx context.Context, path string) (SignatureResult, error) {
	if err := ctx.Err(); err != nil {
		return SignatureResult{}, err
	}
	sig, err := identity.InspectSignature(path)
	return SignatureResult{Path: path, Valid: err == nil, Signature: &sig}, err
}
func (s *Service) SignatureVerify(ctx context.Context, input, path string) (SignatureResult, error) {
	if err := ctx.Err(); err != nil {
		return SignatureResult{}, err
	}
	err := identity.Verify(input, path)
	return SignatureResult{Path: path, Valid: err == nil}, err
}
