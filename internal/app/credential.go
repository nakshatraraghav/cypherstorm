package app

import (
	"context"
	"fmt"

	"github.com/nakshatraraghav/cypherstorm/internal/credentialstore"
	"github.com/nakshatraraghav/cypherstorm/internal/keymanage"
)

type CredentialDescriptor struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func (s *Service) CredentialAdd(ctx context.Context, name string, c Credential) (CredentialDescriptor, error) {
	var stored credentialstore.SecretCredential
	var d credentialstore.Descriptor
	switch c.Kind {
	case CredentialPassword:
		if len(c.Password) == 0 {
			return CredentialDescriptor{}, fmt.Errorf("app: password is empty")
		}
		stored = credentialstore.SecretCredential{Kind: credentialstore.KindPassword, Secret: c.Password}
	case CredentialRawKey:
		if len(c.RawKey) != 32 {
			return CredentialDescriptor{}, fmt.Errorf("app: raw key must be exactly 32 bytes")
		}
		fp, err := keymanage.Fingerprint(c.RawKey)
		if err != nil {
			return CredentialDescriptor{}, err
		}
		stored = credentialstore.SecretCredential{Kind: credentialstore.KindRawKey, Secret: c.RawKey}
		d.Fingerprint = fp
	default:
		return CredentialDescriptor{}, fmt.Errorf("app: unsupported credential kind")
	}
	if err := s.credentialStore.Put(ctx, name, stored, d); err != nil {
		return CredentialDescriptor{}, err
	}
	return CredentialDescriptor{Name: name, Kind: string(stored.Kind), Fingerprint: d.Fingerprint}, nil
}
func (s *Service) CredentialList(ctx context.Context) ([]CredentialDescriptor, error) {
	list, err := s.credentialStore.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]CredentialDescriptor, len(list))
	for i, d := range list {
		out[i] = CredentialDescriptor{Name: d.Name, Kind: string(d.Kind), Fingerprint: d.Fingerprint}
	}
	return out, nil
}
func (s *Service) CredentialInspect(ctx context.Context, name string) (CredentialDescriptor, error) {
	list, err := s.CredentialList(ctx)
	if err != nil {
		return CredentialDescriptor{}, err
	}
	for _, d := range list {
		if d.Name == name {
			return d, nil
		}
	}
	return CredentialDescriptor{}, fmt.Errorf("credential: %q not found", name)
}
func (s *Service) CredentialRemove(ctx context.Context, name string) error {
	return s.credentialStore.Delete(ctx, name)
}
func (s *Service) ResolveSavedCredential(ctx context.Context, name string) (Credential, error) {
	c, err := s.credentialStore.Get(ctx, name)
	if err != nil {
		return Credential{}, err
	}
	switch c.Kind {
	case credentialstore.KindPassword:
		return Credential{Kind: CredentialPassword, Password: c.Secret}, nil
	case credentialstore.KindRawKey:
		return Credential{Kind: CredentialRawKey, RawKey: c.Secret}, nil
	default:
		clearSecret(c.Secret)
		return Credential{}, fmt.Errorf("credential: unsupported stored kind %q", c.Kind)
	}
}
