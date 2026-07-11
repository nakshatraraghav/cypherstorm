package credentialstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"sync"

	keyring "github.com/zalando/go-keyring"
)

const serviceName = "CypherStorm"
const indexAccount = "__credential_index_v1__"

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Kind string

const (
	KindPassword Kind = "password"
	KindRawKey   Kind = "raw-key"
)

type SecretCredential struct {
	Kind   Kind
	Secret []byte
}
type Descriptor struct {
	Name        string `json:"name"`
	Kind        Kind   `json:"kind"`
	Fingerprint string `json:"fingerprint,omitempty"`
}
type Store interface {
	Put(context.Context, string, SecretCredential, Descriptor) error
	Get(context.Context, string) (SecretCredential, error)
	Delete(context.Context, string) error
	List(context.Context) ([]Descriptor, error)
}

type Backend interface {
	Set(service, user, password string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}
type nativeBackend struct{}

func (nativeBackend) Set(s, u, p string) error        { return keyring.Set(s, u, p) }
func (nativeBackend) Get(s, u string) (string, error) { return keyring.Get(s, u) }
func (nativeBackend) Delete(s, u string) error        { return keyring.Delete(s, u) }

type KeychainStore struct {
	backend Backend
	mu      sync.Mutex
}

func New() *KeychainStore                     { return &KeychainStore{backend: nativeBackend{}} }
func NewWithBackend(b Backend) *KeychainStore { return &KeychainStore{backend: b} }

func ValidateName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("credential: name must match %s", validName.String())
	}
	return nil
}
func (s *KeychainStore) Put(ctx context.Context, name string, c SecretCredential, d Descriptor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateName(name); err != nil {
		return err
	}
	if c.Kind != KindPassword && c.Kind != KindRawKey {
		return fmt.Errorf("credential: unsupported kind %q", c.Kind)
	}
	if len(c.Secret) == 0 {
		return fmt.Errorf("credential: secret is empty")
	}
	payload, err := json.Marshal(struct {
		Kind   Kind   `json:"kind"`
		Secret string `json:"secret"`
	}{c.Kind, base64.StdEncoding.EncodeToString(c.Secret)})
	if err != nil {
		return err
	}
	if err = s.backend.Set(serviceName, name, string(payload)); err != nil {
		return fmt.Errorf("credential: store in OS keychain: %w", err)
	}
	d.Name, d.Kind = name, c.Kind
	list, _ := s.listLocked()
	found := false
	for i := range list {
		if list[i].Name == name {
			list[i] = d
			found = true
		}
	}
	if !found {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	index, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if err = s.backend.Set(serviceName, indexAccount, string(index)); err != nil {
		_ = s.backend.Delete(serviceName, name)
		return fmt.Errorf("credential: update keychain index: %w", err)
	}
	return nil
}
func (s *KeychainStore) Get(ctx context.Context, name string) (SecretCredential, error) {
	if err := ctx.Err(); err != nil {
		return SecretCredential{}, err
	}
	if err := ValidateName(name); err != nil {
		return SecretCredential{}, err
	}
	value, err := s.backend.Get(serviceName, name)
	if err != nil {
		return SecretCredential{}, fmt.Errorf("credential: read OS keychain: %w", err)
	}
	var payload struct {
		Kind   Kind   `json:"kind"`
		Secret string `json:"secret"`
	}
	if err = json.Unmarshal([]byte(value), &payload); err != nil {
		return SecretCredential{}, fmt.Errorf("credential: malformed keychain record: %w", err)
	}
	secret, err := base64.StdEncoding.DecodeString(payload.Secret)
	if err != nil {
		return SecretCredential{}, fmt.Errorf("credential: malformed keychain secret: %w", err)
	}
	return SecretCredential{Kind: payload.Kind, Secret: secret}, nil
}
func (s *KeychainStore) Delete(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := s.backend.Delete(serviceName, name); err != nil {
		return fmt.Errorf("credential: remove from OS keychain: %w", err)
	}
	list, _ := s.listLocked()
	out := list[:0]
	for _, d := range list {
		if d.Name != name {
			out = append(out, d)
		}
	}
	data, _ := json.Marshal(out)
	if err := s.backend.Set(serviceName, indexAccount, string(data)); err != nil {
		return fmt.Errorf("credential: update keychain index: %w", err)
	}
	return nil
}
func (s *KeychainStore) List(ctx context.Context) ([]Descriptor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.listLocked()
}
func (s *KeychainStore) listLocked() ([]Descriptor, error) {
	value, err := s.backend.Get(serviceName, indexAccount)
	if err == keyring.ErrNotFound {
		return []Descriptor{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("credential: list OS keychain: %w", err)
	}
	if len(value) > 1<<20 {
		return nil, fmt.Errorf("credential: keychain index exceeds size limit")
	}
	var list []Descriptor
	if err = json.Unmarshal([]byte(value), &list); err != nil {
		return nil, fmt.Errorf("credential: malformed keychain index: %w", err)
	}
	if len(list) > 1024 {
		return nil, fmt.Errorf("credential: keychain index exceeds entry limit")
	}
	return list, nil
}
