package credentialstore

import (
	"context"
	"errors"
	"sync"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

type memoryBackend struct {
	mu       sync.Mutex
	values   map[string]string
	getError map[string]error
	setError map[string]error
}

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{
		values:   make(map[string]string),
		getError: make(map[string]error),
		setError: make(map[string]error),
	}
}

func (b *memoryBackend) Set(_, user, value string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.setError[user]; err != nil {
		return err
	}
	b.values[user] = value
	return nil
}

func (b *memoryBackend) Get(_, user string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.getError[user]; err != nil {
		return "", err
	}
	value, ok := b.values[user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (b *memoryBackend) Delete(_, user string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.values, user)
	return nil
}

func putTestCredential(t *testing.T, store *KeychainStore, name string) {
	t.Helper()
	if err := store.Put(context.Background(), name, SecretCredential{Kind: KindPassword, Secret: []byte(name + "-secret")}, Descriptor{Fingerprint: name + "-fingerprint"}); err != nil {
		t.Fatalf("Put(%q): %v", name, err)
	}
}

func TestPutPreservesIndexWhenIndexReadFails(t *testing.T) {
	backend := newMemoryBackend()
	store := NewWithBackend(backend)
	putTestCredential(t, store, "alpha")
	putTestCredential(t, store, "bravo")

	backend.mu.Lock()
	backend.getError[indexAccount] = errors.New("simulated keychain read failure")
	backend.mu.Unlock()
	if err := store.Put(context.Background(), "charlie", SecretCredential{Kind: KindPassword, Secret: []byte("charlie-secret")}, Descriptor{}); err == nil {
		t.Fatal("Put succeeded despite unreadable credential index")
	}

	backend.mu.Lock()
	delete(backend.getError, indexAccount)
	backend.mu.Unlock()
	list, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List after failed Put: %v", err)
	}
	if len(list) != 2 || list[0].Name != "alpha" || list[1].Name != "bravo" {
		t.Fatalf("index was changed after failed Put: %+v", list)
	}
	if _, err := store.Get(context.Background(), "charlie"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("failed Put wrote a secret: %v", err)
	}
}

func TestDeletePreservesSecretWhenIndexReadFails(t *testing.T) {
	backend := newMemoryBackend()
	store := NewWithBackend(backend)
	putTestCredential(t, store, "alpha")

	backend.mu.Lock()
	backend.getError[indexAccount] = errors.New("simulated keychain read failure")
	backend.mu.Unlock()
	if err := store.Delete(context.Background(), "alpha"); err == nil {
		t.Fatal("Delete succeeded despite unreadable credential index")
	}

	backend.mu.Lock()
	delete(backend.getError, indexAccount)
	backend.mu.Unlock()
	credential, err := store.Get(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("Delete lost existing secret after failed index read: %v", err)
	}
	if string(credential.Secret) != "alpha-secret" {
		t.Fatalf("restored secret = %q", credential.Secret)
	}
}

func TestPutRollsBackSecretWhenIndexWriteFails(t *testing.T) {
	backend := newMemoryBackend()
	store := NewWithBackend(backend)
	putTestCredential(t, store, "alpha")

	backend.mu.Lock()
	backend.setError[indexAccount] = errors.New("simulated index write failure")
	backend.mu.Unlock()
	if err := store.Put(context.Background(), "alpha", SecretCredential{Kind: KindPassword, Secret: []byte("replacement")}, Descriptor{}); err == nil {
		t.Fatal("Put succeeded despite index write failure")
	}

	backend.mu.Lock()
	delete(backend.setError, indexAccount)
	backend.mu.Unlock()
	credential, err := store.Get(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("Get after failed replacement: %v", err)
	}
	if string(credential.Secret) != "alpha-secret" {
		t.Fatalf("replacement was not rolled back: %q", credential.Secret)
	}
}
